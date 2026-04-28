from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
import pytest

import vibap.mission as mission_module
from vibap.mission import load_mission_declaration
from vibap.passport import ALGORITHM, MissionPassport, issue_passport
from vibap.proxy import Decision
from vibap.receipt import verify_chain


class _Response:
    def __init__(self, body: str | bytes) -> None:
        self._body = body.encode("utf-8") if isinstance(body, str) else body

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return self._body
        return self._body[:size]

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def _install_fetch_map(monkeypatch, mapping: dict[str, str]) -> None:
    def fake_urlopen(request, timeout=0, context=None):  # noqa: ANN001, ARG001
        url = request.full_url if hasattr(request, "full_url") else str(request)
        return _Response(mapping[url])

    monkeypatch.setattr(mission_module, "urlopen", fake_urlopen)


def _issue_md(
    private_key,
    *,
    mission_id: str,
    allowed_tools: list[str] | None = None,
    max_tool_calls: int = 3,
) -> str:
    mission = MissionPassport(
        agent_id="md-authority",
        mission="authoritative AAT-backed mission",
        allowed_tools=allowed_tools or ["read"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=max_tool_calls,
        max_duration_s=300,
        delegation_allowed=True,
        max_delegation_depth=2,
    )
    return issue_passport(
        mission,
        private_key,
        ttl_s=300,
        extra_claims={"mission_id": mission_id},
    )


def _issue_aat(
    private_key,
    *,
    mission_ref: dict[str, str] | None,
    tools: list[str],
    max_tool_calls: int = 2,
    grant_id: str | None = None,
    aat_type: str = "delegation",
    del_depth: int = 0,
    del_max_depth: int = 2,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "https://tenuo.example/issuer",
        "sub": "aat-agent",
        "iat": now,
        "exp": now + 300,
        "jti": grant_id or str(uuid.uuid4()),
        "aat_type": aat_type,
        "del_depth": del_depth,
        "del_max_depth": del_max_depth,
        "authorization_details": [
            {
                "type": "attenuating_agent_token",
                "tools": {tool: {} for tool in tools},
                "max_tool_calls": max_tool_calls,
            }
        ],
        "cnf": {"jwk": {"kid": "holder-key"}},
    }
    if mission_ref is not None:
        claims["mission_ref"] = mission_ref
    return jwt.encode(claims, private_key, algorithm=ALGORITHM)


def _receipt_entries(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_start_session_from_aat_evaluates_and_emits_mission_bound_receipt(
    proxy,
    private_key,
    public_key,
    monkeypatch,
):
    mission_id = "urn:ardur:mission:aat:permit"
    md_url = "https://issuer.example/md/aat-permit.jwt"
    md_token = _issue_md(private_key, mission_id=mission_id)
    md = load_mission_declaration(md_token, public_key)
    _install_fetch_map(monkeypatch, {md_url: md_token})
    aat_jti = str(uuid.uuid4())
    aat_token = _issue_aat(
        private_key,
        grant_id=aat_jti,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
        tools=["read"],
    )

    session = proxy.start_session_from_aat(aat_token, signing_key=private_key)
    decision, reason = proxy.evaluate_tool_call(session, "read", {})

    assert session.jti == aat_jti
    assert session.passport_claims["credential_format"] == "aat-compatible-jwt"
    assert session.passport_claims["aat_grant_id"] == aat_jti
    assert session.passport_claims["mission_digest"] == md.payload_digest
    assert decision == Decision.PERMIT
    assert reason == "within scope"

    entries = _receipt_entries(proxy.receipts_log_path)
    claims = verify_chain([entry["jwt"] for entry in entries], public_key)
    assert claims[0]["grant_id"] == aat_jti
    assert claims[0]["evidence_proof_ref"]["mission_digest"] == md.payload_digest


def test_aat_missing_mission_ref_fails_closed(proxy, private_key):
    aat_token = _issue_aat(private_key, mission_ref=None, tools=["read"])

    with pytest.raises(PermissionError, match="mission_ref"):
        proxy.start_session_from_aat(aat_token, signing_key=private_key)


def test_aat_mission_digest_mismatch_fails_closed(
    proxy,
    private_key,
    public_key,
    monkeypatch,
):
    mission_id = "urn:ardur:mission:aat:digest"
    md_url = "https://issuer.example/md/aat-digest.jwt"
    md_token = _issue_md(private_key, mission_id=mission_id)
    _install_fetch_map(monkeypatch, {md_url: md_token})
    aat_token = _issue_aat(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": "sha-256:" + ("0" * 64),
        },
        tools=["read"],
    )

    with pytest.raises(PermissionError, match="mission_digest"):
        proxy.start_session_from_aat(aat_token, signing_key=private_key)


def test_aat_unsupported_token_shape_fails_closed(proxy, private_key):
    aat_token = _issue_aat(
        private_key,
        mission_ref={"uri": "https://issuer.example/md/unused.jwt"},
        tools=["read"],
        aat_type="execution",
    )

    with pytest.raises(PermissionError, match="aat_type"):
        proxy.start_session_from_aat(aat_token, signing_key=private_key)


def test_aat_child_tool_widening_fails_closed(
    proxy,
    private_key,
    public_key,
    monkeypatch,
):
    mission_id = "urn:ardur:mission:aat:widen"
    md_url = "https://issuer.example/md/aat-widen.jwt"
    md_token = _issue_md(
        private_key,
        mission_id=mission_id,
        allowed_tools=["read", "delete_file"],
    )
    md = load_mission_declaration(md_token, public_key)
    _install_fetch_map(monkeypatch, {md_url: md_token})
    mission_ref = {
        "uri": md_url,
        "mission_id": mission_id,
        "mission_digest": md.payload_digest,
    }
    parent = _issue_aat(
        private_key,
        mission_ref=mission_ref,
        tools=["read"],
        max_tool_calls=2,
    )
    child = _issue_aat(
        private_key,
        mission_ref=mission_ref,
        tools=["read", "delete_file"],
        max_tool_calls=1,
        del_depth=1,
        del_max_depth=2,
    )

    with pytest.raises(PermissionError, match="widens parent tools"):
        proxy.start_session_from_aat(
            child,
            signing_key=private_key,
            parent_aat_token=parent,
        )


# H2: AAT proof-of-possession enforcement. Before this, cnf was structurally
# copied into extra_claims["aat_cnf"] but never verified — a captured AAT could
# be replayed by anyone who observed it. Setting require_pop=True now demands
# holder_public_key + kb_jwt when the AAT carries a cnf claim.
class TestAATProofOfPossession:
    def test_cnf_without_pop_inputs_raises_when_require_pop_true(
        self, proxy, private_key, tmp_path, monkeypatch
    ):
        from vibap.aat_adapter import material_from_aat_grant
        from vibap.mission import MissionCache

        # Mint an authoritative mission declaration so the adapter can resolve mission_ref.
        mission_id = "urn:mission:pop-test"
        md_jwt = _issue_md(private_key, mission_id=mission_id)
        md_url = "https://tenuo.example/missions/pop-test"
        _install_fetch_map(monkeypatch, {md_url: md_jwt})
        aat_token = _issue_aat(
            private_key,
            mission_ref={
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": load_mission_declaration(
                    md_jwt, proxy.public_key
                ).payload_digest,
            },
            tools=["read"],
        )
        cache = MissionCache()
        with pytest.raises(PermissionError, match="PoP inputs were not supplied"):
            material_from_aat_grant(
                aat_token,
                proxy.public_key,
                cache,
                require_pop=True,
            )

    def test_cnf_without_pop_inputs_is_accepted_when_require_pop_false(
        self, proxy, private_key, tmp_path, monkeypatch
    ):
        """Default back-compat behavior: legacy callers (require_pop unset)
        retain bearer-style acceptance."""
        from vibap.aat_adapter import material_from_aat_grant
        from vibap.mission import MissionCache

        mission_id = "urn:mission:pop-backcompat"
        md_jwt = _issue_md(private_key, mission_id=mission_id)
        md_url = "https://tenuo.example/missions/pop-backcompat"
        _install_fetch_map(monkeypatch, {md_url: md_jwt})
        aat_token = _issue_aat(
            private_key,
            mission_ref={
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": load_mission_declaration(
                    md_jwt, proxy.public_key
                ).payload_digest,
            },
            tools=["read"],
        )
        cache = MissionCache()
        material = material_from_aat_grant(
            aat_token,
            proxy.public_key,
            cache,
            # require_pop defaults to False — cnf is copied structurally only.
        )
        assert material.extra_claims["aat_cnf"] == {"jwk": {"kid": "holder-key"}}

    def test_bearer_aat_no_cnf_accepted_with_require_pop_true(
        self, proxy, private_key, tmp_path, monkeypatch
    ):
        """An AAT without any cnf claim is bearer-mode and must be accepted
        even when require_pop=True — the flag only gates cnf-carrying AATs."""
        from vibap.aat_adapter import material_from_aat_grant
        from vibap.mission import MissionCache

        mission_id = "urn:mission:bearer-aat"
        md_jwt = _issue_md(private_key, mission_id=mission_id)
        md_url = "https://tenuo.example/missions/bearer-aat"
        _install_fetch_map(monkeypatch, {md_url: md_jwt})

        # Issue an AAT WITHOUT cnf (strip via custom claim set).
        now = int(time.time())
        grant_id = str(uuid.uuid4())
        claims = {
            "iss": "https://tenuo.example/issuer",
            "sub": "aat-agent",
            "iat": now,
            "exp": now + 300,
            "jti": grant_id,
            "aat_type": "delegation",
            "del_depth": 0,
            "del_max_depth": 2,
            "authorization_details": [
                {
                    "type": "attenuating_agent_token",
                    "tools": {"read": {}},
                    "max_tool_calls": 2,
                }
            ],
            "mission_ref": {
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": load_mission_declaration(
                    md_jwt, proxy.public_key
                ).payload_digest,
            },
        }
        aat_token = jwt.encode(claims, private_key, algorithm=ALGORITHM)

        cache = MissionCache()
        material = material_from_aat_grant(
            aat_token,
            proxy.public_key,
            cache,
            require_pop=True,  # still accepted because no cnf in the AAT
        )
        assert "aat_cnf" not in material.extra_claims
        assert material.grant_id == grant_id
