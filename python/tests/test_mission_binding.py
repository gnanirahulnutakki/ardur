from __future__ import annotations

import base64
import json
import time
import urllib.error
import zlib
from pathlib import Path

import jwt
import pytest

import vibap.mission as mission_module
from vibap.mission import MissionStatusUnavailableError, load_mission_declaration
from vibap.passport import MissionPassport, issue_passport
from vibap.proxy import Decision


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url_json(segment: str) -> dict[str, object]:
    padded = segment + ("=" * (-len(segment) % 4))
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


def _tamper_jwt_payload(token: str, updates: dict[str, object]) -> str:
    header, payload, signature = token.split(".")
    claims = _decode_b64url_json(payload)
    claims.update(updates)
    tampered_payload = _b64url(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    return ".".join([header, tampered_payload, signature])


def _status_list_token(private_key, *, idx: int, revoked: bool) -> str:
    size_bits = max(8, idx + 1)
    raw = bytearray((size_bits + 7) // 8)
    if revoked:
        raw[idx // 8] |= 1 << (7 - (idx % 8))
    now = int(time.time())
    claims = {
        "iss": "status-authority",
        "sub": "status-list",
        "iat": now,
        "exp": now + 300,
        "status_list": {
            "bits": 1,
            "lst": _b64url(zlib.compress(bytes(raw))),
        },
    }
    return jwt.encode(claims, private_key, algorithm="ES256")


def _issue_md(private_key, *, mission_id: str, revocation_ref: str) -> str:
    mission = MissionPassport(
        agent_id="md-authority",
        mission="authoritative report mission",
        allowed_tools=["read_file"],
        forbidden_tools=["delete_file"],
        resource_scope=["/allowed/*"],
        max_tool_calls=3,
        max_duration_s=120,
        delegation_allowed=False,
        max_delegation_depth=0,
    )
    return issue_passport(
        mission,
        private_key,
        ttl_s=120,
        extra_claims={
            "mission_id": mission_id,
            "revocation_ref": revocation_ref,
        },
    )


def _issue_dg(private_key, *, mission_ref: dict[str, str] | str) -> str:
    dg = MissionPassport(
        agent_id="delegate-agent",
        mission="delegated task",
        allowed_tools=["read_file", "delete_file"],
        forbidden_tools=[],
        resource_scope=["/wide/*"],
        max_tool_calls=20,
        max_duration_s=120,
        delegation_allowed=False,
        max_delegation_depth=0,
    )
    return issue_passport(dg, private_key, ttl_s=120, extra_claims={"mission_ref": mission_ref})


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


@pytest.fixture(autouse=True)
def _isolate_mission_fetch_binding(monkeypatch):
    original_urlopen = mission_module.urllib.request.urlopen
    monkeypatch.setattr(mission_module, "urlopen", original_urlopen)
    yield
    monkeypatch.setattr(mission_module, "urlopen", original_urlopen)


def _install_fetch_map(monkeypatch, mapping: dict[str, str | Exception]) -> list[str]:
    calls: list[str] = []

    def fake_urlopen(request, timeout=0, context=None):  # noqa: ANN001, ARG001
        url = request.full_url if hasattr(request, "full_url") else str(request)
        calls.append(url)
        value = mapping[url]
        if isinstance(value, Exception):
            raise value
        return _Response(value)

    monkeypatch.setattr(mission_module, "urlopen", fake_urlopen)
    return calls


def _receipt_entries(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_proxy_verifies_md_and_emits_receipt(proxy, private_key, public_key, monkeypatch):
    mission_id = "urn:ardur:mission:test:permit"
    md_url = "https://issuer.example/md/permit.jwt"
    status_url = "https://issuer.example/status/permit.jwt"
    revocation_ref = status_url + "#idx=4"
    md_token = _issue_md(private_key, mission_id=mission_id, revocation_ref=revocation_ref)
    md = load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: _status_list_token(private_key, idx=4, revoked=False),
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(
        session,
        "read_file",
        {"path": "/allowed/report.txt", "operator_id": "op-1"},
    )

    assert decision == Decision.PERMIT
    assert reason == "within scope"
    receipts = _receipt_entries(proxy.receipts_log_path)
    assert len(receipts) == 1
    assert receipts[0]["grant_id"] == session.jti
    assert receipts[0]["verdict"] == "compliant"


def test_md_policy_is_authoritative_over_dg_scope(proxy, private_key, public_key, monkeypatch):
    mission_id = "urn:ardur:mission:test:scope"
    md_url = "https://issuer.example/md/scope.jwt"
    status_url = "https://issuer.example/status/scope.jwt"
    md_token = _issue_md(private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=1")
    md = load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={"uri": md_url, "mission_id": mission_id, "mission_digest": md.payload_digest},
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: _status_list_token(private_key, idx=1, revoked=False),
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(session, "read_file", {"path": "/wide/report.txt"})

    assert decision == Decision.DENY
    assert "outside resource_scope" in reason


def test_revoked_md_returns_violation(proxy, private_key, public_key, monkeypatch):
    mission_id = "urn:ardur:mission:test:revoked"
    md_url = "https://issuer.example/md/revoked.jwt"
    status_url = "https://issuer.example/status/revoked.jwt"
    md_token = _issue_md(private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=7")
    md = load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={"uri": md_url, "mission_id": mission_id, "mission_digest": md.payload_digest},
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: _status_list_token(private_key, idx=7, revoked=True),
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(session, "read_file", {"path": "/allowed/report.txt"})

    assert decision == Decision.VIOLATION
    assert reason == "revoked"

def test_tampered_md_returns_chain_invalid(tmp_path, private_key, public_key, session_keys_dir, monkeypatch):
    from vibap.proxy import GovernanceProxy
    proxy = GovernanceProxy(
        log_path=tmp_path / "tampered_log.jsonl",
        state_dir=tmp_path / "tampered_state",
        public_key=public_key,
        keys_dir=session_keys_dir,
    )
    mission_id = "urn:ardur:mission:test:tampered"
    md_url = "https://issuer.example/md/tampered.jwt"
    status_url = "https://issuer.example/status/tampered.jwt"
    md_token = _issue_md(private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=2")
    md = load_mission_declaration(md_token, public_key)
    tampered = _tamper_jwt_payload(md_token, {"mission": "tampered mission"})
    dg_token = _issue_dg(
        private_key,
        mission_ref={"uri": md_url, "mission_id": mission_id, "mission_digest": md.payload_digest},
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: tampered,
            status_url: _status_list_token(private_key, idx=2, revoked=False),
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(session, "read_file", {"path": "/allowed/report.txt"})

    assert decision == Decision.VIOLATION
    assert reason == "chain_invalid"


def test_status_list_network_error_fails_closed(proxy, private_key, public_key, monkeypatch):
    mission_id = "urn:ardur:mission:test:network"
    md_url = "https://issuer.example/md/network.jwt"
    status_url = "https://issuer.example/status/network.jwt"
    md_token = _issue_md(private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=5")
    md = load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={"uri": md_url, "mission_id": mission_id, "mission_digest": md.payload_digest},
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: urllib.error.URLError("boom"),
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(session, "read_file", {"path": "/allowed/report.txt"})

    assert decision == Decision.INSUFFICIENT_EVIDENCE
    assert reason == "revocation_unavailable"


def test_oversized_status_list_rejected(proxy, private_key, public_key, monkeypatch):
    mission_id = "urn:ardur:mission:test:oversized-status-list"
    md_url = "https://issuer.example/md/oversized.jwt"
    status_url = "https://issuer.example/status/oversized.jwt"
    md_token = _issue_md(private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=0")
    md = load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={"uri": md_url, "mission_id": mission_id, "mission_digest": md.payload_digest},
    )

    oversized_body = b"x" * ((2 << 20) + 1)
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: oversized_body,
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(session, "read_file", {"path": "/allowed/report.txt"})

    assert decision == Decision.INSUFFICIENT_EVIDENCE
    assert reason == "status_list_too_large"
    with pytest.raises(MissionStatusUnavailableError, match="size limit"):
        mission_module._fetch_text(status_url)


def test_zip_bomb_rejected(proxy, private_key, public_key, monkeypatch):
    mission_id = "urn:ardur:mission:test:zip-bomb"
    md_url = "https://issuer.example/md/zip-bomb.jwt"
    status_url = "https://issuer.example/status/zip-bomb.jwt"
    revocation_ref = status_url + "#idx=0"
    md_token = _issue_md(private_key, mission_id=mission_id, revocation_ref=revocation_ref)
    md = load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={"uri": md_url, "mission_id": mission_id, "mission_digest": md.payload_digest},
    )

    compressed = zlib.compress(b"\x00" * (mission_module.MAX_DECOMPRESSED_BYTES + 1024))
    claims = jwt.encode(
        {
            "iss": "status-authority",
            "sub": "status-list",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "status_list": {
                "bits": 1,
                "lst": _b64url(compressed),
            },
        },
        private_key,
        algorithm="ES256",
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: claims,
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(session, "read_file", {"path": "/allowed/report.txt"})

    assert decision == Decision.INSUFFICIENT_EVIDENCE
    assert reason == "status_list_too_large"
    with pytest.raises(MissionStatusUnavailableError, match="decompression limit"):
        mission_module.mission_is_revoked(md, public_key)


def test_mission_cache_avoids_refetching_md(proxy, private_key, public_key, monkeypatch):
    mission_id = "urn:ardur:mission:test:cache"
    md_url = "https://issuer.example/md/cache.jwt"
    status_url = "https://issuer.example/status/cache.jwt"
    md_token = _issue_md(private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=3")
    md = load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={"uri": md_url, "mission_id": mission_id, "mission_digest": md.payload_digest},
    )
    calls = _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: _status_list_token(private_key, idx=3, revoked=False),
        },
    )

    session = proxy.start_session(dg_token)
    first = proxy.evaluate_tool_call(session, "read_file", {"path": "/allowed/one.txt"})
    second = proxy.evaluate_tool_call(session, "read_file", {"path": "/allowed/two.txt"})

    assert first[0] == Decision.PERMIT
    assert second[0] == Decision.PERMIT
    assert calls.count(md_url) == 1
    assert calls.count(status_url) == 2


@pytest.mark.parametrize(
    "url,reason",
    [
        ("https://169.254.169.254/latest/meta-data/iam/", "AWS IMDS"),
        ("https://127.0.0.1:8080/md.jwt", "loopback"),
        ("https://10.0.0.1/md.jwt", "RFC1918 class A"),
        ("https://192.168.1.10/md.jwt", "RFC1918 class C"),
        ("https://172.16.0.5/md.jwt", "RFC1918 class B"),
        ("https://[::1]/md.jwt", "IPv6 loopback"),
        ("https://[fe80::1]/md.jwt", "IPv6 link-local"),
    ],
)
def test_fetch_rejects_ssrf_target_ip_classes(url, reason):
    """M1 regression: _assert_public_target must reject IP-literal URLs
    pointing at loopback, RFC1918, link-local, and IMDS ranges."""
    from vibap.mission import MissionBindingError, _assert_public_target
    with pytest.raises(MissionBindingError, match="non-public IP"):
        _assert_public_target(url)


def test_fetch_accepts_public_ip_literal():
    """M1 sanity: a public IP literal must NOT be blocked by _assert_public_target."""
    from vibap.mission import _assert_public_target
    _assert_public_target("https://8.8.8.8/foo")  # should not raise
