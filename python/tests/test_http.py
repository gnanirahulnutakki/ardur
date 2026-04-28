"""HTTP endpoint tests.

We don't spawn a full subprocess (too slow, fragile on CI) — instead we
instantiate a ThreadingHTTPServer in-process on an ephemeral port and drive
it with urllib. This matches the real code path in serve_proxy except for
signal handling, which we don't exercise."""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from typing import Any

import jwt
import pytest

# We reach inside serve_proxy to grab the Handler class. The simplest path
# that preserves the production code path is to re-import and re-build the
# server via the public function's logic. Here we clone enough of serve_proxy
# to stand up an HTTP server for testing. If serve_proxy gets refactored into
# a factory, swap this for a direct call.
import vibap.mission as mission_module
from vibap.mission import load_mission_declaration
from vibap.passport import ALGORITHM, MissionPassport, issue_passport, verify_passport
from vibap.proxy import GovernanceProxy, serve_proxy
from vibap.receipt import verify_chain


def _build_server_thread(proxy: GovernanceProxy, private_key, port: int):
    """Start serve_proxy in a background daemon thread bound to 127.0.0.1:port.

    Returns (thread, server_url, shutdown_callable). We monkeypatch
    ThreadingHTTPServer.serve_forever to return after shutdown and
    avoid registering a SIGTERM handler in a thread (signals only work on
    the main thread)."""
    # Swap serve_proxy's signal.signal for a no-op in this thread via a
    # monkeypatch-free approach: we run the server manually here.
    # Easier path: import the Handler factory used internally. But it's a
    # closure inside serve_proxy, so we simply call serve_proxy and let it
    # install its signal handler — signal.signal() from a non-main thread
    # raises ValueError. To work around, monkeypatch signal.signal before
    # running.
    import signal as _signal

    original = _signal.signal
    _signal.signal = lambda *_a, **_kw: None  # type: ignore[assignment]

    stop_event = threading.Event()

    def run() -> None:
        try:
            serve_proxy(
                proxy=proxy,
                private_key=private_key,
                host="127.0.0.1",
                port=port,
                require_auth=False,
            )
        finally:
            stop_event.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    # Wait for the server to respond to /health.
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 5
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/health", timeout=0.5) as resp:
                if resp.status == 200:
                    break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(0.05)
    else:
        raise RuntimeError(f"proxy never became healthy: {last_exc}")

    def shutdown() -> None:
        # Send a shutdown by closing the server via an internal request.
        # ThreadingHTTPServer exposes shutdown() but we don't have a handle to
        # the server instance. Fallback: rely on daemon=True + test process
        # teardown. This is fine for unit tests.
        _signal.signal = original

    return thread, base, shutdown


def _post(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    status, body, _ = _post_with_headers(url, payload)
    return status, body


def _post_with_headers(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, str]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"raw": body}
        return exc.code, parsed, dict(exc.headers.items())


def _get(url: str) -> tuple[int, dict[str, Any]]:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def http_proxy(proxy, private_key, unused_tcp_port):
    thread, base, shutdown = _build_server_thread(proxy, private_key, unused_tcp_port)
    yield base, proxy
    shutdown()


class TestHTTPHealth:
    def test_get_health_returns_200(self, http_proxy):
        base, _ = http_proxy
        status, body = _get(base + "/health")
        assert status == 200
        assert body["status"] == "ok"
        assert "version" in body


class TestHTTPEvaluate:
    def test_permit_decision(self, http_proxy, example_mission, private_key):
        base, _ = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        status, start = _post(base + "/session/start", {"token": token})
        assert status == 200
        session_id = start["session_id"]

        status, body = _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "read_file", "arguments": {"path": "/x"}},
        )
        assert status == 200
        assert body["decision"] == "PERMIT"

    def test_deny_decision(self, http_proxy, example_mission, private_key):
        base, _ = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        _, start = _post(base + "/session/start", {"token": token})
        session_id = start["session_id"]

        status, body = _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "delete_file", "arguments": {}},
        )
        assert status == 200
        assert body["decision"] == "DENY"
        assert "reason" in body

    def test_revoked_active_session_returns_403(self, http_proxy, example_mission, private_key):
        base, proxy = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        _, start = _post(base + "/session/start", {"token": token})
        session_id = start["session_id"]

        status, body = _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "read_file", "arguments": {"path": "/x"}},
        )
        assert status == 200
        assert body["decision"] == "PERMIT"

        proxy.revoke(session_id)

        status, body = _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "read_file", "arguments": {"path": "/x"}},
        )
        assert status == 403
        assert body == {"error": "passport_revoked"}


class TestHTTPDelegate:
    def test_valid_delegation_returns_200(self, http_proxy, private_key):
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="p",
            allowed_tools=["read", "write"],
            delegation_allowed=True,
            max_delegation_depth=2,
            max_duration_s=300,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        # Parent session must be started before delegation (Phase 2e / gemini F3)
        _post(base + "/session/start", {"token": parent_token})
        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child",
                "child_mission": "sub",
                "child_allowed_tools": ["read"],
                "child_ttl_s": 60,
            },
        )
        assert status == 200
        assert "child_token" in body
        assert body["child_claims"]["allowed_tools"] == ["read"]

    def test_delegation_escalation_returns_403(self, http_proxy, private_key):
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="p",
            allowed_tools=["read"],
            delegation_allowed=True,
            max_delegation_depth=2,
            max_duration_s=300,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _post(base + "/session/start", {"token": parent_token})
        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child",
                "child_mission": "evil",
                "child_allowed_tools": ["read", "rm_rf"],
                "child_ttl_s": 60,
            },
        )
        assert status == 403
        assert "scope escalation" in body.get("error", "")

    def test_duplicate_delegation_request_id_is_idempotent(
        self, http_proxy, private_key
    ):
        base, proxy = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=1,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})

        request = {
            "parent_token": parent_token,
            "child_agent_id": "child",
            "child_mission": "sub",
            "child_allowed_tools": ["read"],
            "child_max_tool_calls": 1,
            "delegation_request_id": "retry-1",
        }

        status1, body1 = _post(base + "/delegate", request)
        status2, body2 = _post(base + "/delegate", request)

        assert status1 == 200
        assert status2 == 200
        assert body1["child_claims"]["max_tool_calls"] == 1
        assert body2["child_claims"]["max_tool_calls"] == 1
        snapshot = proxy.lineage_budget_ledger.snapshot(start["session_id"])
        assert snapshot["reserved_total"] == 1
        assert len(snapshot["reservations"]) == 1

    def test_conflicting_delegation_request_id_returns_409(
        self, http_proxy, private_key
    ):
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=2,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _post(base + "/session/start", {"token": parent_token})

        first = {
            "parent_token": parent_token,
            "child_agent_id": "child-a",
            "child_mission": "sub",
            "child_allowed_tools": ["read"],
            "child_max_tool_calls": 1,
            "delegation_request_id": "dup",
        }
        second = dict(first, child_agent_id="child-b")

        status1, _ = _post(base + "/delegate", first)
        status2, body2 = _post(base + "/delegate", second)

        assert status1 == 200
        assert status2 == 409
        assert "different reservation" in body2.get("error", "")

    def test_two_http_proxies_shared_state_concurrent_sibling_budget(
        self, tmp_path, public_key, private_key, session_keys_dir
    ):
        shared_state = tmp_path / "shared-state"
        p1 = GovernanceProxy(
            log_path=tmp_path / "p1.jsonl",
            state_dir=shared_state,
            public_key=public_key,
            keys_dir=session_keys_dir,
        )
        p2 = GovernanceProxy(
            log_path=tmp_path / "p2.jsonl",
            state_dir=shared_state,
            public_key=public_key,
            keys_dir=session_keys_dir,
        )
        _, base1, shutdown1 = _build_server_thread(p1, private_key, _free_port())
        _, base2, shutdown2 = _build_server_thread(p2, private_key, _free_port())
        try:
            parent_mission = MissionPassport(
                agent_id="parent",
                mission="coord",
                allowed_tools=["read"],
                max_tool_calls=5,
                delegation_allowed=True,
                max_delegation_depth=2,
            )
            parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
            _, start = _post(base1 + "/session/start", {"token": parent_token})

            def delegate(i: int) -> tuple[int, dict[str, Any]]:
                base = base1 if i % 2 == 0 else base2
                return _post(
                    base + "/delegate",
                    {
                        "parent_token": parent_token,
                        "child_agent_id": f"child-{i}",
                        "child_mission": f"sub-{i}",
                        "child_allowed_tools": ["read"],
                        "child_max_tool_calls": 1,
                        "delegation_request_id": f"r{i}",
                    },
                )

            with ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(delegate, range(24)))

            accepted = [
                body["child_claims"]["max_tool_calls"]
                for status, body in results
                if status == 200
            ]
            rejected = [status for status, _ in results if status != 200]

            assert sum(accepted) == 5
            assert all(status == 403 for status in rejected)
            assert p1.lineage_budget_ledger.snapshot(start["session_id"])[
                "reserved_total"
            ] == 5
        finally:
            shutdown2()
            shutdown1()


class TestHTTPAuthAndValidation:
    @pytest.mark.parametrize(
        ("path", "payload"),
        [
            ("/verify", {"token": "not-a-jwt"}),
            ("/session/start", {"token": "not-a-jwt"}),
            ("/sessions", {"token": "not-a-jwt"}),
            (
                "/delegate",
                {
                    "parent_token": "not-a-jwt",
                    "child_agent_id": "child",
                    "child_mission": "subtask",
                    "child_allowed_tools": ["read"],
                },
            ),
        ],
    )
    def test_invalid_jwt_returns_401_with_www_authenticate(
        self, http_proxy, path, payload
    ):
        base, _ = http_proxy
        status, body, headers = _post_with_headers(base + path, payload)
        assert status == 401
        assert body == {"error": "invalid_token"}
        assert headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'

    def test_issue_with_non_object_mission_returns_400(self, http_proxy):
        base, _ = http_proxy
        status, body = _post(base + "/issue", {"mission": None})
        assert status == 400
        assert body == {"error": "mission must be a JSON object"}

    def test_delegate_rejects_string_child_tools_before_char_splitting(
        self, http_proxy, private_key
    ):
        base, _ = http_proxy
        parent = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent, private_key, ttl_s=300)
        _post(base + "/session/start", {"token": parent_token})

        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child",
                "child_mission": "sub",
                "child_allowed_tools": "read",
            },
        )

        assert status == 400
        assert body == {
            "error": "child_allowed_tools must be a JSON array of non-empty strings"
        }

    def test_delegate_rejects_string_child_resource_scope_before_char_splitting(
        self, http_proxy, private_key
    ):
        base, _ = http_proxy
        parent = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            resource_scope=["/data/*"],
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent, private_key, ttl_s=300)
        _post(base + "/session/start", {"token": parent_token})

        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "child",
                "child_mission": "sub",
                "child_allowed_tools": ["read"],
                "child_resource_scope": "/data/*",
            },
        )

        assert status == 400
        assert body == {
            "error": "child_resource_scope must be a JSON array of non-empty strings"
        }


class TestHTTPSessionEnd:
    def test_session_end_includes_attestation(self, http_proxy, example_mission, private_key):
        base, _ = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        _, start = _post(base + "/session/start", {"token": token})
        session_id = start["session_id"]

        _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "read_file", "arguments": {}},
        )
        status, body = _post(base + "/session/end", {"session_id": session_id})
        assert status == 200
        assert "attestation_token" in body
        assert "summary" in body
        assert body["summary"]["permits"] >= 1

    def test_session_start_returns_503_when_replay_cache_deleted(self, http_proxy, example_mission, private_key):
        base, proxy = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        _post(base + "/session/start", {"token": token})
        proxy.replay_cache_path.unlink()
        fresh_token = issue_passport(example_mission, private_key, ttl_s=60)

        status, body = _post(base + "/session/start", {"token": fresh_token})
        assert status == 503
        assert body == {"error": "replay_cache_unavailable"}

    def test_attest_is_idempotent_after_end(self, http_proxy, example_mission, private_key):
        base, _ = http_proxy
        token = issue_passport(example_mission, private_key, ttl_s=60)
        _, start = _post(base + "/session/start", {"token": token})
        session_id = start["session_id"]

        _post(
            base + "/evaluate",
            {"session_id": session_id, "tool_name": "read_file", "arguments": {}},
        )
        status, body = _post(base + "/end", {"session": session_id})
        assert status == 200
        assert "summary" in body

        status1, attestation1 = _post(base + "/attest", {"session": session_id})
        time.sleep(1.1)
        status2, attestation2 = _post(base + "/attest", {"session": session_id})

        assert status1 == 200
        assert status2 == 200
        assert attestation1 == attestation2


class TestDelegateRequiresActiveParentSession:
    """Regression test for gemini F3: /delegate previously fell back to the
    parent's ceiling if the parent session wasn't in the in-memory dict.
    Now it must refuse unless there's a persisted session for the parent jti."""

    def test_delegate_without_started_parent_returns_403(
        self, http_proxy, private_key
    ):
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=100,  # Big budget
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)

        # Do NOT call /session/start. Attempt to delegate directly.
        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c",
                "child_mission": "sub",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 999,  # try to get huge budget
            },
        )
        assert status == 403
        assert "parent session" in body.get("error", "").lower()

    def test_delegate_with_ended_parent_returns_403(
        self, http_proxy, private_key
    ):
        """A parent session that's been ended should not be able to spawn children."""
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=100,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})
        session_id = start["session_id"]
        _post(base + "/session/end", {"session_id": session_id})

        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c",
                "child_mission": "sub",
                "child_allowed_tools": ["read"],
            },
        )
        assert status == 403
        assert "ended" in body.get("error", "").lower()

    def test_delegate_with_active_parent_caps_child_at_remaining(
        self, http_proxy, private_key
    ):
        """With a real parent session that has used some budget, the child's
        budget is clamped to the remaining, not the ceiling."""
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=10,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})
        session_id = start["session_id"]

        # Burn 7 calls of the 10 budget
        for _ in range(7):
            _post(base + "/evaluate", {
                "session_id": session_id,
                "tool_name": "read",
                "arguments": {},
            })

        # Delegate — parent has 3 remaining; child should get at most 3
        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c",
                "child_mission": "sub",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 999,  # ask for way more
            },
        )
        assert status == 200
        assert body["child_claims"]["max_tool_calls"] == 3
        assert body["parent_calls_remaining_at_delegation"] == 3


class _AATResponse:
    def __init__(self, body: str | bytes) -> None:
        self._body = body.encode("utf-8") if isinstance(body, str) else body

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return self._body
        return self._body[:size]

    def __enter__(self) -> "_AATResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def _install_aat_fetch_map(monkeypatch, mapping: dict[str, str]) -> None:
    def fake_urlopen(request, timeout=0, context=None):  # noqa: ANN001, ARG001
        url = request.full_url if hasattr(request, "full_url") else str(request)
        return _AATResponse(mapping[url])

    monkeypatch.setattr(mission_module, "urlopen", fake_urlopen)


def _issue_aat_md(private_key, *, mission_id: str) -> str:
    mission = MissionPassport(
        agent_id="md-authority",
        mission="authoritative AAT HTTP mission",
        allowed_tools=["read"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=3,
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


def _issue_aat_http_token(
    private_key,
    *,
    mission_ref: dict[str, str],
    tools: list[str],
    grant_id: str | None = None,
) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": "https://tenuo.example/issuer",
            "sub": "aat-http-agent",
            "iat": now,
            "exp": now + 300,
            "jti": grant_id or str(uuid.uuid4()),
            "aat_type": "delegation",
            "del_depth": 0,
            "del_max_depth": 2,
            "mission_ref": mission_ref,
            "authorization_details": [
                {
                    "type": "attenuating_agent_token",
                    "tools": {tool: {} for tool in tools},
                    "max_tool_calls": 2,
                }
            ],
            "cnf": {"jwk": {"kid": "holder-key"}},
        },
        private_key,
        algorithm=ALGORITHM,
    )


class TestHTTPAATInterop:
    def test_aat_session_evaluate_delegate_receipt_chain(
        self, http_proxy, private_key, public_key, monkeypatch
    ):
        base, proxy = http_proxy
        mission_id = "urn:ardur:mission:aat:http"
        md_url = "https://issuer.example/md/aat-http.jwt"
        md_token = _issue_aat_md(private_key, mission_id=mission_id)
        md = load_mission_declaration(md_token, public_key)
        _install_aat_fetch_map(monkeypatch, {md_url: md_token})
        aat_jti = str(uuid.uuid4())
        aat_token = _issue_aat_http_token(
            private_key,
            grant_id=aat_jti,
            mission_ref={
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": md.payload_digest,
            },
            tools=["read"],
        )

        status, start = _post(
            base + "/session/start",
            {"token_type": "aat", "token": aat_token},
        )
        assert status == 200
        assert start["session_id"] == aat_jti
        assert start["credential_format"] == "aat-compatible-jwt"

        status, body = _post(
            base + "/evaluate",
            {"session_id": aat_jti, "tool_name": "read", "arguments": {}},
        )
        assert status == 200
        assert body["decision"] == "PERMIT"

        status, delegated = _post(
            base + "/delegate",
            {
                "parent_token": aat_token,
                "child_agent_id": "aat-child",
                "child_mission": "subtask",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 1,
                "delegation_request_id": "aat-http-child",
            },
        )
        assert status == 200
        assert delegated["parent_jti"] == aat_jti

        entries = [
            json.loads(line)
            for line in proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
        ]
        claims = verify_chain([entry["jwt"] for entry in entries], public_key)
        assert [claim["tool"] for claim in claims] == ["read", "delegate_passport"]
        assert {claim["grant_id"] for claim in claims} == {aat_jti}
        assert claims[0]["evidence_proof_ref"]["mission_digest"] == md.payload_digest

    def test_delegate_reserves_budget_across_siblings(
        self, http_proxy, private_key
    ):
        """Round-3 H1: sibling delegations must not reuse the same remainder snapshot."""
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=10,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})
        session_id = start["session_id"]

        for _ in range(7):
            _post(base + "/evaluate", {
                "session_id": session_id,
                "tool_name": "read",
                "arguments": {},
            })

        status1, body1 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c1",
                "child_mission": "sub-1",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 2,
            },
        )
        assert status1 == 200
        assert body1["child_claims"]["max_tool_calls"] == 2
        assert body1["parent_calls_remaining_at_delegation"] == 3

        status2, body2 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c2",
                "child_mission": "sub-2",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 2,
            },
        )
        assert status2 == 200
        assert body2["child_claims"]["max_tool_calls"] == 1
        assert body2["parent_calls_remaining_at_delegation"] == 1

        status3, body3 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c3",
                "child_mission": "sub-3",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 1,
            },
        )
        assert status3 == 403
        assert "budget exhausted" in body3.get("error", "").lower()

    def test_http_e2e_receipts_chain_budget_reservations(
        self, http_proxy, private_key, public_key
    ):
        base, proxy = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=4,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})
        session_id = start["session_id"]

        for _ in range(2):
            status, body = _post(base + "/evaluate", {
                "session_id": session_id,
                "tool_name": "read",
                "arguments": {},
            })
            assert status == 200
            assert body["decision"] == "PERMIT"

        status1, body1 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c1",
                "child_mission": "sub-1",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 1,
            },
        )
        assert status1 == 200
        assert body1["child_claims"]["max_tool_calls"] == 1

        status2, body2 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c2",
                "child_mission": "sub-2",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 1,
            },
        )
        assert status2 == 200
        assert body2["child_claims"]["max_tool_calls"] == 1

        status3, body3 = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "c3",
                "child_mission": "sub-3",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 1,
            },
        )
        assert status3 == 403
        assert "budget exhausted" in body3.get("error", "").lower()

        entries = [
            json.loads(line)
            for line in proxy.receipts_log_path.read_text(encoding="utf-8").splitlines()
        ]
        assert len(entries) == 4
        claims = verify_chain([entry["jwt"] for entry in entries], public_key)
        assert {claim["trace_id"] for claim in claims} == {session_id}
        assert len({claim["run_nonce"] for claim in claims}) == 1
        assert all(claim["invocation_digest"]["scope"] == "normalized_input" for claim in claims)
        assert [claim["tool"] for claim in claims] == [
            "read",
            "read",
            "delegate_passport",
            "delegate_passport",
        ]
        for claim in claims[:2]:
            assert "public_denial_reason" not in claim
            assert claim["budget_delta"]["operation"] == "consume"
            assert claim["budget_delta"]["amount"] == 1
        assert claims[0]["budget_delta"]["remaining_for_parent"] == 4
        assert claims[0]["budget_delta"]["remaining_after"] == 3
        assert claims[0]["budget_delta"]["used_total"] == 0
        assert claims[1]["budget_delta"]["remaining_for_parent"] == 3
        assert claims[1]["budget_delta"]["remaining_after"] == 2
        assert claims[1]["budget_delta"]["used_total"] == 1
        for claim in claims[2:]:
            assert "public_denial_reason" not in claim
            assert claim["budget_delta"]["operation"] == "reserve"
            assert claim["budget_delta"]["resource"] == "lineage_budget"
            assert claim["budget_delta"]["amount"] == 1

    def test_failed_delegate_does_not_consume_reserved_budget(
        self, http_proxy, private_key
    ):
        """Round-3 H1: failed child minting must leave the parent's reserved budget unchanged."""
        base, _ = http_proxy
        parent_mission = MissionPassport(
            agent_id="parent",
            mission="coord",
            allowed_tools=["read"],
            max_tool_calls=10,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        parent_token = issue_passport(parent_mission, private_key, ttl_s=300)
        _, start = _post(base + "/session/start", {"token": parent_token})
        session_id = start["session_id"]

        for _ in range(7):
            _post(base + "/evaluate", {
                "session_id": session_id,
                "tool_name": "read",
                "arguments": {},
            })

        failed_status, failed_body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "bad-child",
                "child_mission": "sub-bad",
                "child_allowed_tools": ["write"],
                "child_max_tool_calls": 2,
            },
        )
        assert failed_status == 403
        assert "scope escalation" in failed_body.get("error", "").lower()

        status, body = _post(
            base + "/delegate",
            {
                "parent_token": parent_token,
                "child_agent_id": "good-child",
                "child_mission": "sub-good",
                "child_allowed_tools": ["read"],
                "child_max_tool_calls": 3,
            },
        )
        assert status == 200
        assert body["child_claims"]["max_tool_calls"] == 3
        assert body["parent_calls_remaining_at_delegation"] == 3
