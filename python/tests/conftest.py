"""Shared pytest fixtures for the VIBAP test suite.

Keys are generated once per session to avoid paying the ES256 keygen cost on
every test. Filesystem-dependent fixtures use tmp_path so tests never touch
the user's real ~/.vibap directory.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.passport import MissionPassport, generate_keypair, issue_passport
from vibap.proxy import GovernanceProxy


@pytest.fixture(scope="session")
def session_keys_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Session-scoped keys directory so we only generate one keypair."""
    keys_dir = tmp_path_factory.mktemp("vibap-keys")
    # Materialize the keypair once; subsequent loads reuse the PEM files.
    generate_keypair(keys_dir=keys_dir)
    return keys_dir


@pytest.fixture(scope="session")
def keypair(session_keys_dir: Path) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    return generate_keypair(keys_dir=session_keys_dir)


@pytest.fixture(scope="session")
def private_key(keypair) -> ec.EllipticCurvePrivateKey:
    return keypair[0]


@pytest.fixture(scope="session")
def public_key(keypair) -> ec.EllipticCurvePublicKey:
    return keypair[1]


@pytest.fixture
def example_mission() -> MissionPassport:
    """A plain, non-delegating mission used for simple pass/fail flows.

    resource_scope is intentionally empty here so tests can use arbitrary
    arguments without having to match a glob. There's a separate
    ``scoped_mission`` fixture for resource-scope tests.
    """
    return MissionPassport(
        agent_id="agent-test",
        mission="run Q1 sales analysis",
        allowed_tools=["read_file", "write_file", "analyze"],
        forbidden_tools=["delete_file", "execute_shell"],
        resource_scope=[],
        max_tool_calls=5,
        max_duration_s=60,
        delegation_allowed=False,
        max_delegation_depth=0,
    )


@pytest.fixture
def delegating_mission() -> MissionPassport:
    """A mission that permits multi-level delegation for delegation tests."""
    return MissionPassport(
        agent_id="agent-parent",
        mission="coordinate research subtasks",
        allowed_tools=["read_file", "write_file", "analyze", "search"],
        forbidden_tools=["delete_file"],
        resource_scope=["/data/*"],
        max_tool_calls=100,
        max_duration_s=600,
        delegation_allowed=True,
        max_delegation_depth=3,
    )


@pytest.fixture
def issued_passport(example_mission, private_key) -> str:
    return issue_passport(example_mission, private_key, ttl_s=example_mission.max_duration_s)


@pytest.fixture
def issued_delegating_passport(delegating_mission, private_key) -> str:
    return issue_passport(delegating_mission, private_key, ttl_s=delegating_mission.max_duration_s)


@pytest.fixture
def proxy(tmp_path: Path, public_key, session_keys_dir: Path) -> GovernanceProxy:
    """A fresh GovernanceProxy rooted in tmp_path so tests never pollute $HOME."""
    return GovernanceProxy(
        log_path=tmp_path / "governance_log.jsonl",
        state_dir=tmp_path / "state",
        public_key=public_key,
        keys_dir=session_keys_dir,
    )


@pytest.fixture
def proxy_factory(tmp_path: Path, public_key, session_keys_dir: Path) -> Callable[[], GovernanceProxy]:
    """Create independent proxy instances sharing the session keypair."""
    counter = {"n": 0}

    def _make() -> GovernanceProxy:
        counter["n"] += 1
        n = counter["n"]
        return GovernanceProxy(
            log_path=tmp_path / f"log-{n}.jsonl",
            state_dir=tmp_path / f"state-{n}",
            public_key=public_key,
            keys_dir=session_keys_dir,
        )

    return _make


@pytest.fixture
def unused_tcp_port() -> int:
    """Allocate an ephemeral TCP port. Falls back to socket.bind(0) so we don't
    depend on pytest-asyncio being installed."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(autouse=True)
def _isolate_vibap_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point VIBAP_HOME at tmp_path for every test so nothing leaks into $HOME."""
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path / "vibap-home"))
