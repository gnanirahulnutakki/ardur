"""Console entry point for the pip-installable VIBAP proxy package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .ardur_personal_native_host import (
    build_native_host_manifest,
    handle_native_host_message,
    run_native_host,
)
from .passport import MissionPassport, generate_keypair, issue_passport, load_mission_file, verify_passport
from .proxy import GovernanceProxy, serve_proxy


def _print_json(payload: dict) -> None:
    print(json.dumps(payload, indent=2))


def cmd_start(args: argparse.Namespace) -> int:
    private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    proxy = GovernanceProxy(
        log_path=args.log_path,
        state_dir=args.state_dir,
        keys_dir=args.keys_dir,
        public_key=public_key,
    )

    initial_session_id = None
    if args.mission:
        mission, ttl_s, _ = load_mission_file(args.mission)
        token = issue_passport(mission, private_key, ttl_s=ttl_s)
        session = proxy.start_session(token)
        initial_session_id = session.jti
        _print_json(
            {
                "status": "session_started",
                "mission_file": str(Path(args.mission).expanduser()),
                "session_id": session.jti,
                "agent_id": mission.agent_id,
                "mission": mission.mission,
                "token": token,
            }
        )

    serve_proxy(
        proxy=proxy,
        private_key=private_key,
        host=args.host,
        port=args.port,
        initial_session_id=initial_session_id,
        require_auth=args.require_auth,
    )
    return 0


def cmd_issue(args: argparse.Namespace) -> int:
    private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    mission = MissionPassport(
        agent_id=args.agent_id,
        mission=args.mission,
        allowed_tools=list(args.allowed_tools or []),
        forbidden_tools=list(args.forbidden_tools or []),
        resource_scope=list(args.resource_scope or []),
        max_tool_calls=args.max_tool_calls,
        max_duration_s=args.max_duration_s,
        delegation_allowed=args.delegation_allowed,
        max_delegation_depth=args.max_delegation_depth,
    )
    token = issue_passport(mission, private_key, ttl_s=args.ttl_s)
    claims = verify_passport(token, public_key)
    _print_json({"token": token, "claims": claims})
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    _, public_key = generate_keypair(keys_dir=args.keys_dir)
    claims = verify_passport(args.token, public_key)
    _print_json({"valid": True, "claims": claims})
    return 0


def cmd_attest(args: argparse.Namespace) -> int:
    private_key, public_key = generate_keypair(keys_dir=args.keys_dir)
    proxy = GovernanceProxy(
        log_path=args.log_path,
        state_dir=args.state_dir,
        keys_dir=args.keys_dir,
        public_key=public_key,
    )
    token, claims = proxy.issue_attestation_for_session(args.session, private_key)
    _print_json({"token": token, "claims": claims})
    return 0


def cmd_personal_native_host(args: argparse.Namespace) -> int:
    caller_origin = _native_caller_origin(args.browser_args)
    if args.once_json:
        message = json.loads(args.once_json.read_text(encoding="utf-8"))
        response = handle_native_host_message(
            message,
            storage_dir=args.storage_dir,
            keys_dir=args.keys_dir,
            caller_origin=caller_origin,
        )
        _print_json(response)
        return 0 if response.get("ok") else 1
    run_native_host(
        sys.stdin.buffer,
        sys.stdout.buffer,
        storage_dir=args.storage_dir,
        keys_dir=args.keys_dir,
        caller_origin=caller_origin,
    )
    return 0


def _native_caller_origin(browser_args: Sequence[str] | None) -> str | None:
    for value in browser_args or []:
        if value.startswith("chrome-extension://"):
            return value
    return None


def cmd_personal_native_manifest(args: argparse.Namespace) -> int:
    manifest = build_native_host_manifest(
        args.host_path,
        args.extension_id,
        browser=args.browser,
    )
    _print_json(manifest)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ardur",
        description="Ardur governance proxy and mission-passport tooling",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="start the VIBAP proxy HTTP service")
    start.add_argument("--host", default="127.0.0.1", help="bind address")
    start.add_argument("--port", type=int, default=8080, help="listen port")
    start.add_argument("--mission", type=Path, help="optional mission JSON to issue and start immediately")
    start.add_argument("--keys-dir", type=Path, help="directory containing VIBAP signing keys")
    start.add_argument("--state-dir", type=Path, help="directory for persisted sessions")
    start.add_argument("--log-path", type=Path, help="JSONL audit log path")
    auth_group = start.add_mutually_exclusive_group()
    auth_group.add_argument(
        "--require-auth",
        dest="require_auth",
        action="store_true",
        help="require Bearer token on all endpoints except /health and /healthz (default)",
    )
    auth_group.add_argument(
        "--no-require-auth",
        dest="require_auth",
        action="store_false",
        help="DISABLE Bearer auth — DO NOT USE IN PRODUCTION",
    )
    start.set_defaults(func=cmd_start, require_auth=True)

    issue = subparsers.add_parser("issue", help="issue a mission passport JWT")
    issue.add_argument("--agent-id", required=True, help="agent subject identifier")
    issue.add_argument("--mission", required=True, help="declared mission string")
    issue.add_argument("--allowed-tools", nargs="*", default=[], help="allowed tool names")
    issue.add_argument("--forbidden-tools", nargs="*", default=[], help="forbidden tool names")
    issue.add_argument("--resource-scope", nargs="*", default=[], help="resource scope patterns")
    issue.add_argument("--max-tool-calls", type=int, default=50, help="max permitted tool calls")
    issue.add_argument("--max-duration-s", type=int, default=600, help="max mission duration in seconds")
    issue.add_argument("--delegation-allowed", action="store_true", help="allow one-step delegation")
    issue.add_argument("--max-delegation-depth", type=int, default=0, help="delegation depth budget")
    issue.add_argument("--ttl-s", type=int, help="override token TTL in seconds")
    issue.add_argument("--keys-dir", type=Path, help="directory containing VIBAP signing keys")
    issue.set_defaults(func=cmd_issue)

    verify = subparsers.add_parser("verify", help="verify a mission passport JWT")
    verify.add_argument("--token", required=True, help="passport token to verify")
    verify.add_argument("--keys-dir", type=Path, help="directory containing VIBAP signing keys")
    verify.set_defaults(func=cmd_verify)

    attest = subparsers.add_parser("attest", help="issue a behavioral attestation for a saved session")
    attest.add_argument("--session", required=True, help="session identifier / passport jti")
    attest.add_argument("--keys-dir", type=Path, help="directory containing VIBAP signing keys")
    attest.add_argument("--state-dir", type=Path, help="directory containing persisted sessions")
    attest.add_argument("--log-path", type=Path, help="JSONL audit log path")
    attest.set_defaults(func=cmd_attest)

    personal_native_host = subparsers.add_parser(
        "personal-native-host",
        help="run the Ardur Personal native messaging host",
    )
    personal_native_host.add_argument(
        "--storage-dir",
        type=Path,
        help="native-host evidence directory (default: $ARDUR_PERSONAL_HOST_DIR or VIBAP home)",
    )
    personal_native_host.add_argument(
        "--keys-dir",
        type=Path,
        help="native-host signing key directory (default: storage-dir/keys)",
    )
    personal_native_host.add_argument(
        "--once-json",
        type=Path,
        help="development mode: process a plain JSON message file and print JSON response",
    )
    personal_native_host.add_argument("browser_args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    personal_native_host.set_defaults(func=cmd_personal_native_host)

    personal_native_manifest = subparsers.add_parser(
        "personal-native-manifest",
        help="print a native messaging host manifest",
    )
    personal_native_manifest.add_argument(
        "--host-path",
        type=Path,
        required=True,
        help="absolute or relative path to the native host executable/wrapper",
    )
    personal_native_manifest.add_argument(
        "--extension-id",
        required=True,
        help="Chrome extension id or Firefox add-on id allowed to call the host",
    )
    personal_native_manifest.add_argument(
        "--browser",
        choices=["chrome", "chrome-for-testing", "chromium", "edge", "firefox"],
        default="chrome",
        help="manifest flavor to print",
    )
    personal_native_manifest.set_defaults(func=cmd_personal_native_manifest)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
