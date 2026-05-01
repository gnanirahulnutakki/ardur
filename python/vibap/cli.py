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
from .personal_hub import (
    DEFAULT_HUB_HOST,
    DEFAULT_HUB_PORT,
    DEFAULT_HUB_URL,
    desktop_observe,
    doctor_personal,
    hub_request,
    run_under_hub,
    serve_hub,
    setup_personal,
    uninstall_personal,
)
from .claude_code_hook import main as claude_code_hook_main
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


def cmd_claude_code_hook(args: argparse.Namespace) -> int:
    argv = [args.phase]
    if args.keys_dir:
        argv.extend(["--keys-dir", str(args.keys_dir)])
    return claude_code_hook_main(argv)


def cmd_hub(args: argparse.Namespace) -> int:
    serve_hub(host=args.host, port=args.port, home=args.home)
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    _print_json(setup_personal(args))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    response = hub_request("GET", "/v1/status", hub_url=args.hub_url)
    _print_json(response)
    return 0 if response.get("ok") else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    response = doctor_personal(args)
    _print_json(response)
    return 0 if response.get("ok") else 1


def cmd_uninstall(args: argparse.Namespace) -> int:
    _print_json(uninstall_personal(args))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    return run_under_hub(args)


def cmd_desktop_observe(args: argparse.Namespace) -> int:
    response = desktop_observe(args)
    _print_json(response)
    return 0 if response.get("ok") else 1


def cmd_personal_native_host(args: argparse.Namespace) -> int:
    if args.once_json:
        message = json.loads(args.once_json.read_text(encoding="utf-8"))
        response = handle_native_host_message(message, hub_url=args.hub_url)
        _print_json(response)
        return 0 if response.get("ok") else 1
    run_native_host(sys.stdin.buffer, sys.stdout.buffer, hub_url=args.hub_url)
    return 0


def cmd_personal_native_manifest(args: argparse.Namespace) -> int:
    _print_json(
        build_native_host_manifest(
            args.host_path,
            args.extension_id,
            browser=args.browser,
        )
    )
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

    cc_hook = subparsers.add_parser(
        "claude-code-hook",
        help="run the Claude Code PreToolUse / PostToolUse adapter",
    )
    cc_hook.add_argument(
        "phase",
        choices=["pre", "post"],
        help="hook lifecycle phase to invoke",
    )
    cc_hook.add_argument(
        "--keys-dir",
        type=Path,
        help="signing keys directory",
    )
    cc_hook.set_defaults(func=cmd_claude_code_hook)

    hub = subparsers.add_parser("hub", help="start the local Ardur Personal Hub")
    hub.add_argument("--host", default=DEFAULT_HUB_HOST, help="bind address")
    hub.add_argument("--port", type=int, default=DEFAULT_HUB_PORT, help="listen port")
    hub.add_argument("--home", type=Path, help="Ardur Personal home directory")
    hub.set_defaults(func=cmd_hub)

    setup = subparsers.add_parser("setup", help="configure Ardur Personal on this Mac")
    setup.add_argument("--host", default=DEFAULT_HUB_HOST, help="Hub bind address")
    setup.add_argument("--port", type=int, default=DEFAULT_HUB_PORT, help="Hub port")
    setup.add_argument("--home", type=Path, help="Ardur Personal home directory")
    setup.add_argument(
        "--extension-path",
        type=Path,
        default=Path("examples/ardur-personal-extension"),
        help="browser extension directory to show in setup output",
    )
    setup.set_defaults(func=cmd_setup)

    status = subparsers.add_parser("status", help="show Ardur Personal Hub status")
    status.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    status.set_defaults(func=cmd_status)

    doctor = subparsers.add_parser("doctor", help="check local Ardur Personal setup")
    doctor.add_argument("--home", type=Path, help="Ardur Personal home directory")
    doctor.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    doctor.set_defaults(func=cmd_doctor)

    uninstall = subparsers.add_parser("uninstall", help="remove Ardur Personal launch files")
    uninstall.add_argument("--home", type=Path, help="Ardur Personal home directory")
    uninstall.add_argument(
        "--remove-data",
        action="store_true",
        help="also remove local Ardur Personal evidence and keys",
    )
    uninstall.set_defaults(func=cmd_uninstall)

    run = subparsers.add_parser("run", help="run a CLI command through Ardur Personal Hub")
    run.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    run.add_argument("command", nargs=argparse.REMAINDER, help="command to run after --")
    run.set_defaults(func=cmd_run)

    desktop = subparsers.add_parser(
        "desktop-observe",
        help="record a Mac desktop app observation through Ardur Personal Hub",
    )
    desktop.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    desktop.add_argument("--session-id", help="stable desktop session id")
    desktop.add_argument("--app", help="application name; autodetected on macOS when omitted")
    desktop.add_argument("--title", help="window title; autodetected on macOS when omitted")
    desktop.add_argument(
        "--text",
        help="explicit-consent visible text excerpt to include in the session review",
    )
    desktop.set_defaults(func=cmd_desktop_observe)

    personal_native_host = subparsers.add_parser(
        "personal-native-host",
        help="run the Ardur Personal native messaging bridge",
    )
    personal_native_host.add_argument("--hub-url", default=DEFAULT_HUB_URL, help="Hub base URL")
    personal_native_host.add_argument(
        "--once-json",
        type=Path,
        help="development mode: process one JSON message file",
    )
    personal_native_host.set_defaults(func=cmd_personal_native_host)

    personal_native_manifest = subparsers.add_parser(
        "personal-native-manifest",
        help="print a native messaging manifest for the Hub bridge",
    )
    personal_native_manifest.add_argument("--host-path", type=Path, required=True)
    personal_native_manifest.add_argument("--extension-id", required=True)
    personal_native_manifest.add_argument(
        "--browser",
        choices=["chrome", "chrome-for-testing", "chromium", "edge", "firefox"],
        default="chrome",
    )
    personal_native_manifest.set_defaults(func=cmd_personal_native_manifest)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if getattr(args, "command", None) and args.command[0] == "--":
        args.command = args.command[1:]
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
