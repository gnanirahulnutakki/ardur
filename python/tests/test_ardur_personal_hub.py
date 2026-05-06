from __future__ import annotations

import hashlib

import pytest

from vibap.personal_hub import HubError, PersonalHub
from vibap.receipt import verify_receipt


def _digest(text: str) -> str:
    return "sha-256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _browser_payload(text: str = "hello from ChatGPT") -> dict:
    digest = _digest(text)
    return {
        "schema_version": "ardur.personal.event.v0.1",
        "source": {
            "type": "browser",
            "app": "ChatGPT",
            "origin": "https://chatgpt.com",
        },
        "session": {
            "id": "https://chatgpt.com:test-tab",
            "title": "ChatGPT test",
        },
        "event": {
            "kind": "browser_visible_observation",
            "action_class": "observe",
            "target": "manual_collect",
            "capture_mode": "structured_visible_text",
            "content_digest": digest,
            "raw_content_included": False,
            "text_snapshot_included": True,
            "text_excerpt": text,
            "messages": [
                {
                    "role": "user",
                    "text_digest": _digest("summarize this"),
                    "text_excerpt": "summarize this",
                },
                {
                    "role": "assistant",
                    "text_digest": _digest(text),
                    "text_excerpt": text,
                },
            ],
            "consent": {"visible_text": True},
        },
    }


def test_browser_observation_uses_standard_ardur_receipt(tmp_path):
    hub = PersonalHub(tmp_path)

    result = hub.observe(_browser_payload())

    assert result["ok"] is True
    assert result["decision"] == "PERMIT"
    assert result["receipt"]["type"] == "execution_receipt"
    assert result["session_review"]["provider"] == "ChatGPT"
    assert {"observed", "attested", "allowed"} <= set(
        result["session_review"]["policy_labels"]
    )
    assert any(
        action["kind"] == "assistant_response_observed"
        for action in result["session_review"]["actions"]
    )
    claims = verify_receipt(
        result["receipt"]["jwt"],
        hub.public_key,
        verify_expiry=False,
    )
    assert claims["verdict"] == "compliant"
    assert claims["tool"] == "browser_observe"


def test_cli_dangerous_command_is_blocked_and_receipted(tmp_path):
    hub = PersonalHub(tmp_path)
    payload = {
        "source": {"type": "cli", "app": "sh", "process": "sudo rm -rf /"},
        "session": {"id": "cli:test", "title": "sudo rm -rf /"},
        "event": {
            "kind": "cli_command",
            "action_class": "observe",
            "target": "sh",
            "command": ["sudo", "rm", "-rf", "/"],
            "raw_content_included": False,
        },
    }

    policy = hub.check_policy(payload)
    result = hub.observe(payload)

    assert policy["verdict"] == "blocked"
    assert result["decision"] == "DENY"
    assert "blocked" in result["session_review"]["policy_labels"]
    claims = verify_receipt(
        result["receipt"]["jwt"],
        hub.public_key,
        verify_expiry=False,
    )
    assert claims["verdict"] == "violation"
    assert claims["tool"] == "cli_blocked_action"


def test_visible_text_requires_explicit_consent(tmp_path):
    hub = PersonalHub(tmp_path)
    payload = _browser_payload()
    payload["event"]["consent"] = {"visible_text": False}

    with pytest.raises(HubError):
        hub.observe(payload)


def test_export_includes_session_reviews_and_receipts(tmp_path):
    hub = PersonalHub(tmp_path)
    hub.observe(_browser_payload("answer text"))

    exported = hub.export()

    assert exported["ok"] is True
    assert exported["session_reviews"]
    assert exported["receipts"]
