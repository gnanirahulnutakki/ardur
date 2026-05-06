"""Plain Markdown Ardur profile parsing for non-technical local setup."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


FRIENDLY_TOOL_ALIASES = {
    "read files": ["Read"],
    "read": ["Read"],
    "search files": ["Glob", "Grep"],
    "search": ["Glob", "Grep"],
    "edit files": ["Edit", "MultiEdit"],
    "edit": ["Edit", "MultiEdit"],
    "write files": ["Write"],
    "write": ["Write"],
    "run shell commands": ["Bash"],
    "shell commands": ["Bash"],
    "run commands": ["Bash"],
    "bash": ["Bash"],
}

PROFILE_TEMPLATES = {
    "read-only": """# Ardur Guardrails
Mode: read only
Mission: Review this project without changing files or running commands.
Protect folder: .
Max tool calls: 100
Duration: 1d

## Allow
- Read files
- Search files

## Block
- Run shell commands
- Edit files
- Write files
""",
    "safe-coding": """# Ardur Guardrails
Mode: safe coding
Mission: Help with coding inside this project, but do not run shell commands.
Protect folder: .
Max tool calls: 250
Duration: 1d

## Allow
- Read files
- Search files
- Edit files
- Write files

## Block
- Run shell commands
""",
}


_SCALAR_KEYS = {
    "mode": "mode",
    "mission": "mission",
    "protect folder": "scope",
    "scope": "scope",
    "folder": "scope",
    "max tool calls": "max_tool_calls",
    "max duration seconds": "max_duration_s",
    "duration seconds": "max_duration_s",
    "duration": "max_duration_s",
}


@dataclass(frozen=True)
class ArdurProfile:
    mode: str | None = None
    mission: str | None = None
    scope: str | None = None
    allowed_tools: list[str] = field(default_factory=list)
    forbidden_tools: list[str] = field(default_factory=list)
    max_tool_calls: int | None = None
    max_duration_s: int | None = None


def load_ardur_profile(path: str | Path) -> ArdurProfile:
    source = Path(path).expanduser()
    values: dict[str, Any] = {}
    lists: dict[str, list[str]] = {
        "allow": [],
        "block": [],
        "allowed_tools": [],
        "forbidden_tools": [],
    }
    section = ""

    for raw_line in source.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("<!--"):
            continue
        if line.startswith("#"):
            section = _normalize_key(line.lstrip("#").strip())
            continue
        if ":" in line and not line.startswith(("-", "*")):
            key, value = line.split(":", 1)
            normalized = _normalize_key(key)
            value = value.strip()
            if normalized in _SCALAR_KEYS:
                values[_SCALAR_KEYS[normalized]] = value
                continue
            if normalized in {"allowed tools", "allow tools"}:
                lists["allowed_tools"].extend(_split_inline_list(value))
                continue
            if normalized in {"forbidden tools", "blocked tools", "block tools"}:
                lists["forbidden_tools"].extend(_split_inline_list(value))
                continue
        item = _list_item(line)
        if item is None:
            continue
        if section in {"allow", "allowed", "what ai can do", "what the ai can do"}:
            lists["allow"].append(item)
        elif section in {"block", "blocked", "what ai cannot do", "what the ai cannot do"}:
            lists["block"].append(item)
        elif section in {"allowed tools", "advanced allowed tools"}:
            lists["allowed_tools"].append(item)
        elif section in {"forbidden tools", "blocked tools", "advanced forbidden tools"}:
            lists["forbidden_tools"].append(item)

    return ArdurProfile(
        mode=_string_or_none(values.get("mode")),
        mission=_string_or_none(values.get("mission")),
        scope=_string_or_none(values.get("scope")),
        allowed_tools=_dedupe(_expand_tool_items(lists["allow"]) + lists["allowed_tools"]),
        forbidden_tools=_dedupe(_expand_tool_items(lists["block"]) + lists["forbidden_tools"]),
        max_tool_calls=_int_or_none(values.get("max_tool_calls")),
        max_duration_s=_int_or_none(values.get("max_duration_s")),
    )


def write_profile_template(
    path: str | Path,
    *,
    template: str,
    force: bool = False,
) -> Path:
    if template not in PROFILE_TEMPLATES:
        raise ValueError(f"unknown Ardur profile template: {template}")
    target = Path(path).expanduser()
    if target.exists() and not force:
        raise FileExistsError(f"{target} already exists; use --force to replace it")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(PROFILE_TEMPLATES[template], encoding="utf-8")
    return target


def _normalize_key(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _list_item(line: str) -> str | None:
    if line.startswith(("- ", "* ")):
        return line[2:].strip()
    return None


def _split_inline_list(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[,;]", value) if part.strip()]


def _expand_tool_items(items: list[str]) -> list[str]:
    expanded: list[str] = []
    for item in items:
        key = _normalize_key(item)
        expanded.extend(FRIENDLY_TOOL_ALIASES.get(key, [item]))
    return expanded


def _dedupe(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result


def _string_or_none(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    match = re.fullmatch(r"(\d+)\s*([smhd])?", text)
    if not match:
        return int(text)
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return amount * multipliers[unit]
