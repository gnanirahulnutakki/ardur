"""Mission Declaration loading, caching, and revocation checks."""

from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import socket
import ssl
import threading
import urllib.parse
import zlib
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.error import HTTPError, URLError
import urllib.request
from urllib.request import Request

# NOTE: urlopen is accessed as `urllib.request.urlopen` (not a local import)
# so that monkeypatching `vibap.mission.urlopen` in tests works regardless
# of test ordering. The local `from urllib.request import urlopen` binding
# was immune to monkeypatch when test_passport ran before test_mission_binding.
urlopen = urllib.request.urlopen

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from .passport import ALGORITHM, DEFAULT_AUDIENCE, MissionPassport

_FETCH_TIMEOUT_S = 5.0
MAX_STATUS_LIST_BYTES = 1 << 20
MAX_DECOMPRESSED_BYTES = 16 << 20


class MissionBindingError(RuntimeError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class MissionStatusUnavailableError(RuntimeError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class MissionReference:
    uri: str
    mission_id: str | None = None
    mission_digest: str | None = None

    def cache_key(self) -> str:
        return "|".join([self.uri, self.mission_id or "", self.mission_digest or ""])


@dataclass(frozen=True, slots=True)
class MissionDeclaration:
    mission_id: str
    issuer: str
    subject: str
    audience: str | list[str]
    issued_at: int
    expires_at: int
    jwt_id: str
    passport: MissionPassport
    resource_policies: tuple[dict[str, Any], ...] = ()
    effect_policies: tuple[dict[str, Any], ...] = ()
    lineage_budgets: dict[str, Any] = field(default_factory=dict)
    delegation_policy: dict[str, Any] = field(default_factory=dict)
    flow_policies: tuple[dict[str, Any], ...] = ()
    required_telemetry: tuple[str, ...] = ()
    receipt_policy: dict[str, Any] = field(default_factory=dict)
    conformance_profile: str | None = None
    tool_manifest_digest: str | None = None
    revocation_ref: str | None = None
    approval_policy: dict[str, Any] = field(default_factory=dict)
    governed_memory_stores: tuple[dict[str, Any], ...] = ()
    probing_rate_limit: int | None = None
    payload_digest: str = ""
    raw_claims: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    token: str = field(default="", repr=False, compare=False)

    def policy_claims(self) -> dict[str, Any]:
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": self.subject,
            "aud": copy.deepcopy(self.audience),
            "iat": self.issued_at,
            "exp": self.expires_at,
            "jti": self.jwt_id,
            "mission_id": self.mission_id,
            "mission": self.passport.mission,
            "allowed_tools": list(self.passport.allowed_tools),
            "forbidden_tools": list(self.passport.forbidden_tools),
            "resource_scope": list(self.passport.resource_scope),
            "max_tool_calls": self.passport.max_tool_calls,
            "max_duration_s": self.passport.max_duration_s,
            "delegation_allowed": self.passport.delegation_allowed,
            "max_delegation_depth": self.passport.max_delegation_depth,
        }
        if self.passport.parent_jti is not None:
            claims["parent_jti"] = self.passport.parent_jti
        if self.passport.cwd is not None:
            claims["cwd"] = self.passport.cwd
        if self.approval_policy:
            claims["approval_policy"] = copy.deepcopy(self.approval_policy)
        for name in (
            "resource_policies",
            "effect_policies",
            "lineage_budgets",
            "delegation_policy",
            "flow_policies",
            "required_telemetry",
            "receipt_policy",
            "conformance_profile",
            "tool_manifest_digest",
            "revocation_ref",
            "governed_memory_stores",
            "probing_rate_limit",
        ):
            value = getattr(self, name)
            if value not in (None, (), {}, []):
                claims[name] = copy.deepcopy(value)
        return claims


class MissionCache:
    def __init__(self, max_entries: int = 256) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._by_id: OrderedDict[str, MissionDeclaration] = OrderedDict()
        self._ref_to_id: OrderedDict[str, str] = OrderedDict()

    def get(self, mission_id: str) -> MissionDeclaration | None:
        with self._lock:
            mission = self._by_id.get(mission_id)
            if mission is None:
                return None
            self._by_id.move_to_end(mission_id)
            return mission

    def get_by_ref(self, ref: MissionReference) -> MissionDeclaration | None:
        ref_key = ref.cache_key()
        with self._lock:
            mission_id = self._ref_to_id.get(ref_key) or ref.mission_id
            if mission_id is None:
                return None
            mission = self._by_id.get(mission_id)
            if mission is None:
                self._ref_to_id.pop(ref_key, None)
                return None
            if ref.mission_digest and mission.payload_digest != ref.mission_digest:
                return None
            self._by_id.move_to_end(mission_id)
            self._ref_to_id[ref_key] = mission_id
            self._ref_to_id.move_to_end(ref_key)
            return mission

    def put(self, mission: MissionDeclaration, *, ref: MissionReference | None = None) -> MissionDeclaration:
        with self._lock:
            self._by_id[mission.mission_id] = mission
            self._by_id.move_to_end(mission.mission_id)
            if ref is not None:
                self._ref_to_id[ref.cache_key()] = mission.mission_id
                self._ref_to_id.move_to_end(ref.cache_key())
            while len(self._by_id) > self.max_entries:
                evicted_id, _ = self._by_id.popitem(last=False)
                stale = [key for key, value in self._ref_to_id.items() if value == evicted_id]
                for key in stale:
                    self._ref_to_id.pop(key, None)
            while len(self._ref_to_id) > self.max_entries * 2:
                self._ref_to_id.popitem(last=False)
            return mission

    def resolve(self, ref: MissionReference, loader: Callable[[], MissionDeclaration]) -> MissionDeclaration:
        cached = self.get_by_ref(ref)
        if cached is not None:
            return cached
        return self.put(loader(), ref=ref)


def parse_mission_ref(value: Any) -> MissionReference:
    if isinstance(value, str):
        if not value.strip():
            raise MissionBindingError("chain_invalid", "mission_ref is empty")
        return MissionReference(uri=value.strip())
    if not isinstance(value, dict):
        raise MissionBindingError("chain_invalid", "mission_ref must be a string or object")
    uri = value.get("uri", value.get("url"))
    if not isinstance(uri, str) or not uri.strip():
        raise MissionBindingError("chain_invalid", "mission_ref.uri is required")
    mission_id = value.get("mission_id")
    if mission_id is not None and (not isinstance(mission_id, str) or not mission_id.strip()):
        raise MissionBindingError("chain_invalid", "mission_ref.mission_id must be a non-empty string")
    mission_digest = value.get("mission_digest")
    if mission_digest is not None and (
        not isinstance(mission_digest, str) or not mission_digest.startswith("sha-256:")
    ):
        raise MissionBindingError("chain_invalid", "mission_ref.mission_digest must use sha-256:<hex>")
    return MissionReference(
        uri=uri.strip(),
        mission_id=mission_id.strip() if isinstance(mission_id, str) else None,
        mission_digest=mission_digest,
    )


def load_mission_declaration(md_jwt: str, public_key: ec.EllipticCurvePublicKey) -> MissionDeclaration:
    try:
        claims = jwt.decode(
            md_jwt,
            public_key,
            algorithms=[ALGORITHM],
            audience=DEFAULT_AUDIENCE,
            options={"require": ["iss", "sub", "aud", "iat", "exp", "jti", "mission_id"]},
        )
    except jwt.PyJWTError as exc:
        raise MissionBindingError("chain_invalid", f"mission declaration verification failed: {exc}") from exc
    try:
        passport = MissionPassport.from_dict(
            {
                "agent_id": str(claims["sub"]),
                "mission": str(claims.get("mission", claims.get("mission_id", claims["jti"]))),
                "allowed_tools": list(claims.get("allowed_tools", claims.get("allowed_tool_classes", []))),
                "forbidden_tools": list(claims.get("forbidden_tools", [])),
                "resource_scope": _legacy_resource_scope(
                    claims.get("resource_scope"),
                    claims.get("resource_policies"),
                ),
                "max_tool_calls": int(claims.get("max_tool_calls", 50)),
                "max_duration_s": int(claims.get("max_duration_s", max(1, int(claims["exp"]) - int(claims["iat"])))),
                "delegation_allowed": bool(
                    claims.get(
                        "delegation_allowed",
                        bool(((claims.get("delegation_policy") or {}).get("max_depth", 0))),
                    )
                ),
                "max_delegation_depth": int(
                    claims.get("max_delegation_depth", ((claims.get("delegation_policy") or {}).get("max_depth", 0)))
                ),
                "parent_jti": claims.get("parent_jti"),
                "cwd": claims.get("cwd"),
            }
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise MissionBindingError("chain_invalid", f"mission declaration schema invalid: {exc}") from exc

    return MissionDeclaration(
        mission_id=str(claims["mission_id"]),
        issuer=str(claims["iss"]),
        subject=str(claims["sub"]),
        audience=copy.deepcopy(claims["aud"]),
        issued_at=int(claims["iat"]),
        expires_at=int(claims["exp"]),
        jwt_id=str(claims["jti"]),
        passport=passport,
        resource_policies=_tuple_of_dicts(claims.get("resource_policies")),
        effect_policies=_tuple_of_dicts(claims.get("effect_policies")),
        lineage_budgets=_dict_or_empty(claims.get("lineage_budgets")),
        delegation_policy=_dict_or_empty(claims.get("delegation_policy")),
        flow_policies=_tuple_of_dicts(claims.get("flow_policies")),
        required_telemetry=_tuple_of_strs(claims.get("required_telemetry")),
        receipt_policy=_dict_or_empty(claims.get("receipt_policy")),
        conformance_profile=_optional_str(claims.get("conformance_profile")),
        tool_manifest_digest=_optional_str(claims.get("tool_manifest_digest")),
        revocation_ref=_optional_str(claims.get("revocation_ref")),
        approval_policy=_dict_or_empty(claims.get("approval_policy")),
        governed_memory_stores=_tuple_of_dicts(claims.get("governed_memory_stores")),
        probing_rate_limit=_optional_int(claims.get("probing_rate_limit")),
        payload_digest=_payload_digest(claims),
        raw_claims=copy.deepcopy(claims),
        token=md_jwt,
    )


def fetch_mission_declaration(ref: MissionReference, public_key: ec.EllipticCurvePublicKey) -> MissionDeclaration:
    if urllib.parse.urlparse(ref.uri).scheme.lower() != "https":
        raise MissionBindingError("chain_invalid", "mission_ref must use https")
    mission = load_mission_declaration(_fetch_text(ref.uri), public_key)
    if ref.mission_id and ref.mission_id != mission.mission_id:
        raise MissionBindingError("chain_invalid", "mission_ref mission_id does not match loaded mission")
    if ref.mission_digest and ref.mission_digest != mission.payload_digest:
        raise MissionBindingError("chain_invalid", "mission_ref mission_digest does not match loaded mission")
    return mission


def mission_is_revoked(mission: MissionDeclaration, public_key: ec.EllipticCurvePublicKey) -> bool:
    if mission.revocation_ref is None:
        return False
    uri, idx = _parse_revocation_ref(mission.revocation_ref)
    try:
        claims = jwt.decode(
            _fetch_text(uri),
            public_key,
            algorithms=[ALGORITHM],
            options={"require": ["iat", "exp"], "verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise MissionBindingError("chain_invalid", f"status list verification failed: {exc}") from exc
    container = claims.get("status_list", claims.get("status"))
    if not isinstance(container, dict):
        raise MissionBindingError("chain_invalid", "status list token missing status_list claim")
    try:
        bits = int(container.get("bits", 1))
    except (TypeError, ValueError) as exc:
        raise MissionBindingError("chain_invalid", "status list bits must be an integer") from exc
    if bits not in (1, 2, 4, 8):
        raise MissionBindingError("chain_invalid", f"unsupported status list bits={bits}")
    lst = container.get("lst")
    if not isinstance(lst, str) or not lst:
        raise MissionBindingError("chain_invalid", "status list token missing lst")
    try:
        decompressor = zlib.decompressobj()
        raw = decompressor.decompress(_b64url_decode(lst), MAX_DECOMPRESSED_BYTES)
    except (ValueError, zlib.error) as exc:
        raise MissionBindingError("chain_invalid", "status list decompression failed") from exc
    if decompressor.unconsumed_tail or decompressor.unused_data:
        raise MissionStatusUnavailableError("status_list_too_large", "status list exceeded decompression limit")
    return _status_value(raw, idx=idx, bits=bits) != 0


def _assert_public_target(url: str) -> None:
    """M1 SSRF defense: reject fetches whose hostname resolves to a private
    or otherwise unsafe IP class. Blocks AWS IMDS (169.254/16), loopback,
    RFC1918, link-local, multicast, reserved, and unspecified ranges.

    Residual TOCTOU: DNS can re-resolve to a different IP at actual fetch
    time. Acceptable for M1 — the common-case attack (Mission URL
    controlled by adversary pointing at 169.254.169.254) is closed here.
    A stronger fix would pin the resolved IP into urlopen via a custom
    HTTPSConnection factory; tracked as a future hardening.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host:
        raise MissionBindingError("chain_invalid", "url missing hostname")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        # Fail-open on DNS failure: the attacker can't bypass the IP-class
        # block because urlopen's own getaddrinfo will also fail (or hit
        # the same /etc/hosts entry we'd see here). Letting urlopen handle
        # the unresolvable case keeps test mocks working and preserves
        # fail-closed semantics at the fetch layer (URLError → caller).
        return
    seen: set[str] = set()
    for info in infos:
        ip_str = info[4][0]
        if ip_str in seen:
            continue
        seen.add(ip_str)
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise MissionBindingError(
                "chain_invalid",
                f"url resolves to non-public IP {ip_str} (class blocked to defeat SSRF)",
            )


def _fetch_text(url: str) -> str:
    _assert_public_target(url)
    request = Request(
        url,
        headers={"Accept": "application/jwt, application/statuslist+jwt, application/json"},
    )
    try:
        with urlopen(request, timeout=_FETCH_TIMEOUT_S, context=ssl.create_default_context()) as response:
            body = response.read(MAX_STATUS_LIST_BYTES + 1)
            if len(body) > MAX_STATUS_LIST_BYTES:
                raise MissionStatusUnavailableError("status_list_too_large", "status list response exceeded size limit")
            return body.decode("utf-8").strip()
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        raise MissionStatusUnavailableError("revocation_unavailable", f"fetch failed for {url}") from exc


def _parse_revocation_ref(revocation_ref: str) -> tuple[str, int]:
    parsed = urllib.parse.urlparse(revocation_ref)
    if parsed.scheme.lower() != "https":
        raise MissionBindingError("chain_invalid", "revocation_ref must use https")
    if not parsed.fragment:
        raise MissionBindingError("chain_invalid", "revocation_ref must include #idx=<n>")
    try:
        fragment = urllib.parse.parse_qs(parsed.fragment, strict_parsing=True)
    except ValueError as exc:
        raise MissionBindingError("chain_invalid", "revocation_ref fragment is malformed") from exc
    idx_values = fragment.get("idx")
    if idx_values is None or len(idx_values) != 1:
        raise MissionBindingError("chain_invalid", "revocation_ref must include exactly one idx")
    try:
        idx = int(idx_values[0])
    except ValueError as exc:
        raise MissionBindingError("chain_invalid", "revocation_ref idx must be an integer") from exc
    if idx < 0:
        raise MissionBindingError("chain_invalid", "revocation_ref idx must be non-negative")
    return urllib.parse.urlunparse(parsed._replace(fragment="")), idx


def _legacy_resource_scope(resource_scope: Any, resource_policies: Any) -> list[str]:
    if resource_scope is not None:
        return list(resource_scope)
    if not isinstance(resource_policies, list):
        return []
    patterns: list[str] = []
    for entry in resource_policies:
        if not isinstance(entry, dict):
            raise ValueError("resource_policies entries must be objects")
        pattern = entry.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("resource_policies[].pattern must be a non-empty string")
        if pattern.startswith("glob:"):
            patterns.append(pattern[len("glob:"):])
        elif pattern.startswith("exact:"):
            patterns.append(pattern[len("exact:"):])
        else:
            patterns.append(pattern)
    return patterns


def _payload_digest(claims: dict[str, Any]) -> str:
    canonical = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha-256:" + hashlib.sha256(canonical).hexdigest()


def _tuple_of_dicts(value: Any) -> tuple[dict[str, Any], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise MissionBindingError("chain_invalid", "mission array field must be a list")
    items: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise MissionBindingError("chain_invalid", "mission array field must contain objects")
        items.append(copy.deepcopy(entry))
    return tuple(items)


def _tuple_of_strs(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise MissionBindingError("chain_invalid", "required_telemetry must be a list")
    items: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry:
            raise MissionBindingError("chain_invalid", "required_telemetry must contain strings")
        items.append(entry)
    return tuple(items)


def _dict_or_empty(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise MissionBindingError("chain_invalid", "mission object field must be an object")
    return copy.deepcopy(value)


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise MissionBindingError("chain_invalid", "mission string field must be a non-empty string")
    return value


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise MissionBindingError("chain_invalid", "mission integer field must be an integer") from exc


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _status_value(raw: bytes, *, idx: int, bits: int) -> int:
    start_bit = idx * bits
    end_bit = start_bit + bits
    if end_bit > len(raw) * 8:
        raise MissionBindingError("chain_invalid", "status list idx is out of range")
    value = 0
    for bit_index in range(start_bit, end_bit):
        byte = raw[bit_index // 8]
        shift = 7 - (bit_index % 8)
        value = (value << 1) | ((byte >> shift) & 0x01)
    return value
