"""Strict project/app-scoped audit keys for Zoom removal history.

The v2 registry selects a ring only from the authenticated project and its
locked database app. Client-Agent's event-id HMAC remains outside this
service's assertion schema.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass

from django.conf import settings


class AuditKeyringError(Exception):
    """A fail-closed, response-safe audit-key failure."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_KID_RE = re.compile(r"^[A-Za-z0-9._:/-]+$")
_PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]+$")
_REGISTRY_KEYS = {"v", "rings"}
_RING_KEYS = {"current_kid", "keys"}
_MAX_PROJECTS = 64
_MAX_APPS_PER_PROJECT = 64
_MAX_KEYS_PER_RING = 32
AUDIT_KEY_ALGORITHM = "HMAC-SHA-256"
AUDIT_KEY_DERIVATION_DOMAIN = "attendee-zoom-removal-audit-v1"
AUDIT_KEY_DERIVATION_VERSION = 1


def _reject_duplicate_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AuditKeyringError("audit_key_unavailable")
        value[key] = item
    return value


def _safe_identifier(value, *, maximum: int = 64, pattern=_KID_RE) -> str:
    if type(value) is not str or not value:
        raise AuditKeyringError("audit_key_unavailable")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise AuditKeyringError("audit_key_unavailable") from None
    if len(encoded) > maximum or not pattern.fullmatch(value):
        raise AuditKeyringError("audit_key_unavailable")
    return value


def _canonical_app_binding(value) -> str:
    if type(value) is not str:
        raise AuditKeyringError("audit_key_unavailable")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise AuditKeyringError("audit_key_unavailable") from None
    if parsed.version != 4 or str(parsed) != value:
        raise AuditKeyringError("audit_key_unavailable")
    return value


def _decode_key(value) -> bytes:
    if type(value) is not str or not value or "=" in value or not _B64URL_RE.fullmatch(value):
        raise AuditKeyringError("audit_key_unavailable")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        raise AuditKeyringError("audit_key_unavailable") from None
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise AuditKeyringError("audit_key_unavailable")
    if not 32 <= len(decoded) <= 64:
        raise AuditKeyringError("audit_key_unavailable")
    return decoded


def key_fingerprint(raw_key: bytes) -> str:
    return hashlib.sha256(raw_key).hexdigest()


@dataclass(frozen=True)
class AuditKeyring:
    project_object_id: str
    app_binding: str
    current_kid: str
    keys: tuple[tuple[str, bytes], ...]
    fingerprint: str

    @property
    def current_key(self) -> bytes:
        return dict(self.keys)[self.current_kid]

    @property
    def kids(self) -> tuple[str, ...]:
        return tuple(kid for kid, _key in self.keys)

    @property
    def key_fingerprints(self) -> dict[str, str]:
        return {kid: key_fingerprint(raw_key) for kid, raw_key in self.keys}


@dataclass(frozen=True)
class AuditKeyringRegistry:
    rings: tuple[AuditKeyring, ...]
    fingerprint: str

    def select(self, project_object_id: str, app_binding) -> AuditKeyring:
        canonical_binding = str(app_binding)
        matches = [
            ring
            for ring in self.rings
            if ring.project_object_id == project_object_id and ring.app_binding == canonical_binding
        ]
        if len(matches) != 1:
            raise AuditKeyringError("audit_key_unavailable")
        return matches[0]


def configured_audit_keyrings() -> AuditKeyringRegistry:
    configured = settings.ZOOM_REMOVAL_AUDIT_KEYRING_JSON
    if type(configured) is not str:
        raise AuditKeyringError("audit_key_unavailable")
    try:
        parsed = json.loads(configured, object_pairs_hook=_reject_duplicate_pairs)
    except AuditKeyringError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise AuditKeyringError("audit_key_unavailable") from None
    if (
        type(parsed) is not dict
        or set(parsed) != _REGISTRY_KEYS
        or type(parsed.get("v")) is not int
        or parsed["v"] != 2
        or type(parsed.get("rings")) is not dict
        or not parsed["rings"]
        or len(parsed["rings"]) > _MAX_PROJECTS
    ):
        raise AuditKeyringError("audit_key_unavailable")

    rings = []
    raw_fingerprints = set()
    for project_object_id, project_rings in parsed["rings"].items():
        project_object_id = _safe_identifier(project_object_id, maximum=32, pattern=_PROJECT_ID_RE)
        if (
            type(project_rings) is not dict
            or not project_rings
            or len(project_rings) > _MAX_APPS_PER_PROJECT
        ):
            raise AuditKeyringError("audit_key_unavailable")
        for app_binding, ring_value in project_rings.items():
            app_binding = _canonical_app_binding(app_binding)
            if type(ring_value) is not dict or set(ring_value) != _RING_KEYS:
                raise AuditKeyringError("audit_key_unavailable")
            current_kid = _safe_identifier(ring_value.get("current_kid"))
            encoded_keys = ring_value.get("keys")
            if (
                type(encoded_keys) is not dict
                or not encoded_keys
                or len(encoded_keys) > _MAX_KEYS_PER_RING
                or current_kid not in encoded_keys
            ):
                raise AuditKeyringError("audit_key_unavailable")
            decoded = []
            for kid, encoded in encoded_keys.items():
                kid = _safe_identifier(kid)
                raw_key = _decode_key(encoded)
                fingerprint = key_fingerprint(raw_key)
                if fingerprint in raw_fingerprints:
                    raise AuditKeyringError("audit_key_conflict")
                raw_fingerprints.add(fingerprint)
                decoded.append((kid, raw_key))
            canonical_ring = json.dumps(
                ring_value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
            rings.append(
                AuditKeyring(
                    project_object_id=project_object_id,
                    app_binding=app_binding,
                    current_kid=current_kid,
                    keys=tuple(sorted(decoded)),
                    fingerprint=hashlib.sha256(canonical_ring).hexdigest(),
                )
            )

    canonical_registry = json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return AuditKeyringRegistry(
        rings=tuple(sorted(rings, key=lambda ring: (ring.project_object_id, ring.app_binding))),
        fingerprint=hashlib.sha256(canonical_registry).hexdigest(),
    )


def configured_audit_keyring(project, zoom_app) -> AuditKeyring:
    """Select one ring only from authenticated/locked database scope."""

    if zoom_app.project_id != project.pk:
        raise AuditKeyringError("audit_key_unavailable")
    return configured_audit_keyrings().select(project.object_id, zoom_app.deauthorization_binding_id)


def digest_with_key(raw_key: bytes, domain: str, *parts: str) -> str:
    purpose = AUDIT_KEY_DERIVATION_DOMAIN.encode("ascii")
    key = hmac.new(raw_key, purpose, hashlib.sha256).digest()
    material = "\x00".join((domain, *parts)).encode("utf-8")
    return hmac.new(key, material, hashlib.sha256).hexdigest()
