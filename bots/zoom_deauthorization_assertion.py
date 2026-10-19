"""Strict, purpose-specific verification for signed Zoom deauthorization proof.

This module intentionally exposes no arbitrary signing or generic JWT API.  It
accepts only the two closed assertion schemas used by the resolver and
settlement boundaries, hard-codes Ed25519, and returns bounded error codes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone as datetime_timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings

ASSERTION_TYP = "skyterra-zoom-deauthorization+jwt"
# v2 trusted static continuous/step_free declarations and is accepted only for
# existing_only recovery of already-recorded receipts. v3 carries
# operation-coupled sampled error bounds (a measurement policy, not a claim
# that any clock is continuous or step-free).
TEMPORAL_POLICY_V2 = "first-grant-fresh30-u62-v2"
TEMPORAL_POLICY = "first-grant-sampled-u62-v3"
CLOCK_MEASUREMENT_POLICY = "operation-sampled-utc-bound-v1"
SETTLE_PURPOSE = "zoom-deauthorization:settle"
RESOLVE_PURPOSE = "zoom-deauthorization:resolve"
RECOVER_PURPOSE = "zoom-deauthorization:recover"
CREATE_IF_FRESH = "create_if_fresh"
EXISTING_ONLY = "existing_only"
MAX_ASSERTION_BYTES = 8192
MAX_ASSERTION_LIFETIME_SECONDS = 300
MAX_SERVICE_CLOCK_DELTA_SECONDS = 30

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]+$")
_EVENT_ID_RE = re.compile(r"^zev_[0-9a-f]{64}$")

_COMMON_CLAIMS = {
    "v",
    "iss",
    "aud",
    "purpose",
    "binding_mode",
    "project_id",
    "zoom_oauth_app_binding",
    "zoom_event_id",
    "zoom_event_at",
    "zoom_request_signed_at",
    "first_verified_at",
    "zoom_event_precision_ms",
    "zoom_request_precision_ms",
    "temporal_policy",
    "iat",
    "nbf",
    "exp",
    "jti",
}
_V2_CLOCK_CLAIMS = {
    "client_clock_health_id",
    "client_clock_continuous",
    "client_clock_step_free",
    "client_clock_error_ms",
}
_V3_CLOCK_CLAIMS = {
    "clock_measurement_policy",
    "client_clock_source_policy_id",
    "client_receipt_clock_error_ms",
    "client_issuance_clock_error_ms",
}
_SETTLE_CLAIMS = _COMMON_CLAIMS | {
    "operation_id",
    "grant_binding_id",
    "connection_digest",
    "connection_generation",
    "temporal_evidence_digest",
}
_RESOLVE_CLAIMS = _COMMON_CLAIMS | {"zoom_client_id", "zoom_user_id", "zoom_account_id"}


class AssertionRejected(Exception):
    """A fail-closed assertion rejection with a response-safe reason code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class VerifiedDeauthorizationAssertion:
    header: dict
    claims: dict
    signer: dict
    claims_digest: str
    nonce_digest: str
    event_digest: str
    app_digest: str
    received_at: datetime


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AssertionRejected("duplicate_json_member")
        result[key] = value
    return result


def _decode_segment(segment: str) -> bytes:
    if not segment or "=" in segment or not _B64URL_RE.fullmatch(segment):
        raise AssertionRejected("noncanonical_base64url")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, binascii.Error):
        raise AssertionRejected("noncanonical_base64url") from None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != segment:
        raise AssertionRejected("noncanonical_base64url")
    return raw


def _decode_json_object(segment: str) -> dict:
    try:
        raw = _decode_segment(segment)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except AssertionRejected:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise AssertionRejected("malformed_assertion") from None
    if type(value) is not dict:
        raise AssertionRejected("non_object_assertion")
    return value


def _canonical_uuid(value, code: str) -> str:
    if type(value) is not str or len(value) != 36:
        raise AssertionRejected(code)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise AssertionRejected(code) from None
    if str(parsed) != value or parsed.version != 4:
        raise AssertionRejected(code)
    return value


def _bounded_string(value, code: str, *, maximum: int = 255, pattern=None) -> str:
    if type(value) is not str or not value:
        raise AssertionRejected(code)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise AssertionRejected(code) from None
    if len(encoded) > maximum:
        raise AssertionRejected(code)
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise AssertionRejected(code)
    if pattern is not None and not pattern.fullmatch(value):
        raise AssertionRejected(code)
    return value


def _integer(value, code: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    if type(value) is not int:
        raise AssertionRejected(code)
    if minimum is not None and value < minimum:
        raise AssertionRejected(code)
    if maximum is not None and value > maximum:
        raise AssertionRejected(code)
    return value


def _registry() -> dict:
    configured = settings.ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON
    if isinstance(configured, str):
        try:
            configured = json.loads(configured, object_pairs_hook=_reject_duplicate_pairs)
        except AssertionRejected:
            raise
        except (json.JSONDecodeError, ValueError):
            raise AssertionRejected("signer_registry_invalid") from None
    if type(configured) is not dict:
        raise AssertionRejected("signer_registry_invalid")
    return configured


def _select_signer(project_object_id: str, unverified_claims: dict, header: dict) -> dict:
    app_binding = _canonical_uuid(unverified_claims.get("zoom_oauth_app_binding"), "app_binding_invalid")
    issuer = _bounded_string(unverified_claims.get("iss"), "issuer_invalid")
    kid = _bounded_string(header.get("kid"), "unknown_key", maximum=128, pattern=_SAFE_ID_RE)
    project_registry = _registry().get(project_object_id)
    if type(project_registry) is not dict:
        raise AssertionRejected("unknown_key")
    signer = project_registry.get(app_binding)
    if type(signer) is not dict:
        raise AssertionRejected("unknown_key")
    required = {"zoom_oauth_app_id", "expected_client_id_digest", "issuer", "audience", "keys"}
    if set(signer) != required or signer.get("issuer") != issuer or type(signer.get("keys")) is not dict:
        raise AssertionRejected("unknown_key")
    if (
        type(signer.get("zoom_oauth_app_id")) is not int
        or signer["zoom_oauth_app_id"] <= 0
        or type(signer.get("expected_client_id_digest")) is not str
        or not _HEX64_RE.fullmatch(signer["expected_client_id_digest"])
    ):
        raise AssertionRejected("signer_registry_invalid")
    _bounded_string(
        signer.get("audience"),
        "signer_registry_invalid",
        maximum=512,
    )
    public_key = signer["keys"].get(kid)
    if type(public_key) is not str:
        raise AssertionRejected("unknown_key")
    selected = dict(signer)
    selected["public_key"] = public_key
    selected["kid"] = kid
    selected["app_binding"] = app_binding
    return selected


def _validate_claim_schema(claims: dict, purpose: str) -> None:
    expected = _SETTLE_CLAIMS if purpose == SETTLE_PURPOSE else _RESOLVE_CLAIMS
    expected = expected | (_V2_CLOCK_CLAIMS if claims.get("temporal_policy") == TEMPORAL_POLICY_V2 else _V3_CLOCK_CLAIMS)
    if purpose == SETTLE_PURPOSE and "resolution_id" in claims:
        expected = expected | {"resolution_id"}
    if set(claims) != expected:
        raise AssertionRejected("claims_schema_invalid")


def _validate_common_claims(claims: dict, signer: dict, project_object_id: str, received_at: datetime) -> None:
    if type(claims.get("v")) is not int or claims["v"] != 1:
        raise AssertionRejected("version_invalid")
    if claims.get("iss") != signer["issuer"]:
        raise AssertionRejected("issuer_invalid")
    if type(claims.get("aud")) is not str or claims["aud"] != signer["audience"]:
        raise AssertionRejected("audience_invalid")
    if claims.get("project_id") != project_object_id:
        raise AssertionRejected("project_invalid")
    if claims.get("zoom_oauth_app_binding") != signer["app_binding"]:
        raise AssertionRejected("app_binding_invalid")
    if claims.get("binding_mode") not in {CREATE_IF_FRESH, EXISTING_ONLY}:
        raise AssertionRejected("binding_mode_invalid")
    if claims.get("temporal_policy") not in {TEMPORAL_POLICY_V2, TEMPORAL_POLICY}:
        raise AssertionRejected("temporal_policy_invalid")
    _bounded_string(claims.get("zoom_event_id"), "event_id_invalid", pattern=_EVENT_ID_RE)
    for name in ("zoom_event_at", "zoom_request_signed_at", "first_verified_at", "iat", "nbf", "exp"):
        _integer(claims.get(name), f"{name}_invalid", minimum=0)
    _integer(claims.get("zoom_event_precision_ms"), "event_precision_invalid", minimum=1, maximum=1000)
    _integer(claims.get("zoom_request_precision_ms"), "request_precision_invalid", minimum=1, maximum=1000)
    if claims["temporal_policy"] == TEMPORAL_POLICY_V2:
        # Recorded v2 receipts recover existing bindings only; a static
        # declaration can never create a fresh binding.
        if claims["binding_mode"] != EXISTING_ONLY:
            raise AssertionRejected("clock_untrusted")
        _bounded_string(claims.get("client_clock_health_id"), "clock_health_invalid", maximum=64, pattern=_SAFE_ID_RE)
        if claims.get("client_clock_continuous") is not True or claims.get("client_clock_step_free") is not True:
            raise AssertionRejected("clock_untrusted")
        _integer(claims.get("client_clock_error_ms"), "clock_error_invalid", minimum=0, maximum=1000)
    else:
        if claims.get("clock_measurement_policy") != CLOCK_MEASUREMENT_POLICY:
            raise AssertionRejected("clock_untrusted")
        fresh = claims["binding_mode"] == CREATE_IF_FRESH
        if fresh or claims.get("client_clock_source_policy_id") is not None:
            _bounded_string(claims.get("client_clock_source_policy_id"), "clock_source_invalid", maximum=64, pattern=_SAFE_ID_RE)
        for name in ("client_receipt_clock_error_ms", "client_issuance_clock_error_ms"):
            # Missing samples are permitted only for existing_only recovery.
            if fresh or claims.get(name) is not None:
                _integer(claims.get(name), "clock_error_invalid", minimum=0, maximum=1000)
    _canonical_uuid(claims.get("jti"), "nonce_invalid")
    if not (claims["nbf"] <= claims["iat"] < claims["exp"]):
        raise AssertionRejected("assertion_time_invalid")
    if claims["exp"] - claims["nbf"] > MAX_ASSERTION_LIFETIME_SECONDS:
        raise AssertionRejected("assertion_lifetime_invalid")
    received_epoch = received_at.timestamp()
    if received_epoch < claims["nbf"] or received_epoch >= claims["exp"]:
        raise AssertionRejected("assertion_stale")
    if abs(received_epoch - claims["iat"]) > MAX_SERVICE_CLOCK_DELTA_SECONDS:
        raise AssertionRejected("clock_untrusted")


def verify_deauthorization_assertion(assertion: str, *, project, purpose: str, received_at: datetime) -> VerifiedDeauthorizationAssertion:
    """Verify one closed resolver or settlement assertion for ``project``."""

    if purpose not in {SETTLE_PURPOSE, RESOLVE_PURPOSE, RECOVER_PURPOSE}:
        raise AssertionRejected("purpose_invalid")
    if type(assertion) is not str or not assertion or len(assertion.encode("ascii", "ignore")) != len(assertion) or len(assertion) > MAX_ASSERTION_BYTES:
        raise AssertionRejected("assertion_invalid")
    segments = assertion.split(".")
    if len(segments) != 3:
        raise AssertionRejected("malformed_assertion")
    header = _decode_json_object(segments[0])
    claims = _decode_json_object(segments[1])
    if set(header) != {"alg", "kid", "typ"} or header.get("alg") != "EdDSA" or header.get("typ") != ASSERTION_TYP:
        raise AssertionRejected("header_invalid")
    signer = _select_signer(project.object_id, claims, header)
    try:
        public_key_raw = _decode_segment(signer["public_key"])
        if len(public_key_raw) != 32:
            raise AssertionRejected("signer_registry_invalid")
        signature = _decode_segment(segments[2])
        if len(signature) != 64:
            raise AssertionRejected("bad_signature")
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(
            signature,
            f"{segments[0]}.{segments[1]}".encode("ascii"),
        )
    except InvalidSignature:
        raise AssertionRejected("bad_signature") from None
    except (ValueError, TypeError):
        raise AssertionRejected("signer_registry_invalid") from None

    if claims.get("purpose") != purpose:
        raise AssertionRejected("purpose_invalid")
    _validate_claim_schema(claims, purpose)
    _validate_common_claims(claims, signer, project.object_id, received_at)

    if purpose == RECOVER_PURPOSE and (claims["temporal_policy"] != TEMPORAL_POLICY or claims["binding_mode"] != EXISTING_ONLY):
        raise AssertionRejected("recovery_mode_invalid")

    if purpose == SETTLE_PURPOSE:
        for name in ("operation_id", "grant_binding_id", "connection_generation"):
            _canonical_uuid(claims.get(name), f"{name}_invalid")
        for name in ("connection_digest", "temporal_evidence_digest"):
            if type(claims.get(name)) is not str or not _HEX64_RE.fullmatch(claims[name]):
                raise AssertionRejected(f"{name}_invalid")
        if "resolution_id" in claims:
            _canonical_uuid(claims["resolution_id"], "resolution_id_invalid")
    else:
        for name in ("zoom_client_id", "zoom_user_id", "zoom_account_id"):
            _bounded_string(claims.get(name), f"{name}_invalid")

    signing_input = f"{segments[0]}.{segments[1]}".encode("ascii")
    return VerifiedDeauthorizationAssertion(
        header=header,
        claims=claims,
        signer=signer,
        claims_digest=hashlib.sha256(signing_input).hexdigest(),
        nonce_digest=hashlib.sha256(claims["jti"].encode("ascii")).hexdigest(),
        event_digest=hashlib.sha256(claims["zoom_event_id"].encode("ascii")).hexdigest(),
        app_digest=hashlib.sha256(claims["zoom_oauth_app_binding"].encode("ascii")).hexdigest(),
        received_at=received_at.astimezone(datetime_timezone.utc),
    )
