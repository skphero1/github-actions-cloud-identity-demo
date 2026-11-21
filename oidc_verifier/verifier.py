"""Cryptographic OIDC JWT verification and exact IAM-style subject authorization."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Final

import jwt

ALLOWED_ALGORITHM: Final[str] = "RS256"
REQUIRED_CLAIMS: Final[tuple[str, ...]] = ("iss", "aud", "exp", "iat", "sub")


@dataclass(frozen=True)
class TrustPolicy:
    """Mirrors the AWS IAM OIDC role trust policy conditions."""

    expected_issuer: str
    expected_audience: str
    expected_subject: str


@dataclass(frozen=True)
class CheckStep:
    """Outcome of a single verification gate for auditability and CLI teaching output."""

    gate: str
    status: str  # "PASS", "FAIL", or "SKIP"
    detail: str


@dataclass(frozen=True)
class VerificationDecision:
    """Result of verifying an OIDC JWT against a cryptographic key and trust policy.

    `authenticated_claims` is populated ONLY when every cryptographic and policy
    check passes (`allowed is True`). Unverified or unauthorized claims are never
    exposed as authenticated identity data.
    """

    allowed: bool
    failure_code: str | None
    reason: str
    checks: tuple[CheckStep, ...]
    authenticated_claims: Mapping[str, Any] | None = None


def verify_oidc_token(
    token: str,
    public_key_pem: bytes,
    policy: TrustPolicy,
) -> VerificationDecision:
    """Verify JWT signature with RS256, then validate iss, aud, exp, and exact sub.

    Never decodes claims with `verify_signature=False`. Any failure during signature
    or registered-claim validation halts immediately with `authenticated_claims=None`.
    """
    try:
        # PyJWT verifies the JOSE algorithm allowlist (`RS256` only) and RSA signature
        # BEFORE inspecting or trusting any payload claims, then validates required
        # claims, `exp`, `iss`, and `aud`.
        verified_payload: dict[str, Any] = jwt.decode(
            token,
            public_key_pem,
            algorithms=[ALLOWED_ALGORITHM],
            issuer=policy.expected_issuer,
            audience=policy.expected_audience,
            options={
                "require": list(REQUIRED_CLAIMS),
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except jwt.InvalidAlgorithmError:
        return VerificationDecision(
            allowed=False,
            failure_code="invalid_algorithm",
            reason=f"Token algorithm rejected; only {ALLOWED_ALGORITHM} is permitted.",
            checks=(
                CheckStep("Signature & Alg", "FAIL", f"Header alg != {ALLOWED_ALGORITHM}"),
                CheckStep("Issuer (iss)", "SKIP", "Halted before claim checks"),
                CheckStep("Audience (aud)", "SKIP", "Halted before claim checks"),
                CheckStep("Expiration (exp)", "SKIP", "Halted before claim checks"),
                CheckStep("Subject (sub)", "SKIP", "Halted before claim checks"),
            ),
        )
    except jwt.InvalidSignatureError:
        return VerificationDecision(
            allowed=False,
            failure_code="invalid_signature",
            reason="Cryptographic RSA signature verification failed; claims are untrusted.",
            checks=(
                CheckStep("Signature & Alg", "FAIL", "RSA signature invalid"),
                CheckStep("Issuer (iss)", "SKIP", "Untrusted payload ignored"),
                CheckStep("Audience (aud)", "SKIP", "Untrusted payload ignored"),
                CheckStep("Expiration (exp)", "SKIP", "Untrusted payload ignored"),
                CheckStep("Subject (sub)", "SKIP", "Untrusted payload ignored"),
            ),
        )
    except jwt.ExpiredSignatureError:
        return VerificationDecision(
            allowed=False,
            failure_code="expired_token",
            reason="Token expiration time (exp) has already passed.",
            checks=(
                CheckStep("Signature & Alg", "PASS", f"Verified with {ALLOWED_ALGORITHM}"),
                CheckStep("Issuer (iss)", "SKIP", "Halted on expired token"),
                CheckStep("Audience (aud)", "SKIP", "Halted on expired token"),
                CheckStep("Expiration (exp)", "FAIL", "Token is expired"),
                CheckStep("Subject (sub)", "SKIP", "Halted on expired token"),
            ),
        )
    except jwt.InvalidIssuerError:
        return VerificationDecision(
            allowed=False,
            failure_code="invalid_issuer",
            reason=f"Issuer claim (iss) did not match '{policy.expected_issuer}'.",
            checks=(
                CheckStep("Signature & Alg", "PASS", f"Verified with {ALLOWED_ALGORITHM}"),
                CheckStep("Issuer (iss)", "FAIL", f"Expected '{policy.expected_issuer}'"),
                CheckStep("Audience (aud)", "SKIP", "Halted on issuer mismatch"),
                CheckStep("Expiration (exp)", "PASS", "Not expired"),
                CheckStep("Subject (sub)", "SKIP", "Halted on issuer mismatch"),
            ),
        )
    except jwt.InvalidAudienceError:
        return VerificationDecision(
            allowed=False,
            failure_code="invalid_audience",
            reason=f"Audience claim (aud) did not match '{policy.expected_audience}'.",
            checks=(
                CheckStep("Signature & Alg", "PASS", f"Verified with {ALLOWED_ALGORITHM}"),
                CheckStep("Issuer (iss)", "PASS", policy.expected_issuer),
                CheckStep("Audience (aud)", "FAIL", f"Expected '{policy.expected_audience}'"),
                CheckStep("Expiration (exp)", "PASS", "Not expired"),
                CheckStep("Subject (sub)", "SKIP", "Halted on audience mismatch"),
            ),
        )
    except jwt.MissingRequiredClaimError as exc:
        return VerificationDecision(
            allowed=False,
            failure_code="missing_claim",
            reason=f"Token is missing a required OIDC claim: {exc.claim}.",
            checks=(
                CheckStep("Signature & Alg", "PASS", f"Verified with {ALLOWED_ALGORITHM}"),
                CheckStep("Issuer (iss)", "FAIL", f"Missing required claim: {exc.claim}"),
                CheckStep("Audience (aud)", "SKIP", "Halted on missing claim"),
                CheckStep("Expiration (exp)", "SKIP", "Halted on missing claim"),
                CheckStep("Subject (sub)", "SKIP", "Halted on missing claim"),
            ),
        )
    except jwt.PyJWTError as exc:
        return VerificationDecision(
            allowed=False,
            failure_code="malformed_token",
            reason=f"Token could not be parsed or verified: {type(exc).__name__}.",
            checks=(
                CheckStep("Signature & Alg", "FAIL", f"Malformed JWT ({type(exc).__name__})"),
                CheckStep("Issuer (iss)", "SKIP", "Untrusted payload ignored"),
                CheckStep("Audience (aud)", "SKIP", "Untrusted payload ignored"),
                CheckStep("Expiration (exp)", "SKIP", "Untrusted payload ignored"),
                CheckStep("Subject (sub)", "SKIP", "Untrusted payload ignored"),
            ),
        )

    # Enforce exact string match on `aud` (mirrors IAM `StringEquals` on `:aud`).
    actual_aud = verified_payload.get("aud")
    if not isinstance(actual_aud, str) or actual_aud != policy.expected_audience:
        return VerificationDecision(
            allowed=False,
            failure_code="invalid_audience",
            reason=f"Audience claim must equal exact string '{policy.expected_audience}'.",
            checks=(
                CheckStep("Signature & Alg", "PASS", f"Verified with {ALLOWED_ALGORITHM}"),
                CheckStep("Issuer (iss)", "PASS", policy.expected_issuer),
                CheckStep("Audience (aud)", "FAIL", f"Expected exact string '{policy.expected_audience}'"),
                CheckStep("Expiration (exp)", "PASS", "Not expired"),
                CheckStep("Subject (sub)", "SKIP", "Halted on audience mismatch"),
            ),
        )

    exp_ts = int(verified_payload["exp"])
    remaining_s = max(0, exp_ts - int(datetime.now(tz=UTC).timestamp()))
    exp_detail = f"Valid (+{remaining_s}s remaining)"

    # Enforce exact string match on `sub` (mirrors IAM `StringEquals` on `:sub`).
    actual_sub = verified_payload.get("sub")
    if not isinstance(actual_sub, str) or actual_sub != policy.expected_subject:
        return VerificationDecision(
            allowed=False,
            failure_code="subject_mismatch",
            reason=(
                f"AccessDenied: token is genuine, but subject '{actual_sub}' "
                f"does not match allowed subject '{policy.expected_subject}'."
            ),
            checks=(
                CheckStep("Signature & Alg", "PASS", f"Verified with {ALLOWED_ALGORITHM}"),
                CheckStep("Issuer (iss)", "PASS", verified_payload["iss"]),
                CheckStep("Audience (aud)", "PASS", actual_aud),
                CheckStep("Expiration (exp)", "PASS", exp_detail),
                CheckStep("Subject (sub)", "FAIL", str(actual_sub)),
            ),
            authenticated_claims=None,
        )

    return VerificationDecision(
        allowed=True,
        failure_code=None,
        reason="AssumeRoleWithWebIdentity allowed: all cryptographic and trust policy checks passed.",
        checks=(
            CheckStep("Signature & Alg", "PASS", f"Verified with {ALLOWED_ALGORITHM}"),
            CheckStep("Issuer (iss)", "PASS", verified_payload["iss"]),
            CheckStep("Audience (aud)", "PASS", actual_aud),
            CheckStep("Expiration (exp)", "PASS", exp_detail),
            CheckStep("Subject (sub)", "PASS", actual_sub),
        ),
        authenticated_claims=MappingProxyType(dict(verified_payload)),
    )
