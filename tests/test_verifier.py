"""Offline unit tests for cryptographic OIDC JWT verification and exact subject matching."""

from __future__ import annotations

import base64
import json

import jwt
import pytest

from oidc_verifier.cli import main as cli_main
from oidc_verifier.fixtures import (
    DEFAULT_AUDIENCE,
    DEFAULT_OWNER,
    DEFAULT_REPO,
    FIXTURE_ISSUER,
    EphemeralKeyPair,
    build_branch_subject,
    generate_ephemeral_keypair,
    mint_simulated_oidc_token,
)
from oidc_verifier.verifier import TrustPolicy, verify_oidc_token


@pytest.fixture(scope="module")
def keypair() -> EphemeralKeyPair:
    return generate_ephemeral_keypair()


@pytest.fixture(scope="module")
def trust_policy() -> TrustPolicy:
    return TrustPolicy(
        expected_issuer=FIXTURE_ISSUER,
        expected_audience=DEFAULT_AUDIENCE,
        expected_subject=build_branch_subject(DEFAULT_OWNER, DEFAULT_REPO, "release"),
    )


def test_allowed_release_branch_token_succeeds(
    keypair: EphemeralKeyPair,
    trust_policy: TrustPolicy,
) -> None:
    token = mint_simulated_oidc_token(keypair, branch="release")
    decision = verify_oidc_token(token, keypair.public_pem, trust_policy)

    assert decision.allowed is True
    assert decision.failure_code is None
    assert decision.authenticated_claims is not None
    assert decision.authenticated_claims["sub"] == trust_policy.expected_subject
    assert all(step.status == "PASS" for step in decision.checks)


def test_wrong_branch_passes_crypto_checks_but_fails_exact_subject(
    keypair: EphemeralKeyPair,
    trust_policy: TrustPolicy,
) -> None:
    token = mint_simulated_oidc_token(keypair, branch="identity-denied-demo")
    decision = verify_oidc_token(token, keypair.public_pem, trust_policy)

    assert decision.allowed is False
    assert decision.failure_code == "subject_mismatch"
    assert decision.authenticated_claims is None

    by_gate = {step.gate: step.status for step in decision.checks}
    assert by_gate["Signature & Alg"] == "PASS"
    assert by_gate["Issuer (iss)"] == "PASS"
    assert by_gate["Audience (aud)"] == "PASS"
    assert by_gate["Expiration (exp)"] == "PASS"
    assert by_gate["Subject (sub)"] == "FAIL"


def test_wrong_repository_fails_exact_subject(
    keypair: EphemeralKeyPair,
    trust_policy: TrustPolicy,
) -> None:
    token = mint_simulated_oidc_token(
        keypair,
        owner=DEFAULT_OWNER,
        repo="some-other-repository",
        branch="release",
    )
    decision = verify_oidc_token(token, keypair.public_pem, trust_policy)

    assert decision.allowed is False
    assert decision.failure_code == "subject_mismatch"
    assert decision.authenticated_claims is None


def test_wrong_issuer_is_rejected(
    keypair: EphemeralKeyPair,
    trust_policy: TrustPolicy,
) -> None:
    token = mint_simulated_oidc_token(
        keypair,
        branch="release",
        issuer="https://untrusted-idp.example.invalid",
    )
    decision = verify_oidc_token(token, keypair.public_pem, trust_policy)

    assert decision.allowed is False
    assert decision.failure_code == "invalid_issuer"
    assert decision.authenticated_claims is None


def test_wrong_audience_is_rejected(
    keypair: EphemeralKeyPair,
    trust_policy: TrustPolicy,
) -> None:
    token = mint_simulated_oidc_token(
        keypair,
        branch="release",
        audience="https://wrong-audience.example.invalid",
    )
    decision = verify_oidc_token(token, keypair.public_pem, trust_policy)

    assert decision.allowed is False
    assert decision.failure_code == "invalid_audience"
    assert decision.authenticated_claims is None


def test_expired_token_is_rejected(
    keypair: EphemeralKeyPair,
    trust_policy: TrustPolicy,
) -> None:
    token = mint_simulated_oidc_token(keypair, branch="release", ttl_seconds=-60)
    decision = verify_oidc_token(token, keypair.public_pem, trust_policy)

    assert decision.allowed is False
    assert decision.failure_code == "expired_token"
    assert decision.authenticated_claims is None


def test_invalid_signature_from_untrusted_key_and_tampered_payload_are_rejected(
    keypair: EphemeralKeyPair,
    trust_policy: TrustPolicy,
) -> None:
    # Case A: Token signed with a different RSA private key.
    attacker_keypair = generate_ephemeral_keypair(key_id="attacker-ephemeral-key")
    forged_token = mint_simulated_oidc_token(attacker_keypair, branch="release")
    forged_decision = verify_oidc_token(forged_token, keypair.public_pem, trust_policy)

    assert forged_decision.allowed is False
    assert forged_decision.failure_code == "invalid_signature"
    assert forged_decision.authenticated_claims is None

    # Case B: Genuine denied token whose payload is modified to claim the `release` branch
    # without a matching signature. Proves unverified claims are never treated as authenticated.
    denied_token = mint_simulated_oidc_token(keypair, branch="identity-denied-demo")
    header_b64, payload_b64, signature_b64 = denied_token.split(".")
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    tampered_claims = json.loads(base64.urlsafe_b64decode(padded))
    tampered_claims["sub"] = trust_policy.expected_subject
    tampered_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(tampered_claims).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    tampered_token = f"{header_b64}.{tampered_payload_b64}.{signature_b64}"

    tampered_decision = verify_oidc_token(tampered_token, keypair.public_pem, trust_policy)
    assert tampered_decision.allowed is False
    assert tampered_decision.failure_code == "invalid_signature"
    assert tampered_decision.authenticated_claims is None


def test_disallowed_algorithm_is_rejected(
    keypair: EphemeralKeyPair,
    trust_policy: TrustPolicy,
) -> None:
    hs256_token = jwt.encode(
        {
            "iss": FIXTURE_ISSUER,
            "aud": DEFAULT_AUDIENCE,
            "sub": trust_policy.expected_subject,
            "iat": 1_700_000_000,
            "exp": 4_000_000_000,
        },
        "symmetric-secret-at-least-32-bytes-long!!",
        algorithm="HS256",
    )
    decision = verify_oidc_token(hs256_token, keypair.public_pem, trust_policy)

    assert decision.allowed is False
    assert decision.failure_code == "invalid_algorithm"
    assert decision.authenticated_claims is None


def test_cli_side_by_side_output_shows_teaching_point(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli_main()
    captured = capsys.readouterr().out
    # The table renderer wraps long header cells across two rows, so strip
    # the "|" cell borders and collapse whitespace before comparing.
    normalised = " ".join(captured.replace("|", " ").split())

    assert exit_code == 0
    assert "Workflow 1: push -> release" in normalised
    assert "Workflow 2: push -> identity-denied-demo" in normalised
    assert "DENIED (subject_mismatch)" in normalised
