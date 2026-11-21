"""Offline simulation of GitHub Actions OIDC token verification by AWS STS."""

from oidc_verifier.fixtures import (
    DEFAULT_AUDIENCE,
    DEFAULT_OWNER,
    DEFAULT_REPO,
    FIXTURE_ISSUER,
    EphemeralKeyPair,
    generate_ephemeral_keypair,
    mint_simulated_oidc_token,
)
from oidc_verifier.verifier import (
    ALLOWED_ALGORITHM,
    CheckStep,
    TrustPolicy,
    VerificationDecision,
    verify_oidc_token,
)

__all__ = [
    "ALLOWED_ALGORITHM",
    "DEFAULT_AUDIENCE",
    "DEFAULT_OWNER",
    "DEFAULT_REPO",
    "FIXTURE_ISSUER",
    "CheckStep",
    "EphemeralKeyPair",
    "TrustPolicy",
    "VerificationDecision",
    "generate_ephemeral_keypair",
    "mint_simulated_oidc_token",
    "verify_oidc_token",
]
