"""Ephemeral RSA key generation and simulated OIDC token minting for offline tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

from oidc_verifier.verifier import ALLOWED_ALGORITHM

# RFC 2606 reserves `.invalid` so this fixture issuer can never collide with a real IdP.
FIXTURE_ISSUER = "https://oidc-fixture.example.invalid"
DEFAULT_AUDIENCE = "sts.amazonaws.com"
DEFAULT_OWNER = "demo-owner"
DEFAULT_REPO = "github-actions-cloud-identity-demo"


@dataclass(frozen=True)
class EphemeralKeyPair:
    """In-memory RSA keypair generated at runtime for offline signing and verification."""

    private_pem: bytes
    public_pem: bytes
    key_id: str


def generate_ephemeral_keypair(key_id: str = "fixture-ephemeral-rs256-1") -> EphemeralKeyPair:
    """Generate a fresh 2048-bit RSA keypair in memory without touching disk or network."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return EphemeralKeyPair(
        private_pem=private_pem,
        public_pem=public_pem,
        key_id=key_id,
    )


def build_branch_subject(owner: str, repo: str, branch: str) -> str:
    """Format the standard GitHub Actions branch subject claim without an Environment."""
    return f"repo:{owner}/{repo}:ref:refs/heads/{branch}"


def mint_simulated_oidc_token(
    keypair: EphemeralKeyPair,
    *,
    owner: str = DEFAULT_OWNER,
    repo: str = DEFAULT_REPO,
    branch: str = "release",
    issuer: str = FIXTURE_ISSUER,
    audience: str | list[str] = DEFAULT_AUDIENCE,
    ttl_seconds: int = 300,
    subject_override: str | None = None,
    algorithm: str = ALLOWED_ALGORITHM,
) -> str:
    """Sign a simulated GitHub-style OIDC JWT using the supplied ephemeral RSA keypair."""
    now = datetime.now(tz=UTC)
    exp = now + timedelta(seconds=ttl_seconds)
    issued_at = now if ttl_seconds >= 0 else exp - timedelta(seconds=300)
    subject = subject_override if subject_override is not None else build_branch_subject(owner, repo, branch)

    payload: dict[str, Any] = {
        "jti": str(uuid.uuid4()),
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": int(issued_at.timestamp()),
        "nbf": int(issued_at.timestamp()),
        "exp": int(exp.timestamp()),
        "repository": f"{owner}/{repo}",
        "repository_owner": owner,
        "ref": f"refs/heads/{branch}",
        "ref_type": "branch",
        "event_name": "push",
        "runner_environment": "github-hosted",
    }
    headers = {"kid": keypair.key_id}
    return jwt.encode(payload, keypair.private_pem, algorithm=algorithm, headers=headers)
