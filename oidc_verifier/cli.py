"""Side-by-side offline CLI demonstrating allowed vs. branch-denied OIDC tokens."""

from __future__ import annotations

import textwrap

from oidc_verifier.fixtures import (
    DEFAULT_AUDIENCE,
    DEFAULT_OWNER,
    DEFAULT_REPO,
    FIXTURE_ISSUER,
    build_branch_subject,
    generate_ephemeral_keypair,
    mint_simulated_oidc_token,
)
from oidc_verifier.verifier import TrustPolicy, VerificationDecision, verify_oidc_token

COL_LABEL = 19
COL_VALUE = 38


def _wrap_cell(text: str, width: int) -> list[str]:
    lines = textwrap.wrap(text, width=width, break_long_words=True, break_on_hyphens=False)
    return lines or [""]


def _format_row(label: str, left: str, right: str) -> str:
    left_lines = _wrap_cell(left, COL_VALUE)
    right_lines = _wrap_cell(right, COL_VALUE)
    label_lines = _wrap_cell(label, COL_LABEL)
    height = max(len(label_lines), len(left_lines), len(right_lines))

    rendered: list[str] = []
    for idx in range(height):
        c0 = label_lines[idx] if idx < len(label_lines) else ""
        c1 = left_lines[idx] if idx < len(left_lines) else ""
        c2 = right_lines[idx] if idx < len(right_lines) else ""
        rendered.append(f"| {c0:<{COL_LABEL}} | {c1:<{COL_VALUE}} | {c2:<{COL_VALUE}} |")
    return "\n".join(rendered)


def _divider(char: str = "-") -> str:
    return f"+{char * (COL_LABEL + 2)}+{char * (COL_VALUE + 2)}+{char * (COL_VALUE + 2)}+"


def render_comparison(
    policy: TrustPolicy,
    allow_decision: VerificationDecision,
    deny_decision: VerificationDecision,
) -> str:
    """Render a side-by-side table comparing the `release` and `identity-denied-demo` runs."""
    lines: list[str] = [
        "Offline GitHub Actions -> AWS STS OIDC Trust Policy Simulation",
        f"Fixture Issuer   : {policy.expected_issuer} (offline simulation only)",
        f"Trusted Audience : {policy.expected_audience}",
        f"Trusted Subject  : {policy.expected_subject}",
        "",
        _divider("="),
        _format_row(
            "Verification Gate",
            "Workflow 1: push -> release",
            "Workflow 2: push -> identity-denied-demo",
        ),
        _divider("="),
    ]

    for left_step, right_step in zip(allow_decision.checks, deny_decision.checks, strict=True):
        left_cell = f"[{left_step.status}] {left_step.detail}"
        right_cell = f"[{right_step.status}] {right_step.detail}"
        lines.append(_format_row(left_step.gate, left_cell, right_cell))
        lines.append(_divider("-"))

    left_outcome = (
        "ALLOWED -> STS issues short-lived S3 PutObject credentials"
        if allow_decision.allowed
        else f"DENIED ({allow_decision.failure_code})"
    )
    right_outcome = (
        "ALLOWED (UNEXPECTED)"
        if deny_decision.allowed
        else f"DENIED ({deny_decision.failure_code}) -> STS returns AccessDenied"
    )
    lines.append(_format_row("STS Role Decision", left_outcome, right_outcome))
    lines.append(_divider("="))
    lines.extend(
        [
            "",
            "Key takeaway:",
            "  The `identity-denied-demo` token is cryptographically genuine (signed by the same",
            "  ephemeral RSA key, for the same issuer and `sts.amazonaws.com` audience, and unexpired).",
            "  AWS STS still rejects AssumeRoleWithWebIdentity because `sub` encodes the git ref,",
            "  and `refs/heads/identity-denied-demo` fails the exact `StringEquals` trust check.",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    """Generate an ephemeral keypair, mint both branch tokens, and compare STS decisions."""
    keypair = generate_ephemeral_keypair()
    allowed_subject = build_branch_subject(DEFAULT_OWNER, DEFAULT_REPO, "release")
    policy = TrustPolicy(
        expected_issuer=FIXTURE_ISSUER,
        expected_audience=DEFAULT_AUDIENCE,
        expected_subject=allowed_subject,
    )

    release_token = mint_simulated_oidc_token(keypair, branch="release")
    denied_branch_token = mint_simulated_oidc_token(keypair, branch="identity-denied-demo")

    allow_decision = verify_oidc_token(release_token, keypair.public_pem, policy)
    deny_decision = verify_oidc_token(denied_branch_token, keypair.public_pem, policy)

    print(render_comparison(policy, allow_decision, deny_decision))

    # Exit non-zero if either simulation invariants ever break.
    if not allow_decision.allowed or deny_decision.allowed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
