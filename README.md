# `github-actions-cloud-identity-demo`

Replace long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets in CI/CD with short-lived [GitHub Actions OpenID Connect (OIDC)](https://docs.github.com/en/actions/concepts/security/openid-connect) tokens and [AWS STS `AssumeRoleWithWebIdentity`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html).

If you come from JavaScript/TypeScript web development, think of this like replacing a hardcoded admin API key in `.env` with an OAuth/OIDC ID token flow for CI runners:

1. **GitHub's OIDC provider** (`https://token.actions.githubusercontent.com`) signs a short-lived JSON Web Token (JWT) describing the exact repository and Git branch running the workflow.
2. **AWS STS** verifies GitHub's cryptographic signature and checks the IAM role's **trust policy**.
3. **Only the `release` branch** passes the exact `sub` check and receives 15-minute AWS credentials scoped strictly to upload `release.json` under `s3://<bucket>/releases/*`.
4. **A second branch (`identity-denied-demo`)** requests a genuine GitHub JWT for the exact same `sts.amazonaws.com` audience and asks for the exact same AWS role—and proves AWS STS denies it with `AccessDenied` because its `sub` claim identifies a different branch.

## Repository Layout

```text
github-actions-cloud-identity-demo/
├── .github/
│   ├── scripts/oidc_sts_helper.sh          # Shared token exchange & strict AccessDenied check
│   └── workflows/
│       ├── ci.yml                          # Offline Python 3.12 tests on PRs (zero cloud perms)
│       ├── publish-release.yml             # Push to `release` -> STS allow -> S3 PutObject
│       └── verify-denial.yml               # Push to `identity-denied-demo` -> STS AccessDenied
├── oidc_verifier/
│   ├── cli.py                              # Side-by-side local simulation CLI
│   ├── fixtures.py                         # Ephemeral 2048-bit RSA keypair & fixture JWT minter
│   └── verifier.py                         # Strict RS256 PyJWT verifier + exact claim checks
├── terraform/                              # Private S3 bucket, OIDC provider, IAM role & policies
├── tests/test_verifier.py                  # Offline pytest suite (allowed + 7 rejection paths)
├── pyproject.toml
└── requirements.txt
```

## 1. 60-Second Local Walkthrough (No AWS Account, GitHub Login, or API Key)

You can run the complete signature and claim verification model locally on Windows 11 with WSL2 (Ubuntu) using an in-memory 2048-bit RSA keypair and a fictional RFC 2606 fixture issuer (`https://oidc-fixture.example.invalid`). Once `PyJWT[crypto]` and `pytest` are installed in your virtual environment, the simulation and tests run completely offline.

> **WSL2 Ubuntu prerequisite:** Ensure Python 3.12 with `venv` is installed (`sudo apt update && sudo apt install -y python3.12 python3.12-venv unzip`).

From the directory where you extracted `github-actions-cloud-identity-demo.zip`, run:

```bash
cd github-actions-cloud-identity-demo
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m oidc_verifier.cli
pytest -v
```

### Illustrative Sample Output (`python -m oidc_verifier.cli`)

*Illustrative output (run locally in WSL2 to verify; remaining TTL seconds vary slightly per run):*

```text
Offline GitHub Actions -> AWS STS OIDC Trust Policy Simulation
Fixture Issuer   : https://oidc-fixture.example.invalid (offline simulation only)
Trusted Audience : sts.amazonaws.com
Trusted Subject  : repo:demo-owner/github-actions-cloud-identity-demo:ref:refs/heads/release

+---------------------+----------------------------------------+----------------------------------------+
| Verification Gate   | Workflow 1: push -> release            | Workflow 2: push ->                    |
|                     |                                        | identity-denied-demo                   |
+=====================+========================================+========================================+
| Signature & Alg     | [PASS] Verified with RS256             | [PASS] Verified with RS256             |
+---------------------+----------------------------------------+----------------------------------------+
| Issuer (iss)        | [PASS]                                 | [PASS]                                 |
|                     | https://oidc-fixture.example.invalid   | https://oidc-fixture.example.invalid   |
+---------------------+----------------------------------------+----------------------------------------+
| Audience (aud)      | [PASS] sts.amazonaws.com               | [PASS] sts.amazonaws.com               |
+---------------------+----------------------------------------+----------------------------------------+
| Expiration (exp)    | [PASS] Valid (+300s remaining)         | [PASS] Valid (+300s remaining)         |
+---------------------+----------------------------------------+----------------------------------------+
| Subject (sub)       | [PASS] repo:demo-owner/github-actions- | [FAIL] repo:demo-owner/github-actions- |
|                     | cloud-identity-demo:ref:refs/heads/rel | cloud-identity-demo:ref:refs/heads/ide |
|                     | ease                                   | ntity-denied-demo                      |
+---------------------+----------------------------------------+----------------------------------------+
| STS Role Decision   | ALLOWED -> STS issues short-lived S3   | DENIED (subject_mismatch) -> STS       |
|                     | PutObject credentials                  | returns AccessDenied                   |
+---------------------+----------------------------------------+----------------------------------------+
```

### What `oidc_verifier/verifier.py` Enforces

- **Cryptographic verification before reading claims:** Calls [PyJWT](https://pyjwt.readthedocs.io/en/stable/usage.html) `jwt.decode(..., algorithms=["RS256"])` with `verify_signature=True`. Unverified claims (`verify_signature=False`) are never decoded anywhere in the project, and `decision.authenticated_claims` stays `None` whenever any check fails.
- **Eight automated test cases in `tests/test_verifier.py`:** Validates the allowed `release` branch, wrong branch (`identity-denied-demo`), wrong repository, wrong issuer, wrong audience, expired token, invalid RSA signature (both an untrusted signing key and a tampered payload claiming `release`), and algorithm confusion (`HS256` token against an `RS256` policy).

## 2. How the Token Exchange Works

```mermaid
sequenceDiagram
    autonumber
    participant GHA as GitHub Actions Runner<br/>(publish-release or verify-denial)
    participant OIDC as GitHub OIDC Provider<br/>(token.actions.githubusercontent.com)
    participant STS as AWS STS<br/>(AssumeRoleWithWebIdentity)
    participant S3 as Private Amazon S3 Bucket<br/>(releases/*)

    GHA->>OIDC: Request JWT with audience=sts.amazonaws.com<br/>(Bearer ACTIONS_ID_TOKEN_REQUEST_TOKEN)
    OIDC-->>GHA: Signed RS256 JWT (iss, aud, exp, sub=repo:OWNER/REPO:ref:refs/heads/<branch>)
    GHA->>STS: AssumeRoleWithWebIdentity(RoleArn, WebIdentityToken, DurationSeconds=900)
    Note over STS: 1. Verify RS256 signature via GitHub JWKS<br/>2. Check StringEquals aud == "sts.amazonaws.com"<br/>3. Check StringEquals sub == "...:ref:refs/heads/release"
    alt Branch is refs/heads/release
        STS-->>GHA: Temporary credentials (AccessKeyId, SecretAccessKey, SessionToken)
        GHA->>S3: PutObject s3://<bucket>/releases/<run>-<attempt>-<sha>/release.json
        S3-->>GHA: 200 OK
    else Branch is refs/heads/identity-denied-demo
        STS-->>GHA: AccessDenied (Not authorized to perform sts:AssumeRoleWithWebIdentity)
        Note over GHA,S3: No credentials issued; verify-denial.yml asserts AccessDenied and never calls S3
    end
```

## 3. Security Architecture: Trust Policy vs. Permissions Policy & Branch Protection

Understanding AWS workload identity comes down to separating **three independent controls** ([AWS IAM Identity-Based vs. Resource-Based Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html)):

1. **IAM Role Trust Policy (`assume_role_policy` in `terraform/main.tf`) — *Who can step into the role?***
   A trust policy is a resource-based policy attached to the IAM role itself. AWS STS evaluates it **before** any AWS credentials exist. Here, `StringEquals` requires `token.actions.githubusercontent.com:aud` to equal `sts.amazonaws.com` and `token.actions.githubusercontent.com:sub` to equal `repo:OWNER/REPO:ref:refs/heads/release`. Using `StringEquals` instead of a wildcard `repo:OWNER/REPO:*` stops feature branches, pull requests, and tags from assuming the release role.
2. **S3 Permissions Policy (`aws_iam_role_policy` in `terraform/main.tf`) — *What can the role do once assumed?***
   An identity-based permissions policy limits blast radius **after** authentication succeeds. Even on the `release` branch, the 15-minute session credentials only grant `s3:PutObject` on `arn:aws:s3:::<bucket>/releases/*`. The job cannot list the bucket, read other objects, delete artifacts, or call IAM/EC2. Meanwhile, `aws_s3_bucket_public_access_block` enforces all four [Amazon S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html) settings.
3. **GitHub Branch Protection on `release` — *Who controls the code running as that identity?***
   Because AWS trusts commits pushed to `refs/heads/release`, anyone allowed to push directly to `release` could edit `.github/workflows/publish-release.yml` and use that IAM role. Configuring a [GitHub branch protection rule](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule) on `release` (requiring pull request reviews, requiring the `Python 3.12 OIDC Verifier & Pytest` status check to pass, and blocking force-pushes) prevents unreviewed workflow changes from reaching your trusted branch.

## 4. Optional Live Walkthrough (AWS + GitHub Actions)

Skip this section if you only want the offline demo. Follow these steps when you are ready to verify live OIDC federation in your own AWS account and GitHub repository.

### Step 1: Create Your GitHub Repository and Push `main` First

Create an empty repository named `github-actions-cloud-identity-demo` on GitHub, then push `main` **before** creating `release` or `identity-denied-demo` (so those branch-specific workflows do not run before your repository variables exist):

```bash
git init -b main
git add .
git commit -m "Initial commit: GitHub Actions to AWS OIDC identity demo"
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/github-actions-cloud-identity-demo.git
git push -u origin main
```

Pushing `main` runs `.github/workflows/ci.yml` (`Offline Verifier CI`), which requires only `contents: read` and zero AWS configuration.

> **Important note on GitHub's subject claim format ([GitHub OIDC Reference](https://docs.github.com/en/actions/reference/security/oidc)):**
> Repositories created on GitHub.com **before July 15, 2026** (or on GitHub Enterprise Server) emit `sub` as `repo:OWNER/REPO:ref:refs/heads/release`. Repositories created on GitHub.com **after July 15, 2026** default to an immutable subject format that appends numeric IDs: `repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/release`. If your repository was newly created on GitHub.com, check its IDs with `gh api repos/YOUR_GITHUB_USERNAME/github-actions-cloud-identity-demo --jq '"\(.owner.login)@\(.owner.id) and \(.name)@\(.id)"'` and pass those `OWNER@OWNER_ID` / `REPO@REPO_ID` values for `github_owner` and `github_repo` in `terraform.tfvars` so the exact `StringEquals` check matches your repo's `sub` claim.

### Step 2: Provision the AWS Infrastructure with Terraform

Authenticate your local terminal to AWS (for example via `aws sso login` or short-lived environment credentials) and apply `terraform/`:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform/terraform.tfvars`:

- Set `github_owner` (and `github_repo` if you renamed the repository).
- AWS allows only one [IAM OIDC identity provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html) per account for `https://token.actions.githubusercontent.com`. Leave `create_oidc_provider = true` if your AWS account does not have one yet, or set `create_oidc_provider = false` and set `existing_oidc_provider_arn` if one already exists.

Run Terraform:

```bash
terraform init
terraform validate
terraform apply
terraform output github_repository_variables
cd ..
```

### Step 3: Set GitHub Actions Repository Variables

Both `.github/workflows/publish-release.yml` and `.github/workflows/verify-denial.yml` read the exact same three **Repository Variables** (under **Settings -> Secrets and variables -> Actions -> Variables** -> **New repository variable**):

| GitHub Repository Variable | Terraform Output Key | Purpose |
| :--- | :--- | :--- |
| `AWS_ROLE_ARN` | `aws_role_arn` | IAM role ARN requested by `AssumeRoleWithWebIdentity` |
| `AWS_REGION` | `aws_region` | AWS region for STS and S3 API calls (e.g., `us-east-1`) |
| `S3_BUCKET_NAME` | `s3_bucket_name` | Private S3 bucket receiving `releases/.../release.json` |

Notice there are **zero GitHub Secrets**—role ARNs, regions, and bucket names are non-secret configuration identifiers, while actual credentials are minted per job and kept only in process memory for 15 minutes (`DurationSeconds: 900`).

### Step 4: Create Both Branches and Trigger the Two Cloud Workflows

Create and push `release` and `identity-denied-demo` **only after** `terraform apply` succeeds and all three repository variables are saved:

```bash
# 1. Trigger the allowed workflow (.github/workflows/publish-release.yml)
git checkout -b release main
git push -u origin release

# 2. Trigger the denial proof workflow (.github/workflows/verify-denial.yml)
git checkout -b identity-denied-demo main
git push -u origin identity-denied-demo

git checkout main
```

After pushing `release`, enable a branch protection rule or ruleset on `release` under **Settings -> Branches** requiring pull request reviews and passing status checks before future merges. To re-trigger either workflow later without changing files, push an empty commit (`git commit --allow-empty -m "Re-run OIDC check" && git push`).

### Step 5: Verify Workflow Logs and the Private S3 Object

1. In GitHub **Actions**:
   - **Publish Release Metadata via OIDC** (`release` branch) succeeds: `.github/scripts/oidc_sts_helper.sh` masks the JWT and temporary STS keys, assumes the role, and uploads `releases/<run_id>-<attempt>-<sha>/release.json`.
   - **Verify Unauthorized Branch OIDC Denial** (`identity-denied-demo` branch) also turns **green**, because `verify-denial` passes **only** when GitHub OIDC token acquisition succeeds and AWS STS fails with `(AccessDenied)` on `AssumeRoleWithWebIdentity` (missing variables, network timeouts, unexpected STS success, or unrelated AWS errors all fail the job).
2. From your local AWS-authenticated WSL2 shell, verify the uploaded JSON object and confirm only the `release` run wrote to `releases/`:

```bash
BUCKET="$(terraform -chdir=terraform output -raw s3_bucket_name)"
aws s3 ls "s3://${BUCKET}/releases/" --recursive

# Copy the key printed above and inspect its JSON contents:
aws s3 cp "s3://${BUCKET}/releases/<RUN_ID>-<ATTEMPT>-<SHA>/release.json" -
```

*Illustrative sample `release.json` content:*

```json
{
  "repository": "YOUR_GITHUB_USERNAME/github-actions-cloud-identity-demo",
  "sha": "0123456789abcdef0123456789abcdef01234567",
  "run_id": "12345678901",
  "ref": "refs/heads/release",
  "generated_at_utc": "2026-11-18T12:00:00Z"
}
```

### Step 6: Clean Up AWS Resources

`force_destroy_bucket = true` is enabled by default in `terraform/variables.tf` so teardown removes demo `releases/*` objects and the bucket in one step:

```bash
cd terraform
terraform destroy
cd ..
```

## 5. Verification Status

| Check | Where Executed | Status | Notes |
| :--- | :--- | :--- | :--- |
| Python syntax & AST compilation (`oidc_verifier/*`, `tests/test_verifier.py`) | Run in generation session | Verified | Compiled cleanly via `py_compile` and AST inspection |
| Workflow YAML parsing & variable alignment (`ci.yml`, `publish-release.yml`, `verify-denial.yml`, `terraform/*`) | Run in generation session | Verified | Parsed with `PyYAML`; confirmed `AWS_ROLE_ARN`, `AWS_REGION`, and `S3_BUCKET_NAME` match across workflows, Terraform, and README |
| Shared helper shell syntax & mocked behavior (`.github/scripts/oidc_sts_helper.sh`) | Run in generation session | Verified | Tested `bash -n` plus mocked `curl`/`aws` runs covering allowed upload, expected `AccessDenied`, unexpected allow, missing config, network timeout, unrelated AWS error, and `::add-mask::` secret masking |
| Archive layout (`github-actions-cloud-identity-demo.zip`) | Run in generation session | Verified | Confirmed single top-level `github-actions-cloud-identity-demo/` directory including `.github/workflows/` and `.github/scripts/` |
| Offline cryptographic JWT CLI & `pytest -v` under Python 3.12 | Run locally in WSL2 | Pending your local run | Generation sandbox did not pre-install `PyJWT`/`pytest`; run the 60-second WSL2 walkthrough above |
| `terraform init && terraform validate && terraform apply` | Run in your AWS account | Pending optional live run | Requires Terraform `>= 1.5` and AWS credentials |
| Live GitHub OIDC -> AWS STS `release` upload & `identity-denied-demo` `AccessDenied` | Run in your GitHub + AWS accounts | Pending optional live run | Requires pushing `release` and `identity-denied-demo` after setting repository variables |

## 6. Official Documentation References

- [GitHub Docs: OpenID Connect overview](https://docs.github.com/en/actions/concepts/security/openid-connect)
- [GitHub Docs: Configuring OpenID Connect in Amazon Web Services](https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [GitHub Docs: OpenID Connect reference (claims & subject formats)](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub Docs: Managing a branch protection rule](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule)
- [AWS STS API Reference: `AssumeRoleWithWebIdentity`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
- [AWS CLI Reference: `aws sts assume-role-with-web-identity`](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role-with-web-identity.html)
- [AWS IAM User Guide: Creating OpenID Connect (OIDC) identity providers](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
- [AWS IAM User Guide: Identity-based policies and resource-based policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html)
- [Amazon S3 User Guide: Blocking public access to your Amazon S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [PyJWT Documentation: RS256 and claim validation](https://pyjwt.readthedocs.io/en/stable/usage.html)
