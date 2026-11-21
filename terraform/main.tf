locals {
  github_oidc_issuer_host = "token.actions.githubusercontent.com"
  github_oidc_issuer_url  = "https://token.actions.githubusercontent.com"
  oidc_audience           = "sts.amazonaws.com"

  # Default GitHub Actions branch subject format with no GitHub Environment set on the job.
  allowed_oidc_subject = "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/release"

  oidc_provider_arn = (
    var.create_oidc_provider
    ? aws_iam_openid_connect_provider.github[0].arn
    : var.existing_oidc_provider_arn
  )
}

# 1. Optional GitHub Actions OIDC Identity Provider (one per AWS account per issuer URL)
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url             = local.github_oidc_issuer_url
  client_id_list  = [local.oidc_audience]
  thumbprint_list = var.github_oidc_thumbprints
}

# 2. Private S3 Bucket with all four Block Public Access controls enabled
resource "aws_s3_bucket" "releases" {
  bucket        = var.bucket_name != "" ? var.bucket_name : null
  bucket_prefix = var.bucket_name == "" ? var.bucket_prefix : null
  force_destroy = var.force_destroy_bucket
}

resource "aws_s3_bucket_public_access_block" "releases" {
  bucket = aws_s3_bucket.releases.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "releases" {
  bucket = aws_s3_bucket.releases.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 3. IAM Role Trust Policy (Authentication / Principal Gate: WHO may assume the role)
data "aws_iam_policy_document" "oidc_trust" {
  statement {
    sid     = "AllowGitHubActionsReleaseBranchOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_issuer_host}:aud"
      values   = [local.oidc_audience]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_issuer_host}:sub"
      values   = [local.allowed_oidc_subject]
    }
  }
}

resource "aws_iam_role" "release_publisher" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.oidc_trust.json
  max_session_duration = 3600
}

# 4. S3 Permissions Policy (Authorization Gate: WHAT the assumed role may do)
data "aws_iam_policy_document" "s3_put_releases_only" {
  statement {
    sid       = "AllowPutObjectUnderReleasesPrefixOnly"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.releases.arn}/releases/*"]
  }
}

resource "aws_iam_role_policy" "s3_put_releases_only" {
  name   = "s3-put-releases-prefix-only"
  role   = aws_iam_role.release_publisher.id
  policy = data.aws_iam_policy_document.s3_put_releases_only.json
}
