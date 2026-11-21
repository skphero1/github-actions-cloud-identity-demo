variable "aws_region" {
  description = "AWS region for the S3 bucket and STS regional endpoint (stored in GitHub variable AWS_REGION)."
  type        = string
  default     = "us-east-1"
}

variable "github_owner" {
  description = "GitHub username or organization owning the repository (for post-July-2026 immutable subjects, pass OWNER@OWNER_ID)."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+(@[0-9]+)?$", var.github_owner))
    error_message = "github_owner must be a valid GitHub user/organization name (optionally suffixed with @OWNER_ID)."
  }
}

variable "github_repo" {
  description = "GitHub repository name (for post-July-2026 immutable subjects, pass REPO@REPO_ID)."
  type        = string
  default     = "github-actions-cloud-identity-demo"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+(@[0-9]+)?$", var.github_repo))
    error_message = "github_repo must be a valid GitHub repository name (optionally suffixed with @REPO_ID)."
  }
}

variable "create_oidc_provider" {
  description = "Set true to create the IAM OIDC provider for token.actions.githubusercontent.com, or false to reuse existing_oidc_provider_arn."
  type        = bool
  default     = true
}

variable "existing_oidc_provider_arn" {
  description = "ARN of an existing IAM OIDC provider for token.actions.githubusercontent.com when create_oidc_provider is false."
  type        = string
  default     = ""

  validation {
    condition = (
      var.create_oidc_provider ||
      can(regex("^arn:aws(-[a-z]+)?:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.existing_oidc_provider_arn))
    )
    error_message = "When create_oidc_provider is false, existing_oidc_provider_arn must be a valid IAM OIDC provider ARN for token.actions.githubusercontent.com."
  }
}

variable "bucket_name" {
  description = "Optional explicit name for the private S3 bucket. Leave empty to let AWS generate a unique name with bucket_prefix."
  type        = string
  default     = ""
}

variable "bucket_prefix" {
  description = "Prefix used when bucket_name is left empty."
  type        = string
  default     = "gha-oidc-demo-"
}

variable "force_destroy_bucket" {
  description = "Allow terraform destroy to delete uploaded demo objects under releases/ cleanly during teardown."
  type        = bool
  default     = true
}

variable "role_name" {
  description = "Name of the IAM role assumed by the GitHub Actions release workflow."
  type        = string
  default     = "github-actions-cloud-identity-demo-release"
}

variable "github_oidc_thumbprints" {
  description = "Thumbprint list for aws_iam_openid_connect_provider compatibility across AWS provider 5.x releases (AWS validates GitHub via root CAs)."
  type        = list(string)
  default     = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}
