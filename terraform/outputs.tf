output "aws_role_arn" {
  description = "IAM role ARN to copy into GitHub repository variable AWS_ROLE_ARN."
  value       = aws_iam_role.release_publisher.arn
}

output "s3_bucket_name" {
  description = "Private S3 bucket name to copy into GitHub repository variable S3_BUCKET_NAME."
  value       = aws_s3_bucket.releases.bucket
}

output "aws_region" {
  description = "AWS region to copy into GitHub repository variable AWS_REGION."
  value       = var.aws_region
}

output "allowed_oidc_subject" {
  description = "Exact OIDC subject claim required by the IAM role trust policy."
  value       = local.allowed_oidc_subject
}

output "github_repository_variables" {
  description = "Exact GitHub Actions repository variables consumed by publish-release.yml and verify-denial.yml."
  value = {
    AWS_ROLE_ARN   = aws_iam_role.release_publisher.arn
    AWS_REGION     = var.aws_region
    S3_BUCKET_NAME = aws_s3_bucket.releases.bucket
  }
}
