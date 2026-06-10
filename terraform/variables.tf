variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for storing audit artifacts"
  type        = string
  default     = "cloudguard-artifacts"
}

variable "environment" {
  description = "Deployment environment (development, staging, production)"
  type        = string
  default     = "development"
}

variable "localstack_endpoint" {
  description = "LocalStack endpoint URL for local development"
  type        = string
  default     = "http://localhost:4566"
}
