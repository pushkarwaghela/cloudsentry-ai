# CloudSentry AI - AWS Infrastructure as Code (Terraform)
# Provisions least-privilege telemetry infrastructure for multi-cloud SOC ingestion.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# ==============================================================================
# 1. S3 Bucket for CloudTrail Telemetry (Hardened Posture)
# ==============================================================================

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "cloudsentry-trail-${data.aws_caller_identity.current.account_id}-${var.environment}"
  force_destroy = false

  tags = {
    Project     = "CloudSentry-AI"
    Environment = var.environment
    Compliance  = "SOC2-HIPAA"
  }
}

# CIS AWS Benchmark: Enforce default server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_sse" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# CIS AWS Benchmark: Block all public access at bucket level
resource "aws_s3_bucket_public_access_block" "cloudtrail_pab" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Secure Transport (HTTPS only) Bucket Policy
resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_bucket.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail_bucket.arn,
          "${aws_s3_bucket.cloudtrail_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ==============================================================================
# 2. AWS CloudTrail Multi-Region Trail
# ==============================================================================

resource "aws_cloudtrail" "main_trail" {
  name                          = "cloudsentry-multi-region-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]
}

# ==============================================================================
# 3. SQS Ingestion Queue with Dead Letter Queue (DLQ)
# ==============================================================================

resource "aws_sqs_queue" "ingestion_dlq" {
  name                      = "cloudsentry-telemetry-dlq"
  message_retention_seconds = 1209600 # 14 days
}

resource "aws_sqs_queue" "ingestion_queue" {
  name                      = "cloudsentry-telemetry-queue"
  receive_wait_time_seconds = 20 # Long polling

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.ingestion_dlq.arn
    maxReceiveCount     = 3
  })
}

# Route S3 ObjectCreated events to SQS
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  queue {
    queue_arn = aws_sqs_queue.ingestion_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

# ==============================================================================
# 4. Least-Privilege IAM Role for CloudSentry Worker
# ==============================================================================

resource "aws_iam_role" "cloudsentry_worker_role" {
  name = "CloudSentryIngestionWorkerRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Strictly scoped permissions: Read from SQS queue and fetch S3 CloudTrail logs
resource "aws_iam_policy" "cloudsentry_worker_policy" {
  name        = "CloudSentryWorkerLeastPrivilegePolicy"
  description = "Grants strictly scoped read permissions for telemetry ingestion."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SQSReceiveAndDelete"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.ingestion_queue.arn
      },
      {
        Sid    = "S3ReadLogsOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_worker_policy" {
  role       = aws_iam_role.cloudsentry_worker_role.name
  policy_arn = aws_iam_policy.cloudsentry_worker_policy.arn
}

# ==============================================================================
# 5. AWS GuardDuty Detector
# ==============================================================================

resource "aws_guardduty_detector" "primary" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

output "cloudtrail_bucket_name" {
  value = aws_s3_bucket.cloudtrail_bucket.id
}

output "sqs_queue_url" {
  value = aws_sqs_queue.ingestion_queue.url
}
