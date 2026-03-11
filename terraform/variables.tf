variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Deployment environment (e.g. dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "cgr-event-notify"
}

# ------------------------------------------------------------------------------
# Chainguard configuration
# ------------------------------------------------------------------------------

variable "chainguard_org_name" {
  description = "Chainguard organization name (e.g. 'troylab')"
  type        = string
}

variable "aws_sts_issuer_url" {
  description = "AWS STS outbound identity federation token issuer URL (https://<uuid>.tokens.sts.global.api.aws)"
  type        = string
}

variable "chainguard_identity_name" {
  description = "Name for the Chainguard assumable identity"
  type        = string
  default     = "cgr-event-notify-scanner"
}

# ------------------------------------------------------------------------------
# CVE scanning configuration
# ------------------------------------------------------------------------------

variable "scan_schedule" {
  description = "How often to poll for CVE changes (EventBridge rate expression)"
  type        = string
  default     = "rate(1 hour)"
}

variable "watched_images" {
  description = "Chainguard image refs to monitor for CVE changes (e.g. cgr.dev/troylab/nginx:latest)"
  type        = list(string)
  default     = []
}

# ------------------------------------------------------------------------------
# Notification channels
# ------------------------------------------------------------------------------

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL for posting CVE alerts"
  type        = string
  sensitive   = true
  default     = ""
}

variable "notification_emails" {
  description = "Email addresses to subscribe to the SNS alert topic"
  type        = list(string)
  default     = []
}

# ------------------------------------------------------------------------------
# Lambda configuration
# ------------------------------------------------------------------------------

variable "lambda_log_level" {
  description = "Log level for Lambda functions (DEBUG, INFO, WARNING, ERROR)"
  type        = string
  default     = "INFO"
}

variable "lambda_runtime" {
  description = "Python runtime for Lambda functions"
  type        = string
  default     = "python3.12"
}
