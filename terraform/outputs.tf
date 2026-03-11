output "sns_topic_arn" {
  description = "ARN of the SNS topic that receives CVE alerts"
  value       = aws_sns_topic.alerts.arn
}

output "cve_scanner_function_name" {
  description = "Name of the CVE scanner Lambda function"
  value       = aws_lambda_function.cve_scanner.function_name
}

output "slack_notifier_function_name" {
  description = "Name of the Slack notifier Lambda function"
  value       = aws_lambda_function.slack_notifier.function_name
}

output "state_bucket" {
  description = "S3 bucket storing the advisory state between scans"
  value       = aws_s3_bucket.state.id
}

output "scan_schedule" {
  description = "How often the scanner checks for CVE changes"
  value       = var.scan_schedule
}

output "chainguard_identity_id" {
  description = "UIDP of the Chainguard assumable identity used by the scanner"
  value       = chainguard_identity.cve_scanner.id
}
