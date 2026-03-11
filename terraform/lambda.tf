# ==============================================================================
# CVE Scanner Lambda
# ==============================================================================

data "archive_file" "cve_scanner" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/cve_scanner"
  output_path = "${path.module}/../.build/cve_scanner.zip"
}

resource "aws_lambda_function" "cve_scanner" {
  function_name    = "${var.project_name}-cve-scanner"
  description      = "Queries Chainguard APIs for image vulnerabilities, diffs for new/changed CVEs, publishes alerts to SNS"
  role             = aws_iam_role.cve_scanner.arn
  handler          = "handler.lambda_handler"
  runtime          = var.lambda_runtime
  timeout          = 300
  memory_size      = 512
  filename         = data.archive_file.cve_scanner.output_path
  source_code_hash = data.archive_file.cve_scanner.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN          = aws_sns_topic.alerts.arn
      STATE_BUCKET           = aws_s3_bucket.state.id
      STATE_KEY              = "advisory-state.json"
      CHAINGUARD_IDENTITY_ID = chainguard_identity.cve_scanner.id
      CHAINGUARD_GROUP_ID    = data.chainguard_group.org.id
      CHAINGUARD_API_URL     = "https://console-api.enforce.dev"
      CHAINGUARD_ISSUER_URL  = "https://issuer.enforce.dev"
      WATCHED_IMAGES         = jsonencode(var.watched_images)
      LOG_LEVEL              = var.lambda_log_level
    }
  }
}

resource "aws_cloudwatch_log_group" "cve_scanner" {
  name              = "/aws/lambda/${var.project_name}-cve-scanner"
  retention_in_days = 30
}

# --- IAM ---

resource "aws_iam_role" "cve_scanner" {
  name = "${var.project_name}-cve-scanner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "cve_scanner_sns" {
  name = "sns-publish"
  role = aws_iam_role.cve_scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sns:Publish"
      Resource = aws_sns_topic.alerts.arn
    }]
  })
}

resource "aws_iam_role_policy" "cve_scanner_s3" {
  name = "s3-state"
  role = aws_iam_role.cve_scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
        ]
        Resource = "${aws_s3_bucket.state.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.state.arn
      },
    ]
  })
}

resource "aws_iam_role_policy" "cve_scanner_sts" {
  name = "web-identity-token"
  role = aws_iam_role.cve_scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:GetWebIdentityToken"
      Resource = "*"
      Condition = {
        "ForAnyValue:StringEquals" = {
          "sts:IdentityTokenAudience" = "https://issuer.enforce.dev"
        }
        "NumericLessThanEquals" = {
          "sts:DurationSeconds" = 300
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cve_scanner_logs" {
  role       = aws_iam_role.cve_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ==============================================================================
# Slack Notifier Lambda
# ==============================================================================

data "archive_file" "slack_notifier" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/slack_notifier"
  output_path = "${path.module}/../.build/slack_notifier.zip"
}

resource "aws_lambda_function" "slack_notifier" {
  function_name    = "${var.project_name}-slack-notifier"
  description      = "Formats CVE alerts and posts to Slack via incoming webhook"
  role             = aws_iam_role.slack_notifier.arn
  handler          = "handler.lambda_handler"
  runtime          = var.lambda_runtime
  timeout          = 15
  memory_size      = 128
  filename         = data.archive_file.slack_notifier.output_path
  source_code_hash = data.archive_file.slack_notifier.output_base64sha256

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      LOG_LEVEL         = var.lambda_log_level
    }
  }
}

resource "aws_cloudwatch_log_group" "slack_notifier" {
  name              = "/aws/lambda/${var.project_name}-slack-notifier"
  retention_in_days = 30
}

# --- IAM ---

resource "aws_iam_role" "slack_notifier" {
  name = "${var.project_name}-slack-notifier"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "slack_notifier_logs" {
  role       = aws_iam_role.slack_notifier.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
