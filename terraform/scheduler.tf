resource "aws_scheduler_schedule" "cve_scan" {
  name        = "${var.project_name}-cve-scan"
  description = "Triggers the CVE scanner Lambda on a schedule"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = var.scan_schedule

  target {
    arn      = aws_lambda_function.cve_scanner.arn
    role_arn = aws_iam_role.scheduler.arn

    input = jsonencode({
      source = "scheduled"
    })
  }
}

resource "aws_iam_role" "scheduler" {
  name = "${var.project_name}-scheduler"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "scheduler.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler_invoke" {
  name = "lambda-invoke"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.cve_scanner.arn
    }]
  })
}
