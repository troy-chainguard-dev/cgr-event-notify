terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
    chainguard = {
      source = "chainguard-dev/chainguard"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      team        = "pubsec-se"
      Project     = "cgr-event-notify"
      ManagedBy   = "terraform"
      Environment = var.environment
    }
  }
}
