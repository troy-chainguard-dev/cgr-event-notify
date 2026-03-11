# ==============================================================================
# Chainguard Identity + Role Binding
#
# Creates an assumable identity that the CVE scanner Lambda can use to
# authenticate with the Chainguard platform via AWS outbound identity
# federation.  The identity is bound to the Lambda's IAM role ARN and
# granted viewer permissions on the organization.
# ==============================================================================

data "chainguard_group" "org" {
  name = var.chainguard_org_name
}

resource "chainguard_identity" "cve_scanner" {
  parent_id   = data.chainguard_group.org.id
  name        = var.chainguard_identity_name
  description = "Assumable identity for the cgr-event-notify CVE scanner Lambda"

  claim_match {
    issuer  = var.aws_sts_issuer_url
    subject = aws_iam_role.cve_scanner.arn
  }
}

data "chainguard_role" "viewer" {
  name = "viewer"
}

resource "chainguard_rolebinding" "cve_scanner_viewer" {
  identity = chainguard_identity.cve_scanner.id
  role     = data.chainguard_role.viewer.items[0].id
  group    = data.chainguard_group.org.id
}
