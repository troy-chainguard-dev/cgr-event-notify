"""
CVE scanner Lambda.

Authenticates with Chainguard via AWS outbound identity federation, queries
the Chainguard platform APIs for vulnerability reports on each watched image,
diffs against the previously-seen state stored in S3, and publishes
new/changed CVE advisories to SNS for downstream notification.
"""

import json
import logging
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

import boto3
import botocore.auth
import botocore.awsrequest
import botocore.session

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

s3 = boto3.client("s3")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
STATE_BUCKET = os.environ["STATE_BUCKET"]
STATE_KEY = os.environ.get("STATE_KEY", "advisory-state.json")

CHAINGUARD_IDENTITY_ID = os.environ["CHAINGUARD_IDENTITY_ID"]
CHAINGUARD_GROUP_ID = os.environ["CHAINGUARD_GROUP_ID"]
CHAINGUARD_API_URL = os.environ.get("CHAINGUARD_API_URL", "https://console-api.enforce.dev")
CHAINGUARD_ISSUER_URL = os.environ.get("CHAINGUARD_ISSUER_URL", "https://issuer.enforce.dev")

WATCHED_IMAGES = json.loads(os.environ.get("WATCHED_IMAGES", "[]"))

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def lambda_handler(event, context):
    """EventBridge Scheduler trigger."""
    if not WATCHED_IMAGES:
        logger.warning("No watched images configured, nothing to scan")
        return {"status": "ok", "message": "no watched images"}

    logger.info("Starting CVE scan for %d image(s)", len(WATCHED_IMAGES))

    token = _get_chainguard_token()
    if not token:
        return {"status": "error", "reason": "auth_failed"}

    current_state = {}
    for image_ref in WATCHED_IMAGES:
        try:
            vulns = _scan_image(token, image_ref)
            current_state[image_ref] = vulns
        except Exception:
            logger.exception("Failed to scan image %s", image_ref)
            current_state[image_ref] = None

    previous_state = _load_previous_state()

    new_cves, resolved_cves, severity_changes = _diff_states(previous_state, current_state)

    total = len(new_cves) + len(resolved_cves) + len(severity_changes)
    logger.info(
        "Diff complete: %d new, %d resolved, %d severity changes (%d total)",
        len(new_cves), len(resolved_cves), len(severity_changes), total,
    )

    if new_cves:
        _publish_alerts("new_cves", new_cves)
    if resolved_cves:
        _publish_alerts("resolved_cves", resolved_cves)
    if severity_changes:
        _publish_alerts("severity_changes", severity_changes)

    _save_current_state(current_state)

    return {
        "status": "ok",
        "new_cves": len(new_cves),
        "resolved_cves": len(resolved_cves),
        "severity_changes": len(severity_changes),
    }


# =============================================================================
# Authentication
# =============================================================================


def _get_chainguard_token() -> str | None:
    """
    Obtain a Chainguard access token via AWS outbound identity federation.

    1. Call AWS STS GetWebIdentityToken (raw SigV4 request) to get an AWS-signed JWT
    2. Exchange that JWT with Chainguard STS for a platform access token
    """
    aws_jwt = _get_aws_web_identity_token()
    if not aws_jwt:
        return None

    try:
        logger.info("Exchanging AWS token for Chainguard token (identity: %s)", CHAINGUARD_IDENTITY_ID)
        params = urlencode({
            "identity": CHAINGUARD_IDENTITY_ID,
            "aud": CHAINGUARD_API_URL,
        })
        req = Request(
            f"{CHAINGUARD_ISSUER_URL}/sts/exchange?{params}",
            headers={"Authorization": f"Bearer {aws_jwt}"},
        )
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        return data.get("token")
    except Exception:
        logger.exception("Failed to exchange token with Chainguard STS")
        return None


def _get_aws_web_identity_token() -> str | None:
    """
    Call AWS STS GetWebIdentityToken using a raw SigV4-signed HTTP request.

    The Lambda runtime's bundled boto3 may not include this API method,
    so we sign and send the request directly using botocore primitives.
    """
    try:
        logger.info("Requesting AWS web identity token (audience: %s)", CHAINGUARD_ISSUER_URL)
        session = botocore.session.get_session()
        credentials = session.get_credentials().get_frozen_credentials()
        region = os.environ.get("AWS_REGION", "us-east-1")

        body = urlencode({
            "Action": "GetWebIdentityToken",
            "Version": "2011-06-15",
            "Audience.member.1": CHAINGUARD_ISSUER_URL,
            "SigningAlgorithm": "ES384",
        })

        url = f"https://sts.{region}.amazonaws.com/"
        aws_request = botocore.awsrequest.AWSRequest(
            method="POST",
            url=url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        botocore.auth.SigV4Auth(credentials, "sts", region).add_auth(aws_request)

        req = Request(url, data=body.encode(), headers=dict(aws_request.headers), method="POST")
        with urlopen(req, timeout=15) as resp:
            response_xml = resp.read().decode()

        root = ET.fromstring(response_xml)
        ns = {"sts": "https://sts.amazonaws.com/doc/2011-06-15/"}
        token_elem = root.find(".//sts:WebIdentityToken", ns)
        if token_elem is not None and token_elem.text:
            logger.info("Successfully obtained AWS web identity token")
            return token_elem.text

        logger.error("WebIdentityToken not found in STS response: %s", response_xml[:500])
        return None
    except HTTPError as e:
        body = e.read().decode() if e.readable() else ""
        logger.error("AWS STS error %d: %s", e.code, body[:500])
        return None
    except Exception:
        logger.exception("Failed to get AWS web identity token")
        return None


# =============================================================================
# Chainguard API helpers
# =============================================================================


def _cgapi(token: str, path: str, params: dict | None = None) -> dict:
    """Make an authenticated GET request to the Chainguard platform API."""
    url = f"{CHAINGUARD_API_URL}{path}"
    if params:
        url += "?" + urlencode(params)
    req = Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    logger.debug("GET %s", url)
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        body = e.read().decode() if e.readable() else ""
        logger.error("Chainguard API error %d for %s: %s", e.code, path, body[:500])
        raise


def _find_repo_id(token: str, repo_name: str) -> str | None:
    """Look up a Chainguard repo UIDP by name within the configured group."""
    data = _cgapi(token, "/registry/v1/repos", {
        "uidp.descendants_of": CHAINGUARD_GROUP_ID,
        "name": repo_name,
    })
    items = data.get("items", [])
    if not items:
        logger.warning("Repo not found: %s", repo_name)
        return None
    return items[0]["id"]


def _find_tag_digest(token: str, repo_id: str, tag_name: str) -> str | None:
    """Resolve a tag to its current manifest digest."""
    data = _cgapi(token, "/registry/v1/tags", {
        "uidp.children_of": repo_id,
        "name": tag_name,
    })
    items = data.get("items", [])
    if not items:
        logger.warning("Tag '%s' not found in repo %s", tag_name, repo_id)
        return None
    return items[0].get("digest")


def _get_vuln_report(token: str, repo_id: str, digest: str) -> dict:
    """Fetch the vulnerability report for a specific image digest."""
    encoded_repo = quote(repo_id, safe="")
    return _cgapi(token, f"/registry/v1/repos/{encoded_repo}/digests/{digest}/vulnreport")


# =============================================================================
# Image scanning
# =============================================================================


def _parse_image_ref(image_ref: str) -> tuple[str, str]:
    """
    Parse 'cgr.dev/<org>/<repo>:<tag>' into (repo_name, tag).

    Returns (repo_name, tag) where repo_name is the part after the org
    (e.g. 'nginx' from 'cgr.dev/troylab/nginx:latest').
    """
    ref = image_ref
    if ref.startswith("cgr.dev/"):
        ref = ref[len("cgr.dev/"):]

    if ":" in ref:
        path, tag = ref.rsplit(":", 1)
    else:
        path, tag = ref, "latest"

    parts = path.split("/", 1)
    if len(parts) == 2:
        repo_name = parts[1]
    else:
        repo_name = parts[0]

    return repo_name, tag


def _normalize_vulns(report: dict) -> dict[str, dict]:
    """
    Normalize a VulnReport into a flat dict keyed by vulnerability ID.

    Output format:
    {
        "CVE-XXXX-YYYY": {
            "severity": "HIGH",
            "package": "openssl",
            "package_version": "3.1.0-r0",
            "fix_state": "FIXED",
            "fix_versions": ["3.1.1-r0"],
            "source": "nvd",
            "description": "..."
        }
    }
    """
    vulns = {}
    for match in report.get("vulnerabilityMatches", []):
        vuln_record = match.get("vulnerability", {})
        pkg = match.get("pkg", {})
        fix = match.get("fix") or {}

        vuln_id = vuln_record.get("displayId") or vuln_record.get("id", "")
        if not vuln_id:
            continue

        severity = vuln_record.get("severity", "UNKNOWN")
        if isinstance(severity, int):
            severity = {0: "UNKNOWN", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}.get(severity, "UNKNOWN")

        fix_state = fix.get("state", "UNKNOWN")
        if isinstance(fix_state, int):
            fix_state = {0: "UNKNOWN", 1: "FIXED", 2: "NOT_FIXED", 3: "WONT_FIX"}.get(fix_state, "UNKNOWN")

        key = f"{vuln_id}|{pkg.get('name', '')}|{pkg.get('version', '')}"
        vulns[key] = {
            "vuln_id": vuln_id,
            "severity": severity,
            "package": pkg.get("name", "unknown"),
            "package_version": pkg.get("version", ""),
            "fix_state": fix_state,
            "fix_versions": fix.get("versions", []),
            "source": vuln_record.get("source", ""),
            "description": vuln_record.get("description", "")[:200],
        }

    return vulns


def _scan_image(token: str, image_ref: str) -> dict | None:
    """Scan a single image and return its normalized vulnerability state."""
    repo_name, tag = _parse_image_ref(image_ref)
    logger.info("Scanning %s (repo=%s, tag=%s)", image_ref, repo_name, tag)

    repo_id = _find_repo_id(token, repo_name)
    if not repo_id:
        return None

    digest = _find_tag_digest(token, repo_id, tag)
    if not digest:
        return None

    logger.info("Resolved %s → repo=%s digest=%s", image_ref, repo_id, digest[:24])
    try:
        report = _get_vuln_report(token, repo_id, digest)
    except HTTPError as e:
        if e.code == 404:
            logger.warning("No vuln report available yet for %s (scanner may not have processed this digest)", image_ref)
            return {}
        raise
    vulns = _normalize_vulns(report)
    logger.info("Image %s has %d vulnerability match(es)", image_ref, len(vulns))
    return vulns


# =============================================================================
# State management
# =============================================================================


def _load_previous_state() -> dict:
    """Load the last-seen state from S3. Returns empty dict on first run."""
    try:
        resp = s3.get_object(Bucket=STATE_BUCKET, Key=STATE_KEY)
        return json.loads(resp["Body"].read().decode())
    except s3.exceptions.NoSuchKey:
        logger.info("No previous state found (first run)")
        return {}
    except Exception:
        logger.warning("Failed to load previous state", exc_info=True)
        return {}


def _save_current_state(state: dict):
    """Persist the current state to S3."""
    serializable = {}
    for image, vulns in state.items():
        if vulns is not None:
            serializable[image] = vulns

    s3.put_object(
        Bucket=STATE_BUCKET,
        Key=STATE_KEY,
        Body=json.dumps(serializable).encode(),
        ContentType="application/json",
    )
    logger.info("State saved to s3://%s/%s", STATE_BUCKET, STATE_KEY)


# =============================================================================
# Diff engine
# =============================================================================


def _diff_states(previous: dict, current: dict) -> tuple[list, list, list]:
    """
    Compare previous and current vulnerability states across all images.

    Returns:
        new_cves:         Vulnerabilities present now but not before.
        resolved_cves:    Vulnerabilities present before but gone now.
        severity_changes: Vulnerabilities whose severity or fix state changed.
    """
    new_cves = []
    resolved_cves = []
    severity_changes = []

    all_images = set(list(previous.keys()) + list(current.keys()))

    for image in all_images:
        prev_vulns = previous.get(image) or {}
        curr_vulns = current.get(image) or {}

        for key, vuln in curr_vulns.items():
            if key not in prev_vulns:
                new_cves.append({**vuln, "image": image, "change": "new"})
            else:
                prev = prev_vulns[key]
                changes = []
                if prev.get("severity") != vuln.get("severity"):
                    changes.append(f"severity {prev.get('severity')} → {vuln.get('severity')}")
                if prev.get("fix_state") != vuln.get("fix_state"):
                    changes.append(f"fix {prev.get('fix_state')} → {vuln.get('fix_state')}")
                if changes:
                    severity_changes.append({
                        **vuln,
                        "image": image,
                        "change": "updated",
                        "changes": changes,
                        "previous_severity": prev.get("severity"),
                        "previous_fix_state": prev.get("fix_state"),
                    })

        for key, vuln in prev_vulns.items():
            if key not in curr_vulns:
                resolved_cves.append({**vuln, "image": image, "change": "resolved"})

    return new_cves, resolved_cves, severity_changes


# =============================================================================
# SNS publishing
# =============================================================================


def _publish_alerts(alert_type: str, items: list):
    """Publish a batch of CVE alerts to SNS, grouped by image."""
    SUBJECTS = {
        "new_cves": "New CVE(s) detected",
        "resolved_cves": "CVE(s) resolved",
        "severity_changes": "CVE status change(s)",
    }

    for batch in _chunk(items, 20):
        images_affected = sorted(set(i["image"] for i in batch))
        message = {
            "alert_type": alert_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "count": len(batch),
            "images_affected": images_affected,
            "items": batch,
        }
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[Chainguard CVE] {len(batch)} {SUBJECTS.get(alert_type, alert_type)}",
            Message=json.dumps(message, indent=2),
            MessageAttributes={
                "alert_type": {"DataType": "String", "StringValue": alert_type},
            },
        )
        logger.info("Published %d %s alert(s)", len(batch), alert_type)


def _chunk(items: list, size: int):
    """Yield successive chunks of the given size."""
    for i in range(0, len(items), size):
        yield items[i : i + size]
