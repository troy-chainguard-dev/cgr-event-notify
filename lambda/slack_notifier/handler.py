"""
Slack notifier Lambda.

Receives CVE alert messages from SNS and posts formatted
Slack Block Kit messages to an incoming webhook.
"""

import json
import logging
import os
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
NVD_BASE_URL = "https://nvd.nist.gov/vuln/detail"

SEVERITY_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH": ":large_orange_circle:",
    "MEDIUM": ":large_yellow_circle:",
    "LOW": ":white_circle:",
    "UNKNOWN": ":black_circle:",
}


def lambda_handler(event, context):
    """SNS trigger handler."""
    for record in event.get("Records", []):
        message_str = record.get("Sns", {}).get("Message", "{}")
        try:
            alert = json.loads(message_str)
        except json.JSONDecodeError:
            logger.error("Failed to parse SNS message: %s", message_str[:200])
            continue

        alert_type = alert.get("alert_type", "unknown")
        formatters = {
            "new_cves": _format_new_cves,
            "resolved_cves": _format_resolved_cves,
            "severity_changes": _format_severity_changes,
        }

        formatter = formatters.get(alert_type)
        if not formatter:
            logger.warning("Unknown alert type: %s", alert_type)
            continue

        _post_to_slack(formatter(alert))


# =============================================================================
# Formatters
# =============================================================================


def _format_new_cves(alert: dict) -> dict:
    """Format new CVE detections as a Slack message."""
    items = alert.get("items", [])
    count = alert.get("count", len(items))
    timestamp = alert.get("timestamp", "")
    images = alert.get("images_affected", [])

    blocks = [
        _header(f"New CVE(s) Detected: {count} found"),
        _section(
            f":rotating_light: *{count}* new CVE(s) discovered across *{len(images)}* image(s).\n"
            f"Scanned at: `{timestamp}`"
        ),
        {"type": "divider"},
    ]

    by_image = _group_by_image(items)
    for image, vulns in by_image.items():
        blocks.append(_section(f"*Image:* `{image}`"))
        for v in vulns[:10]:
            blocks.append(_vuln_block(v))
        if len(vulns) > 10:
            blocks.append(_context(f"_...and {len(vulns) - 10} more in this image._"))
        blocks.append({"type": "divider"})

    return {"attachments": [{"color": "#d00000", "blocks": blocks[:50]}]}


def _format_resolved_cves(alert: dict) -> dict:
    """Format resolved (fixed/removed) CVEs as a Slack message."""
    items = alert.get("items", [])
    count = alert.get("count", len(items))
    timestamp = alert.get("timestamp", "")
    images = alert.get("images_affected", [])

    blocks = [
        _header(f"CVE(s) Resolved: {count} fixed"),
        _section(
            f":white_check_mark: *{count}* CVE(s) resolved across *{len(images)}* image(s).\n"
            f"Scanned at: `{timestamp}`"
        ),
        {"type": "divider"},
    ]

    by_image = _group_by_image(items)
    for image, vulns in by_image.items():
        blocks.append(_section(f"*Image:* `{image}`"))
        for v in vulns[:10]:
            vuln_id = v.get("vuln_id", "unknown")
            pkg = v.get("package", "unknown")
            sev = v.get("severity", "UNKNOWN")
            emoji = SEVERITY_EMOJI.get(sev, ":black_circle:")
            nvd_link = f"<{NVD_BASE_URL}/{vuln_id}|{vuln_id}>"
            blocks.append(_section(f"{emoji} {nvd_link} in *{pkg}* ({sev}) — resolved"))
        if len(vulns) > 10:
            blocks.append(_context(f"_...and {len(vulns) - 10} more in this image._"))
        blocks.append({"type": "divider"})

    return {"attachments": [{"color": "#28a745", "blocks": blocks[:50]}]}


def _format_severity_changes(alert: dict) -> dict:
    """Format CVE severity/status changes as a Slack message."""
    items = alert.get("items", [])
    count = alert.get("count", len(items))
    timestamp = alert.get("timestamp", "")
    images = alert.get("images_affected", [])

    blocks = [
        _header(f"CVE Status Changes: {count} updated"),
        _section(
            f":arrows_counterclockwise: *{count}* CVE(s) changed status across *{len(images)}* image(s).\n"
            f"Scanned at: `{timestamp}`"
        ),
        {"type": "divider"},
    ]

    by_image = _group_by_image(items)
    for image, vulns in by_image.items():
        blocks.append(_section(f"*Image:* `{image}`"))
        for v in vulns[:10]:
            vuln_id = v.get("vuln_id", "unknown")
            pkg = v.get("package", "unknown")
            changes = v.get("changes", [])
            nvd_link = f"<{NVD_BASE_URL}/{vuln_id}|{vuln_id}>"
            change_text = ", ".join(changes) if changes else "status updated"
            blocks.append(_section(f":arrows_counterclockwise: {nvd_link} in *{pkg}*\n{change_text}"))
        if len(vulns) > 10:
            blocks.append(_context(f"_...and {len(vulns) - 10} more in this image._"))
        blocks.append({"type": "divider"})

    return {"attachments": [{"color": "#f0ad4e", "blocks": blocks[:50]}]}


# =============================================================================
# Block Kit helpers
# =============================================================================


def _header(text: str) -> dict:
    return {"type": "header", "text": {"type": "plain_text", "text": text[:150]}}


def _section(text: str) -> dict:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def _context(text: str) -> dict:
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": text}]}


def _vuln_block(v: dict) -> dict:
    """Render a single vulnerability as a Slack section block."""
    vuln_id = v.get("vuln_id", "unknown")
    pkg = v.get("package", "unknown")
    pkg_ver = v.get("package_version", "")
    sev = v.get("severity", "UNKNOWN")
    fix_state = v.get("fix_state", "UNKNOWN")
    fix_versions = v.get("fix_versions", [])

    emoji = SEVERITY_EMOJI.get(sev, ":black_circle:")
    nvd_link = f"<{NVD_BASE_URL}/{vuln_id}|{vuln_id}>"

    pkg_text = f"*{pkg}*"
    if pkg_ver:
        pkg_text += f" `{pkg_ver}`"

    if fix_state == "FIXED" and fix_versions:
        status = f"Fixed in `{fix_versions[0]}`"
    elif fix_state == "NOT_FIXED":
        status = "No fix available"
    elif fix_state == "WONT_FIX":
        status = "Won't fix"
    else:
        status = fix_state.replace("_", " ").title()

    return _section(f"{emoji} {nvd_link} ({sev}) in {pkg_text}\n{status}")


def _group_by_image(items: list) -> dict:
    """Group alert items by their image reference."""
    groups = {}
    for item in items:
        image = item.get("image", "unknown")
        groups.setdefault(image, []).append(item)
    return groups


# =============================================================================
# Slack posting
# =============================================================================


def _post_to_slack(payload: dict):
    """POST the payload to the Slack incoming webhook."""
    data = json.dumps(payload).encode()
    req = Request(
        SLACK_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(req, timeout=10) as resp:
            response_body = resp.read().decode()
            logger.info("Slack response (%d): %s", resp.status, response_body)
    except URLError as e:
        logger.error("Failed to post to Slack: %s", e)
        raise
