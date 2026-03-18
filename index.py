"""
Security Group Drift Detection & Auto-Remediation Lambda
Compliance Foundry Technical Assessment — Task 2.1

Triggered by: EventBridge rule on AuthorizeSecurityGroupIngress API calls
Actions:
  - Evaluates each new SG rule against the allowed CIDR policy
  - Revokes non-compliant rules immediately
  - Writes all events (compliant and non-compliant) to DynamoDB audit trail
  - Publishes SNS alert for all drift events
"""

import json
import os
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Configure structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients (outside handler for connection reuse)
ec2 = boto3.client("ec2")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

# Configuration from environment variables
ALLOWED_CIDRS: list[str] = os.environ["ALLOWED_CIDRS"].split(",")
AUDIT_TABLE_NAME: str = os.environ["AUDIT_TABLE_NAME"]
SNS_TOPIC_ARN: str = os.environ["SNS_TOPIC_ARN"]
ENVIRONMENT: str = os.environ.get("ENVIRONMENT", "unknown")
AUDIT_RETENTION_DAYS: int = int(os.environ.get("AUDIT_RETENTION_DAYS", "2555"))


def handler(event: dict, context: Any) -> dict:
    """
    Main Lambda handler. Processes EventBridge events from CloudTrail
    capturing AuthorizeSecurityGroupIngress API calls.
    """
    logger.info("Processing SG modification event", extra={"event": json.dumps(event)})

    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {})
    user_identity = detail.get("userIdentity", {})

    # Extract event metadata
    sg_id = request_params.get("groupId", "unknown")
    actor_arn = user_identity.get("arn", "unknown")
    actor_type = user_identity.get("type", "unknown")
    region = detail.get("awsRegion", "unknown")
    event_time = detail.get("eventTime", datetime.now(timezone.utc).isoformat())
    source_ip = detail.get("sourceIPAddress", "unknown")

    logger.info(
        "SG modification detected",
        extra={
            "sg_id": sg_id,
            "actor": actor_arn,
            "region": region,
            "source_ip": source_ip,
        },
    )

    # Extract IP permissions from the event
    ip_permissions_raw = request_params.get("ipPermissions", {})
    ip_permissions = ip_permissions_raw.get("items", [])

    if not ip_permissions:
        logger.warning("No IP permissions found in event — skipping", extra={"sg_id": sg_id})
        return {"status": "skipped", "reason": "no_ip_permissions"}

    # Evaluate each permission rule
    violations: list[dict] = []
    compliant_rules: list[dict] = []

    for perm in ip_permissions:
        protocol = perm.get("ipProtocol", "-1")
        from_port = perm.get("fromPort", 0)
        to_port = perm.get("toPort", 65535)

        # Check IPv4 ranges
        for cidr_item in perm.get("ipRanges", {}).get("items", []):
            cidr = cidr_item.get("cidrIp", "")
            rule = {
                "cidr": cidr,
                "protocol": protocol,
                "from_port": from_port,
                "to_port": to_port,
                "ip_version": "ipv4",
            }
            if _is_compliant_cidr(cidr):
                compliant_rules.append(rule)
            else:
                violations.append(rule)

        # Check IPv6 ranges
        for cidr6_item in perm.get("ipv6Ranges", {}).get("items", []):
            cidr6 = cidr6_item.get("cidrIpv6", "")
            rule = {
                "cidr": cidr6,
                "protocol": protocol,
                "from_port": from_port,
                "to_port": to_port,
                "ip_version": "ipv6",
            }
            # ::/0 is always a violation
            if cidr6 == "::/0":
                violations.append(rule)
            else:
                compliant_rules.append(rule)

    if not violations:
        logger.info("All rules compliant — no action required", extra={"sg_id": sg_id})
        _write_audit_record(
            sg_id=sg_id,
            actor=actor_arn,
            actor_type=actor_type,
            status="COMPLIANT",
            violations=[],
            compliant_rules=compliant_rules,
            region=region,
            source_ip=source_ip,
            event_time=event_time,
        )
        return {"status": "compliant", "sg_id": sg_id}

    # Non-compliant rules detected — remediate
    logger.warning(
        "Non-compliant SG rules detected",
        extra={"sg_id": sg_id, "violation_count": len(violations), "actor": actor_arn},
    )

    remediated: list[dict] = []
    failed_remediation: list[dict] = []

    for violation in violations:
        success = _revoke_rule(sg_id=sg_id, rule=violation)
        if success:
            remediated.append(violation)
        else:
            failed_remediation.append(violation)

    # Write audit record regardless of remediation success
    status = "DRIFT_REVERTED" if not failed_remediation else "DRIFT_PARTIAL_REMEDIATION"
    _write_audit_record(
        sg_id=sg_id,
        actor=actor_arn,
        actor_type=actor_type,
        status=status,
        violations=violations,
        compliant_rules=compliant_rules,
        region=region,
        source_ip=source_ip,
        event_time=event_time,
        remediated=remediated,
        failed=failed_remediation,
    )

    # Send security alert
    _publish_alert(
        sg_id=sg_id,
        actor=actor_arn,
        violations=violations,
        remediated=remediated,
        failed=failed_remediation,
        region=region,
        event_time=event_time,
        source_ip=source_ip,
    )

    return {
        "status": status,
        "sg_id": sg_id,
        "violations_found": len(violations),
        "remediated": len(remediated),
        "failed_remediation": len(failed_remediation),
    }


def _is_compliant_cidr(cidr: str) -> bool:
    """
    Returns True if the CIDR is in the approved list.
    Flags 0.0.0.0/0 as non-compliant regardless of allowed_cidrs list.
    """
    if cidr in ("0.0.0.0/0", "::/0"):
        return False

    return any(cidr == allowed or cidr.startswith(allowed.split("/")[0][:7])
               for allowed in ALLOWED_CIDRS)


def _revoke_rule(sg_id: str, rule: dict) -> bool:
    """
    Revokes a single SG ingress rule. Returns True on success, False on failure.
    """
    try:
        ip_permission = {
            "IpProtocol": rule["protocol"],
        }

        # Add port range only for non-wildcard protocols
        if rule["protocol"] not in ("-1", "all"):
            ip_permission["FromPort"] = rule["from_port"]
            ip_permission["ToPort"] = rule["to_port"]

        # Set the correct CIDR type
        if rule["ip_version"] == "ipv6":
            ip_permission["Ipv6Ranges"] = [{"CidrIpv6": rule["cidr"]}]
        else:
            ip_permission["IpRanges"] = [{"CidrIp": rule["cidr"]}]

        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[ip_permission],
        )

        logger.info(
            "Successfully revoked non-compliant SG rule",
            extra={"sg_id": sg_id, "cidr": rule["cidr"], "protocol": rule["protocol"]},
        )
        return True

    except ClientError as e:
        logger.error(
            "Failed to revoke SG rule",
            extra={
                "sg_id": sg_id,
                "cidr": rule["cidr"],
                "error": str(e),
                "error_code": e.response["Error"]["Code"],
            },
        )
        return False


def _write_audit_record(
    sg_id: str,
    actor: str,
    actor_type: str,
    status: str,
    violations: list,
    compliant_rules: list,
    region: str,
    source_ip: str,
    event_time: str,
    remediated: list = None,
    failed: list = None,
) -> None:
    """
    Writes a drift event record to DynamoDB for compliance audit trail.
    All events are recorded — both compliant and non-compliant.
    """
    table = dynamodb.Table(AUDIT_TABLE_NAME)
    now = datetime.now(timezone.utc)
    expires_at = int((now + timedelta(days=AUDIT_RETENTION_DAYS)).timestamp())

    try:
        table.put_item(
            Item={
                "event_id": str(uuid.uuid4()),
                "timestamp": now.isoformat(),
                "sg_id": sg_id,
                "actor_arn": actor,
                "actor_type": actor_type,
                "status": status,
                "environment": ENVIRONMENT,
                "region": region,
                "source_ip": source_ip,
                "event_time": event_time,
                "violations": json.dumps(violations or []),
                "compliant_rules": json.dumps(compliant_rules or []),
                "remediated": json.dumps(remediated or []),
                "failed_remediation": json.dumps(failed or []),
                "expires_at": expires_at,
            }
        )
        logger.info("Audit record written", extra={"sg_id": sg_id, "status": status})
    except ClientError as e:
        logger.error(
            "Failed to write audit record",
            extra={"sg_id": sg_id, "error": str(e)},
        )


def _publish_alert(
    sg_id: str,
    actor: str,
    violations: list,
    remediated: list,
    failed: list,
    region: str,
    event_time: str,
    source_ip: str,
) -> None:
    """
    Publishes a structured security alert to SNS for distribution
    to the security team via email, Slack, and Security Hub.
    """
    fully_remediated = len(failed) == 0
    subject = (
        f"[SECURITY DRIFT - {ENVIRONMENT.upper()}] SG {sg_id} — "
        f"{'Auto-reverted' if fully_remediated else 'PARTIAL REMEDIATION REQUIRED'}"
    )

    message_body = {
        "severity": "HIGH" if not fully_remediated else "MEDIUM",
        "environment": ENVIRONMENT,
        "timestamp": event_time,
        "sg_id": sg_id,
        "actor_arn": actor,
        "source_ip": source_ip,
        "region": region,
        "violations": violations,
        "remediation": {
            "status": "complete" if fully_remediated else "partial",
            "reverted": remediated,
            "failed_to_revert": failed,
        },
        "action_required": not fully_remediated,
        "next_steps": (
            "All violations were automatically reverted. "
            "Review the audit trail in DynamoDB for full details."
        ) if fully_remediated else (
            "MANUAL ACTION REQUIRED: Some rules could not be automatically reverted. "
            "Log into AWS and manually review the security group."
        ),
    }

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=json.dumps(message_body, indent=2),
        )
        logger.info("Security alert published", extra={"sg_id": sg_id, "subject": subject})
    except ClientError as e:
        logger.error("Failed to publish SNS alert", extra={"sg_id": sg_id, "error": str(e)})
