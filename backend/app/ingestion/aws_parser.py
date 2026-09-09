"""
CloudSentry AI - AWS Telemetry Parser & Normalizer
=================================================

Translates raw AWS CloudTrail, GuardDuty findings, and VPC Flow Logs into
standardized OCSF (Open Cybersecurity Schema Framework) UnifiedOCSFEvent objects.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4
from app.schemas.ocsf import (
    CloudProvider,
    OCSFCategory,
    EventSeverity,
    EventStatus,
    GeoLocation,
    ActorIdentity,
    NetworkEndpoint,
    TargetResource,
    SecurityFindingMetadata,
    UnifiedOCSFEvent,
)
from app.schemas.raw_events import (
    AWSCloudTrailRaw,
    AWSGuardDutyFindingRaw,
    AWSVPCFlowRaw,
)

# Reference table for standard protocols in VPC Flow Logs
IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
}


def _resolve_mock_geo(ip: str) -> GeoLocation:
    """
    Simulates IP Geolocation lookup for SOC analysis.
    In production, this queries MaxMind GeoIP2 / IP2Location database or a Redis cache.
    """
    if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168.") or ip == "127.0.0.1":
        return GeoLocation(
            country="Private Network",
            country_code="RFC1918",
            city="Internal VPC",
            latitude=0.0,
            longitude=0.0,
            isp="Internal",
        )
    # Known simulated attack / threat intelligence IP ranges
    if ip.startswith("185.220."):
        return GeoLocation(
            country="Germany",
            country_code="DE",
            city="Frankfurt",
            latitude=50.1109,
            longitude=8.6821,
            isp="Tor Exit Node / Bulletproof Hosting",
        )
    if ip.startswith("45.33."):
        return GeoLocation(
            country="Russia",
            country_code="RU",
            city="Moscow",
            latitude=55.7558,
            longitude=37.6173,
            isp="HostKey Hosting",
        )
    if ip.startswith("198.51."):
        return GeoLocation(
            country="United States",
            country_code="US",
            city="Seattle",
            region="WA",
            latitude=47.6062,
            longitude=-122.3321,
            isp="Corporate Branch Office",
        )
    if ip.startswith("203.0.113."):
        return GeoLocation(
            country="United Kingdom",
            country_code="GB",
            city="London",
            latitude=51.5074,
            longitude=-0.1278,
            isp="London Datacenter",
        )
    # Default public fallback
    return GeoLocation(
        country="United States",
        country_code="US",
        city="Ashburn",
        region="VA",
        latitude=39.0438,
        longitude=-77.4874,
        isp="Public Cloud Provider",
    )


def parse_cloudtrail_event(raw: Dict[str, Any]) -> UnifiedOCSFEvent:
    """
    Parses native AWS CloudTrail log dictionary into UnifiedOCSFEvent.
    """
    model = AWSCloudTrailRaw.model_validate(raw)

    # Determine Category
    event_name = model.eventName
    event_source = model.eventSource.lower()

    if event_name in ["ConsoleLogin", "CheckMfa"] or "signin" in event_source:
        category = OCSFCategory.AUTHENTICATION
        action_name = "LOGIN"
    elif event_name.startswith("AssumeRole") or event_name.startswith("GetFederationToken"):
        category = OCSFCategory.AUTHORIZATION
        action_name = "ASSUME_ROLE"
    elif "iam" in event_source:
        category = OCSFCategory.AUTHORIZATION
        action_name = f"IAM_{event_name.upper()}"
    else:
        category = OCSFCategory.API_ACTIVITY
        action_name = event_name.upper()

    # Determine Status
    if model.errorCode:
        if "Unauthorized" in model.errorCode or "AccessDenied" in model.errorCode:
            status = EventStatus.DENIED
            severity = EventSeverity.HIGH if "iam" in event_source else EventSeverity.MEDIUM
        else:
            status = EventStatus.FAILURE
            severity = EventSeverity.LOW
    else:
        status = EventStatus.SUCCESS
        # Default severity based on risk of action
        if event_name in ["AttachUserPolicy", "AttachRolePolicy", "PutBucketPolicy", "DeleteTrail", "StopLogging"]:
            severity = EventSeverity.HIGH
        elif event_name in ["CreateAccessKey", "CreateUser", "UpdateAssumeRolePolicy"]:
            severity = EventSeverity.MEDIUM
        else:
            severity = EventSeverity.INFORMATIONAL

    # Parse Timestamp
    try:
        ts = datetime.fromisoformat(model.eventTime.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    # Actor extraction
    uid = model.userIdentity
    actor_name = uid.userName or (uid.principalId.split(":")[-1] if uid.principalId else "Unknown")
    actor = ActorIdentity(
        user_name=actor_name,
        user_id=uid.principalId,
        account_id=uid.accountId,
        principal_type=uid.type,
        session_issuer=uid.arn,
    )

    # Network Source
    geo = _resolve_mock_geo(model.sourceIPAddress)
    src_endpoint = NetworkEndpoint(
        ip=model.sourceIPAddress,
        geo=geo,
    )

    # Target Resource Extraction
    req = model.requestParameters or {}
    target_res = None
    if "s3" in event_source:
        bucket = req.get("bucketName") or req.get("Bucket")
        key = req.get("key") or req.get("Key")
        res_name = f"{bucket}/{key}" if (bucket and key) else (bucket or "s3-service")
        target_res = TargetResource(
            resource_type="s3_bucket",
            resource_name=res_name,
            region=model.awsRegion,
            details={"bucket": bucket, "key": key},
        )
    elif "iam" in event_source:
        target_user = req.get("userName") or req.get("roleName") or req.get("policyArn")
        target_res = TargetResource(
            resource_type="iam_identity",
            resource_name=target_user or "iam-resource",
            region="global",
            details=req,
        )
    else:
        target_res = TargetResource(
            resource_type="cloud_service",
            resource_name=model.eventSource,
            region=model.awsRegion,
            details={"eventName": model.eventName},
        )

    return UnifiedOCSFEvent(
        event_id=model.eventID or str(uuid4()),
        timestamp=ts,
        cloud_provider=CloudProvider.AWS,
        source_service="cloudtrail",
        original_event_name=model.eventName,
        category=category,
        severity=severity,
        status=status,
        status_code=model.errorCode,
        status_detail=model.errorMessage,
        actor=actor,
        src_endpoint=src_endpoint,
        user_agent=model.userAgent,
        action=action_name,
        target=target_res,
        raw_log=raw,
        tags=[f"aws:{model.awsRegion}", f"source:{model.eventSource}"],
    )


def parse_guardduty_finding(raw: Dict[str, Any]) -> UnifiedOCSFEvent:
    """
    Parses native AWS GuardDuty finding dictionary into UnifiedOCSFEvent.
    """
    model = AWSGuardDutyFindingRaw.model_validate(raw)

    # GuardDuty severity translation
    # 0.1 - 3.9: Low
    # 4.0 - 6.9: Medium
    # 7.0 - 8.9: High
    # 9.0+: Critical
    if model.severity >= 8.0:
        sev = EventSeverity.CRITICAL
    elif model.severity >= 7.0:
        sev = EventSeverity.HIGH
    elif model.severity >= 4.0:
        sev = EventSeverity.MEDIUM
    else:
        sev = EventSeverity.LOW

    try:
        ts = datetime.fromisoformat(model.createdAt.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    # Extract source IP from service network action if present
    service = model.service or {}
    action_info = service.get("action", {})
    net_action = action_info.get("networkConnectionAction", {})
    remote_ip_details = net_action.get("remoteIpDetails", {})
    remote_ip = remote_ip_details.get("ipAddressV4")

    # Or from awsApiCallAction
    if not remote_ip:
        api_action = action_info.get("awsApiCallAction", {})
        remote_ip = api_action.get("remoteIpDetails", {}).get("ipAddressV4")

    src_endpoint = None
    if remote_ip:
        src_endpoint = NetworkEndpoint(
            ip=remote_ip,
            geo=_resolve_mock_geo(remote_ip),
        )

    # Extract targeted resource
    res = model.resource or {}
    res_type = res.get("resourceType", "unknown_resource")
    res_id = (
        res.get("instanceDetails", {}).get("instanceId")
        or res.get("accessKeyDetails", {}).get("userName")
        or res.get("s3BucketDetails", [{}])[0].get("name")
        if isinstance(res.get("s3BucketDetails"), list) and len(res.get("s3BucketDetails")) > 0
        else "unknown"
    )

    finding_meta = SecurityFindingMetadata(
        finding_id=model.id,
        scanner_name="AWS GuardDuty",
        finding_type=model.type,
        title=model.title,
        description=model.description,
        remediation_steps="Isolate compromised instance/credentials and rotate active access keys.",
    )

    actor = ActorIdentity(
        user_name=res.get("accessKeyDetails", {}).get("userName", "GuardDutyTarget"),
        account_id=model.accountId,
    )

    return UnifiedOCSFEvent(
        event_id=model.id,
        timestamp=ts,
        cloud_provider=CloudProvider.AWS,
        source_service="guardduty",
        original_event_name=model.type,
        category=OCSFCategory.SECURITY_FINDING,
        severity=sev,
        status=EventStatus.FAILURE,
        actor=actor,
        src_endpoint=src_endpoint,
        action="GUARDDUTY_DETECTION",
        target=TargetResource(
            resource_type=res_type,
            resource_id=res_id,
            resource_name=res_id,
            region=model.region,
        ),
        finding_metadata=finding_meta,
        raw_log=raw,
        tags=["security_finding", "guardduty", model.type.split(":")[0].lower()],
    )


def parse_vpc_flow_log(raw: Dict[str, Any]) -> UnifiedOCSFEvent:
    """
    Parses native AWS VPC Flow Log record dictionary into UnifiedOCSFEvent.
    """
    model = AWSVPCFlowRaw.model_validate(raw)
    ts = datetime.fromtimestamp(model.start, timezone.utc)

    protocol_name = IP_PROTOCOLS.get(model.protocol, f"PROTO_{model.protocol}")
    action_status = EventStatus.SUCCESS if model.action == "ACCEPT" else EventStatus.DENIED
    severity = EventSeverity.INFORMATIONAL if model.action == "ACCEPT" else EventSeverity.LOW

    # Flag high-risk port connections or massive transfers as potential elevated severity
    if model.dstport in [4444, 1337, 31337, 6667] or model.bytes > 500_000_000:
        severity = EventSeverity.HIGH

    src_geo = _resolve_mock_geo(model.srcaddr)
    src_endpoint = NetworkEndpoint(
        ip=model.srcaddr,
        port=model.srcport,
        geo=src_geo,
        interface_id=model.interface_id,
    )

    dst_geo = _resolve_mock_geo(model.dstaddr)
    dst_endpoint = NetworkEndpoint(
        ip=model.dstaddr,
        port=model.dstport,
        geo=dst_geo,
    )

    return UnifiedOCSFEvent(
        timestamp=ts,
        cloud_provider=CloudProvider.AWS,
        source_service="vpc_flow",
        original_event_name=f"VPC_FLOW_{model.action}",
        category=OCSFCategory.NETWORK_ACTIVITY,
        severity=severity,
        status=action_status,
        src_endpoint=src_endpoint,
        dst_endpoint=dst_endpoint,
        action=f"FLOW_{model.action}",
        bytes_transferred=model.bytes,
        packets_transferred=model.packets,
        protocol=protocol_name,
        target=TargetResource(
            resource_type="network_interface",
            resource_id=model.interface_id,
            resource_name=model.interface_id,
            details={"srcaddr": model.srcaddr, "dstaddr": model.dstaddr},
        ),
        raw_log=raw,
        tags=["network", "vpc_flow", model.action.lower()],
    )
