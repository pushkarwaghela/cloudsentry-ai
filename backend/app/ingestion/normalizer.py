"""
CloudSentry AI - Multi-Cloud Ingestion & OCSF Normalizer Engine
==============================================================

Inspects raw event payloads from AWS and Azure, automatically determines
the originating cloud provider and telemetry service, and transforms them into
standardized OCSF UnifiedOCSFEvent objects.
"""

import logging
from typing import Any, Dict, List, Tuple
from app.schemas.ocsf import UnifiedOCSFEvent
from app.ingestion.aws_parser import (
    parse_cloudtrail_event,
    parse_guardduty_finding,
    parse_vpc_flow_log,
)
from app.ingestion.azure_parser import (
    parse_activity_log,
    parse_entra_signin_log,
    parse_defender_alert,
)

logger = logging.getLogger("cloudsentry.normalizer")


def detect_telemetry_type(raw: Dict[str, Any]) -> Tuple[str, str]:
    """
    Fingerprints raw JSON payloads by identifying distinguishing schema signatures.
    Returns: (cloud_provider, service_type)
    """
    # 1. AWS CloudTrail
    if "userIdentity" in raw and ("eventSource" in raw or "eventName" in raw):
        return ("aws", "cloudtrail")

    # 2. AWS GuardDuty
    if "schemaVersion" in raw and "accountId" in raw and "service" in raw and "resource" in raw:
        return ("aws", "guardduty")

    # 3. AWS VPC Flow Log
    if "srcaddr" in raw and "dstaddr" in raw and "interface_id" in raw:
        return ("aws", "vpc_flow")

    # 4. Azure Entra ID Sign-in
    if "userPrincipalName" in raw and "createdDateTime" in raw:
        return ("azure", "azure_ad")

    # 5. Azure Defender for Cloud
    if ("type" in raw and "Microsoft.Security" in str(raw.get("type"))) or (
        "properties" in raw and "alertDisplayName" in raw.get("properties", {})
    ):
        return ("azure", "defender")

    # 6. Azure Activity Log
    if "operationName" in raw and ("resourceId" in raw or "caller" in raw):
        return ("azure", "activity_log")

    raise ValueError(f"Unrecognized multi-cloud telemetry format: {list(raw.keys())[:5]}")


def normalize_event(raw: Dict[str, Any]) -> UnifiedOCSFEvent:
    """
    Dispatches a single raw log payload to its dedicated cloud parser.
    """
    cloud, service = detect_telemetry_type(raw)

    if cloud == "aws":
        if service == "cloudtrail":
            return parse_cloudtrail_event(raw)
        elif service == "guardduty":
            return parse_guardduty_finding(raw)
        elif service == "vpc_flow":
            return parse_vpc_flow_log(raw)
    elif cloud == "azure":
        if service == "activity_log":
            return parse_activity_log(raw)
        elif service == "azure_ad":
            return parse_entra_signin_log(raw)
        elif service == "defender":
            return parse_defender_alert(raw)

    raise NotImplementedError(f"Parser for {cloud}:{service} is not implemented.")


def normalize_batch(records: List[Dict[str, Any]]) -> List[UnifiedOCSFEvent]:
    """
    Normalizes a batch of heterogeneous multi-cloud logs.
    Continues processing even if an individual malformed record fails.
    """
    normalized: List[UnifiedOCSFEvent] = []
    errors = 0

    for idx, record in enumerate(records):
        try:
            event = normalize_event(record)
            normalized.append(event)
        except Exception as e:
            errors += 1
            logger.warning(f"Failed to normalize record #{idx}: {e}")

    logger.info(f"Normalized {len(normalized)} events successfully ({errors} failed/skipped).")
    return normalized
