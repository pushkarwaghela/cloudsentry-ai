"""
CloudSentry AI - Azure Telemetry Parser & Normalizer
===================================================

Translates raw Azure Activity Logs, Microsoft Entra ID (Azure AD) sign-in logs,
and Microsoft Defender for Cloud alerts into standardized OCSF UnifiedOCSFEvent objects.
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
    AzureActivityLogRaw,
    AzureEntraSignInRaw,
    AzureDefenderAlertRaw,
)
from app.ingestion.aws_parser import _resolve_mock_geo


def _parse_azure_resource_id(resource_id: str) -> Dict[str, str]:
    """
    Parses hierarchical Azure Resource ID:
    /subscriptions/{subId}/resourceGroups/{rg}/providers/{provider}/{resourceType}/{resourceName}
    """
    parts = resource_id.strip("/").split("/")
    parsed = {}
    i = 0
    while i < len(parts) - 1:
        key = parts[i].lower()
        val = parts[i + 1]
        if key == "subscriptions":
            parsed["subscription_id"] = val
        elif key == "resourcegroups":
            parsed["resource_group"] = val
        elif key == "providers":
            parsed["provider"] = val
            if i + 3 < len(parts):
                parsed["resource_type"] = f"{val}/{parts[i + 2]}"
                parsed["resource_name"] = parts[i + 3]
        i += 2
    return parsed


def parse_activity_log(raw: Dict[str, Any]) -> UnifiedOCSFEvent:
    """
    Parses native Azure Monitor Activity Log dictionary into UnifiedOCSFEvent.
    """
    model = AzureActivityLogRaw.model_validate(raw)

    op = model.operationName.lower()
    if "roleassignments" in op or "authorization" in op:
        category = OCSFCategory.AUTHORIZATION
        action_name = "AZURE_RBAC_MUTATION"
        severity = EventSeverity.HIGH if "write" in op or "delete" in op else EventSeverity.LOW
    elif "action" in op or "write" in op:
        category = OCSFCategory.API_ACTIVITY
        action_name = "RESOURCE_WRITE"
        severity = EventSeverity.MEDIUM if "delete" in op else EventSeverity.INFORMATIONAL
    else:
        category = OCSFCategory.API_ACTIVITY
        action_name = "RESOURCE_READ"
        severity = EventSeverity.INFORMATIONAL

    # Determine Status
    if model.resultType.lower() == "success":
        status = EventStatus.SUCCESS
    elif "denied" in model.resultType.lower() or "unauthorized" in str(model.properties).lower():
        status = EventStatus.DENIED
        severity = EventSeverity.HIGH
    else:
        status = EventStatus.FAILURE

    try:
        ts = datetime.fromisoformat(model.time.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    # Actor extraction
    actor = ActorIdentity(
        user_name=model.caller,
        email=model.caller if "@" in model.caller else None,
        account_id=model.subscriptionId,
        principal_type="User" if "@" in model.caller else "ServicePrincipal",
    )

    # Source Endpoint
    src_endpoint = None
    if model.callerIpAddress:
        src_endpoint = NetworkEndpoint(
            ip=model.callerIpAddress,
            geo=_resolve_mock_geo(model.callerIpAddress),
        )

    # Target Resource Extraction
    parsed_id = _parse_azure_resource_id(model.resourceId)
    target_res = TargetResource(
        resource_type=parsed_id.get("resource_type", "azure_resource"),
        resource_id=model.resourceId,
        resource_name=parsed_id.get("resource_name", model.resourceId.split("/")[-1]),
        region=model.properties.get("region", "global"),
        details=parsed_id,
    )

    return UnifiedOCSFEvent(
        event_id=model.correlationId or str(uuid4()),
        timestamp=ts,
        cloud_provider=CloudProvider.AZURE,
        source_service="activity_log",
        original_event_name=model.operationName,
        category=category,
        severity=severity,
        status=status,
        status_code=model.resultType,
        actor=actor,
        src_endpoint=src_endpoint,
        action=action_name,
        target=target_res,
        raw_log=raw,
        tags=["azure", "activity_log", parsed_id.get("provider", "microsoft")],
    )


def parse_entra_signin_log(raw: Dict[str, Any]) -> UnifiedOCSFEvent:
    """
    Parses native Microsoft Entra ID (Azure AD) sign-in record into UnifiedOCSFEvent.
    """
    model = AzureEntraSignInRaw.model_validate(raw)

    # Status evaluation
    # Azure error code 0 = Success
    # 50126 = Invalid username or password
    # 50076 = MFA required
    # 53003 = Conditional Access policy blocked access
    if model.status.errorCode == 0:
        status = EventStatus.SUCCESS
        status_detail = "Success"
    elif model.status.errorCode == 53003:
        status = EventStatus.DENIED
        status_detail = "Conditional Access Block"
    else:
        status = EventStatus.FAILURE
        status_detail = model.status.failureReason or f"Error {model.status.errorCode}"

    # Severity & Risk Evaluation from Entra Identity Protection
    risk_level = (model.riskLevelAggregated or "none").lower()
    if risk_level in ["high", "critical"] or model.riskDetail not in ["none", None, ""]:
        severity = EventSeverity.CRITICAL if risk_level == "high" else EventSeverity.HIGH
    elif status == EventStatus.DENIED:
        severity = EventSeverity.MEDIUM
    elif status == EventStatus.FAILURE:
        severity = EventSeverity.LOW
    else:
        severity = EventSeverity.INFORMATIONAL

    try:
        ts = datetime.fromisoformat(model.createdDateTime.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    # Geo extraction (prefer native Entra ID geo if present)
    if model.location and model.location.geoCoordinates:
        coords = model.location.geoCoordinates
        geo = GeoLocation(
            country=model.location.countryOrRegion or "Unknown",
            city=model.location.city or "Unknown",
            region=model.location.state,
            latitude=coords.get("latitude"),
            longitude=coords.get("longitude"),
        )
    else:
        geo = _resolve_mock_geo(model.ipAddress)

    src_endpoint = NetworkEndpoint(
        ip=model.ipAddress,
        geo=geo,
    )

    actor = ActorIdentity(
        user_name=model.userPrincipalName,
        user_id=model.userId,
        email=model.userPrincipalName,
        principal_type="EntraUser",
    )

    target_res = TargetResource(
        resource_type="application",
        resource_id=model.appId or "azure_portal",
        resource_name=model.appDisplayName or "Azure Management",
    )

    return UnifiedOCSFEvent(
        event_id=model.id,
        timestamp=ts,
        cloud_provider=CloudProvider.AZURE,
        source_service="azure_ad",
        original_event_name="UserSignIn",
        category=OCSFCategory.AUTHENTICATION,
        severity=severity,
        status=status,
        status_code=str(model.status.errorCode),
        status_detail=status_detail,
        actor=actor,
        src_endpoint=src_endpoint,
        user_agent=model.userAgent,
        action="ENTRA_SIGNIN",
        target=target_res,
        raw_log=raw,
        tags=["azure", "entra_id", f"app:{model.appDisplayName}", f"risk:{risk_level}"],
    )


def parse_defender_alert(raw: Dict[str, Any]) -> UnifiedOCSFEvent:
    """
    Parses native Microsoft Defender for Cloud security alert into UnifiedOCSFEvent.
    """
    model = AzureDefenderAlertRaw.model_validate(raw)
    props = model.properties

    # Defender severity mapping: "High", "Medium", "Low", "Informational"
    def_sev = props.get("severity", "Medium").upper()
    if def_sev == "HIGH":
        sev = EventSeverity.HIGH
    elif def_sev == "CRITICAL":
        sev = EventSeverity.CRITICAL
    elif def_sev == "MEDIUM":
        sev = EventSeverity.MEDIUM
    else:
        sev = EventSeverity.LOW

    alert_title = props.get("alertDisplayName") or model.name
    desc = props.get("description", "")
    remediation = props.get("remediationSteps", "")
    compromised = props.get("compromisedEntity", "unknown_entity")

    finding_meta = SecurityFindingMetadata(
        finding_id=model.id,
        scanner_name="Microsoft Defender for Cloud",
        finding_type=props.get("alertType", "SecurityAlert"),
        title=alert_title,
        description=desc,
        remediation_steps=remediation,
    )

    target_res = TargetResource(
        resource_type="azure_resource",
        resource_id=compromised,
        resource_name=compromised.split("/")[-1],
    )

    return UnifiedOCSFEvent(
        event_id=model.id,
        timestamp=datetime.now(timezone.utc),
        cloud_provider=CloudProvider.AZURE,
        source_service="defender",
        original_event_name=props.get("alertType", "DefenderAlert"),
        category=OCSFCategory.SECURITY_FINDING,
        severity=sev,
        status=EventStatus.FAILURE,
        action="DEFENDER_DETECTION",
        target=target_res,
        finding_metadata=finding_meta,
        raw_log=raw,
        tags=["azure", "defender", def_sev.lower()],
    )
