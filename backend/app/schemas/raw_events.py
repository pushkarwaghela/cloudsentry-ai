"""
CloudSentry AI - Raw Multi-Cloud Telemetry Schemas
=================================================

WHY ACCURATE RAW SCHEMAS MATTER FOR SOC ANALYSTS:
During SOC interviews, interviewers frequently test whether candidates know
real cloud log structures (e.g. "Where is the caller identity in CloudTrail?" ->
userIdentity.arn/userName, or "How does Azure represent RBAC mutations?" ->
operationName with Microsoft.Authorization/roleAssignments/write).

This module defines Pydantic validation models matching the exact schemas emitted
by native AWS and Azure cloud monitoring services.
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


# ==============================================================================
# AWS Raw Log Schemas
# ==============================================================================

class AWSUserIdentity(BaseModel):
    type: str                                  # "IAMUser", "AssumedRole", "Root", "FederatedUser", "AWSService"
    principalId: Optional[str] = None
    arn: Optional[str] = None
    accountId: Optional[str] = None
    userName: Optional[str] = None
    sessionContext: Optional[Dict[str, Any]] = None
    invokedBy: Optional[str] = None


class AWSCloudTrailRaw(BaseModel):
    """Native AWS CloudTrail Event Record Schema (v1.08/v1.09)."""
    eventVersion: Optional[str] = "1.08"
    userIdentity: AWSUserIdentity
    eventTime: str                             # ISO-8601 UTC
    eventSource: str                           # e.g., "iam.amazonaws.com", "s3.amazonaws.com", "signin.amazonaws.com"
    eventName: str                             # e.g., "ConsoleLogin", "AttachUserPolicy", "PutBucketPolicy"
    awsRegion: str                             # e.g., "us-east-1"
    sourceIPAddress: str
    userAgent: Optional[str] = None
    requestParameters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    responseElements: Optional[Dict[str, Any]] = None
    additionalEventData: Optional[Dict[str, Any]] = Field(default_factory=dict)
    eventID: Optional[str] = None
    eventType: Optional[str] = "AwsApiCall"
    errorCode: Optional[str] = None            # e.g. "AccessDenied", "Client.UnauthorizedOperation"
    errorMessage: Optional[str] = None


class AWSGuardDutyFindingRaw(BaseModel):
    """Native AWS GuardDuty Finding Schema."""
    schemaVersion: Optional[str] = "2.0"
    accountId: str
    region: str
    type: str                                  # Finding type e.g., "Recon:IAMUser/MaliciousIPCaller"
    id: str                                    # Finding ID
    arn: Optional[str] = None
    severity: float                            # GuardDuty native severity: 0.1 - 8.9 (0.1-3.9 Low, 4.0-6.9 Med, 7.0-8.9 High)
    createdAt: str
    updatedAt: Optional[str] = None
    title: str
    description: str
    service: Dict[str, Any]                    # action, evidence, archived, count, etc.
    resource: Dict[str, Any]                   # accessKeyDetails, instanceDetails, s3BucketDetails


class AWSVPCFlowRaw(BaseModel):
    """Native AWS VPC Flow Log Record (Default v2 format)."""
    version: int = 2
    account_id: str
    interface_id: str                          # eni-xxxxxxxxx
    srcaddr: str                               # Source IPv4/IPv6
    dstaddr: str                               # Destination IPv4/IPv6
    srcport: int
    dstport: int
    protocol: int                              # 6=TCP, 17=UDP, 1=ICMP
    packets: int
    bytes: int
    start: int                                 # Unix epoch seconds
    end: int                                   # Unix epoch seconds
    action: str                                # "ACCEPT" | "REJECT"
    log_status: str = "OK"                     # "OK" | "NODATA" | "SKIPDATA"


# ==============================================================================
# Azure Raw Log Schemas
# ==============================================================================

class AzureActivityLogRaw(BaseModel):
    """Native Azure Monitor Activity Log Schema."""
    time: str                                  # ISO-8601 UTC
    resourceId: str                            # e.g. /subscriptions/{subId}/resourceGroups/{rg}/...
    operationName: str                         # e.g., "Microsoft.Authorization/roleAssignments/write"
    category: Optional[str] = "Administrative" # Administrative, Security, Policy, Alert
    resultType: str                            # "Success", "Failed", "Started"
    resultSignature: Optional[str] = None
    durationMs: Optional[int] = 0
    caller: str                                # e.g. "admin@contoso.com" or Service Principal AppID
    callerIpAddress: Optional[str] = None
    correlationId: Optional[str] = None
    claims: Optional[Dict[str, Any]] = Field(default_factory=dict)
    properties: Optional[Dict[str, Any]] = Field(default_factory=dict)
    subscriptionId: Optional[str] = None


class AzureLocation(BaseModel):
    city: Optional[str] = None
    state: Optional[str] = None
    countryOrRegion: Optional[str] = None
    geoCoordinates: Optional[Dict[str, float]] = None # {"latitude": x, "longitude": y}


class AzureSignInStatus(BaseModel):
    errorCode: int = 0
    failureReason: Optional[str] = None
    additionalDetails: Optional[str] = None


class AzureEntraSignInRaw(BaseModel):
    """Native Microsoft Entra ID (formerly Azure AD) Interactive & Non-interactive Sign-in Log."""
    id: str
    createdDateTime: str
    userPrincipalName: str                     # user@company.com
    userId: Optional[str] = None
    appDisplayName: Optional[str] = "Azure Portal"
    appId: Optional[str] = None
    ipAddress: str
    clientAppUsed: Optional[str] = "Browser"
    userAgent: Optional[str] = None
    location: Optional[AzureLocation] = None
    status: AzureSignInStatus = Field(default_factory=AzureSignInStatus)
    conditionalAccessStatus: Optional[str] = "success" # success, failure, notApplied
    riskDetail: Optional[str] = "none"         # e.g., "none", "hiddenRuleTriggered", "unlikelyTravel"
    riskLevelAggregated: Optional[str] = "none"# "none", "low", "medium", "high"
    riskState: Optional[str] = "none"          # "none", "atRisk", "confirmedCompromised", "dismissed"


class AzureDefenderAlertRaw(BaseModel):
    """Native Microsoft Defender for Cloud (formerly ASC) Security Alert Schema."""
    id: str
    name: str
    type: str = "Microsoft.Security/locations/alerts"
    properties: Dict[str, Any]                 # alertDisplayName, alertType, description, severity, remediationSteps, entities
