"""
CloudSentry AI - Cloud Security Posture Management (CSPM) Engine
================================================================

WHY CSPM MATTERS FOR A SOC ANALYST INTERVIEW:
While SIEM/SOC analysts monitor runtime security logs (e.g. CloudTrail, Entra ID),
CSPM proactively evaluates cloud infrastructure configuration state against CIS
Benchmarks. Modern SOC analysts increasingly conduct "Shift-Left" posture checks
to prevent incidents before adversaries exploit misconfigurations.

This module evaluates CIS Benchmark and AWS Well-Architected / Azure Cloud Adoption
guardrails across storage, identity, and network resources.
"""

from typing import Any, Dict, List
from pydantic import BaseModel, ConfigDict


class CSPMFinding(BaseModel):
    id: str
    cloud: str                           # "aws" or "azure"
    title: str
    benchmark: str                       # e.g., "CIS AWS Benchmark 1.16", "CIS Azure 5.1"
    severity: str                        # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    status: str                          # "FAILED" or "PASSED"
    resource_id: str
    resource_type: str
    description: str
    impact: str
    remediation_command: str
    iac_recommendation: str

    model_config = ConfigDict(populate_by_name=True)


class CSPMReport(BaseModel):
    posture_score: int                   # 0 to 100
    total_checks: int
    passed_checks: int
    failed_checks: int
    findings: List[CSPMFinding]

    model_config = ConfigDict(populate_by_name=True)


# Pre-defined production cloud posture evaluations
DEFAULT_CSPM_FINDINGS: List[CSPMFinding] = [
    # AWS Controls
    CSPMFinding(
        id="AWS-CIS-1.16",
        cloud="aws",
        title="IAM Policies Grant Full Administrative Access (*:*)",
        benchmark="CIS AWS Foundations Benchmark v1.4.0 (1.16)",
        severity="CRITICAL",
        status="FAILED",
        resource_id="arn:aws:iam::123456789012:policy/OverlyPermissiveDevOps",
        resource_type="iam_policy",
        description="IAM policy allows wildcard 'Action: *' across 'Resource: *' without boundary constraints.",
        impact="A single compromised credential allows total AWS account takeover and destruction.",
        remediation_command="aws iam detach-user-policy --user-name devops_user --policy-arn arn:aws:iam::123456789012:policy/OverlyPermissiveDevOps",
        iac_recommendation="Use AWS IAM Access Analyzer or tfsec to flag wildcard action statements in Terraform.",
    ),
    CSPMFinding(
        id="AWS-CIS-2.1.1",
        cloud="aws",
        title="S3 Bucket Has Public Read Access Enabled",
        benchmark="CIS AWS Foundations Benchmark v1.4.0 (2.1.1)",
        severity="CRITICAL",
        status="FAILED",
        resource_id="corp-confidential-mna-financials",
        resource_type="s3_bucket",
        description="Bucket policy permits unauthenticated anonymous GET requests.",
        impact="Exposure of sensitive M&A and regulatory financial files to public internet crawlers.",
        remediation_command="aws s3api put-public-access-block --bucket corp-confidential-mna-financials --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        iac_recommendation="resource 'aws_s3_bucket_public_access_block' 'pab' { block_public_acls = true }",
    ),
    CSPMFinding(
        id="AWS-CIS-5.2",
        cloud="aws",
        title="Security Group Allows Unrestricted Inbound SSH (0.0.0.0/0:22)",
        benchmark="CIS AWS Foundations Benchmark v1.4.0 (5.2)",
        severity="HIGH",
        status="FAILED",
        resource_id="sg-04a187c3b999",
        resource_type="security_group",
        description="Ingress rule permits TCP port 22 from the entire IPv4 Internet.",
        impact="Exposes cloud workloads to automated brute-force attacks and zero-day SSH vulnerabilities.",
        remediation_command="aws ec2 revoke-security-group-ingress --group-id sg-04a187c3b999 --protocol tcp --port 22 --cidr 0.0.0.0/0",
        iac_recommendation="Replace 0.0.0.0/0 with corporate VPN CIDR or deploy AWS Systems Manager Session Manager.",
    ),
    CSPMFinding(
        id="AWS-CIS-1.4",
        cloud="aws",
        title="Root Account Access Keys Active",
        benchmark="CIS AWS Foundations Benchmark v1.4.0 (1.4)",
        severity="CRITICAL",
        status="PASSED",
        resource_id="arn:aws:iam::123456789012:root",
        resource_type="iam_root",
        description="AWS Root account has zero active programmatic access keys.",
        impact="Best practice compliant.",
        remediation_command="# No action required",
        iac_recommendation="Enforce AWS Organizations Service Control Policy (SCP) preventing root API access.",
    ),
    # Azure Controls
    CSPMFinding(
        id="AZ-CIS-1.1",
        cloud="azure",
        title="Subscription Owner Role Assigned to External Guest Account",
        benchmark="CIS Microsoft Azure Foundations Benchmark v1.4.0 (1.1)",
        severity="CRITICAL",
        status="FAILED",
        resource_id="/subscriptions/sub-prod-001/providers/Microsoft.Authorization/roleAssignments/ra-shadow-owner-99",
        resource_type="azure_role_assignment",
        description="Guest account (usr-ext-rogue-shadow@evilcorp.org) holds root subscription Owner privileges.",
        impact="Allows external identities to create shadow backdoors and read KeyVault secrets.",
        remediation_command="az role assignment delete --ids '/subscriptions/sub-prod-001/providers/Microsoft.Authorization/roleAssignments/ra-shadow-owner-99'",
        iac_recommendation="Use Azure Policy 'Allowed members for built-in subscription Owner role' to prevent guest assignments.",
    ),
    CSPMFinding(
        id="AZ-CIS-3.1",
        cloud="azure",
        title="Storage Account Allows Public Blob Access",
        benchmark="CIS Microsoft Azure Foundations Benchmark v1.4.0 (3.1)",
        severity="HIGH",
        status="FAILED",
        resource_id="/subscriptions/sub-prod-001/resourceGroups/rg-prod-us/providers/Microsoft.Storage/storageAccounts/stproddata01",
        resource_type="storage_account",
        description="Storage account 'stproddata01' has allowBlobPublicAccess set to true.",
        impact="Anonymous users can download sensitive blobs if containers are misconfigured.",
        remediation_command="az storage account update --name stproddata01 --resource-group rg-prod-us --allow-blob-public-access false",
        iac_recommendation="azurerm_storage_account: set allow_nested_items_to_be_public = false in Terraform.",
    ),
    CSPMFinding(
        id="AZ-CIS-1.3",
        cloud="azure",
        title="Entra ID Privileged Roles Enforce Conditional Access MFA",
        benchmark="CIS Microsoft Azure Foundations Benchmark v1.4.0 (1.3)",
        severity="HIGH",
        status="PASSED",
        resource_id="tenant-prod-contoso",
        resource_type="entra_conditional_access",
        description="Global Administrators and Security Admins require Phishing-Resistant FIDO2/MFA.",
        impact="Best practice compliant.",
        remediation_command="# No action required",
        iac_recommendation="Deploy Azure Conditional Access Policy templates as code.",
    ),
]


def evaluate_cspm_posture() -> CSPMReport:
    """Evaluates posture checks and computes aggregate security score."""
    passed = sum(1 for f in DEFAULT_CSPM_FINDINGS if f.status == "PASSED")
    failed = len(DEFAULT_CSPM_FINDINGS) - passed
    score = int((passed / len(DEFAULT_CSPM_FINDINGS)) * 100)

    return CSPMReport(
        posture_score=score,
        total_checks=len(DEFAULT_CSPM_FINDINGS),
        passed_checks=passed,
        failed_checks=failed,
        findings=DEFAULT_CSPM_FINDINGS,
    )
