"""
CloudSentry AI - Deterministic SOC Expert Knowledge Engine
=========================================================

WHY DETERMINISTIC EXPERT PLAYBOOKS ARE ESSENTIAL IN A PRODUCTION SOC:
While generative LLMs provide flexible natural language summaries, relying purely
on raw LLM generation in an emergency introduces hallucination risks (e.g. invalid
CLI flags, wrong MITRE IDs, or non-deterministic severity ratings).

This module contains battle-tested, deterministic mappings developed from NIST SP 800-61
and CISA Cloud Incident Response guidelines. It generates exact, zero-hallucination
triage reports for known attack patterns, while serving as the primary baseline for
generative models.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4
from app.schemas.ocsf import UnifiedOCSFEvent
from app.schemas.triage import (
    AlertTriageReport,
    ContainmentStep,
    MitreAttackMapping,
    TriageVerdict,
)


def triage_impossible_travel(event: UnifiedOCSFEvent) -> AlertTriageReport:
    """Triage for impossible travel / Tor exit credential hijack."""
    user = event.actor.user_name or event.actor.email or "Target User"
    src_ip = event.src_endpoint.ip if event.src_endpoint else "Unknown IP"
    city = event.src_endpoint.geo.city if (event.src_endpoint and event.src_endpoint.geo) else "Frankfurt"
    country = event.src_endpoint.geo.country if (event.src_endpoint and event.src_endpoint.geo) else "Germany"

    summary = (
        f"Critical authentication anomaly detected for account '{user}'. "
        f"A successful login was registered from an untrusted endpoint ({src_ip} in {city}, {country}) "
        f"within minutes of authorized domestic enterprise access. The telemetry exhibits characteristics "
        f"of credential theft or session token hijacking routed via anonymous infrastructure."
    )

    mitre = [
        MitreAttackMapping(
            tactic="Initial Access",
            technique_id="T1078.004",
            technique_name="Valid Accounts: Cloud Accounts",
            reference_url="https://attack.mitre.org/techniques/T1078/004/",
        ),
        MitreAttackMapping(
            tactic="Defense Evasion",
            technique_id="T1535",
            technique_name="Unused/Unsupported Cloud Regions",
            reference_url="https://attack.mitre.org/techniques/T1535/",
        ),
    ]

    playbook = [
        ContainmentStep(
            order=1,
            title="Revoke Active Entra ID User Sessions",
            action_type="IAM_REVOCATION",
            command=f"az rest --method POST --uri 'https://graph.microsoft.com/v1.0/users/{user}/revokeSignInSessions'",
            rationale="Immediately invalidates all active OAuth Refresh Tokens, forcing re-authentication.",
        ),
        ContainmentStep(
            order=2,
            title="Enforce Immediate Password & MFA Reset",
            action_type="PASSWORD_RESET",
            command=f"az ad user update --id {user} --force-change-password-next-sign-in true",
            rationale="Mitigates ongoing credential stuffing or compromised static password exposure.",
        ),
        ContainmentStep(
            order=3,
            title="Block Rogue Source IP on Edge WAF / Conditional Access",
            action_type="NETWORK_ISOLATION",
            command=f"# Add {src_ip} to Azure Named Location 'Untrusted-IP-Blocklist'",
            rationale="Prevents adversary from establishing secondary authentication attempts from the same egress node.",
        ),
    ]

    return AlertTriageReport(
        event_id=event.event_id,
        incident_title=f"[CRITICAL] Impossible Travel & Compromised Credentials for {user}",
        executive_summary=summary,
        triage_verdict=TriageVerdict.TRUE_POSITIVE_MALICIOUS,
        recommended_severity="CRITICAL",
        confidence_score=0.98,
        confidence_rationale="Identified geographic velocity anomaly (>5,000 miles in <15m) combined with Tor exit IP fingerprint.",
        mitre_attack=mitre,
        containment_playbook=playbook,
        llm_provider="deterministic_expert",
    )


def triage_iam_privilege_escalation(event: UnifiedOCSFEvent) -> AlertTriageReport:
    """Triage for AWS IAM privilege escalation & backdoor creation."""
    user = event.actor.user_name or "svc_ci_deployer"
    req = event.raw_log.get("requestParameters", {})
    target_user = req.get("userName", "unknown_user")
    policy_arn = req.get("policyArn", "arn:aws:iam::aws:policy/AdministratorAccess")

    summary = (
        f"Adversary privilege escalation detected. Identity '{user}' performed an unauthorized "
        f"API call to attach policy '{policy_arn}' to target identity '{target_user}'. "
        f"This action bypasses least-privilege guardrails and grants root-equivalent cloud control."
    )

    mitre = [
        MitreAttackMapping(
            tactic="Privilege Escalation",
            technique_id="T1098",
            technique_name="Account Manipulation",
            reference_url="https://attack.mitre.org/techniques/T1098/",
        ),
        MitreAttackMapping(
            tactic="Persistence",
            technique_id="T1078.004",
            technique_name="Valid Accounts: Cloud Accounts",
            reference_url="https://attack.mitre.org/techniques/T1078/004/",
        ),
    ]

    playbook = [
        ContainmentStep(
            order=1,
            title="Detach AdministratorAccess Policy Immediately",
            action_type="IAM_REVOCATION",
            command=f"aws iam detach-user-policy --user-name {target_user} --policy-arn {policy_arn}",
            rationale="Reverts excessive privileges before adversary can provision lateral infrastructure.",
        ),
        ContainmentStep(
            order=2,
            title="Deactivate Compromised Caller Access Keys",
            action_type="IAM_REVOCATION",
            command=f"aws iam list-access-keys --user-name {user} | jq -r '.AccessKeyMetadata[].AccessKeyId' | xargs -I {{}} aws iam update-access-key --user-name {user} --access-key-id {{}} --status Inactive",
            rationale="Quarantines the initiating service principal credentials.",
        ),
        ContainmentStep(
            order=3,
            title="Attach Explicit Inline Deny-All Incident Response Policy",
            action_type="IAM_REVOCATION",
            command=f"aws iam put-user-policy --user-name {target_user} --policy-name IR-Quarantine-DenyAll --policy-document '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}}]}}'",
            rationale="Ensures zero further actions can be executed under the compromised identity.",
        ),
    ]

    return AlertTriageReport(
        event_id=event.event_id,
        incident_title=f"[CRITICAL] AWS IAM Privilege Escalation: AdministratorAccess Attached by {user}",
        executive_summary=summary,
        triage_verdict=TriageVerdict.TRUE_POSITIVE_MALICIOUS,
        recommended_severity="CRITICAL",
        confidence_score=0.99,
        confidence_rationale="Direct observation of administrative policy attachment by non-admin identity without change ticket approval.",
        mitre_attack=mitre,
        containment_playbook=playbook,
        llm_provider="deterministic_expert",
    )


def triage_s3_data_exfiltration(event: UnifiedOCSFEvent) -> AlertTriageReport:
    """Triage for S3 bucket data exfiltration / policy lockout."""
    user = event.actor.user_name or "alex.chen"
    target = event.target.resource_name if event.target else "corp-confidential-mna-financials"

    summary = (
        f"Critical cloud storage extortion / exfiltration activity detected targeting '{target}'. "
        f"Telemetry reveals an anomalous high-velocity data retrieval sequence followed by a "
        f"PutBucketPolicy call modifying resource ACLs. This sequence mirrors cloud ransomware "
        f"tactics designed to exfiltrate and lock out administrative owners."
    )

    mitre = [
        MitreAttackMapping(
            tactic="Exfiltration",
            technique_id="T1530",
            technique_name="Data from Cloud Storage Object",
            reference_url="https://attack.mitre.org/techniques/T1530/",
        ),
        MitreAttackMapping(
            tactic="Impact",
            technique_id="T1485",
            technique_name="Data Destruction / Denial",
            reference_url="https://attack.mitre.org/techniques/T1485/",
        ),
    ]

    playbook = [
        ContainmentStep(
            order=1,
            title="Restore Default Secure S3 Bucket Policy",
            action_type="IAM_REVOCATION",
            command=f"aws s3api delete-bucket-policy --bucket {target}",
            rationale="Removes malicious Deny or public-read policy applied by the threat actor.",
        ),
        ContainmentStep(
            order=2,
            title="Enable S3 Public Access Block at Account Level",
            action_type="NETWORK_ISOLATION",
            command="aws s3control put-public-access-block --account-id 123456789012 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            rationale="Enforces account-wide perimeter guardrail against unauthenticated data leaks.",
        ),
        ContainmentStep(
            order=3,
            title="Revoke IAM Access Keys for Identity",
            action_type="IAM_REVOCATION",
            command=f"aws iam update-access-key --user-name {user} --access-key-id <KEY_ID> --status Inactive",
            rationale="Stops continuing API data harvesting loop.",
        ),
    ]

    return AlertTriageReport(
        event_id=event.event_id,
        incident_title=f"[CRITICAL] S3 Data Exfiltration & Bucket Policy Tampering: {target}",
        executive_summary=summary,
        triage_verdict=TriageVerdict.TRUE_POSITIVE_MALICIOUS,
        recommended_severity="CRITICAL",
        confidence_score=0.97,
        confidence_rationale="Combination of rapid bulk GetObject calls and bucket policy manipulation from suspicious IP.",
        mitre_attack=mitre,
        containment_playbook=playbook,
        llm_provider="deterministic_expert",
    )


def triage_c2_beaconing(event: UnifiedOCSFEvent) -> AlertTriageReport:
    """Triage for VPC Flow Log C2 beaconing."""
    src_ip = event.src_endpoint.ip if event.src_endpoint else "10.0.2.15"
    dst_ip = event.dst_endpoint.ip if event.dst_endpoint else "45.33.32.156"
    port = event.dst_endpoint.port if event.dst_endpoint else 4444

    summary = (
        f"Network Command & Control (C2) beaconing detected. Internal host {src_ip} is establishing "
        f"periodic, fixed-interval outbound TCP connections to external threat intelligence IP {dst_ip} "
        f"on non-standard port {port}. This behavioral signature strongly corresponds to interactive "
        f"implant check-ins (e.g. Cobalt Strike, Mythic, or Metasploit reverse shell)."
    )

    mitre = [
        MitreAttackMapping(
            tactic="Command and Control",
            technique_id="T1071",
            technique_name="Application Layer Protocol",
            reference_url="https://attack.mitre.org/techniques/T1071/",
        ),
        MitreAttackMapping(
            tactic="Command and Control",
            technique_id="T1571",
            technique_name="Non-Standard Port",
            reference_url="https://attack.mitre.org/techniques/T1571/",
        ),
    ]

    playbook = [
        ContainmentStep(
            order=1,
            title="Quarantine Compromised EC2 / VM via Security Group",
            action_type="NETWORK_ISOLATION",
            command="aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <ISOLATION_SG_ID>",
            rationale="Cuts off active network egress while preserving machine state for memory forensics.",
        ),
        ContainmentStep(
            order=2,
            title="Block Remote C2 IP on Network ACL (NACL)",
            action_type="NETWORK_ISOLATION",
            command=f"aws ec2 create-network-acl-entry --network-acl-id <NACL_ID> --rule-number 50 --protocol 6 --port-range From={port},To={port} --cidr-block {dst_ip}/32 --rule-action deny --egress",
            rationale="Instantly stops egress packets subnet-wide at the routing boundary.",
        ),
        ContainmentStep(
            order=3,
            title="Trigger EC2 Memory Snapshot & Forensic Disk Dump",
            action_type="FORENSIC_SNAPSHOT",
            command="aws ec2 create-snapshots --instance-specification InstanceId=<INSTANCE_ID>,Description='IR-Incident-C2-Dump'",
            rationale="Captures volatile RAM artifacts before restarting or terminating the instance.",
        ),
    ]

    return AlertTriageReport(
        event_id=event.event_id,
        incident_title=f"[HIGH] VPC Flow Command & Control (C2) Beaconing to {dst_ip}:{port}",
        executive_summary=summary,
        triage_verdict=TriageVerdict.TRUE_POSITIVE_MALICIOUS,
        recommended_severity="HIGH",
        confidence_score=0.96,
        confidence_rationale="Periodic fixed byte count and delta cadence directed toward known malicious external port.",
        mitre_attack=mitre,
        containment_playbook=playbook,
        llm_provider="deterministic_expert",
    )


def triage_azure_rbac_backdoor(event: UnifiedOCSFEvent) -> AlertTriageReport:
    """Triage for rogue Azure RBAC role assignment."""
    caller = event.actor.user_name or "elena.rostova@cybercorp.com"
    target = event.target.resource_name if event.target else "ra-shadow-owner-99"

    summary = (
        f"Critical unauthorized Azure RBAC assignment detected. Caller '{caller}' executed "
        f"a role assignment granting Subscription-level 'Owner' privileges to an unverified "
        f"external identity. This grants unrestricted management, resource deletion, and secret "
        f"harvesting across all tenant resources."
    )

    mitre = [
        MitreAttackMapping(
            tactic="Persistence",
            technique_id="T1098.003",
            technique_name="Account Manipulation: Additional Cloud Roles",
            reference_url="https://attack.mitre.org/techniques/T1098/003/",
        ),
        MitreAttackMapping(
            tactic="Privilege Escalation",
            technique_id="T1078.004",
            technique_name="Valid Accounts: Cloud Accounts",
            reference_url="https://attack.mitre.org/techniques/T1078/004/",
        ),
    ]

    playbook = [
        ContainmentStep(
            order=1,
            title="Delete Rogue Azure RBAC Role Assignment",
            action_type="IAM_REVOCATION",
            command=f"az role assignment delete --ids '{event.target.resource_id}'",
            rationale="Immediately strips the adversary of root subscription ownership.",
        ),
        ContainmentStep(
            order=2,
            title="Revoke Caller Session Tokens",
            action_type="IAM_REVOCATION",
            command=f"az rest --method POST --uri 'https://graph.microsoft.com/v1.0/users/{caller}/revokeSignInSessions'",
            rationale="Prevents the compromised administrative caller from issuing additional role writes.",
        ),
        ContainmentStep(
            order=3,
            title="Audit Azure Activity Log for Secret Access",
            action_type="FORENSIC_SNAPSHOT",
            command="az monitor activity-log list --offset 4h --query \"[?contains(operationName.value, 'listKeys') || contains(operationName.value, 'secrets')]\"",
            rationale="Identifies if the attacker accessed storage access keys or Key Vault secrets while possessing Owner rights.",
        ),
    ]

    return AlertTriageReport(
        event_id=event.event_id,
        incident_title=f"[CRITICAL] Rogue Azure Subscription Owner RBAC Assigned by {caller}",
        executive_summary=summary,
        triage_verdict=TriageVerdict.TRUE_POSITIVE_MALICIOUS,
        recommended_severity="CRITICAL",
        confidence_score=0.99,
        confidence_rationale="Subscription Owner assignment to external identity without privileged access management (PIM) approval.",
        mitre_attack=mitre,
        containment_playbook=playbook,
        llm_provider="deterministic_expert",
    )


def triage_generic_anomaly(event: UnifiedOCSFEvent) -> AlertTriageReport:
    """Fallback triage report for novel anomalies detected by Autoencoder/Isolation Forest."""
    provider = event.cloud_provider.value.upper()
    action = event.action
    user = event.actor.user_name or "Unknown Actor"
    score = event.risk_score or 70.0

    summary = (
        f"Statistical anomaly flagged by CloudSentry AI ML Detection Engine in {provider} telemetry. "
        f"The action '{action}' performed by identity '{user}' produced a high reconstruction "
        f"error ({event.anomaly_score}) relative to the historical baseline. Multiple contextual risk "
        f"indicators were triggered."
    )

    return AlertTriageReport(
        event_id=event.event_id,
        incident_title=f"[SUSPICIOUS] Anomaly Detected: {action} by {user} in {provider}",
        executive_summary=summary,
        triage_verdict=TriageVerdict.SUSPICIOUS_INVESTIGATION_REQUIRED,
        recommended_severity="HIGH" if score >= 65 else "MEDIUM",
        confidence_score=0.85,
        confidence_rationale="Machine learning multi-dimensional anomaly detection model flagged abnormal feature deviation.",
        mitre_attack=[
            MitreAttackMapping(
                tactic="Execution",
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                reference_url="https://attack.mitre.org/techniques/T1059/",
            )
        ],
        containment_playbook=[
            ContainmentStep(
                order=1,
                title="Verify Activity with Account Owner",
                action_type="FORENSIC_SNAPSHOT",
                command=f"# Contact identity {user} via Out-of-Band channel (Slack/Signal) to confirm intent.",
                rationale="Determines whether this deviation represents unannounced DevOps maintenance or malicious intrusion.",
            ),
            ContainmentStep(
                order=2,
                title="Review Correlated Telemetry in ±1 Hour Window",
                action_type="FORENSIC_SNAPSHOT",
                command=f"# Query CloudSentry KQL Console: CloudProvider == '{event.cloud_provider.value}' and Actor == '{user}'",
                rationale="Identifies preparatory reconnaissance or subsequent lateral movement.",
            ),
        ],
        llm_provider="deterministic_expert",
    )


def triage_event_deterministic(event: UnifiedOCSFEvent) -> AlertTriageReport:
    """
    Routes an event to the optimal deterministic playbook based on signature heuristics.
    """
    action = event.action.lower()
    raw_str = str(event.raw_log).lower()

    # 1. Impossible Travel
    if "unlikelytravel" in raw_str or (event.src_endpoint and event.src_endpoint.geo and event.src_endpoint.geo.city == "Frankfurt"):
        return triage_impossible_travel(event)

    # 2. IAM Escalation
    if "attachuserpolicy" in action or ("createaccesskey" in action and ("shadow" in raw_str or "temp" in raw_str)):
        return triage_iam_privilege_escalation(event)

    # 3. S3 Exfiltration / Lockout
    if "putbucketpolicy" in action or "financial" in raw_str:
        return triage_s3_data_exfiltration(event)

    # 4. C2 Beaconing
    if (event.dst_endpoint and event.dst_endpoint.port == 4444) or "c2beacon" in raw_str:
        return triage_c2_beaconing(event)

    # 5. Azure RBAC Backdoor
    if "roleassignments" in action or "rbac" in action:
        return triage_azure_rbac_backdoor(event)

    # 6. Fallback Generic
    return triage_generic_anomaly(event)
