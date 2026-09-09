# CloudSentry AI — SOC Analyst Technical Interview Defense Guide

This document is your master cheat sheet for technical interviews. It breaks down every design decision, mathematical trade-off, cloud architecture nuance, and AI implementation detail in plain English so you can defend this project with confidence.

---

## 1. High-Level Elevator Pitch (30-Second Interview Opener)

> *"In modern hybrid and multi-cloud enterprises, SOC analysts suffer from two critical pain points: **multi-cloud log fragmentation** (AWS and Azure logging things completely differently) and **alert fatigue** (thousands of raw alerts with no context).*
> 
> *I built **CloudSentry AI** to solve both. It ingests telemetry from AWS (CloudTrail, GuardDuty, VPC Flow) and Azure (Activity Log, Entra ID, Defender), normalizes everything into the vendor-neutral **OCSF (Open Cybersecurity Schema Framework)** standard, detects subtle non-linear anomalies using a **GPU-accelerated PyTorch Deep Autoencoder** benchmarked against an **Isolation Forest**, and uses a **pluggable LLM triage engine** to auto-generate incident summaries, MITRE ATT&CK mappings, and actionable CLI containment playbooks. It also includes an interactive **KQL query console** mimicking Azure Sentinel and real-time **CSPM posture checks**."*

---

## 2. Multi-Cloud Telemetry & Normalization (OCSF)

### Q: Why normalize logs into OCSF instead of querying CloudTrail or Azure Activity Logs directly?
- **The Problem**: In AWS CloudTrail, the actor is located at `userIdentity.arn` or `userIdentity.userName`, and the event name might be `AttachUserPolicy`. In Azure Activity Logs, the actor is at `caller`, and the operation is `Microsoft.Authorization/roleAssignments/write`. In Azure Entra ID, the actor is `userPrincipalName`.
- **The Impact in a SOC**: Without normalization, a SOC engineer must write and maintain two or three duplicate detection rules for every single security threat, ML models need separate pipelines per cloud, and SIEM licensing costs balloon.
- **The Solution**: **OCSF (Open Cybersecurity Schema Framework)** is an open standard backed by AWS, Splunk, CrowdStrike, and Palo Alto Networks. By mapping all telemetry into a `UnifiedOCSFEvent` (with standard fields: `actor`, `src_endpoint`, `target`, `action`, `category`, `status`), our detection engine, ML models, and LLM triage pipeline run seamlessly across any cloud provider.

### Q: How do AWS and Azure log schemas differ fundamentally?

| Feature | AWS CloudTrail | Azure Activity Log | Azure Entra ID (Azure AD) | AWS VPC Flow Logs |
| :--- | :--- | :--- | :--- | :--- |
| **Telemetry Type** | Cloud Audit / API control plane | Resource Management / ARM control plane | Identity Authentication & Token issuance | Layer 3/4 Network Flow telemetry |
| **Actor Location** | `userIdentity.userName` or `arn` | `caller` (email or App ID) | `userPrincipalName` | N/A (IP endpoints only) |
| **Action Identifier**| `eventName` (`ConsoleLogin`) | `operationName` (`.../write`) | Hardcoded Sign-in / App ID | `action` (`ACCEPT`/`REJECT`) |
| **Error Handling** | `errorCode` (`AccessDenied`) | `resultType` (`Failed`/`Success`) | `status.errorCode` (e.g. `50126`) | `log_status` (`OK`/`NODATA`) |
| **Location Data** | Raw `sourceIPAddress` | `callerIpAddress` | Structured `location` (City, Geo) | `srcaddr` / `dstaddr` |

---

## 3. AI/ML Threat Detection Engine: Autoencoder vs. Isolation Forest

### Q: Why use an Autoencoder instead of a supervised classifier like Random Forest or XGBoost?
- **Class Imbalance**: In enterprise cloud security, 99.9% of telemetry is benign administrative or automated CI/CD traffic. True malicious attacks represent less than 0.1%. Supervised models severely overfit on benign samples and fail on zero-day attacks.
- **Novelty Detection**: Adversaries constantly change techniques. A supervised model only recognizes attacks it has seen before. An **Autoencoder** is trained solely on *normal* enterprise baseline behavior; anything deviating from the normal pattern produces high reconstruction loss.

### Q: How does the PyTorch Deep Autoencoder work mathematically?
1. **Bottleneck Compression**:
   The network consists of an **Encoder** that compresses 13 continuous security features into a lower-dimensional latent bottleneck layer ($z \in \mathbb{R}^6$), and a **Decoder** that attempts to reconstruct the original input:
   $$\hat{x} = \text{Decoder}(\text{Encoder}(x))$$
2. **Reconstruction Mean Squared Error (MSE)**:
   For every security event, we measure how poorly the network reconstructed it:
   $$\text{MSE}(x, \hat{x}) = \frac{1}{D} \sum_{i=1}^{D} (x_i - \hat{x}_i)^2$$
3. **Thresholding & Score Calibration**:
   During baseline training, the 95th percentile baseline MSE is set as the anomaly threshold. Events exceeding this threshold are scaled non-linearly to an anomaly score between 50 and 100.

### Q: Why did you benchmark against Isolation Forest?
- **Isolation Forest** works by constructing random decision trees. Because anomalies are "few and different", they are isolated near the root of the tree with very short path lengths.
- **Comparison & Defense**:
  - *Isolation Forest Pros*: Fast training, zero neural hyperparameter tuning, low memory footprint.
  - *Isolation Forest Cons*: Evaluates axis-aligned orthogonal feature splits; struggles with complex non-linear correlations across multi-cloud identity, geographic velocity, and network byte ratios.
  - *Autoencoder Pros*: Latent representation captures dense non-linear interactions across high-dimensional data; runs seamlessly on GPU/CUDA accelerators.
- **Conclusion**: CloudSentry AI uses a **Composite Defense-in-Depth Model**:
  $$\text{Risk Score} = 0.50 \times \text{Autoencoder} + 0.15 \times \text{Isolation Forest} + 0.35 \times \text{Signature Heuristic}$$
  If a critical known signature (e.g., AdministratorAccess backdoor or Tor exit node sign-in) is triggered, a rule-based floor guarantees high severity.

---

## 4. LLM-Powered Alert Triage Engine

### Q: What problem does LLM Alert Triage solve in a SOC?
- **Alert Fatigue**: A typical enterprise SOC receives 5,000+ alerts daily. Tier 1 analysts spend 15–20 minutes per alert manually copying IPs, looking up MITRE techniques, determining false positives, and writing incident ticket handoff summaries.
- **The Solution**: CloudSentry AI automatically synthesizes raw telemetry into:
  1. A concise **Executive Incident Summary** (explaining identity, action, asset, and threat impact in plain English).
  2. Exact **MITRE ATT&CK Matrix alignment** (Tactics, Technique ID, Sub-technique, and direct links).
  3. A prioritized **Containment Playbook** with ready-to-execute AWS CLI and Azure CLI mitigation commands.

### Q: How do you prevent LLM hallucinations in a mission-critical security environment?
1. **Strict Pydantic Schema Enforcement**: We use structured outputs (`AlertTriageReport`) requiring exact types for MITRE IDs and containment commands.
2. **Dual-Mode Pluggable Architecture**:
   - **Mode 1: Deterministic Expert Playbooks**: Pre-compiled, zero-hallucination playbooks based on NIST SP 800-61 and CISA guidelines for known attack patterns (Impossible Travel, IAM Escalation, S3 Exfiltration, C2 Beaconing, Azure RBAC Backdoor).
   - **Mode 2: Local Open-Source LLMs (Ollama / Llama-3-8B / Phi-3)**: For air-gapped on-premise deployments requiring zero data egress.
   - **Mode 3: Cloud APIs (Groq / OpenAI / Gemini)**: High-throughput cloud inference when configured.
   - **Graceful Degradation**: If an LLM times out or returns malformed JSON, the engine automatically falls back to the deterministic expert playbook without dropping the alert.

---

## 5. Injected Attack Scenarios (MITRE ATT&CK Breakdown)

During interviews, walk through these 5 attack scenarios you implemented:

### Scenario 1: Impossible Travel & Credential Hijack
- **MITRE**: T1078.004 (Valid Accounts: Cloud Accounts), T1535 (Unused/Unsupported Cloud Regions)
- **Telemetry**: Azure Entra ID Sign-in
- **Mechanism**: Legitimate sign-in from Seattle office IP (`198.51.100.45`). 15 minutes later, an identical login is registered from a Tor Exit Node in Frankfurt, Germany (`185.220.101.5`) with automated user agent (`python-requests`).
- **Containment**: Revoke Entra ID OAuth refresh tokens via Microsoft Graph API and enforce password reset.

### Scenario 2: AWS IAM Privilege Escalation
- **MITRE**: T1098 (Account Manipulation), T1078.004 (Cloud Accounts)
- **Telemetry**: AWS CloudTrail
- **Mechanism**: Compromised low-privilege service account (`svc_ci_deployer`) calls `iam:AttachUserPolicy` attaching `AdministratorAccess` to an inactive user, followed by `iam:CreateAccessKey` to create a persistent backdoor.
- **Containment**: Detach policy via `aws iam detach-user-policy` and deactivate caller access keys.

### Scenario 3: S3 Ransomware & Data Exfiltration
- **MITRE**: T1530 (Data from Cloud Storage Object), T1485 (Data Destruction)
- **Telemetry**: AWS CloudTrail (Data Events)
- **Mechanism**: Burst of `s3:GetObject` against confidential financial bucket, followed immediately by `s3:PutBucketPolicy` injecting a Deny-All policy to lock out administrators.
- **Containment**: Restore bucket policy via `aws s3api delete-bucket-policy` and enable account-wide S3 Public Access Block.

### Scenario 4: VPC Flow C2 Beaconing
- **MITRE**: T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
- **Telemetry**: AWS VPC Flow Logs
- **Mechanism**: Internal EC2 instance (`10.0.2.15`) transmits fixed 320-byte TCP pulses every 60 seconds to external malicious IP (`45.33.32.156`) on port 4444.
- **Containment**: Isolate EC2 instance by attaching quarantine Security Group; block IP on subnet Network ACL (NACL).

### Scenario 5: Rogue Azure Subscription Owner
- **MITRE**: T1098.003 (Additional Cloud Roles), T1078.004 (Cloud Accounts)
- **Telemetry**: Azure Monitor Activity Log
- **Mechanism**: Compromised administrator identity executes `Microsoft.Authorization/roleAssignments/write` assigning the built-in "Owner" role at root subscription scope to an external guest account.
- **Containment**: Immediately delete role assignment via `az role assignment delete` and revoke caller sessions.

---

## 6. CSPM vs. SIEM Runtime Threat Detection

### Q: What is the difference between SIEM and CSPM?
- **SIEM / Runtime Detection (CloudTrail, Entra ID)**: Detects *what is happening right now* (e.g. an attacker actively downloading S3 buckets or logging in from Frankfurt).
- **CSPM (Cloud Security Posture Management)**: Detects *misconfigurations at rest* before an attacker discovers them (e.g., S3 bucket missing encryption, IAM policy with `Action: *`, or security group with `0.0.0.0/0:22` open).
- **Why CloudSentry AI includes both**: Modern SOC analysts do not operate in a vacuum. When an alert triggers on an identity, the analyst immediately cross-references CSPM to verify whether the target resource was already misconfigured.

---

## 7. Enterprise Production Scaling (50,000 Events/Sec)

### Q: If this system were deployed in a Fortune 500 company with 50,000 EPS, how would you architect it?
1. **Streaming Ingestion Layer**:
   - AWS: CloudTrail -> S3 -> SQS -> Apache Kafka / AWS Kinesis.
   - Azure: Diagnostic Settings -> Azure Event Hub (Kafka-compatible).
2. **Stream Processing & Normalization**:
   - Deploy Apache Flink or Spark Streaming consumer groups running our `OCSF Normalizer` in Kubernetes (EKS/AKS).
3. **Hot/Warm/Cold Storage Tiering**:
   - Hot tier (0–30 days): OpenSearch / ClickHouse / Elasticsearch for sub-second KQL querying.
   - Warm/Cold tier (30–365 days): Parquet on S3 / Azure Data Lake with Athena / Databricks SQL for historical compliance audits.
4. **GPU-Accelerated Inference**:
   - Run PyTorch Autoencoder feature extraction in batch micro-windows (e.g., 5-second micro-batches) utilizing Triton Inference Server or NVIDIA TensorRT on GPU worker nodes (`g4dn` or `g5` instances).
   - LLM Triage: Route high-risk anomalies to private quantized models (vLLM serving `Llama-3-8B-Instruct` with AWQ/4-bit quantization) maintaining sub-second generation times with zero third-party API exposure.
