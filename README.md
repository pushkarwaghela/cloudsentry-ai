<div align="center">

# ☁️ CloudSentry AI

### Multi-Cloud AI Threat Detection and Alert Triage

Ingests AWS and Azure telemetry, detects anomalies, and turns them into MITRE ATT&CK-mapped incident summaries.

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-232F3E?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white)

[🐞 Report Bug](../../issues)

</div>

---

## 📌 Overview

Security teams drown in alerts from multiple clouds. **CloudSentry AI** is a full-stack incident triage platform that collects multi-cloud telemetry, detects anomalous behavior with ML, and uses an LLM to write clear, MITRE ATT&CK-mapped incident summaries so analysts can prioritize faster.

## ✨ Features

- 📥 **Multi-cloud ingestion** via REST APIs:
  - AWS CloudTrail
  - AWS GuardDuty
  - Azure Event Hub
- 🤖 **Anomaly detection engine** using PyTorch Autoencoders + Isolation Forest
- 🧾 **LLM-powered triage module** generating MITRE ATT&CK-mapped incident summaries
- 🖥️ React dashboard for reviewing and triaging incidents
- 🐳 Dockerized for easy setup

## 🏗️ Architecture

```
AWS CloudTrail ─┐
AWS GuardDuty  ─┼─► FastAPI Ingestion ─► Anomaly Detection ─► LLM Triage ─► React Dashboard
Azure Event Hub ┘                        (Autoencoder +       (MITRE ATT&CK
                                          Isolation Forest)    summaries)
```

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React |
| Backend | Python, FastAPI |
| ML | PyTorch (Autoencoders), Isolation Forest |
| Cloud | AWS (CloudTrail, GuardDuty), Azure Event Hub |
| DevOps | Docker |

## 🚀 Getting Started

```bash
git clone https://github.com/pushkarwaghela/cloudsentry-ai.git
cd cloudsentry-ai

# Run with Docker
docker compose up --build

# Or run manually
pip install -r requirements.txt
uvicorn main:app --reload
```

> Adjust commands to match this repo. Never commit cloud credentials; use environment variables.

```env
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AZURE_EVENT_HUB_CONNECTION_STRING=...
LLM_API_KEY=...
```

## 🗺️ Roadmap

- [ ] More cloud sources and log types
- [ ] Alert deduplication and severity ranking
- [ ] Analyst feedback loop to improve detection

## 👤 Author

**Pushkar Waghela** · [LinkedIn](https://linkedin.com/in/pushkar-waghela) · [Portfolio](https://pushkarwaghela.netlify.app)
