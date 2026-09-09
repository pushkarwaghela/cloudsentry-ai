"""
CloudSentry AI - Pluggable LLM Alert Triage Engine
=================================================

WHY A PLUGGABLE LLM ARCHITECTURE MATTERS:
In an enterprise SOC:
1. Data Privacy / Compliance (SOC2, HIPAA): Raw logs often contain PII and cannot
   be sent to public third-party APIs without masking. An on-premise local model
   (e.g., Llama-3-8B via Ollama / vLLM on private GPU instances) ensures 100% data sovereignty.
2. Latency & Resilience: High-volume alert bursts require zero-latency fallback
   when LLM services experience rate limits or cold starts.
3. Cost Optimization: Triage routing allows high-confidence anomalies to be summarized
   by local models or deterministic engines, invoking high-parameter models only
   for complex ambiguous threats.

This client supports:
- Mode 1: Deterministic Expert (100% offline, zero latency, zero cost)
- Mode 2: Local Open-Source LLM (Ollama / Llama-3 / Phi-3)
- Mode 3: Cloud APIs (Groq / OpenAI / Gemini via REST)
"""

import json
import logging
import os
import time
from typing import Any, Dict, Optional
import requests
from app.schemas.ocsf import UnifiedOCSFEvent
from app.schemas.triage import AlertTriageReport, TriageVerdict
from app.triage.expert_rules import triage_event_deterministic

logger = logging.getLogger("cloudsentry.llm")

SYSTEM_PROMPT = """You are CloudSentry AI, a Principal Cloud Security Analyst in a Tier 3 SOC.
Your task is to analyze the provided security event telemetry and return a structured JSON triage report.

Enforce the following schema strictly:
{
  "incident_title": "[SEVERITY] Short punchy title",
  "executive_summary": "2-3 clear sentences summarizing identity, action, asset, and threat impact.",
  "triage_verdict": "TRUE_POSITIVE_MALICIOUS" | "SUSPICIOUS_INVESTIGATION_REQUIRED" | "FALSE_POSITIVE_BENIGN",
  "recommended_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence_score": 0.0 to 1.0,
  "confidence_rationale": "Why you reached this conclusion",
  "mitre_attack": [
    {
      "tactic": "string",
      "technique_id": "TXXXX",
      "technique_name": "string",
      "reference_url": "https://attack.mitre.org/techniques/TXXXX/"
    }
  ],
  "containment_playbook": [
    {
      "order": 1,
      "title": "Short title",
      "action_type": "IAM_REVOCATION" | "NETWORK_ISOLATION" | "PASSWORD_RESET" | "FORENSIC_SNAPSHOT",
      "command": "CLI command string",
      "rationale": "Why this mitigates the blast radius"
    }
  ]
}
Return ONLY valid JSON without markdown formatting, code fences, or additional text.
"""


class LLMTriageClient:
    """
    Pluggable multi-provider triage client.
    """

    def __init__(
        self,
        provider: str = "auto",
        ollama_url: str = "http://localhost:11434",
        ollama_model: str = "llama3:8b",
        timeout: float = 8.0,
    ):
        self.provider = os.getenv("LLM_PROVIDER", provider).lower()
        self.ollama_url = os.getenv("OLLAMA_URL", ollama_url)
        self.ollama_model = os.getenv("OLLAMA_MODEL", ollama_model)
        self.timeout = timeout
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.groq_api_key = os.getenv("GROQ_API_KEY")

    def _query_ollama(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Queries local Ollama endpoint."""
        try:
            res = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "system": SYSTEM_PROMPT,
                    "stream": False,
                    "format": "json",
                },
                timeout=self.timeout,
            )
            if res.status_code == 200:
                body = res.json().get("response", "{}")
                return json.loads(body)
        except Exception as e:
            logger.debug(f"Ollama inference unavailable: {e}")
        return None

    def _query_groq_or_openai(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Queries OpenAI or Groq compatible chat endpoint."""
        api_key = self.groq_api_key or self.openai_api_key
        if not api_key:
            return None

        url = "https://api.groq.com/openai/v1/chat/completions" if self.groq_api_key else "https://api.openai.com/v1/chat/completions"
        model = "llama-3.1-8b-instant" if self.groq_api_key else "gpt-4o-mini"

        try:
            res = requests.post(
                url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.1,
                },
                timeout=self.timeout,
            )
            if res.status_code == 200:
                raw_content = res.json()["choices"][0]["message"]["content"]
                return json.loads(raw_content)
        except Exception as err:
            logger.warning(f"Cloud LLM API error: {err}")
        return None

    def triage_event(self, event: UnifiedOCSFEvent) -> AlertTriageReport:
        """
        Executes triage using the configured or active provider with seamless fallback.
        """
        start_t = time.perf_counter()

        # If deterministic provider explicitly requested, execute immediately
        if self.provider == "deterministic":
            report = triage_event_deterministic(event)
            report.inference_time_ms = round((time.perf_counter() - start_t) * 1000, 2)
            return report

        # Prepare context prompt
        event_dict = event.model_dump(mode="json")
        prompt = (
            f"Analyze this security event:\n"
            f"Provider: {event.cloud_provider.value}\n"
            f"Service: {event.source_service}\n"
            f"Action: {event.action}\n"
            f"Actor: {event.actor.user_name} ({event.actor.principal_type})\n"
            f"Source Endpoint: {event.src_endpoint.model_dump() if event.src_endpoint else 'None'}\n"
            f"Target Resource: {event.target.model_dump() if event.target else 'None'}\n"
            f"Status: {event.status.value}\n"
            f"ML Anomaly Score: {event.anomaly_score}/100\n"
            f"Composite Risk Score: {event.risk_score}/100\n"
            f"Raw Telemetry:\n{json.dumps(event.raw_log, indent=2)}\n"
        )

        parsed_json = None
        provider_used = "deterministic_expert"

        # Try Local Ollama first if auto/ollama
        if self.provider in ["auto", "ollama"]:
            parsed_json = self._query_ollama(prompt)
            if parsed_json:
                provider_used = f"ollama:{self.ollama_model}"

        # Try Cloud API next if still none
        if not parsed_json and (self.provider in ["auto", "cloud"]):
            parsed_json = self._query_groq_or_openai(prompt)
            if parsed_json:
                provider_used = "cloud_api"

        # Validate parsed JSON into AlertTriageReport or fall back to deterministic
        if parsed_json:
            try:
                parsed_json["event_id"] = event.event_id
                parsed_json["llm_provider"] = provider_used
                report = AlertTriageReport.model_validate(parsed_json)
                report.inference_time_ms = round((time.perf_counter() - start_t) * 1000, 2)
                return report
            except Exception as e:
                logger.warning(f"LLM JSON schema validation failed: {e}. Falling back to deterministic playbook.")

        # Graceful Deterministic Fallback
        report = triage_event_deterministic(event)
        report.inference_time_ms = round((time.perf_counter() - start_t) * 1000, 2)
        return report
