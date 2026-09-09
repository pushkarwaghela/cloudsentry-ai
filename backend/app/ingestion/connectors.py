"""
CloudSentry AI - Multi-Cloud Live Connectors & Stream Ingestion Stubs
====================================================================

WHY THIS ARCHITECTURE IS INTERVIEW-DEFENSIBLE:
In enterprise production SOCs, telemetry is rarely queried via ad-hoc API calls.
Instead:
- AWS CloudTrail delivers gzip files to an S3 bucket, which emits S3:ObjectCreated
  events to an SQS queue. A worker pool reads from SQS and streams to the normalizer.
- Azure Activity and Entra ID logs are routed via Diagnostic Settings to an Azure
  Event Hub (Kafka-compatible), where consumer groups stream them in real time.

This module provides the production connector interfaces and live adapter stubs.
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Iterator, List, Optional
from app.schemas.ocsf import UnifiedOCSFEvent
from app.ingestion.normalizer import normalize_event

logger = logging.getLogger("cloudsentry.connectors")


class BaseCloudConnector(ABC):
    """Abstract base class for cloud telemetry ingestion adapters."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def connect(self) -> bool:
        """Establishes connection or checks credential validity."""
        pass

    @abstractmethod
    def poll_events(self, max_records: int = 100) -> List[Dict[str, Any]]:
        """Pulls raw records from cloud telemetry queue or stream."""
        pass

    def stream_normalized_events(self, max_records: int = 100) -> Iterator[UnifiedOCSFEvent]:
        """Yields standardized OCSF events from the raw stream."""
        raw_batch = self.poll_events(max_records=max_records)
        for raw in raw_batch:
            try:
                yield normalize_event(raw)
            except Exception as exc:
                logger.error(f"[{self.name}] Error normalizing stream event: {exc}")


class AWSCloudTrailConnector(BaseCloudConnector):
    """
    AWS CloudTrail live connector via S3/SQS event notifications or CloudWatch Logs.
    Requires: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, SQS_QUEUE_URL.
    """

    def __init__(self, queue_url: Optional[str] = None):
        super().__init__("AWS-CloudTrail-SQS")
        self.queue_url = queue_url or os.getenv("AWS_CLOUDTRAIL_SQS_URL")
        self.is_connected = False

    def connect(self) -> bool:
        try:
            import boto3
            session = boto3.Session()
            self.sqs = session.client("sqs")
            self.is_connected = True
            logger.info("Connected to AWS SQS for CloudTrail ingestion.")
            return True
        except ImportError:
            logger.warning("boto3 not installed. Running in offline/simulation mode.")
            return False
        except Exception as e:
            logger.warning(f"AWS connection unavailable: {e}. Fallback to synthetic mode.")
            return False

    def poll_events(self, max_records: int = 10) -> List[Dict[str, Any]]:
        if not self.is_connected or not self.queue_url:
            return []
        try:
            response = self.sqs.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=min(max_records, 10),
                WaitTimeSeconds=2,
            )
            messages = response.get("Messages", [])
            # In production: parse SQS S3 event notification, download gzip from S3, extract records
            return []
        except Exception as err:
            logger.error(f"Error polling AWS SQS: {err}")
            return []


class AzureEventHubConnector(BaseCloudConnector):
    """
    Azure Event Hub connector for streaming Activity & Entra ID logs.
    Requires: AZURE_EVENTHUB_CONN_STR, EVENTHUB_NAME.
    """

    def __init__(self, conn_str: Optional[str] = None, eventhub_name: Optional[str] = None):
        super().__init__("Azure-EventHub")
        self.conn_str = conn_str or os.getenv("AZURE_EVENTHUB_CONN_STR")
        self.eventhub_name = eventhub_name or os.getenv("AZURE_EVENTHUB_NAME")
        self.is_connected = False

    def connect(self) -> bool:
        try:
            # from azure.eventhub import EventHubConsumerClient
            if not self.conn_str:
                return False
            self.is_connected = True
            logger.info("Configured Azure Event Hub connector.")
            return True
        except Exception as e:
            logger.warning(f"Azure EventHub connection unavailable: {e}. Fallback to synthetic mode.")
            return False

    def poll_events(self, max_records: int = 100) -> List[Dict[str, Any]]:
        return []
