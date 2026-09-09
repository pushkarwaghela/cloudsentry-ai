"""
CloudSentry AI - KQL (Kusto Query Language) Query Engine
========================================================

WHY KQL IN A CLOUD SOC?
In enterprise Microsoft Sentinel and Azure Log Analytics environments, SOC analysts
interact with multi-cloud telemetry almost exclusively using KQL.
Demonstrating KQL query processing in your portfolio project proves immediate operational
readiness to SOC hiring managers.

Supported KQL operations:
- Filter: `where <field> == "value"`, `where <field> contains "str"`, `where <field> > 50`
- Projection: `project timestamp, actor, action, cloud, risk_score`
- Sorting: `sort by risk_score desc`
- Slicing: `take 25` or `limit 25`
"""

import re
from typing import Any, Dict, List, Tuple
from app.schemas.ocsf import UnifiedOCSFEvent


def _flatten_event(e: UnifiedOCSFEvent) -> Dict[str, Any]:
    """Flattens a UnifiedOCSFEvent into a 1D key-value record for KQL tabular querying."""
    return {
        "event_id": e.event_id,
        "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "cloud": e.cloud_provider.value,
        "service": e.source_service,
        "category": e.category.value,
        "action": e.action,
        "severity": e.severity.value,
        "status": e.status.value,
        "actor": e.actor.user_name or "Unknown",
        "actor_type": e.actor.principal_type or "Unknown",
        "src_ip": e.src_endpoint.ip if e.src_endpoint else "None",
        "src_city": e.src_endpoint.geo.city if (e.src_endpoint and e.src_endpoint.geo) else "None",
        "src_country": e.src_endpoint.geo.country if (e.src_endpoint and e.src_endpoint.geo) else "None",
        "target": e.target.resource_name if e.target else "None",
        "bytes": e.bytes_transferred or 0,
        "anomaly_score": e.anomaly_score or 0.0,
        "risk_score": e.risk_score or 0.0,
        "is_anomaly": e.is_anomaly,
    }


def execute_kql(query_str: str, events: List[UnifiedOCSFEvent]) -> Dict[str, Any]:
    """
    Executes a KQL-style pipeline against a list of UnifiedOCSFEvent objects.
    Example:
      CloudProvider == "aws" | where Action contains "Policy" | sort by risk_score desc | take 10
    """
    if not query_str or query_str.strip() == "":
        query_str = "take 50"

    # Flatten events
    records = [_flatten_event(e) for e in events]
    pipes = [p.strip() for p in query_str.split("|") if p.strip()]

    for pipe in pipes:
        tokens = pipe.split()
        if not tokens:
            continue
        op = tokens[0].lower()

        # 1. Filter: `where <field> <operator> <value>`
        if op == "where" or "==" in pipe or "!=" in pipe or "contains" in pipe or ">" in pipe or "<" in pipe:
            condition = pipe[5:].strip() if op == "where" else pipe

            # Case: `where field contains "val"`
            if " contains " in condition:
                parts = condition.split(" contains ", 1)
                fld = parts[0].strip().lower()
                val = parts[1].strip().strip("'\"").lower()
                records = [r for r in records if val in str(r.get(fld, "")).lower()]

            # Case: `where field == "val"`
            elif "==" in condition:
                parts = condition.split("==", 1)
                fld = parts[0].strip().lower()
                val = parts[1].strip().strip("'\"")
                records = [r for r in records if str(r.get(fld, "")).lower() == val.lower()]

            # Case: `where field != "val"`
            elif "!=" in condition:
                parts = condition.split("!=", 1)
                fld = parts[0].strip().lower()
                val = parts[1].strip().strip("'\"")
                records = [r for r in records if str(r.get(fld, "")).lower() != val.lower()]

            # Case: `where field >= num`
            elif ">=" in condition:
                parts = condition.split(">=", 1)
                fld = parts[0].strip().lower()
                try:
                    num = float(parts[1].strip())
                    records = [r for r in records if float(r.get(fld, 0)) >= num]
                except ValueError:
                    pass

            # Case: `where field > num`
            elif ">" in condition:
                parts = condition.split(">", 1)
                fld = parts[0].strip().lower()
                try:
                    num = float(parts[1].strip())
                    records = [r for r in records if float(r.get(fld, 0)) > num]
                except ValueError:
                    pass

            # Case: `where field <= num`
            elif "<=" in condition:
                parts = condition.split("<=", 1)
                fld = parts[0].strip().lower()
                try:
                    num = float(parts[1].strip())
                    records = [r for r in records if float(r.get(fld, 0)) <= num]
                except ValueError:
                    pass

            # Case: `where field < num`
            elif "<" in condition:
                parts = condition.split("<", 1)
                fld = parts[0].strip().lower()
                try:
                    num = float(parts[1].strip())
                    records = [r for r in records if float(r.get(fld, 0)) < num]
                except ValueError:
                    pass

        # 2. Sort: `sort by <field> [asc|desc]`
        elif op in ["sort", "order"]:
            # e.g., "sort by risk_score desc"
            by_idx = tokens.index("by") if "by" in tokens else 0
            if by_idx + 1 < len(tokens):
                sort_fld = tokens[by_idx + 1].lower()
                is_desc = "desc" in tokens[by_idx + 2 : by_idx + 3] or "desc" in pipe
                try:
                    records.sort(key=lambda r: r.get(sort_fld, 0), reverse=is_desc)
                except Exception:
                    pass

        # 3. Take / Limit: `take 20` or `limit 20`
        elif op in ["take", "limit"]:
            if len(tokens) > 1 and tokens[1].isdigit():
                records = records[: int(tokens[1])]

        # 4. Project: `project col1, col2, col3`
        elif op == "project":
            raw_cols = pipe[7:].split(",")
            selected_cols = [c.strip().lower() for c in raw_cols if c.strip()]
            if selected_cols:
                projected = []
                for r in records:
                    projected.append({k: r.get(k, "") for k in selected_cols})
                records = projected

    # Extract dynamic column names from results
    columns = list(records[0].keys()) if records else [
        "timestamp", "cloud", "actor", "action", "severity", "risk_score", "status"
    ]

    return {
        "query": query_str,
        "count": len(records),
        "columns": columns,
        "rows": records,
    }
