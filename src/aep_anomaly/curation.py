"""Allowlist-based separation of application traffic during preprocessing."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


DECISION_FIELDS = (
    "timestamp", "method", "route_name", "uri", "normalized_uri", "status",
    "ip", "source_file", "classification", "reason", "raw_line",
)


def curate_event_csv(input_csv: str | Path, output_dir: str | Path,
                     config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Write allowlisted normal events and unlisted review events.

    Matching uses exact configured method/path pairs or exact route names. No
    response code, client IP, URI pattern, or inferred route family is used to
    decide that an event is normal. Unlisted endpoints are quarantined for
    review and therefore cannot enter model fitting or validation calibration.
    """
    source = Path(input_csv)
    destination = Path(output_dir)
    if not source.is_file():
        raise FileNotFoundError(f"event CSV does not exist: {source}")
    settings = config or {}
    if not settings.get("enabled", True):
        return {"enabled": False, "input_csv": str(source)}

    allowed_pairs = {
        (str(item.get("method", "*")).strip().upper(),
         str(item.get("path", "")).strip().rstrip("/") or "/")
        for item in settings.get("application_routes", [])
    }
    allowed_names = {str(name).strip() for name in settings.get("application_route_names", [])
                     if str(name).strip()}
    if not allowed_pairs and not allowed_names:
        raise ValueError("curation is enabled but no application route allowlist is configured")

    destination.mkdir(parents=True, exist_ok=True)
    buckets: dict[str, list[dict[str, str]]] = {"normal": [], "review": []}
    decisions: list[dict[str, str]] = []
    with source.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        input_fields = list(reader.fieldnames or [])
        if not input_fields:
            raise ValueError(f"event CSV has no header: {source}")
        for row in reader:
            method = (row.get("method") or "").strip().upper()
            path = (row.get("normalized_uri") or row.get("uri") or "").strip().split("?", 1)[0]
            path = path.rstrip("/") or "/"
            route_name = (row.get("route_name") or "").strip()
            pair_allowed = ("*", path) in allowed_pairs or (method, path) in allowed_pairs
            name_allowed = route_name in allowed_names
            if pair_allowed or name_allowed:
                classification = "normal"
                reason = "allowlisted_route_name" if name_allowed else "allowlisted_method_path"
            else:
                classification = "review"
                reason = "endpoint_not_in_application_allowlist"
            enriched = dict(row)
            enriched["curation_class"] = classification
            enriched["curation_reason"] = reason
            buckets[classification].append(enriched)
            decisions.append({
                "timestamp": row.get("timestamp", ""), "method": method,
                "route_name": route_name, "uri": row.get("uri", ""),
                "normalized_uri": row.get("normalized_uri", ""),
                "status": row.get("status", ""), "ip": row.get("ip", ""),
                "source_file": row.get("source_file", ""),
                "classification": classification, "reason": reason,
                "raw_line": row.get("raw_line", ""),
            })

    output_fields = [*input_fields, "curation_class", "curation_reason"]
    outputs: dict[str, str] = {}
    for classification, rows in buckets.items():
        output = destination / f"{classification}_route_events.csv"
        with output.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=output_fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        outputs[classification] = str(output)

    decision_path = destination / "curation_decisions.csv"
    with decision_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=DECISION_FIELDS)
        writer.writeheader()
        writer.writerows(decisions)
    counts = dict(Counter(item["classification"] for item in decisions))
    manifest = {
        "schema_version": 1,
        "input_csv": str(source),
        "policy": "exact application route allowlist; all unlisted endpoints require review",
        "allowlist": {"application_routes": sorted([list(item) for item in allowed_pairs]),
                      "application_route_names": sorted(allowed_names)},
        "counts": counts,
        "outputs": outputs,
        "decisions_csv": str(decision_path),
    }
    manifest_path = destination / "curation_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest
