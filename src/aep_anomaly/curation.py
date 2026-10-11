"""Allowlist-based separation of application traffic during preprocessing."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DECISION_FIELDS = (
    "timestamp", "method", "route_name", "uri", "normalized_uri", "status",
    "ip", "source_file", "classification", "reason", "raw_line",
)


def is_excluded_application_route(row: dict[str, Any], config: dict[str, Any] | None = None) -> bool:
    """Check explicit path/name exclusions used by batch and live pipelines."""
    settings = config or {}
    path = str(row.get("normalized_uri") or row.get("uri") or "").split("?", 1)[0]
    path = path.strip().rstrip("/") or "/"
    paths = {str(item).strip().split("?", 1)[0].rstrip("/") or "/"
             for item in settings.get("exclude_paths", []) if str(item).strip()}
    names = {str(item).strip() for item in settings.get("exclude_route_names", [])
             if str(item).strip()}
    return path in paths or str(row.get("route_name") or "").strip() in names


def is_allowlisted_application_route(row: dict[str, Any],
                                     config: dict[str, Any] | None = None) -> bool:
    """Check the same exact method/path and route-name allowlist used by curation."""
    settings = config or {}
    method = str(row.get("method") or "").strip().upper()
    path = str(row.get("normalized_uri") or row.get("uri") or "").strip().split("?", 1)[0]
    path = path.rstrip("/") or "/"
    pairs = {
        (str(item.get("method", "*")).strip().upper(),
         str(item.get("path", "")).strip().rstrip("/") or "/")
        for item in settings.get("application_routes", [])
    }
    names = {str(name).strip() for name in settings.get("application_route_names", [])
             if str(name).strip()}
    return (('*', path) in pairs or (method, path) in pairs
            or str(row.get("route_name") or "").strip() in names)


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
        for row_index, row in enumerate(reader):
            method = (row.get("method") or "").strip().upper()
            path = (row.get("normalized_uri") or row.get("uri") or "").strip().split("?", 1)[0]
            path = path.rstrip("/") or "/"
            route_name = (row.get("route_name") or "").strip()
            allowed = is_allowlisted_application_route(row, settings)
            name_allowed = route_name in allowed_names
            if allowed:
                classification = "normal"
                reason = "allowlisted_route_name" if name_allowed else "allowlisted_method_path"
            else:
                classification = "review"
                reason = "endpoint_not_in_application_allowlist"
            enriched = dict(row)
            enriched["curation_class"] = classification
            enriched["curation_reason"] = reason
            enriched["_curation_index"] = str(row_index)
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

    # Optional whole-session policy uses the same per-IP inactivity boundary
    # as windowing. Mark every event in a session for review if any route fails
    # the allowlist.
    if settings.get("session_control", False):
        timeout_seconds = float(settings.get("session_timeout_seconds", 60))
        missing_ip = str(settings.get("missing_ip", "unknown"))
        session_rows: dict[tuple[str, int], list[int]] = {}
        ordered: list[tuple[datetime, int, str]] = []
        for index, row in enumerate(buckets["normal"] + buckets["review"]):
            try:
                timestamp = datetime.fromisoformat(
                    (row.get("timestamp") or "").replace("Z", "+00:00"))
            except ValueError:
                continue
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            ordered.append((timestamp.astimezone(timezone.utc), index,
                            (row.get("ip") or "").strip() or missing_ip))
        # Sort independently by client and timestamp to match sessionization.
        ordered.sort(key=lambda item: (item[2], item[0], item[1]))
        session_number: dict[str, int] = {}
        previous: dict[str, datetime] = {}
        for timestamp, index, ip in ordered:
            if ip not in previous or (timestamp - previous[ip]).total_seconds() > timeout_seconds:
                session_number[ip] = session_number.get(ip, -1) + 1
            previous[ip] = timestamp
            key = (ip, session_number[ip])
            session_rows.setdefault(key, []).append(index)
        flattened = buckets["normal"] + buckets["review"]
        invalid_sessions = {
            key for key, indices in session_rows.items()
            if any(flattened[index].get("curation_class") == "review" for index in indices)
        }
        for key in invalid_sessions:
            for index in session_rows[key]:
                row = flattened[index]
                row["curation_class"] = "review"
                row["curation_reason"] = "session_contains_unallowlisted_route"
                decision = decisions[int(row["_curation_index"])]
                decision["classification"] = "review"
                decision["reason"] = "session_contains_unallowlisted_route"
        buckets = {"normal": [], "review": []}
        for row in flattened:
            row.pop("_curation_index", None)
            buckets[row["curation_class"]].append(row)

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
        "session_control": bool(settings.get("session_control", False)),
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


def exclude_event_csv(input_csv: str | Path, output_csv: str | Path,
                      config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Remove explicitly configured application-only routes from scoring input."""
    settings = config or {}
    source, destination = Path(input_csv), Path(output_csv)
    with source.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = list(reader.fieldnames or [])
        if not fields:
            raise ValueError(f"event CSV has no header: {source}")
        kept: list[dict[str, str]] = []
        excluded = Counter()
        for row in reader:
            if is_excluded_application_route(row, settings):
                excluded["excluded_application_route"] += 1
            else:
                kept.append(row)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(kept)
    return {"processed_rows": len(kept), "skipped_rows": sum(excluded.values()),
            "skipped_by_reason": dict(excluded)}
