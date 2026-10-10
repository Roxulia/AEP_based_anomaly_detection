"""Prepare parsed route CSV rows as chronologically ordered event states."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .event_encoder import EventEncoder


OUTPUT_FIELDS = (
    "timestamp", "state_id", "state_description", "method", "normalized_uri", "status_class",
    "url_group", "status_category", "ip", "source_file",
    "route_name", "uri", "status", "raw_line", "label",
)


@dataclass(frozen=True)
class PreprocessingSummary:
    input_rows: int
    processed_rows: int
    skipped_rows: int
    skipped_by_reason: dict[str, int]
    missing_ip_rows: int
    output_path: Path


class RoutePreprocessor:
    """Transform the parser's routes CSV without fitting or scoring models."""

    def __init__(self, event_encoder: EventEncoder | None = None) -> None:
        self.event_encoder = event_encoder or EventEncoder()

    def process_csv(self, input_csv: str | Path, output_csv: str | Path) -> PreprocessingSummary:
        """Encode valid rows, sort by timestamp, write output, and report skips.

        Rows with a non-``ok`` parser status or invalid/missing timestamp are
        skipped and counted. Their original raw lines remain in the input CSV.
        Missing request fields are represented as ``unknown`` by EventEncoder.
        """
        input_path = Path(input_csv)
        output_path = Path(output_csv)
        if not input_path.is_file():
            raise FileNotFoundError(f"Parsed routes CSV does not exist: {input_path}")

        skipped: Counter[str] = Counter()
        records: list[tuple[datetime, int, dict[str, str]]] = []
        input_rows = 0
        missing_ip_rows = 0
        with input_path.open("r", encoding="utf-8-sig", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            required_columns = {"timestamp", "method", "uri", "status", "parse_status"}
            missing_columns = required_columns.difference(reader.fieldnames or ())
            if missing_columns:
                missing = ", ".join(sorted(missing_columns))
                raise ValueError(f"routes CSV is missing required columns: {missing}")

            for row_number, row in enumerate(reader, start=2):
                input_rows += 1
                if row.get("parse_status", "").strip().lower() != "ok":
                    skipped["parse_status"] += 1
                    continue
                timestamp = row.get("timestamp", "").strip()
                parsed_timestamp = self._parse_timestamp(timestamp)
                if parsed_timestamp is None:
                    skipped["invalid_timestamp"] += 1
                    continue

                state_id, description = self.event_encoder.encode_with_description(
                    row.get("method"), row.get("uri"), row.get("status"))
                if not (row.get("ip") or "").strip():
                    missing_ip_rows += 1
                normalized_uri = self.event_encoder.route_normalizer.normalize(row.get("uri"))
                status_class = self.event_encoder.status_class(row.get("status"))
                record = {
                    "timestamp": timestamp,
                    "state_id": state_id,
                    "state_description": json.dumps(description, ensure_ascii=False, sort_keys=True),
                    "method": (row.get("method") or "unknown").strip().upper() or "unknown",
                    "normalized_uri": normalized_uri,
                    "status_class": status_class,
                    "url_group": description.get("url_group", ""),
                    "status_category": description.get("status_category", ""),
                    "ip": row.get("ip", ""),
                    "source_file": row.get("source_file", ""),
                    "route_name": row.get("route_name", ""),
                    "uri": row.get("uri", ""),
                    "status": row.get("status", ""),
                    "raw_line": row.get("raw_line", ""),
                    "label": row.get("label", "") or "",
                }
                records.append((parsed_timestamp, row_number, record))

        records.sort(key=lambda item: (item[0], item[1]))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=OUTPUT_FIELDS)
            writer.writeheader()
            writer.writerows(record for _, _, record in records)

        return PreprocessingSummary(
            input_rows=input_rows,
            processed_rows=len(records),
            skipped_rows=sum(skipped.values()),
            skipped_by_reason=dict(skipped),
            missing_ip_rows=missing_ip_rows,
            output_path=output_path,
        )

    @staticmethod
    def _parse_timestamp(value: str) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)


def ensure_state_ids_csv(input_csv: str | Path, output_csv: str | Path,
                         state_fields: tuple[str, ...] | list[str] | None = None) -> Path:
    """Upgrade a legacy prepared event CSV into the preprocessing state-ID format.

    State interpretation remains here in preprocessing. Windowing and statistical
    modules consume only ``state_id`` values from the resulting file.
    """
    source, destination = Path(input_csv), Path(output_csv)
    if not source.is_file():
        raise FileNotFoundError(f"Event CSV does not exist: {source}")
    with source.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        columns = list(reader.fieldnames or ())
        rows = list(reader)
    encoder = EventEncoder(fields=state_fields)
    # Re-encode even previously prepared rows so config changes cannot silently
    # retain state IDs built with a different set of fields.
    has_descriptions = "state_description" in columns
    has_grouped = {"url_group", "status_category"}.issubset(columns)
    if "timestamp" not in columns or "method" not in columns:
        raise ValueError("legacy event CSV requires timestamp and method columns")
    if not has_grouped and not {"normalized_uri", "status_class"}.issubset(columns):
        raise ValueError("legacy event CSV requires grouped-state or normalized URI/status columns")

    new_fields = ["state_id", "state_description", *[field for field in columns
                                                       if field not in {"state_id", "state_description"}]]
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=new_fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            if has_descriptions:
                try:
                    full_description = json.loads(row.get("state_description") or "{}")
                except json.JSONDecodeError as exc:
                    raise ValueError("legacy event CSV contains an invalid state_description") from exc
                description = {}
                for field in encoder.fields:
                    value = full_description.get(field, row.get(field))
                    if value is None or value == "":
                        value = "unknown"
                    value = str(value)
                    description[field] = value.strip().upper() if field == "method" else value
            elif has_grouped:
                full_description = {
                    "method": (row.get("method") or "unknown").strip().upper() or "unknown",
                    "url_group": (row.get("url_group") or "unknown").strip() or "unknown",
                    "status_category": (row.get("status_category") or "unknown").strip() or "unknown",
                }
                description = {field: full_description[field] for field in encoder.fields}
            else:
                description = encoder.describe(row.get("method"),
                                                row.get("uri") or row.get("normalized_uri"),
                                                row.get("status") or row.get("status_class"))
            row["state_id"] = encoder.state_id(description)
            row["state_description"] = json.dumps(description, ensure_ascii=False, sort_keys=True)
            writer.writerow(row)
    return destination
