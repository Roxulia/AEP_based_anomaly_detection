"""Prepare parsed route CSV rows as chronologically ordered event states."""

from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .event_encoder import EventEncoder


OUTPUT_FIELDS = (
    "timestamp", "method", "normalized_uri", "status_class", "source_file",
    "route_name", "uri", "status", "raw_line",
)


@dataclass(frozen=True)
class PreprocessingSummary:
    input_rows: int
    processed_rows: int
    skipped_rows: int
    skipped_by_reason: dict[str, int]
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

                method, normalized_uri, status_class = self.event_encoder.encode(
                    row.get("method"), row.get("uri"), row.get("status")
                )
                record = {
                    "timestamp": timestamp,
                    "method": method,
                    "normalized_uri": normalized_uri,
                    "status_class": status_class,
                    "source_file": row.get("source_file", ""),
                    "route_name": row.get("route_name", ""),
                    "uri": row.get("uri", ""),
                    "status": row.get("status", ""),
                    "raw_line": row.get("raw_line", ""),
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
