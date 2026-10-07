"""Parse route, controller, and service log files into separate CSVs."""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LOG_TYPES: dict[str, tuple[str, ...]] = {
    "routes": (
        "timestamp", "log_level", "method", "route_name", "uri", "status", "ip",
        "parse_status", "source_file", "raw_line",
    ),
    "controllers": (
        "timestamp", "log_level", "controller_action", "status", "parse_status",
        "source_file", "raw_line",
    ),
    "services": (
        "timestamp", "log_level", "operation", "parse_status", "source_file", "raw_line",
    ),
}

EXPECTED_MESSAGES = {
    "routes": {"Route request completed."},
    "controllers": {"Controller request completed."},
    "services": {"Service operation completed.", "Service entry operation completed."},
}

LOG_PREFIX = re.compile(
    r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]"
    r"\s+\S+\.(?P<level>[A-Z]+):\s*(?P<message>.*)$"
)
TIMESTAMP = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")


@dataclass(frozen=True)
class ParseStats:
    """Counts and output location for one parsed log type."""

    files: int
    parsed_rows: int
    malformed_rows: int
    output_path: Path


class LogParser:
    """Parse all recognized log types from a directory into per-type CSVs."""

    def parse_directory(self, input_dir: str | Path, output_dir: str | Path) -> dict[str, ParseStats]:
        """Parse ``routes-*``, ``controllers-*``, and ``services-*`` log files.

        Every input line from a recognized file is represented in its output CSV.
        Invalid lines receive a non-``ok`` ``parse_status`` and retain ``raw_line``.
        """
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        if not input_path.is_dir():
            raise NotADirectoryError(f"Input log directory does not exist: {input_path}")
        output_path.mkdir(parents=True, exist_ok=True)

        files_by_type = {
            log_type: sorted(input_path.glob(f"{log_type}-*.log"), key=lambda path: path.name.lower())
            for log_type in LOG_TYPES
        }
        summaries: dict[str, ParseStats] = {}

        for log_type, fields in LOG_TYPES.items():
            records: list[tuple[str, str, int, dict[str, str]]] = []
            parsed_rows = 0
            malformed_rows = 0

            for source in files_by_type[log_type]:
                with source.open("r", encoding="utf-8", errors="replace", newline="") as log_file:
                    for line_number, original_line in enumerate(log_file, start=1):
                        raw_line = original_line.rstrip("\r\n")
                        row = self._parse_line(log_type, raw_line, source.name)
                        if row["parse_status"] == "ok":
                            parsed_rows += 1
                        else:
                            malformed_rows += 1
                        timestamp = row["timestamp"] or self._extract_timestamp(raw_line)
                        records.append((timestamp, source.name, line_number, row))

            records.sort(key=lambda item: (not bool(item[0]), item[0], item[1].lower(), item[2]))
            csv_path = output_path / f"{log_type}.csv"
            with csv_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(record[3] for record in records)

            summaries[log_type] = ParseStats(
                files=len(files_by_type[log_type]),
                parsed_rows=parsed_rows,
                malformed_rows=malformed_rows,
                output_path=csv_path,
            )

        return summaries

    @staticmethod
    def _parse_line(log_type: str, raw_line: str, source_file: str) -> dict[str, str]:
        row = {field: "" for field in LOG_TYPES[log_type]}
        row.update(source_file=source_file, raw_line=raw_line, parse_status="malformed_line")

        prefix = LOG_PREFIX.match(raw_line)
        if prefix is None:
            row["timestamp"] = LogParser._extract_timestamp(raw_line)
            return row

        row["timestamp"] = prefix.group("timestamp")
        row["log_level"] = prefix.group("level")
        message = prefix.group("message").strip()
        json_start = message.find("{")
        if json_start < 0:
            return row
        if message[:json_start].strip() not in EXPECTED_MESSAGES[log_type]:
            row["parse_status"] = "unexpected_message"
            return row

        try:
            payload: Any = json.loads(message[json_start:])
        except (json.JSONDecodeError, TypeError):
            row["parse_status"] = "invalid_json"
            return row
        if not isinstance(payload, dict):
            row["parse_status"] = "invalid_payload"
            return row

        keys_by_type = {
            "routes": ("method", "route_name", "uri", "status", "ip"),
            "controllers": ("controller_action", "status"),
            "services": ("operation",),
        }
        if any(key not in payload for key in keys_by_type[log_type]):
            row["parse_status"] = "missing_fields"
            return row

        for key in keys_by_type[log_type]:
            value = payload[key]
            # Preserve JSON null as an empty cell; stringify other scalar values.
            row[key] = "" if value is None else str(value)
        row["parse_status"] = "ok"
        return row

    @staticmethod
    def _extract_timestamp(raw_line: str) -> str:
        match = TIMESTAMP.search(raw_line)
        return match.group(1) if match else ""
