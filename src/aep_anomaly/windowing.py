"""Chronological event windowing and leakage-safe dataset splits."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .state_types import StateId, StateSequence


@dataclass(frozen=True)
class EventWindow:
    window_id: int
    start_time: str
    end_time: str
    events: tuple[dict[str, str], ...]
    states: StateSequence
    client_ip: str = "unknown"
    state_descriptions: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class DatasetSplit:
    training: tuple[EventWindow, ...]
    validation: tuple[EventWindow, ...]
    testing: tuple[EventWindow, ...]


def load_windows(path: str | Path, *, window_type: str = "ip_session", size: int = 50,
                 include_partial: bool = False, timeout_seconds: float = 60,
                 min_events: int = 1, missing_ip: str = "unknown",
                 type: str | None = None) -> list[EventWindow]:
    """Group preprocessed state IDs into chronological per-IP sessions or windows."""
    # Configuration uses the concise key ``type``; retain ``window_type`` as
    # the explicit Python API name while accepting config dictionaries directly.
    if type is not None:
        window_type = type
    if window_type not in {"ip_session", "fixed_count", "fixed_time"}:
        raise ValueError("window_type must be 'ip_session', 'fixed_count', or 'fixed_time'")
    if size <= 0 or timeout_seconds <= 0 or min_events <= 0:
        raise ValueError("window size must be positive")
    records: list[tuple[datetime, int, dict[str, str], StateId, str, dict[str, str]]] = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"timestamp", "state_id"}
        missing = required.difference(reader.fieldnames or ())
        if missing:
            raise ValueError(f"event CSV is missing required columns: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader):
            try:
                timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                raise ValueError(f"invalid timestamp at CSV row {row_number + 2}: {row.get('timestamp')!r}")
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            timestamp = timestamp.astimezone(timezone.utc)
            state = row["state_id"]
            if not state.strip():
                raise ValueError(f"empty state_id at CSV row {row_number + 2}")
            raw_description = row.get("state_description") or "{}"
            try:
                description = json.loads(raw_description)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid state_description at CSV row {row_number + 2}") from exc
            if not isinstance(description, dict):
                raise ValueError(f"state_description must be an object at CSV row {row_number + 2}")
            ip = (row.get("ip") or row.get("client_ip") or "").strip() or missing_ip
            records.append((timestamp, row_number, dict(row), state, ip,
                            {str(key): str(value) for key, value in description.items()}))
    records.sort(key=lambda item: (item[0], item[1]))
    groups: list[list[tuple[datetime, int, dict[str, str], StateId, str, dict[str, str]]]] = []
    if window_type == "ip_session":
        by_ip: dict[str, list[tuple[datetime, int, dict[str, str], StateId, str, dict[str, str]]]] = {}
        for record in records:
            by_ip.setdefault(record[4], []).append(record)
        timeout = timedelta(seconds=float(timeout_seconds))
        for ip in sorted(by_ip):
            current: list[tuple[datetime, int, dict[str, str], StateId, str, dict[str, str]]] = []
            for record in by_ip[ip]:
                if current and record[0] - current[-1][0] > timeout:
                    if len(current) >= min_events:
                        groups.append(current)
                    current = []
                current.append(record)
            if current and len(current) >= min_events:
                groups.append(current)
        groups.sort(key=lambda group: (group[0][0], group[0][1]))
    elif window_type == "fixed_count":
        groups = [records[index:index + size] for index in range(0, len(records), size)]
        if groups and len(groups[-1]) < size and not include_partial:
            groups.pop()
    else:
        duration = timedelta(seconds=size)
        current: list[tuple[datetime, int, dict[str, str], StateId, str, dict[str, str]]] = []
        bucket_start: datetime | None = None
        for record in records:
            timestamp = record[0]
            if bucket_start is None:
                bucket_start = timestamp
            while timestamp >= bucket_start + duration:
                if current:
                    groups.append(current)
                bucket_start += duration
                current = []
            current.append(record)
        if current:
            groups.append(current)
    windows = []
    for index, group in enumerate(groups):
        windows.append(EventWindow(
            window_id=index,
            start_time=group[0][0].isoformat(),
            end_time=group[-1][0].isoformat(),
            events=tuple(item[2] for item in group),
            states=tuple(item[3] for item in group),
            client_ip=group[0][4],
            state_descriptions=tuple(item[5] for item in group),
        ))
    return windows


def chronological_split(windows: list[EventWindow], training_ratio: float = 0.65,
                        validation_ratio: float = 0.15, testing_ratio: float = 0.20) -> DatasetSplit:
    """Split in time order, rejecting ratios or sample counts that leave a partition empty."""
    ratios = (training_ratio, validation_ratio, testing_ratio)
    if any(value <= 0 for value in ratios) or abs(sum(ratios) - 1.0) > 1e-9:
        raise ValueError("split ratios must be positive and sum to 1")
    count = len(windows)
    train_end = int(count * training_ratio)
    validation_end = train_end + int(count * validation_ratio)
    if train_end < 1 or validation_end <= train_end or validation_end >= count:
        raise ValueError("not enough windows for non-empty training, validation, and testing splits")
    return DatasetSplit(tuple(windows[:train_end]), tuple(windows[train_end:validation_end]),
                        tuple(windows[validation_end:]))
