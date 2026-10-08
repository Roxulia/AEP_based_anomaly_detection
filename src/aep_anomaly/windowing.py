"""Chronological event windowing and leakage-safe dataset splits."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .event_encoder import EventEncoder, EventState


@dataclass(frozen=True)
class EventWindow:
    window_id: int
    start_time: str
    end_time: str
    events: tuple[dict[str, str], ...]
    states: tuple[EventState, ...]


@dataclass(frozen=True)
class DatasetSplit:
    training: tuple[EventWindow, ...]
    validation: tuple[EventWindow, ...]
    testing: tuple[EventWindow, ...]


def load_windows(path: str | Path, *, window_type: str = "fixed_count", size: int = 50,
                 include_partial: bool = False, encoder: EventEncoder | None = None) -> list[EventWindow]:
    """Load preprocessed route events and group them chronologically."""
    if window_type not in {"fixed_count", "fixed_time"}:
        raise ValueError("window_type must be 'fixed_count' or 'fixed_time'")
    if size <= 0:
        raise ValueError("window size must be positive")
    event_encoder = encoder or EventEncoder()
    records: list[tuple[datetime, int, dict[str, str], EventState]] = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"timestamp", "method", "normalized_uri", "status_class"}
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
            state = (row["method"], row["normalized_uri"], row["status_class"])
            records.append((timestamp, row_number, dict(row), state))
    records.sort(key=lambda item: (item[0], item[1]))
    groups: list[list[tuple[datetime, int, dict[str, str], EventState]]] = []
    if window_type == "fixed_count":
        groups = [records[index:index + size] for index in range(0, len(records), size)]
        if groups and len(groups[-1]) < size and not include_partial:
            groups.pop()
    else:
        duration = timedelta(seconds=size)
        current: list[tuple[datetime, int, dict[str, str], EventState]] = []
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
