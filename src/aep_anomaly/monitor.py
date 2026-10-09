"""Persistent polling monitor for appended route log files and dashboard alerts."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .event_encoder import EventEncoder
from .log_parser import LogParser
from .pipeline import TrainedDetector
from .route_preprocessor import RoutePreprocessor
from .windowing import EventWindow


class LogFolderMonitor:
    """Poll route logs, score inactive per-IP sessions, and persist alerts."""

    def __init__(self, watch_dir: str | Path, model_dir: str | Path, database: str | Path,
                 window_config: dict[str, Any] | int | None = None) -> None:
        self.watch_dir = Path(watch_dir)
        self.model_dir = Path(model_dir)
        self.database = Path(database)
        if isinstance(window_config, int):
            self.window_config = {"type": "fixed_count", "size": window_config,
                                  "include_partial": False}
        else:
            self.window_config = dict(window_config or {"type": "ip_session", "timeout_seconds": 60,
                                                       "min_events": 1, "missing_ip": "unknown"})
        self.window_type = self.window_config.get("type", "ip_session")
        if self.window_type == "ip_session":
            self.timeout_seconds = float(self.window_config.get("timeout_seconds", 60))
            self.min_events = int(self.window_config.get("min_events", 1))
            self.missing_ip = str(self.window_config.get("missing_ip", "unknown")).strip()
            if self.timeout_seconds <= 0 or self.min_events <= 0 or not self.missing_ip:
                raise ValueError("session timeout, minimum event count, and missing-IP group must be valid")
        elif self.window_type == "fixed_count":
            self.window_size = int(self.window_config.get("size", 50))
            if self.window_size <= 0:
                raise ValueError("window size must be positive")
            self.min_events = 1
            self.missing_ip = "unknown"
        else:
            raise ValueError("live monitoring supports ip_session or fixed_count windows")

    def scan_once(self) -> dict[str, int]:
        if not self.watch_dir.is_dir():
            raise NotADirectoryError(f"Watched log directory does not exist: {self.watch_dir}")
        self.database.parent.mkdir(parents=True, exist_ok=True)
        detector = TrainedDetector(self.model_dir)
        model_window = detector.metadata.get("config", {}).get("window", {})
        compared_keys = (("type", "timeout_seconds", "min_events", "missing_ip")
                         if self.window_type == "ip_session" else ("type", "size"))
        defaults = {"type": "ip_session", "timeout_seconds": 60, "min_events": 1,
                    "missing_ip": "unknown", "size": 50}
        if any(self.window_config.get(key, defaults[key]) != model_window.get(key, defaults[key])
               for key in compared_keys):
            raise ValueError("monitor session settings differ from the saved model; rebuild the model or use its configuration")
        encoder = EventEncoder()
        with sqlite3.connect(self.database) as db:
            db.execute("CREATE TABLE IF NOT EXISTS files (file_id TEXT PRIMARY KEY, path TEXT NOT NULL, offset INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_json TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, payload TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE IF NOT EXISTS skipped_lines (id INTEGER PRIMARY KEY AUTOINCREMENT, source_file TEXT NOT NULL, byte_offset INTEGER NOT NULL, parse_status TEXT NOT NULL, raw_line TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS monitor_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            rows_read = 0
            malformed_rows = 0
            for path in sorted(self.watch_dir.glob("routes-*.log"), key=lambda item: item.name.lower()):
                stat = path.stat()
                identity = f"{stat.st_dev}:{stat.st_ino}"
                prior = db.execute("SELECT offset FROM files WHERE file_id = ?", (identity,)).fetchone()
                offset = int(prior[0]) if prior else 0
                if stat.st_size < offset:  # copy-truncated log
                    offset = 0
                with path.open("rb") as stream:
                    stream.seek(offset)
                    while True:
                        line_start = stream.tell()
                        raw = stream.readline()
                        if not raw:
                            break
                        # Leave a trailing partial line for the next poll.
                        if not raw.endswith((b"\n", b"\r")):
                            stream.seek(line_start)
                            break
                        row = LogParser._parse_line("routes", raw.decode("utf-8", errors="replace").rstrip("\r\n"), path.name)
                        if row["parse_status"] == "ok" and RoutePreprocessor._parse_timestamp(row["timestamp"]) is not None:
                            state_id, description = encoder.encode_with_description(
                                row.get("method"), row.get("uri"), row.get("status"))
                            normalized_uri = encoder.route_normalizer.normalize(row.get("uri"))
                            status_class = encoder.status_class(row.get("status"))
                            event = {
                                "timestamp": row["timestamp"], "state_id": state_id,
                                "state_description": json.dumps(description, ensure_ascii=False, sort_keys=True),
                                "method": description["method"],
                                "normalized_uri": normalized_uri, "status_class": status_class,
                                "url_group": description["url_group"],
                                "status_category": description["status_category"],
                                "source_file": path.name, "uri": row.get("uri", ""),
                                "status": row.get("status", ""), "raw_line": row.get("raw_line", ""),
                                "ip": row.get("ip", "") or self.missing_ip,
                            }
                            db.execute("INSERT INTO events(event_json) VALUES (?)", (json.dumps(event),))
                            rows_read += 1
                        else:
                            malformed_rows += 1
                            db.execute("INSERT INTO skipped_lines(source_file,byte_offset,parse_status,raw_line) VALUES(?,?,?,?)",
                                       (str(path), line_start,
                                        row["parse_status"] if row["parse_status"] != "ok" else "invalid_timestamp",
                                        row["raw_line"]))
                    final_offset = stream.tell()
                db.execute("INSERT INTO files(file_id,path,offset) VALUES(?,?,?) ON CONFLICT(file_id) DO UPDATE SET path=excluded.path, offset=excluded.offset",
                           (identity, str(path), final_offset))

            consumed = 0
            scored_sessions = 0
            available = db.execute("SELECT id,event_json FROM events").fetchall()
            grouped: dict[str, list[tuple[int, dict[str, Any], datetime]]] = {}
            for event_id, event_json in available:
                record = json.loads(event_json)
                if not record.get("state_id"):
                    state_id, description = encoder.encode_with_description(
                        record.get("method"), record.get("uri"), record.get("status"))
                    record["state_id"] = state_id
                    record["state_description"] = json.dumps(
                        description, ensure_ascii=False, sort_keys=True)
                timestamp = RoutePreprocessor._parse_timestamp(record.get("timestamp", ""))
                if timestamp is None:
                    continue
                ip = (record.get("ip") or self.missing_ip).strip()
                grouped.setdefault(ip, []).append((int(event_id), record, timestamp))

            now = datetime.now(timezone.utc)
            timeout = timedelta(seconds=self.timeout_seconds) if self.window_type == "ip_session" else None
            closed: list[tuple[str, list[tuple[int, dict[str, Any], datetime]]]] = []
            for ip, records in grouped.items():
                records.sort(key=lambda item: (item[2], item[0]))
                current: list[tuple[int, dict[str, Any], datetime]] = []
                for item in records:
                    if current and timeout is not None and item[2] - current[-1][2] > timeout:
                        closed.append((ip, current))
                        current = []
                    current.append(item)
                if current:
                    if self.window_type == "fixed_count":
                        while len(current) >= self.window_size:
                            closed.append((ip, current[:self.window_size]))
                            current = current[self.window_size:]
                    elif now - current[-1][2] >= timeout:
                        closed.append((ip, current))

            for ip, items in closed:
                records = [item[1] for item in items]
                selected_ids = [item[0] for item in items]
                if len(records) >= self.min_events:
                    states = tuple(item["state_id"] for item in records)
                    descriptions = tuple(json.loads(item.get("state_description", "{}"))
                                         for item in records)
                    window = EventWindow(selected_ids[0], records[0]["timestamp"], records[-1]["timestamp"],
                                         tuple(records), states, client_ip=ip,
                                         state_descriptions=descriptions)
                    result: dict[str, Any] = detector.score(window)
                    result["scorable"] = True
                    result["source"] = "watched_folder"
                    scored_sessions += 1
                    if result.get("final_anomalous") is True:
                        db.execute("INSERT INTO alerts(created_at,payload) VALUES(?,?)",
                                   (datetime.now(timezone.utc).isoformat(), json.dumps(result, ensure_ascii=False)))
                db.executemany("DELETE FROM events WHERE id = ?", [(item_id,) for item_id in selected_ids])
                consumed += len(selected_ids)
            db.commit()
        return {"new_requests": rows_read, "malformed_lines": malformed_rows,
                "scored_windows": scored_sessions, "scored_sessions": scored_sessions,
                "pending_requests": self.pending_count()}

    def pending_count(self) -> int:
        if not self.database.exists():
            return 0
        with sqlite3.connect(self.database) as db:
            try:
                return int(db.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            except sqlite3.OperationalError:
                return 0

    def list_alerts(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.database.exists():
            return []
        with sqlite3.connect(self.database) as db:
            try:
                rows = db.execute("SELECT id,created_at,payload,acknowledged FROM alerts ORDER BY id DESC LIMIT ?",
                                  (max(1, min(int(limit), 1000)),)).fetchall()
            except sqlite3.OperationalError:
                return []
        return [{"id": row[0], "created_at": row[1], "acknowledged": bool(row[3]), **json.loads(row[2])}
                for row in rows]

    def acknowledge(self, alert_id: int) -> bool:
        if not self.database.exists():
            return False
        with sqlite3.connect(self.database) as db:
            try:
                cursor = db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (int(alert_id),))
                db.commit()
            except sqlite3.OperationalError:
                return False
        return cursor.rowcount > 0

    def list_skipped_lines(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.database.exists():
            return []
        with sqlite3.connect(self.database) as db:
            try:
                rows = db.execute("SELECT source_file,byte_offset,parse_status,raw_line FROM skipped_lines ORDER BY id DESC LIMIT ?",
                                  (max(1, min(int(limit), 1000)),)).fetchall()
            except sqlite3.OperationalError:
                return []
        return [{"source_file": row[0], "byte_offset": row[1],
                 "parse_status": row[2], "raw_line": row[3]} for row in rows]
