"""Persistent polling monitor for appended route log files and dashboard alerts."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .event_encoder import EventEncoder
from .log_parser import LogParser
from .pipeline import TrainedDetector
from .route_preprocessor import RoutePreprocessor
from .windowing import EventWindow


class LogFolderMonitor:
    """Poll route log files, score complete fixed-count windows, and persist alerts."""

    def __init__(self, watch_dir: str | Path, model_dir: str | Path, database: str | Path,
                 window_size: int = 50) -> None:
        self.watch_dir = Path(watch_dir)
        self.model_dir = Path(model_dir)
        self.database = Path(database)
        self.window_size = int(window_size)
        if self.window_size <= 0:
            raise ValueError("window_size must be positive")

    def scan_once(self) -> dict[str, int]:
        if not self.watch_dir.is_dir():
            raise NotADirectoryError(f"Watched log directory does not exist: {self.watch_dir}")
        self.database.parent.mkdir(parents=True, exist_ok=True)
        detector = TrainedDetector(self.model_dir)
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
                            state = encoder.encode(row.get("method"), row.get("uri"), row.get("status"))
                            event = {
                                "timestamp": row["timestamp"], "method": state[0],
                                "normalized_uri": state[1], "status_class": state[2],
                                "source_file": path.name, "uri": row.get("uri", ""),
                                "status": row.get("status", ""), "raw_line": row.get("raw_line", ""),
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
            while True:
                available = db.execute("SELECT id,event_json FROM events").fetchall()
                if len(available) < self.window_size:
                    break
                ordered = sorted(((json.loads(item[1]), item[0]) for item in available),
                                 key=lambda item: (item[0]["timestamp"], item[0]["source_file"], item[1]))
                selected = ordered[:self.window_size]
                records = [item[0] for item in selected]
                selected_ids = [int(item[1]) for item in selected]
                states = tuple((item["method"], item["normalized_uri"], item["status_class"])
                               for item in records)
                start_id = selected_ids[0]
                window = EventWindow(start_id, records[0]["timestamp"], records[-1]["timestamp"],
                                     tuple(records), states)
                try:
                    result: dict[str, Any] = detector.score(window)
                    result["scorable"] = True
                except ValueError as exc:
                    if "not observed during fit" not in str(exc):
                        raise
                    result = {"window_id": start_id, "start_time": window.start_time,
                              "end_time": window.end_time, "event_count": len(records),
                              "events": records,
                              "scorable": False, "final_anomalous": None,
                              "unscorable_reason": str(exc), "source": "watched_folder"}
                result["source"] = "watched_folder"
                if result.get("final_anomalous") is True or result.get("scorable") is False:
                    db.execute("INSERT INTO alerts(created_at,payload) VALUES(?,?)",
                               (datetime.now(timezone.utc).isoformat(), json.dumps(result, ensure_ascii=False)))
                db.executemany("DELETE FROM events WHERE id = ?", [(item_id,) for item_id in selected_ids])
                consumed += len(selected_ids)
            db.commit()
        return {"new_requests": rows_read, "malformed_lines": malformed_rows,
                "scored_windows": consumed // self.window_size,
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
