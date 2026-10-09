"""Local HTTP API for detector summaries, log experiments, and monitor alerts."""

from __future__ import annotations

import os
import tempfile
import csv
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .monitor import LogFolderMonitor
from .pipeline import (analyze_uploaded_log, evaluate_directory, load_config,
                       train_from_directories)


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = Path(os.getenv("AEP_CONFIG", ROOT / "config" / "default.yaml"))
CONFIG = load_config(CONFIG_PATH)
MODEL_DIR = Path(os.getenv("AEP_MODEL_DIR", ROOT / "models" / "default"))
WATCH_DIR = Path(os.getenv("AEP_WATCH_DIR", ROOT / "Data" / "live"))
ALERT_DB = Path(os.getenv("AEP_ALERT_DB", ROOT / "Data" / "alerts.sqlite3"))
app = FastAPI(title="Server Statistical Anomaly Analysis API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["*"])


def _monitor() -> LogFolderMonitor:
    return LogFolderMonitor(WATCH_DIR, MODEL_DIR, ALERT_DB, CONFIG["window"])


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "analysis": "statistical anomaly detection"}


@app.get("/api/summary")
def summary() -> dict:
    datasets = CONFIG["datasets"]
    model_path = MODEL_DIR / "model.json"
    model_summary = {}
    if model_path.is_file():
        import json
        document = json.loads(model_path.read_text(encoding="utf-8"))
        model_summary = {"entropy_rate": document["markov"].get("entropy_rate_bits"),
                         "aep_threshold": document.get("aep_threshold"),
                         "density_threshold": document.get("density_threshold"),
                         "sequence_settings": document.get("config", {}).get("window", {}),
                         "window_counts": document.get("window_counts", document.get("split_windows", {}))}
    evaluation_path = ROOT / "reports" / "evaluation" / "evaluation.json"
    evaluation = None
    activity = None
    if evaluation_path.is_file():
        import json
        evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
        event_csv = Path(evaluation.get("test_data", {}).get("event_csv", ""))
        timeline_path = evaluation_path.parent / "hybrid.jsonl"
        route_counts: Counter[str] = Counter()
        status_counts: Counter[str] = Counter()
        total_requests = 0
        if event_csv.is_file():
            with event_csv.open("r", encoding="utf-8-sig", newline="") as stream:
                for row in csv.DictReader(stream):
                    total_requests += 1
                    route_counts[row.get("normalized_uri") or "unknown"] += 1
                    status_counts[row.get("status_class") or "unknown"] += 1
        score_timeline = []
        if timeline_path.is_file():
            with timeline_path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    row = json.loads(line)
                    if row.get("scorable", True):
                        score_timeline.append({key: row.get(key) for key in
                                               ("window_id", "start_time", "information_score",
                                                "entropy_rate", "final_anomalous")})
        activity = {"total_requests": total_requests,
                    "top_routes": [{"route": key, "count": value} for key, value in route_counts.most_common(8)],
                    "status_counts": dict(status_counts), "score_timeline": score_timeline[-30:]}
    return {
        "detector_description": "First-order Markov + AEP + information-score density",
        "model_available": (MODEL_DIR / "model.json").is_file(),
        "model": model_summary,
        "evaluation": evaluation,
        "activity": activity,
        "model_dir": str(MODEL_DIR),
        "datasets": {name: {"path": str(ROOT / value), "available": (ROOT / value).is_dir()}
                     for name, value in (("train", datasets["train_dir"]),
                                         ("validate", datasets["validate_dir"]),
                                         ("test", datasets["test_dir"]))},
        "watch_dir": str(WATCH_DIR), "watch_dir_available": WATCH_DIR.is_dir(),
    }


@app.post("/api/build")
def build_detector() -> dict:
    try:
        data = CONFIG["datasets"]
        return train_from_directories(ROOT / data["train_dir"], ROOT / data["validate_dir"],
                                      MODEL_DIR, CONFIG, ROOT / data["processed_dir"])
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/evaluate")
def evaluate_detector() -> dict:
    try:
        return evaluate_directory(ROOT / CONFIG["datasets"]["test_dir"], MODEL_DIR,
                                  ROOT / "reports" / "evaluation")
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/experiment")
async def experiment(file: UploadFile = File(...)) -> dict:
    if not file.filename or Path(file.filename).suffix.lower() not in {".log", ".txt"}:
        raise HTTPException(status_code=400, detail="Upload a supported raw log file (.log or .txt).")
    if not (MODEL_DIR / "model.json").is_file():
        raise HTTPException(status_code=409, detail="Build a statistical detector before running experiments.")
    with tempfile.TemporaryDirectory(prefix="aep-upload-") as folder:
        path = Path(folder) / Path(file.filename).name
        path.write_bytes(await file.read())
        try:
            return analyze_uploaded_log(path, MODEL_DIR)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/alerts")
def alerts(limit: int = 200) -> list[dict]:
    return _monitor().list_alerts(limit)


@app.get("/api/monitor/skipped-lines")
def skipped_lines(limit: int = 200) -> list[dict]:
    return _monitor().list_skipped_lines(limit)


@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: int) -> dict[str, bool]:
    if not _monitor().acknowledge(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found.")
    return {"acknowledged": True}


@app.post("/api/monitor/scan")
def scan_logs() -> dict[str, int]:
    try:
        return _monitor().scan_once()
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
