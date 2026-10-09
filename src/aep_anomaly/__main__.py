"""Command-line orchestration for the server-log pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time

from .log_parser import LogParser
from .pipeline import (detect_file, evaluate_directory, load_config, prepare_log_directory,
                       train_from_directories, train_model)
from .curation import curate_event_csv
from .monitor import LogFolderMonitor


def main() -> int:
    project_root = Path(__file__).resolve().parents[2]
    arguments = sys.argv[1:]
    if not arguments or arguments[0].startswith("-"):
        arguments.insert(0, "parse")
    parser = argparse.ArgumentParser(description="Server-log AEP anomaly detection workflow.")
    commands = parser.add_subparsers(dest="command", required=True)
    parse = commands.add_parser("parse", help="Parse raw logs into CSV files.")
    parse.add_argument("--input-dir", type=Path, default=project_root / "Data" / "logs")
    parse.add_argument("--output-dir", type=Path, default=project_root / "Data" / "processed")
    curate = commands.add_parser("curate", help="Prepare logs and split allowlisted application routes from review routes.")
    curate.add_argument("--input-dir", type=Path, default=project_root / "Data" / "Train")
    curate.add_argument("--output-dir", type=Path, default=project_root / "Data" / "processed" / "Train")
    curate.add_argument("--config", type=Path, default=project_root / "config" / "default.yaml")
    train = commands.add_parser("train", help="Train and save a detector from preprocessed events.")
    train.add_argument("--input-csv", type=Path, required=True)
    train.add_argument("--model-dir", type=Path, default=project_root / "models" / "default")
    train.add_argument("--config", type=Path, default=project_root / "config" / "default.yaml")
    detect = commands.add_parser("detect", help="Score preprocessed events with a saved detector.")
    detect.add_argument("--input-csv", type=Path, required=True)
    detect.add_argument("--model-dir", type=Path, default=project_root / "models" / "default")
    detect.add_argument("--output", type=Path, default=project_root / "Data" / "processed" / "detections.jsonl")
    build = commands.add_parser("build", help="Fit a statistical detector from Train and Validate folders.")
    build.add_argument("--config", type=Path, default=project_root / "config" / "default.yaml")
    build.add_argument("--train-dir", type=Path)
    build.add_argument("--validate-dir", type=Path)
    build.add_argument("--model-dir", type=Path, default=project_root / "models" / "default")
    build.add_argument("--work-dir", type=Path)
    evaluate = commands.add_parser("evaluate", help="Evaluate a saved detector on a separate Test folder.")
    evaluate.add_argument("--config", type=Path, default=project_root / "config" / "default.yaml")
    evaluate.add_argument("--test-dir", type=Path)
    evaluate.add_argument("--model-dir", type=Path, default=project_root / "models" / "default")
    evaluate.add_argument("--output-dir", type=Path, default=project_root / "reports" / "evaluation")
    evaluate.add_argument("--work-dir", type=Path)
    serve = commands.add_parser("serve", help="Run the local dashboard API.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    monitor = commands.add_parser("monitor", help="Poll a watched folder and persist dashboard alerts.")
    monitor.add_argument("--watch-dir", type=Path, default=project_root / "Data" / "live")
    monitor.add_argument("--model-dir", type=Path, default=project_root / "models" / "default")
    monitor.add_argument("--database", type=Path, default=project_root / "Data" / "alerts.sqlite3")
    monitor.add_argument("--interval", type=float, default=5.0)
    monitor.add_argument("--config", type=Path, default=project_root / "config" / "default.yaml")
    args = parser.parse_args(arguments)

    if args.command == "parse":
        summaries = LogParser().parse_directory(args.input_dir, args.output_dir)
        for log_type, stats in summaries.items():
            print(f"{log_type}: files={stats.files}, parsed={stats.parsed_rows}, "
                  f"malformed={stats.malformed_rows}, output={stats.output_path}")
    elif args.command == "curate":
        config = load_config(args.config)
        prepared = prepare_log_directory(args.input_dir, args.output_dir)
        result = curate_event_csv(prepared["event_csv"], args.output_dir / "curated",
                                  config.get("curation", {}))
        counts = result.get("counts", {})
        print(f"curated {sum(counts.values())} events: {counts}; manifest: {result.get('manifest_path')}")
    elif args.command == "train":
        summary = train_model(args.input_csv, args.model_dir, load_config(args.config))
        print(f"trained model: {summary['model_dir']} ({summary['training']} train, "
              f"{summary['validation']} validation, {summary['testing']} test windows)")
    elif args.command == "build":
        config = load_config(args.config)
        datasets = config["datasets"]
        summary = train_from_directories(args.train_dir or datasets["train_dir"],
                                         args.validate_dir or datasets["validate_dir"],
                                         args.model_dir, config,
                                         args.work_dir or Path(datasets["processed_dir"]))
        print(f"saved statistical detector: {summary['model_dir']} ({summary['training']} train, "
              f"{summary['validation']} validation windows)")
    elif args.command == "evaluate":
        config = load_config(args.config)
        test_dir = args.test_dir or config["datasets"]["test_dir"]
        report = evaluate_directory(test_dir, args.model_dir, args.output_dir, args.work_dir)
        print(f"evaluated {report['window_count']} test windows; report: {args.output_dir / 'evaluation.json'}")
    elif args.command == "serve":
        import uvicorn
        uvicorn.run("src.aep_anomaly.api:app", host=args.host, port=args.port, reload=False)
    elif args.command == "monitor":
        if args.interval <= 0:
            parser.error("--interval must be greater than zero")
        service = LogFolderMonitor(args.watch_dir, args.model_dir, args.database,
                                   load_config(args.config)["window"])
        while True:
            try:
                print(service.scan_once())
            except (OSError, ValueError) as error:
                print(f"monitor scan failed: {error}", file=sys.stderr)
            time.sleep(args.interval)
    else:
        count = detect_file(args.input_csv, args.model_dir, args.output)
        print(f"scored {count} windows: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
