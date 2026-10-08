"""Command-line orchestration for the server-log pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .log_parser import LogParser
from .pipeline import detect_file, load_config, train_model


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
    train = commands.add_parser("train", help="Train and save a detector from preprocessed events.")
    train.add_argument("--input-csv", type=Path, required=True)
    train.add_argument("--model-dir", type=Path, default=project_root / "models" / "default")
    train.add_argument("--config", type=Path, default=project_root / "config" / "default.yaml")
    detect = commands.add_parser("detect", help="Score preprocessed events with a saved detector.")
    detect.add_argument("--input-csv", type=Path, required=True)
    detect.add_argument("--model-dir", type=Path, default=project_root / "models" / "default")
    detect.add_argument("--output", type=Path, default=project_root / "Data" / "processed" / "detections.jsonl")
    args = parser.parse_args(arguments)

    if args.command == "parse":
        summaries = LogParser().parse_directory(args.input_dir, args.output_dir)
        for log_type, stats in summaries.items():
            print(f"{log_type}: files={stats.files}, parsed={stats.parsed_rows}, "
                  f"malformed={stats.malformed_rows}, output={stats.output_path}")
    elif args.command == "train":
        summary = train_model(args.input_csv, args.model_dir, load_config(args.config))
        print(f"trained model: {summary['model_dir']} ({summary['training']} train, "
              f"{summary['validation']} validation, {summary['testing']} test windows)")
    else:
        count = detect_file(args.input_csv, args.model_dir, args.output)
        print(f"scored {count} windows: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
