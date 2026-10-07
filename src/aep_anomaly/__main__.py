"""Command-line orchestration for the server-log pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path

from .log_parser import LogParser


def main() -> int:
    project_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Parse server logs into separate CSV files.")
    parser.add_argument(
        "--input-dir", type=Path, default=project_root / "Data" / "logs",
        help="Directory containing routes-*.log, controllers-*.log, and services-*.log files.",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=project_root / "Data" / "processed",
        help="Directory where routes.csv, controllers.csv, and services.csv are written.",
    )
    args = parser.parse_args()

    summaries = LogParser().parse_directory(args.input_dir, args.output_dir)
    for log_type, stats in summaries.items():
        print(
            f"{log_type}: files={stats.files}, parsed={stats.parsed_rows}, "
            f"malformed={stats.malformed_rows}, output={stats.output_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
