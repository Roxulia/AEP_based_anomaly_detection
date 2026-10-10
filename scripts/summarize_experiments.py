"""Create a ranked CSV from the build/evaluation history JSONL file."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def summarize(history_path: Path, output_path: Path, mode: str, metric: str) -> int:
    records: list[dict[str, Any]] = []
    if history_path.exists():
        with history_path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSON in {history_path} at line {line_number}") from exc

    builds: dict[tuple[str, str | None], dict[str, Any]] = {}
    evaluations: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
    for record in records:
        key = (record.get("model_dir", ""), record.get("model_created_at"))
        if record.get("type") == "build":
            builds[key] = record
        elif record.get("type") == "evaluation":
            evaluations.setdefault(key, []).append(record)

    rows: list[dict[str, Any]] = []
    for key, items in evaluations.items():
        build = builds.get(key, {})
        for evaluation in items:
            comparison = evaluation.get("result", {}).get("comparisons", {}).get(mode, {})
            score = comparison.get("metrics", {}).get(metric)
            rows.append({
                "rank_metric": score,
                "mode": mode,
                "metric": metric,
                "score": score,
                "model_dir": key[0],
                "model_created_at": key[1] or evaluation.get("model_created_at", ""),
                "evaluated_at": evaluation.get("timestamp", ""),
                "dataset": evaluation.get("dataset", ""),
                "parameters": json.dumps(build.get("parameters", evaluation.get("parameters", {})),
                                          ensure_ascii=False, sort_keys=True),
                "comparison": json.dumps(comparison, ensure_ascii=False, sort_keys=True),
            })

    available = [row for row in rows if isinstance(row["rank_metric"], (int, float))]
    unavailable = [row for row in rows if row not in available]
    available.sort(key=lambda row: row["rank_metric"], reverse=True)
    rows = available + unavailable
    output_path.parent.mkdir(parents=True, exist_ok=True)
    columns = ["rank_metric", "mode", "metric", "score", "model_dir", "model_created_at",
               "evaluated_at", "dataset", "parameters", "comparison"]
    with output_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", type=Path, default=Path("reports/experiment_history.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("reports/experiment_summary.csv"))
    parser.add_argument("--mode", choices=("aep", "density", "hybrid"), default="hybrid")
    parser.add_argument("--metric", default="f1",
                        help="metric from the evaluation report (for example f1, pr_auc, roc_auc)")
    args = parser.parse_args()
    count = summarize(args.history, args.output, args.mode, args.metric)
    print(f"wrote {count} evaluation rows to {args.output}")
    if count:
        print("For parameter selection, evaluate on a separate selection dataset; reserve the final Test set.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
