"""Train, persist, and run the configured AEP/Markov/density detector."""

from __future__ import annotations

import json
import csv
import os
import tempfile
import pickle
from datetime import datetime, timezone
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from .aep import AEPDetector
from .density import InformationScoreDensity
from .event_encoder import EventEncoder, STATE_ENCODING_VERSION
from .curation import (curate_event_csv, exclude_event_csv,
                       is_allowlisted_application_route)
from .independent import IndependentMarginalModel
from .markov import MarkovModel
from .route_preprocessor import ensure_state_ids_csv
from .windowing import EventWindow, load_windows


DEFAULT_CONFIG: dict[str, Any] = {
    "datasets": {
        "train_dir": "Data/Train",
        "validate_dir": "Data/Validate",
        "test_dir": "Data/Test",
        "processed_dir": "Data/processed",
    },
    "curation": {
        "enabled": True,
        "session_control": False,
        "exclude_paths": ["/api/app/compatibility"],
        "exclude_route_names": [],
        "application_routes": [
            {"method": "GET", "path": "/"},
            {"method": "GET", "path": "/api/app/compatibility"},
            {"method": "GET", "path": "/api/tenant/resolve-tenant"},
            {"method": "GET", "path": "/api/tenant/me"},
            {"method": "POST", "path": "/api/tenant/login/subdomain-spa"},
        ],
        "application_route_names": ["admin.login.show", "admin.login.submit"],
    },
    "window": {"type": "ip_session", "size": 50, "include_partial": True,
                "timeout_seconds": 60, "min_events": 1, "missing_ip": "unknown"},
    "state": {"fields": ["url_group", "status_category"]},
    "split": {"training": 0.65, "validation": 0.15, "testing": 0.20},
    "markov": {"enabled": True, "smoothing": 0.5},
    "aep": {"quantile": 0.99},
    "density": {"bandwidth": "scott", "epsilon": 1e-12, "quantile": 0.99},
    "detector": {"mode": "hybrid"},
    "evaluation": {"counting_unit": "session"},
}


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    if path is None:
        return config
    with Path(path).open("r", encoding="utf-8") as stream:
        overrides = yaml.safe_load(stream) or {}
    if not isinstance(overrides, dict):
        raise ValueError("configuration root must be a mapping")
    for section, values in overrides.items():
        if section not in config or not isinstance(values, dict):
            raise ValueError(f"unknown or invalid configuration section: {section}")
        config[section].update(values)
    _validate_config(config)
    return config


def _validate_config(config: dict[str, Any]) -> None:
    if not isinstance(config.get("curation", {}).get("session_control", False), bool):
        raise ValueError("curation.session_control must be true or false")
    fields = config.get("state", {}).get("fields")
    valid_fields = EventEncoder.VALID_FIELDS
    if not isinstance(fields, list) or not fields or len(set(fields)) != len(fields) or any(
            field not in valid_fields for field in fields):
        raise ValueError(f"state.fields must be a non-empty unique list chosen from {valid_fields}")
    window = config["window"]
    if window["type"] not in {"ip_session", "fixed_count", "fixed_time"} or int(window["size"]) <= 0:
        raise ValueError("window type must be ip_session/fixed_count/fixed_time and size must be positive")
    if float(window.get("timeout_seconds", 60)) <= 0 or int(window.get("min_events", 1)) <= 0:
        raise ValueError("session timeout and minimum event count must be positive")
    if not str(window.get("missing_ip", "unknown")).strip():
        raise ValueError("missing_ip group must not be empty")
    if config["detector"]["mode"] not in {"aep", "density", "hybrid"}:
        raise ValueError("detector mode must be aep, density, or hybrid")
    markov = config.get("markov", {})
    if not isinstance(markov.get("enabled", True), bool):
        raise ValueError("markov.enabled must be true or false")
    if float(markov.get("smoothing", 0.5)) <= 0:
        raise ValueError("markov.smoothing must be greater than zero")
    if not markov.get("enabled", True) and not {"url_group", "status_category"}.issubset(fields):
        raise ValueError("independent request scoring requires url_group and status_category fields")
    if config.get("evaluation", {}).get("counting_unit", "session") not in {"session", "request"}:
        raise ValueError("evaluation.counting_unit must be 'session' or 'request'")


def _scores(model: MarkovModel, windows: tuple[EventWindow, ...] | list[EventWindow]) -> list[float]:
    return [model.score_sequence(window.states).information_score for window in windows]


def _normal_partition_csv(event_csv: str | Path, output_dir: str | Path,
                          curation_settings: dict[str, Any],
                          window_settings: dict[str, Any] | None = None) -> tuple[Path, dict[str, Any]]:
    """Apply explicit exclusions and the same request allowlist to a partition."""
    destination = Path(output_dir)
    settings = dict(curation_settings)
    settings.setdefault("exclude_paths", DEFAULT_CONFIG["curation"]["exclude_paths"])
    settings.setdefault("exclude_route_names", [])
    if window_settings:
        settings.setdefault("session_timeout_seconds", window_settings.get("timeout_seconds", 60))
        settings.setdefault("missing_ip", window_settings.get("missing_ip", "unknown"))
    filtered_path = destination / "scoring_route_events.csv"
    excluded = exclude_event_csv(event_csv, filtered_path, settings)
    details: dict[str, Any] = {"excluded": excluded}
    if settings.get("enabled", False):
        curated = curate_event_csv(filtered_path, destination / "curated", settings)
        details["curation"] = curated
        return Path(curated["outputs"]["normal"]), details
    return filtered_path, details


def _label_value(window: EventWindow) -> bool | None:
    """Return an upload-window label only when every request has one."""
    values = []
    for event in window.events:
        raw = next((event[key] for key in ("is_anomaly", "label", "ground_truth")
                    if event.get(key, "") != ""), None)
        if raw is None:
            return None
        values.append(str(raw).strip().lower() in {"1", "true", "yes", "anomaly", "abnormal"})
    return any(values) if values else None


def _binary_metrics(labels: list[bool], scores: list[float], decisions: list[bool]) -> dict[str, Any]:
    """Keep optional label metrics for ad hoc uploaded-log experiments."""
    tp = sum(y and p for y, p in zip(labels, decisions))
    tn = sum((not y) and (not p) for y, p in zip(labels, decisions))
    fp = sum((not y) and p for y, p in zip(labels, decisions))
    fn = sum(y and (not p) for y, p in zip(labels, decisions))
    positives, negatives = tp + fn, tn + fp
    anomaly_catch_rate = tp / positives if positives else 0.0
    false_alarm_rate = fp / negatives if negatives else None
    ranked = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    auc = None
    if positives and negatives:
        concordant = sum(1.0 if ps > ns else 0.5 if ps == ns else 0.0
                         for ps, pl in ranked for ns, nl in ranked if pl and not nl)
        auc = concordant / (positives * negatives)
    pr_auc = None
    if positives:
        seen_pos = 0
        precision_sum = 0.0
        for index, (_, label) in enumerate(ranked, start=1):
            if label:
                seen_pos += 1
                precision_sum += seen_pos / index
        pr_auc = precision_sum / positives
    return {
        "available": True, "windows": len(labels), "true_positive": tp, "true_negative": tn,
        "false_positive": fp, "false_negative": fn,
        "total_anomalies": positives,
        "anomaly_catch_rate": anomaly_catch_rate,
        "false_alarms": fp,
        "false_alarm_rate": false_alarm_rate,
        "final_score": tp / (positives + fp) if positives + fp else 0.0,
        "final_score_formula": "true_positive / (total_anomalies + false_alarms)",
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / positives if positives else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
        "false_positive_rate": fp / negatives if negatives else None,
        "false_negative_rate": fn / positives if positives else None,
        "roc_auc": auc, "pr_auc": pr_auc,
    }


def _record_experiment(record: dict[str, Any]) -> None:
    """Append one reproducible build or evaluation record to the shared history."""
    path = Path(os.environ.get("AEP_EXPERIMENT_LOG", "reports/experiment_history.jsonl"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _split_event_csv(event_csv: str | Path, output_dir: str | Path,
                     training_ratio: float, validation_ratio: float,
                     testing_ratio: float) -> tuple[Path, Path, Path]:
    """Split preprocessed events chronologically before training-only curation/windowing."""
    ratios = (float(training_ratio), float(validation_ratio), float(testing_ratio))
    if any(value <= 0 for value in ratios) or abs(sum(ratios) - 1.0) > 1e-9:
        raise ValueError("split ratios must be positive and sum to 1")

    with Path(event_csv).open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = list(reader.fieldnames or ())
        if not fields:
            raise ValueError(f"event CSV has no header: {event_csv}")
        records: list[tuple[datetime, int, dict[str, str]]] = []
        for row_number, row in enumerate(reader):
            raw_timestamp = (row.get("timestamp") or "").strip()
            try:
                timestamp = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"invalid timestamp at CSV row {row_number + 2}: {raw_timestamp!r}") from exc
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            records.append((timestamp.astimezone(timezone.utc), row_number, row))

    records.sort(key=lambda item: (item[0], item[1]))
    count = len(records)
    training_end = int(count * ratios[0])
    validation_end = training_end + int(count * ratios[1])
    if training_end < 1 or validation_end <= training_end or validation_end >= count:
        raise ValueError("not enough events for non-empty training, validation, and testing splits")

    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    boundaries = (0, training_end, validation_end, count)
    outputs = tuple(output_root / f"{name}_events.csv" for name in ("training", "validation", "testing"))
    for index, output in enumerate(outputs):
        with output.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(record[2] for record in records[boundaries[index]:boundaries[index + 1]])
    return outputs


def _load_state_catalog(event_csv: str | Path,
                       allowed_ids: set[str] | None = None) -> dict[str, dict[str, str]]:
    """Read the preprocessing-owned descriptions without interpreting state IDs."""
    catalog: dict[str, dict[str, str]] = {}
    with Path(event_csv).open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            state_id = row.get("state_id", "")
            raw_description = row.get("state_description", "{}") or "{}"
            try:
                description = json.loads(raw_description)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid state description for state ID {state_id!r}") from exc
            if not isinstance(description, dict):
                raise ValueError(f"state description must be an object for state ID {state_id!r}")
            if state_id and (allowed_ids is None or state_id in allowed_ids):
                normalized = {str(key): str(value) for key, value in description.items()}
                prior = catalog.setdefault(state_id, normalized)
                if prior != normalized:
                    raise ValueError(f"state ID collision has inconsistent descriptions: {state_id}")
    return catalog


def prepare_log_directory(input_dir: str | Path, output_dir: str | Path,
                          state_fields: list[str] | tuple[str, ...] | None = None) -> dict[str, Any]:
    """Parse supported raw logs and preprocess route requests into event CSV."""
    from .log_parser import LogParser
    from .route_preprocessor import RoutePreprocessor

    parsed = LogParser().parse_directory(input_dir, output_dir)
    event_csv = Path(output_dir) / "route_events.csv"
    summary = RoutePreprocessor(EventEncoder(fields=state_fields)).process_csv(
        Path(output_dir) / "routes.csv", event_csv)
    return {
        "parsed": {name: {"files": item.files, "parsed_rows": item.parsed_rows,
                          "malformed_rows": item.malformed_rows}
                   for name, item in parsed.items()},
        "preprocessed": {"input_rows": summary.input_rows, "processed_rows": summary.processed_rows,
                         "skipped_rows": summary.skipped_rows,
                         "skipped_by_reason": summary.skipped_by_reason,
                         "missing_ip_rows": summary.missing_ip_rows},
        "event_csv": str(event_csv),
    }


def train_from_directories(train_dir: str | Path, validate_dir: str | Path,
                           model_dir: str | Path, config: dict[str, Any] | None = None,
                           work_dir: str | Path | None = None) -> dict[str, Any]:
    """Fit on Train and calibrate thresholds on Validate, without splitting either."""
    settings = config or load_config()
    _validate_config(settings)
    train_root, validate_root = Path(train_dir), Path(validate_dir)
    if not train_root.is_dir():
        raise NotADirectoryError(f"Training log directory does not exist: {train_root}")
    if not validate_root.is_dir():
        raise NotADirectoryError(f"Validation log directory does not exist: {validate_root}")
    scratch = Path(work_dir) if work_dir else Path(model_dir).parent / "prepared"
    state_fields = settings["state"]["fields"]
    train_data = prepare_log_directory(train_root, scratch / "Train", state_fields)
    validation_data = prepare_log_directory(validate_root, scratch / "Validate", state_fields)
    curation_settings = settings.get("curation", {"enabled": False})
    curation_settings.setdefault("exclude_paths", DEFAULT_CONFIG["curation"]["exclude_paths"])
    curation_settings.setdefault("exclude_route_names", [])
    for name, dataset in (("Train", train_data), ("Validate", validation_data)):
        normal_csv, filtering = _normal_partition_csv(
            dataset["event_csv"], scratch / name / "filtered", curation_settings,
            settings["window"])
        dataset["event_csv"] = str(normal_csv)
        excluded = filtering["excluded"]
        dataset["preprocessed"]["processed_rows"] = excluded["processed_rows"]
        dataset["preprocessed"]["skipped_rows"] += excluded["skipped_rows"]
        dataset["preprocessed"]["skipped_by_reason"].update(excluded["skipped_by_reason"])
        if "curation" in filtering:
            dataset["curation"] = filtering["curation"]
            review_count = filtering["curation"].get("counts", {}).get("review", 0)
            dataset["preprocessed"]["skipped_rows"] += review_count
            if review_count:
                decisions_path = filtering["curation"].get("decisions_csv")
                if decisions_path:
                    with Path(decisions_path).open("r", encoding="utf-8-sig", newline="") as stream:
                        reasons = Counter(row["reason"] for row in csv.DictReader(stream)
                                          if row["classification"] == "review")
                    dataset["preprocessed"]["skipped_by_reason"].update(reasons)
    train_windows = load_windows(train_data["event_csv"], **settings["window"])
    validation_windows = load_windows(validation_data["event_csv"], **settings["window"])
    if not train_windows or not validation_windows:
        raise ValueError("Train and Validate must each contain enough valid requests to form windows")

    use_markov = bool(settings["markov"].get("enabled", True))
    if use_markov:
        model: MarkovModel | IndependentMarginalModel = MarkovModel(
            smoothing=float(settings["markov"]["smoothing"])
        ).fit(window.states for window in train_windows)
        entropy_reference = model.entropy_rate_bits
        train_scores = _scores(model, train_windows)
        validation_scores = [model.score_sequence(window.states).information_score
                             for window in validation_windows]
        unscorable_validation = 0
    else:
        model = IndependentMarginalModel(smoothing=float(settings["markov"]["smoothing"])).fit(
            window.events for window in train_windows
        )
        entropy_reference = model.entropy_bits_per_request
        train_scores = [model.score_events(window.events).information_score
                        for window in train_windows]
        validation_scores = [model.score_events(window.events).information_score
                             for window in validation_windows]
        unscorable_validation = 0
    if not validation_scores:
        raise ValueError("Validate has no scorable sessions")
    aep = AEPDetector(quantile=float(settings["aep"]["quantile"]))
    aep_threshold = aep.fit_threshold(validation_scores, entropy_reference)
    density = InformationScoreDensity(**settings["density"]).fit(train_scores)
    density_threshold = density.fit_threshold(validation_scores)
    destination = Path(model_dir)
    destination.mkdir(parents=True, exist_ok=True)
    model_doc = {
        "schema_version": 3,
        "state_encoding": {"version": STATE_ENCODING_VERSION,
                           "id_format": "sha256-canonical-state-description",
                           "catalog_fields": state_fields},
        "unknown_state_policy": (
            "map_to_reserved_unk_and_report_novelty" if use_markov else
            "map_unseen_url_and_status_marginals_independently_to_reserved_unk"
        ),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "description": ("Fitted statistical anomaly detector (Markov, AEP, information-score KDE)"
                        if use_markov else
                        "Fitted independent URL/status marginal detector (AEP, information-score KDE)"),
        "model_type": "markov" if use_markov else "independent_marginals",
        "config": settings,
        "markov": model.to_dict() if use_markov else None,
        "independent_marginals": model.to_dict() if not use_markov else None,
        "entropy_reference_bits": entropy_reference,
        "state_catalog": (_load_state_catalog(train_data["event_csv"])
                          if use_markov else {}),
        "state_ids": list(model.states) if use_markov else [],
        "aep_threshold": aep_threshold,
        "density_threshold": density_threshold,
        "dataset_folders": {"train": str(train_root), "validate": str(validate_root)},
        "window_counts": {"training": len(train_windows), "validation": len(validation_windows),
                          "validation_unscorable": unscorable_validation},
    }
    (destination / "model.json").write_text(json.dumps(model_doc, indent=2), encoding="utf-8")
    with (destination / "density.pkl").open("wb") as stream:
        pickle.dump(density, stream, protocol=pickle.HIGHEST_PROTOCOL)
    summary = {"model_dir": str(destination), **model_doc["window_counts"],
               "training_data": train_data, "validation_data": validation_data}
    _record_experiment({"type": "build", "timestamp": model_doc["created_at"],
                        "model_created_at": model_doc["created_at"],
                        "model_dir": str(destination.resolve()), "parameters": settings,
                        "result": {key: value for key, value in summary.items()
                                   if key not in {"training_data", "validation_data"}}})
    return summary


def evaluate_event_csv(event_csv: str | Path, model_dir: str | Path,
                       output_dir: str | Path) -> dict[str, Any]:
    """Evaluate original held-out sessions using allowlist violations as labels."""
    detector = TrainedDetector(model_dir)
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    prepared_csv = ensure_state_ids_csv(event_csv, output_root / "prepared" / "state_events.csv",
                                        detector.metadata["config"]["state"]["fields"])
    config = detector.metadata["config"]
    # Keep all Test events so allowlist violations remain visible and can be
    # used as evaluation labels. Curation applies to fitting/calibration only.
    windows = load_windows(prepared_csv, **config["window"])
    if not windows:
        raise ValueError("no Test sessions are available for evaluation")
    curation = config.get("curation", {})
    counting_unit = config.get("evaluation", {}).get("counting_unit", "session")
    results: dict[str, Any] = {}
    for mode in ("aep", "density", "hybrid"):
        rows: list[dict[str, Any]] = []
        session_labels: list[bool] = []
        session_scores: list[float] = []
        session_decisions: list[bool] = []
        request_labels: list[bool] = []
        request_scores: list[float] = []
        request_decisions: list[bool] = []
        unallowlisted_requests = 0
        for window in windows:
            row = detector.score(window, mode=mode)
            request_is_unallowlisted = [
                not is_allowlisted_application_route(event, curation)
                for event in window.events
            ]
            invalid_count = sum(request_is_unallowlisted)
            session_label = invalid_count > 0
            row.update({
                "evaluation_label": "unallowlisted_route" if session_label else "allowlisted_only",
                "session_contains_unallowlisted_route": session_label,
                "unallowlisted_request_count": invalid_count,
            })
            rows.append(row)
            session_labels.append(session_label)
            session_decisions.append(bool(row["final_anomalous"]))
            session_scores.append(float(row["aep_deviation"] if mode == "aep" else
                                         row["density_score"] if mode == "density" else
                                         max(row["aep_deviation"] / max(row["aep_threshold"], 1e-12),
                                             row["density_score"] / max(row["density_threshold"], 1e-12))))
            unallowlisted_requests += invalid_count
            request_labels.extend(request_is_unallowlisted)
            request_scores.extend([session_scores[-1]] * len(request_is_unallowlisted))
            request_decisions.extend([session_decisions[-1]] * len(request_is_unallowlisted))
        labels, scores, decisions = (session_labels, session_scores, session_decisions)
        if counting_unit == "request":
            labels, scores, decisions = request_labels, request_scores, request_decisions
        metrics = _binary_metrics(labels, scores, decisions)
        alerted_sessions = sum(session_decisions)
        results[mode] = {
            "counting_unit": counting_unit,
            "sessions": len(windows),
            "sessions_with_unallowlisted_routes": sum(session_labels),
            "unallowlisted_requests": unallowlisted_requests,
            "alerted_sessions": alerted_sessions,
            "session_alert_rate": alerted_sessions / len(windows) if windows else None,
            "positive_units": sum(labels),
            "detected_positive_units": sum(label and decision for label, decision in zip(labels, decisions)),
            "metrics": metrics,
        }
        with (output_root / f"{mode}.jsonl").open("w", encoding="utf-8") as stream:
            stream.writelines(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    report = {"detector_description": detector.metadata.get("description", "Statistical anomaly detector"),
              "model_type": detector.model_type,
              "model_dir": str(Path(model_dir).resolve()),
              "model_created_at": detector.metadata.get("created_at"),
              "test_event_csv": str(prepared_csv), "control_session_count": len(windows),
              "window_count": len(windows),
              "sequence_settings": config["window"],
              "evaluation_method": "held-out Test sessions labeled by exact application route allowlist",
              "evaluation_counting_unit": counting_unit,
              "allowlist": curation,
              "comparisons": results}
    (output_root / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _record_experiment({"type": "evaluation", "timestamp": datetime.now(timezone.utc).isoformat(),
                        "model_dir": str(Path(model_dir).resolve()),
                        "model_created_at": detector.metadata.get("created_at"),
                        "dataset": str(Path(event_csv).resolve()),
                        "parameters": config, "result": report})
    return report


def evaluate_directory(test_dir: str | Path, model_dir: str | Path,
                       output_dir: str | Path, work_dir: str | Path | None = None) -> dict[str, Any]:
    test_root = Path(test_dir)
    if not test_root.is_dir():
        raise NotADirectoryError(f"Test log directory does not exist: {test_root}")
    scratch = Path(work_dir) if work_dir else Path(output_dir) / "prepared"
    detector = TrainedDetector(model_dir)
    prepared = prepare_log_directory(test_root, scratch, detector.metadata["config"]["state"]["fields"])
    report = evaluate_event_csv(prepared["event_csv"], model_dir, output_dir)
    prepared["event_csv"] = report["test_event_csv"]
    with Path(prepared["event_csv"]).open("r", encoding="utf-8-sig", newline="") as stream:
        prepared["preprocessed"]["processed_rows"] = sum(1 for _ in csv.DictReader(stream))
    filtering = report.get("filtering", {})
    excluded = filtering.get("excluded", {})
    prepared["preprocessed"]["skipped_rows"] += excluded.get("skipped_rows", 0)
    prepared["preprocessed"]["skipped_by_reason"].update(excluded.get("skipped_by_reason", {}))
    curation = filtering.get("curation", {})
    if curation:
        review_count = curation.get("counts", {}).get("review", 0)
        prepared["preprocessed"]["skipped_rows"] += review_count
        if review_count:
            skipped = prepared["preprocessed"]["skipped_by_reason"]
            skipped["endpoint_not_in_application_allowlist"] = review_count
    report["test_data"] = prepared
    (Path(output_dir) / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def analyze_uploaded_log(uploaded_path: str | Path, model_dir: str | Path) -> dict[str, Any]:
    """Analyze one supported raw request log file using a saved detector bundle."""
    from .log_parser import LogParser
    from .route_preprocessor import RoutePreprocessor
    source = Path(uploaded_path)
    if not source.is_file():
        raise FileNotFoundError(f"Uploaded log file does not exist: {source}")
    with tempfile.TemporaryDirectory(prefix="aep-experiment-") as temporary:
        root = Path(temporary)
        named = root / "routes-upload.log"
        named.write_bytes(source.read_bytes())
        parsed = LogParser().parse_directory(root, root / "parsed")
        event_csv = root / "parsed" / "route_events.csv"
        detector = TrainedDetector(model_dir)
        prepared = RoutePreprocessor(EventEncoder(fields=detector.metadata["config"]["state"]["fields"])).process_csv(
            root / "parsed" / "routes.csv", event_csv)
        curation = detector.metadata.get("config", {}).get("curation", {})
        curation.setdefault("exclude_paths", DEFAULT_CONFIG["curation"]["exclude_paths"])
        excluded = exclude_event_csv(event_csv, root / "parsed" / "scoring_route_events.csv", curation)
        event_csv = root / "parsed" / "scoring_route_events.csv"
        windows = load_windows(event_csv, **detector.metadata["config"]["window"])
        modes = ("aep", "density", "hybrid")
        results_by_mode: dict[str, list[dict[str, Any]]] = {mode: [] for mode in modes}
        for mode in modes:
            for window in windows:
                try:
                    results_by_mode[mode].append(detector.score(window, mode=mode))
                except ValueError as exc:
                    if "not observed during fit" not in str(exc):
                        raise
                    results_by_mode[mode].append({
                        "window_id": window.window_id, "start_time": window.start_time,
                        "end_time": window.end_time, "event_count": len(window.events),
                        "client_ip": window.client_ip, "events": list(window.events),
                        "state_descriptions": list(window.state_descriptions),
                        "scorable": False, "final_anomalous": None,
                        "anomaly_reasons": [], "unscorable_reason": str(exc),
                    })
        comparisons: dict[str, dict[str, Any]] = {}
        labels = [_label_value(window) for window in windows]
        for mode, rows in results_by_mode.items():
            scorable = [(label, row) for label, row in zip(labels, rows)
                        if label is not None and row.get("scorable", True)]
            if scorable:
                metric_scores = []
                for _, row in scorable:
                    if mode == "density":
                        metric_scores.append(row["density_score"])
                    elif mode == "aep":
                        metric_scores.append(row["aep_deviation"])
                    else:
                        metric_scores.append(max(
                            row["aep_deviation"] / max(detector.aep.threshold or 0.0, 1e-12),
                            row["density_score"] / max(detector.density.threshold or 0.0, 1e-12),
                        ))
                metrics = _binary_metrics(
                    [item[0] for item in scorable], metric_scores,
                    [bool(item[1]["final_anomalous"]) for item in scorable],
                )
            else:
                metrics = {"available": False,
                           "reason": "No usable ground-truth labels in uploaded log windows."}
            comparisons[mode] = {
                "windows": len(rows),
                "scorable_windows": sum(row.get("scorable", True) for row in rows),
                "unscorable_windows": sum(not row.get("scorable", True) for row in rows),
                "anomalous_windows": sum(row.get("final_anomalous") is True for row in rows),
                "metrics": metrics,
            }
        anomalies_by_mode = {
            mode: [{
                "window_id": row["window_id"],
                "start_time": row.get("start_time"),
                "end_time": row.get("end_time"),
                "client_ip": row.get("client_ip"),
                "event_count": row.get("event_count", len(row.get("events", []))),
                "information_score": row.get("information_score"),
                "entropy_rate": row.get("entropy_rate"),
                "aep_deviation": row.get("aep_deviation"),
                "density_score": row.get("density_score"),
                "anomaly_reasons": row.get("anomaly_reasons", []),
                "activities": row.get("events", []),
            } for row in rows if row.get("final_anomalous") is True]
            for mode, rows in results_by_mode.items()
        }
        selected_mode = detector.mode
        return {"filename": source.name,
                "detector_mode": selected_mode,
                "parse": {name: {"files": stat.files, "parsed_rows": stat.parsed_rows,
                                 "malformed_rows": stat.malformed_rows}
                          for name, stat in parsed.items()},
                "preprocessing": {"input_rows": prepared.input_rows,
                                  "processed_rows": excluded["processed_rows"],
                                  "skipped_rows": prepared.skipped_rows + excluded["skipped_rows"],
                                  "skipped_by_reason": {**prepared.skipped_by_reason,
                                      **excluded["skipped_by_reason"]},
                                  "missing_ip_rows": prepared.missing_ip_rows},
                "window_count": len(windows), "comparisons": comparisons,
                "results_by_mode": results_by_mode, "anomalies_by_mode": anomalies_by_mode,
                "windows": results_by_mode[selected_mode]}


def train_model(event_csv: str | Path, model_dir: str | Path,
                config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Chronologically split events, curate Train and Validate, then fit artifacts."""
    settings = config or load_config()
    _validate_config(settings)
    state_csv = ensure_state_ids_csv(event_csv, Path(model_dir).parent / "prepared" / "training_state_events.csv",
                                     settings["state"]["fields"])
    split_settings = settings["split"]
    partitions = _split_event_csv(
        state_csv,
        Path(model_dir).parent / "prepared" / "event_partitions",
        split_settings["training"], split_settings["validation"], split_settings["testing"],
    )
    train_csv, validation_csv, testing_csv = partitions
    prep_root = Path(model_dir).parent / "prepared"
    curation_settings = settings.get("curation", {"enabled": False})
    train_csv, _ = _normal_partition_csv(train_csv, prep_root / "training", curation_settings,
                                         settings["window"])
    validation_csv, _ = _normal_partition_csv(validation_csv, prep_root / "validation", curation_settings,
                                              settings["window"])
    training_windows = load_windows(train_csv, **settings["window"])
    validation_windows = load_windows(validation_csv, **settings["window"])
    testing_windows = load_windows(testing_csv, **settings["window"])
    if not training_windows or not validation_windows or not testing_windows:
        raise ValueError("Train, Validate, and Test must each contain enough valid requests to form windows")
    use_markov = bool(settings["markov"].get("enabled", True))
    if use_markov:
        model: MarkovModel | IndependentMarginalModel = MarkovModel(
            smoothing=float(settings["markov"]["smoothing"])
        ).fit(window.states for window in training_windows)
        entropy_reference = model.entropy_rate_bits
        train_scores = _scores(model, training_windows)
        validation_scores = _scores(model, validation_windows)
    else:
        model = IndependentMarginalModel(smoothing=float(settings["markov"]["smoothing"])).fit(
            window.events for window in training_windows
        )
        entropy_reference = model.entropy_bits_per_request
        train_scores = [model.score_events(window.events).information_score
                        for window in training_windows]
        validation_scores = [model.score_events(window.events).information_score
                             for window in validation_windows]
    aep = AEPDetector(quantile=float(settings["aep"]["quantile"]))
    aep_threshold = aep.fit_threshold(validation_scores, entropy_reference)
    density = InformationScoreDensity(**settings["density"]).fit(train_scores)
    density_threshold = density.fit_threshold(validation_scores)
    destination = Path(model_dir)
    destination.mkdir(parents=True, exist_ok=True)
    model_doc = {
        "schema_version": 3,
        "state_encoding": {"version": STATE_ENCODING_VERSION,
                           "id_format": "sha256-canonical-state-description",
                           "catalog_fields": settings["state"]["fields"]},
        "unknown_state_policy": (
            "map_to_reserved_unk_and_report_novelty" if use_markov else
            "map_unseen_url_and_status_marginals_independently_to_reserved_unk"
        ),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model_type": "markov" if use_markov else "independent_marginals",
        "description": ("Fitted statistical anomaly detector (Markov, AEP, information-score KDE)"
                        if use_markov else
                        "Fitted independent URL/status marginal detector (AEP, information-score KDE)"),
        "config": settings,
        "markov": model.to_dict() if use_markov else None,
        "independent_marginals": model.to_dict() if not use_markov else None,
        "entropy_reference_bits": entropy_reference,
        "state_catalog": (_load_state_catalog(train_csv, set(model.states))
                          if use_markov else {}),
        "state_ids": list(model.states) if use_markov else [],
        "aep_threshold": aep_threshold,
        "density_threshold": density_threshold,
        "split_windows": {"training": len(training_windows), "validation": len(validation_windows),
                          "testing": len(testing_windows)},
    }
    (destination / "model.json").write_text(json.dumps(model_doc, indent=2), encoding="utf-8")
    with (destination / "density.pkl").open("wb") as stream:
        pickle.dump(density, stream, protocol=pickle.HIGHEST_PROTOCOL)
    summary = {"model_dir": str(destination),
               "windows": len(training_windows) + len(validation_windows) + len(testing_windows),
               **model_doc["split_windows"]}
    _record_experiment({"type": "build", "timestamp": model_doc["created_at"],
                        "model_created_at": model_doc["created_at"],
                        "model_dir": str(destination.resolve()), "parameters": settings,
                        "result": summary})
    return summary


class TrainedDetector:
    """Loaded model bundle that returns explainable per-window results."""

    def __init__(self, model_dir: str | Path) -> None:
        root = Path(model_dir)
        self.metadata = json.loads((root / "model.json").read_text(encoding="utf-8"))
        if self.metadata.get("schema_version") != 3:
            raise ValueError("unsupported model bundle schema version")
        if self.metadata.get("state_encoding", {}).get("version") != STATE_ENCODING_VERSION:
            raise ValueError("model uses a different state encoding; rebuild it with the current pipeline")
        self.metadata.setdefault("config", {}).setdefault(
            "state", {"fields": self.metadata.get("state_encoding", {}).get(
                "catalog_fields", list(EventEncoder.DEFAULT_FIELDS))})
        self.model_type = self.metadata.get("model_type", "markov")
        if self.model_type == "markov":
            self.model: MarkovModel | IndependentMarginalModel = MarkovModel.from_dict(
                self.metadata["markov"])
            self.entropy_reference_bits = self.model.entropy_rate_bits
        elif self.model_type == "independent_marginals":
            payload = self.metadata.get("independent_marginals")
            if not isinstance(payload, dict):
                raise ValueError("independent marginal model bundle is missing its probability tables")
            self.model = IndependentMarginalModel.from_dict(payload)
            self.entropy_reference_bits = self.model.entropy_bits_per_request
        else:
            raise ValueError(f"unsupported probability model type: {self.model_type}")
        with (root / "density.pkl").open("rb") as stream:
            self.density: InformationScoreDensity = pickle.load(stream)
        self.aep = AEPDetector(quantile=self.metadata["config"]["aep"]["quantile"])
        self.aep.threshold = float(self.metadata["aep_threshold"])
        self.density.threshold = float(self.metadata["density_threshold"])
        self.mode = self.metadata["config"]["detector"]["mode"]

    def score(self, window: EventWindow, mode: str | None = None) -> dict[str, Any]:
        independent_score = None
        markov_score = None
        if self.model_type == "markov":
            assert isinstance(self.model, MarkovModel)
            markov_score = self.model.score_sequence(window.states)
            information_score = markov_score.information_score
            log_probability = markov_score.log_probability_bits
            initial_probability = markov_score.initial_probability
            scored_states: list[Any] = list(markov_score.scored_states)
            unknown_indices = list(markov_score.unknown_state_indices)
            unknown_url_indices: list[int] = []
            unknown_status_indices: list[int] = []
            transition_probabilities = list(markov_score.transition_probabilities)
            least_probable_transitions = [
                {"from_state": item.from_state, "to_state": item.to_state,
                 "probability": item.probability}
                for item in markov_score.least_probable_transitions
            ]
        else:
            assert isinstance(self.model, IndependentMarginalModel)
            independent_score = self.model.score_events(window.events)
            information_score = independent_score.information_score
            log_probability = independent_score.log_probability_bits
            initial_probability = independent_score.initial_probability
            scored_states = []
            unknown_url_indices = list(independent_score.unknown_url_indices)
            unknown_status_indices = list(independent_score.unknown_status_indices)
            unknown_indices = sorted(set(unknown_url_indices) | set(unknown_status_indices))
            transition_probabilities = []
            least_probable_transitions = []
        aep_score = self.aep.score(information_score, self.entropy_reference_bits)
        density_score = self.density.score(information_score)
        selected_mode = mode or self.mode
        if selected_mode not in {"aep", "density", "hybrid"}:
            raise ValueError("mode must be aep, density, or hybrid")
        if selected_mode == "aep":
            final = aep_score.anomalous
        elif selected_mode == "density":
            final = bool(density_score.anomalous)
        else:
            final = aep_score.anomalous or bool(density_score.anomalous)
        reasons = []
        if selected_mode in {"aep", "hybrid"} and aep_score.anomalous:
            reasons.append("normalized information score deviates from the learned entropy reference")
        if selected_mode in {"density", "hybrid"} and density_score.anomalous:
            reasons.append("information score lies beyond the validation density threshold")
        unknown_events = []
        for index in unknown_indices:
            item = {
                "event_index": index,
                "state_description": (window.state_descriptions[index]
                                      if index < len(window.state_descriptions) else {}),
                "event": window.events[index],
            }
            if markov_score is not None:
                item["original_state_id"] = window.states[index]
            else:
                item["unknown_url_group"] = index in unknown_url_indices
                item["unknown_status_category"] = index in unknown_status_indices
            unknown_events.append(item)
        return {
            "window_id": window.window_id, "start_time": window.start_time, "end_time": window.end_time,
            "client_ip": window.client_ip,
            "event_count": len(window.events), "events": list(window.events),
            "encoded_states": list(window.states),
            "state_descriptions": [self.metadata.get("state_catalog", {}).get(state)
                                   or (window.state_descriptions[index]
                                       if index < len(window.state_descriptions) else {})
                                   for index, state in enumerate(window.states)],
            "scoring_model": self.model_type,
            "scored_states": scored_states,
            "novelty_detected": bool(unknown_events), "unknown_state_count": len(unknown_events),
            "unknown_url_group_count": len(unknown_url_indices),
            "unknown_status_category_count": len(unknown_status_indices),
            "unknown_state_events": unknown_events,
            "log_probability": log_probability,
            "initial_probability": initial_probability,
            "information_score": information_score,
            "entropy_rate": self.entropy_reference_bits,
            "aep_deviation": aep_score.aep_deviation, "aep_threshold": self.aep.threshold,
            "aep_anomalous": aep_score.anomalous, "density": density_score.density,
            "density_score": density_score.anomaly_score,
            "density_threshold": self.density.threshold,
            "density_anomalous": density_score.anomalous, "final_anomalous": final,
            "anomaly_reasons": reasons if final else [],
            "detector_mode": selected_mode,
            "transition_probabilities": transition_probabilities,
            "least_probable_transitions": least_probable_transitions,
            "url_surprisal_bits": (list(independent_score.url_surprisal_bits)
                                    if independent_score is not None else []),
            "status_surprisal_bits": (list(independent_score.status_surprisal_bits)
                                      if independent_score is not None else []),
        }


def detect_file(event_csv: str | Path, model_dir: str | Path,
                output_path: str | Path) -> int:
    detector = TrainedDetector(model_dir)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    prepared_csv = ensure_state_ids_csv(event_csv, destination.parent / "prepared" / "state_events.csv",
                                        detector.metadata["config"]["state"]["fields"])
    windows = load_windows(prepared_csv, **detector.metadata["config"]["window"])
    with destination.open("w", encoding="utf-8") as stream:
        for window in windows:
            # Future request states are mapped to the model's reserved UNK symbol.
            stream.write(json.dumps(detector.score(window), ensure_ascii=False) + "\n")
    return len(windows)
