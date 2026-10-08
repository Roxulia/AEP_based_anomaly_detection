"""Train, persist, and run the configured AEP/Markov/density detector."""

from __future__ import annotations

import json
import tempfile
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .aep import AEPDetector
from .density import InformationScoreDensity
from .event_encoder import STATE_ENCODING_VERSION
from .markov import MarkovModel
from .windowing import EventWindow, chronological_split, load_windows


DEFAULT_CONFIG: dict[str, Any] = {
    "datasets": {
        "train_dir": "Data/Train",
        "validate_dir": "Data/Validate",
        "test_dir": "Data/Test",
        "processed_dir": "Data/processed",
    },
    "window": {"type": "fixed_count", "size": 50, "include_partial": False},
    "split": {"training": 0.65, "validation": 0.15, "testing": 0.20},
    "markov": {"smoothing": 0.5},
    "aep": {"quantile": 0.99},
    "density": {"bandwidth": "scott", "epsilon": 1e-12, "quantile": 0.99},
    "detector": {"mode": "hybrid"},
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
    window = config["window"]
    if window["type"] not in {"fixed_count", "fixed_time"} or int(window["size"]) <= 0:
        raise ValueError("window type must be fixed_count/fixed_time and size must be positive")
    if config["detector"]["mode"] not in {"aep", "density", "hybrid"}:
        raise ValueError("detector mode must be aep, density, or hybrid")


def _scores(model: MarkovModel, windows: tuple[EventWindow, ...] | list[EventWindow]) -> list[float]:
    return [model.score_sequence(window.states).information_score for window in windows]


def prepare_log_directory(input_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Parse supported raw logs and preprocess route requests into event CSV."""
    from .log_parser import LogParser
    from .route_preprocessor import RoutePreprocessor

    parsed = LogParser().parse_directory(input_dir, output_dir)
    event_csv = Path(output_dir) / "route_events.csv"
    summary = RoutePreprocessor().process_csv(Path(output_dir) / "routes.csv", event_csv)
    return {
        "parsed": {name: {"files": item.files, "parsed_rows": item.parsed_rows,
                          "malformed_rows": item.malformed_rows}
                   for name, item in parsed.items()},
        "preprocessed": {"input_rows": summary.input_rows, "processed_rows": summary.processed_rows,
                         "skipped_rows": summary.skipped_rows,
                         "skipped_by_reason": summary.skipped_by_reason},
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
    train_data = prepare_log_directory(train_root, scratch / "Train")
    validation_data = prepare_log_directory(validate_root, scratch / "Validate")
    train_windows = load_windows(train_data["event_csv"], **settings["window"])
    validation_windows = load_windows(validation_data["event_csv"], **settings["window"])
    if not train_windows or not validation_windows:
        raise ValueError("Train and Validate must each contain enough valid requests to form windows")

    model = MarkovModel(smoothing=float(settings["markov"]["smoothing"])).fit(
        window.states for window in train_windows
    )
    train_scores = _scores(model, train_windows)
    validation_scores: list[float] = []
    unscorable_validation = 0
    for window in validation_windows:
        try:
            validation_scores.append(model.score_sequence(window.states).information_score)
        except ValueError as exc:
            if "not observed during fit" not in str(exc):
                raise
            unscorable_validation += 1
    if not validation_scores:
        raise ValueError("validation data has no windows containing only states seen in Train")
    aep = AEPDetector(quantile=float(settings["aep"]["quantile"]))
    aep_threshold = aep.fit_threshold(validation_scores, model.entropy_rate_bits)
    density = InformationScoreDensity(**settings["density"]).fit(train_scores)
    density_threshold = density.fit_threshold(validation_scores)
    destination = Path(model_dir)
    destination.mkdir(parents=True, exist_ok=True)
    model_doc = {
        "schema_version": 1,
        "state_encoding": {"version": STATE_ENCODING_VERSION,
                           "definition": ["method", "url_group", "status_category"]},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "description": "Fitted statistical anomaly detector (Markov, AEP, information-score KDE)",
        "config": settings,
        "markov": model.to_dict(),
        "encoder_states": [list(state) for state in model.states],
        "aep_threshold": aep_threshold,
        "density_threshold": density_threshold,
        "dataset_folders": {"train": str(train_root), "validate": str(validate_root)},
        "window_counts": {"training": len(train_windows), "validation": len(validation_windows),
                          "validation_unscorable": unscorable_validation},
    }
    (destination / "model.json").write_text(json.dumps(model_doc, indent=2), encoding="utf-8")
    with (destination / "density.pkl").open("wb") as stream:
        pickle.dump(density, stream, protocol=pickle.HIGHEST_PROTOCOL)
    return {"model_dir": str(destination), **model_doc["window_counts"],
            "training_data": train_data, "validation_data": validation_data}


def _label_value(window: EventWindow) -> bool | None:
    """Return a window label only when every request carries an explicit label."""
    values = []
    for event in window.events:
        raw = next((event[key] for key in ("is_anomaly", "label", "ground_truth")
                    if event.get(key, "") != ""), None)
        if raw is None:
            return None
        values.append(str(raw).strip().lower() in {"1", "true", "yes", "anomaly", "abnormal"})
    return any(values) if values else None


def _binary_metrics(labels: list[bool], scores: list[float], decisions: list[bool]) -> dict[str, Any]:
    tp = sum(y and p for y, p in zip(labels, decisions))
    tn = sum((not y) and (not p) for y, p in zip(labels, decisions))
    fp = sum((not y) and p for y, p in zip(labels, decisions))
    fn = sum(y and (not p) for y, p in zip(labels, decisions))
    positives, negatives = tp + fn, tn + fp
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
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / positives if positives else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
        "false_positive_rate": fp / negatives if negatives else None,
        "false_negative_rate": fn / positives if positives else None,
        "roc_auc": auc, "pr_auc": pr_auc,
    }


def evaluate_event_csv(event_csv: str | Path, model_dir: str | Path,
                       output_dir: str | Path) -> dict[str, Any]:
    """Evaluate the saved detector on a separate dataset without fitting or tuning."""
    detector = TrainedDetector(model_dir)
    windows = load_windows(event_csv, **detector.metadata["config"]["window"])
    results: dict[str, Any] = {}
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    all_rows: dict[str, list[dict[str, Any]]] = {mode: [] for mode in ("aep", "density", "hybrid")}
    for mode in all_rows:
        for window in windows:
            try:
                all_rows[mode].append(detector.score(window, mode=mode))
            except ValueError as exc:
                if "not observed during fit" not in str(exc):
                    raise
                all_rows[mode].append({"window_id": window.window_id,
                                       "start_time": window.start_time, "end_time": window.end_time,
                                       "event_count": len(window.events), "scorable": False,
                                       "final_anomalous": None, "unscorable_reason": str(exc)})
        rows = all_rows[mode]
        labels = [_label_value(window) for window in windows]
        scorable = [(label, row) for label, row in zip(labels, rows)
                    if label is not None and row.get("scorable", True)]
        if scorable:
            metrics = _binary_metrics([item[0] for item in scorable],
                                      [item[1]["density_score"] if mode == "density"
                                       else item[1]["aep_deviation"] if mode == "aep"
                                       else max(item[1]["aep_deviation"] / max(detector.aep.threshold or 0.0, 1e-12),
                                                item[1]["density_score"] / max(detector.density.threshold or 0.0, 1e-12))
                                       for item in scorable],
                                      [bool(item[1]["final_anomalous"]) for item in scorable])
        else:
            metrics = {"available": False, "reason": "No usable ground-truth labels in test windows."}
        results[mode] = {"windows": len(windows),
                         "scorable_windows": sum(row.get("scorable", True) for row in rows),
                         "unscorable_windows": sum(not row.get("scorable", True) for row in rows),
                         "anomalous_windows": sum(row.get("final_anomalous") is True for row in rows),
                         "metrics": metrics}
        with (output_root / f"{mode}.jsonl").open("w", encoding="utf-8") as stream:
            stream.writelines(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    report = {"detector_description": detector.metadata.get("description", "Statistical anomaly detector"),
              "test_event_csv": str(event_csv), "window_count": len(windows), "comparisons": results}
    (output_root / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def evaluate_directory(test_dir: str | Path, model_dir: str | Path,
                       output_dir: str | Path, work_dir: str | Path | None = None) -> dict[str, Any]:
    test_root = Path(test_dir)
    if not test_root.is_dir():
        raise NotADirectoryError(f"Test log directory does not exist: {test_root}")
    scratch = Path(work_dir) if work_dir else Path(output_dir) / "prepared"
    prepared = prepare_log_directory(test_root, scratch)
    report = evaluate_event_csv(prepared["event_csv"], model_dir, output_dir)
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
        prepared = RoutePreprocessor().process_csv(root / "parsed" / "routes.csv", event_csv)
        detector = TrainedDetector(model_dir)
        windows = load_windows(event_csv, **detector.metadata["config"]["window"])
        rows = []
        for window in windows:
            try:
                rows.append(detector.score(window))
            except ValueError as exc:
                if "not observed during fit" not in str(exc):
                    raise
                rows.append({"window_id": window.window_id, "start_time": window.start_time,
                             "end_time": window.end_time, "scorable": False,
                             "final_anomalous": None, "unscorable_reason": str(exc)})
        return {"filename": source.name,
                "parse": {name: {"files": stat.files, "parsed_rows": stat.parsed_rows,
                                 "malformed_rows": stat.malformed_rows}
                          for name, stat in parsed.items()},
                "preprocessing": {"input_rows": prepared.input_rows,
                                  "processed_rows": prepared.processed_rows,
                                  "skipped_rows": prepared.skipped_rows,
                                  "skipped_by_reason": prepared.skipped_by_reason},
                "windows": rows}


def train_model(event_csv: str | Path, model_dir: str | Path,
                config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fit using training windows and validation-only thresholds, then persist artifacts."""
    settings = config or load_config()
    _validate_config(settings)
    windows = load_windows(event_csv, **settings["window"])
    split_settings = settings["split"]
    split = chronological_split(windows, split_settings["training"], split_settings["validation"],
                                split_settings["testing"])
    model = MarkovModel(smoothing=float(settings["markov"]["smoothing"])).fit(
        window.states for window in split.training
    )
    train_scores = _scores(model, split.training)
    validation_scores = _scores(model, split.validation)
    aep = AEPDetector(quantile=float(settings["aep"]["quantile"]))
    aep_threshold = aep.fit_threshold(validation_scores, model.entropy_rate_bits)
    density = InformationScoreDensity(**settings["density"]).fit(train_scores)
    density_threshold = density.fit_threshold(validation_scores)
    destination = Path(model_dir)
    destination.mkdir(parents=True, exist_ok=True)
    model_doc = {
        "schema_version": 1,
        "state_encoding": {"version": STATE_ENCODING_VERSION,
                           "definition": ["method", "url_group", "status_category"]},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config": settings,
        "markov": model.to_dict(),
        "encoder_states": [list(state) for state in model.states],
        "aep_threshold": aep_threshold,
        "density_threshold": density_threshold,
        "split_windows": {"training": len(split.training), "validation": len(split.validation),
                          "testing": len(split.testing)},
    }
    (destination / "model.json").write_text(json.dumps(model_doc, indent=2), encoding="utf-8")
    with (destination / "density.pkl").open("wb") as stream:
        pickle.dump(density, stream, protocol=pickle.HIGHEST_PROTOCOL)
    return {"model_dir": str(destination), "windows": len(windows), **model_doc["split_windows"]}


class TrainedDetector:
    """Loaded model bundle that returns explainable per-window results."""

    def __init__(self, model_dir: str | Path) -> None:
        root = Path(model_dir)
        self.metadata = json.loads((root / "model.json").read_text(encoding="utf-8"))
        if self.metadata.get("schema_version") != 1:
            raise ValueError("unsupported model bundle schema version")
        if self.metadata.get("state_encoding", {}).get("version") != STATE_ENCODING_VERSION:
            raise ValueError("model uses a different state encoding; rebuild it with the current pipeline")
        self.model = MarkovModel.from_dict(self.metadata["markov"])
        with (root / "density.pkl").open("rb") as stream:
            self.density: InformationScoreDensity = pickle.load(stream)
        self.aep = AEPDetector(quantile=self.metadata["config"]["aep"]["quantile"])
        self.aep.threshold = float(self.metadata["aep_threshold"])
        self.density.threshold = float(self.metadata["density_threshold"])
        self.mode = self.metadata["config"]["detector"]["mode"]

    def score(self, window: EventWindow, mode: str | None = None) -> dict[str, Any]:
        markov_score = self.model.score_sequence(window.states)
        aep_score = self.aep.score(markov_score.information_score, self.model.entropy_rate_bits)
        density_score = self.density.score(markov_score.information_score)
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
        if aep_score.anomalous:
            reasons.append("normalized information score deviates from the learned entropy rate")
        if density_score.anomalous:
            reasons.append("information score lies beyond the validation density threshold")
        return {
            "window_id": window.window_id, "start_time": window.start_time, "end_time": window.end_time,
            "event_count": len(window.events), "events": list(window.events),
            "encoded_states": [list(state) for state in window.states],
            "log_probability": markov_score.log_probability_bits,
            "initial_probability": markov_score.initial_probability,
            "information_score": markov_score.information_score,
            "entropy_rate": self.model.entropy_rate_bits,
            "aep_deviation": aep_score.aep_deviation, "aep_threshold": self.aep.threshold,
            "aep_anomalous": aep_score.anomalous, "density": density_score.density,
            "density_score": density_score.anomaly_score,
            "density_threshold": self.density.threshold,
            "density_anomalous": density_score.anomalous, "final_anomalous": final,
            "anomaly_reasons": reasons if final else [],
            "detector_mode": selected_mode,
            "transition_probabilities": list(markov_score.transition_probabilities),
            "least_probable_transitions": [
                {"from_state": list(item.from_state) if isinstance(item.from_state, tuple) else item.from_state,
                 "to_state": list(item.to_state) if isinstance(item.to_state, tuple) else item.to_state,
                 "probability": item.probability}
                for item in markov_score.least_probable_transitions
            ],
        }


def detect_file(event_csv: str | Path, model_dir: str | Path,
                output_path: str | Path) -> int:
    detector = TrainedDetector(model_dir)
    windows = load_windows(event_csv, **detector.metadata["config"]["window"])
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as stream:
        for window in windows:
            # score_sequence rejects future states instead of mapping them into known states.
            stream.write(json.dumps(detector.score(window), ensure_ascii=False) + "\n")
    return len(windows)
