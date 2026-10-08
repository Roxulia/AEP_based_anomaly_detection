"""Train, persist, and run the configured AEP/Markov/density detector."""

from __future__ import annotations

import json
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .aep import AEPDetector
from .density import InformationScoreDensity
from .markov import MarkovModel
from .windowing import EventWindow, chronological_split, load_windows


DEFAULT_CONFIG: dict[str, Any] = {
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
        self.model = MarkovModel.from_dict(self.metadata["markov"])
        with (root / "density.pkl").open("rb") as stream:
            self.density: InformationScoreDensity = pickle.load(stream)
        self.aep = AEPDetector(quantile=self.metadata["config"]["aep"]["quantile"])
        self.aep.threshold = float(self.metadata["aep_threshold"])
        self.density.threshold = float(self.metadata["density_threshold"])
        self.mode = self.metadata["config"]["detector"]["mode"]

    def score(self, window: EventWindow) -> dict[str, Any]:
        markov_score = self.model.score_sequence(window.states)
        aep_score = self.aep.score(markov_score.information_score, self.model.entropy_rate_bits)
        density_score = self.density.score(markov_score.information_score)
        if self.mode == "aep":
            final = aep_score.anomalous
        elif self.mode == "density":
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
            "detector_mode": self.mode,
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
