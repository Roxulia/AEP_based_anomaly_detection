"""Independent request URL and response-status marginal model."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Mapping

from .event_encoder import EventEncoder


UNKNOWN_CATEGORY = "__UNK__"


@dataclass(frozen=True)
class IndependentRequestScore:
    """Score for an event collection under independent URL/status marginals."""

    log_probability_bits: float
    information_score: float
    event_count: int
    initial_probability: float
    url_surprisal_bits: tuple[float, ...]
    status_surprisal_bits: tuple[float, ...]
    unknown_url_indices: tuple[int, ...]
    unknown_status_indices: tuple[int, ...]


class IndependentMarginalModel:
    """Fit separate categorical distributions for URL group and status category.

    The model makes no Markov-transition or joint URL/status probability
    estimates. A session's information score is the mean summed marginal
    surprisal for its requests.
    """

    MODES = {"independent", "joint", "status_given_url"}

    def __init__(self, smoothing: float = 0.5, mode: str = "independent") -> None:
        if not math.isfinite(smoothing) or smoothing <= 0:
            raise ValueError("smoothing must be finite and greater than zero")
        if mode not in self.MODES:
            raise ValueError(f"mode must be one of {sorted(self.MODES)}")
        self.smoothing = float(smoothing)
        self.mode = mode
        self._fitted = False

    @property
    def url_probabilities(self) -> dict[str, float]:
        self._require_fitted()
        return dict(self._url_probabilities)

    @property
    def status_probabilities(self) -> dict[str, float]:
        self._require_fitted()
        return dict(self._status_probabilities)

    @property
    def entropy_bits_per_request(self) -> float:
        self._require_fitted()
        return self._entropy_bits_per_request

    @property
    def url_entropy_bits(self) -> float:
        self._require_fitted()
        return self._url_entropy_bits

    @property
    def status_entropy_bits(self) -> float:
        self._require_fitted()
        return self._status_entropy_bits

    @property
    def training_event_count(self) -> int:
        self._require_fitted()
        return self._training_event_count

    def fit(self, sessions: Iterable[Iterable[Mapping[str, object]]]) -> "IndependentMarginalModel":
        self._fitted = False
        url_counts: Counter[str] = Counter()
        status_counts: Counter[str] = Counter()
        pair_counts: Counter[tuple[str, str]] = Counter()
        conditional_counts: dict[str, Counter[str]] = {}
        event_count = 0
        for session in sessions:
            for event in session:
                url_group, status_category = self._features(event)
                url_counts[url_group] += 1
                status_counts[status_category] += 1
                pair_counts[(url_group, status_category)] += 1
                conditional_counts.setdefault(url_group, Counter())[status_category] += 1
                event_count += 1
        if event_count == 0:
            raise ValueError("at least one training request is required")

        self._url_counts = dict(url_counts)
        self._status_counts = dict(status_counts)
        self._training_event_count = event_count
        self._url_probabilities = self._smoothed_probabilities(url_counts, event_count)
        self._status_probabilities = self._smoothed_probabilities(status_counts, event_count)
        urls = set(url_counts) | {UNKNOWN_CATEGORY}
        statuses = set(status_counts) | {UNKNOWN_CATEGORY}
        denominator = event_count + self.smoothing * len(urls) * len(statuses)
        self._pair_probabilities = {(url, status): (pair_counts[(url, status)] + self.smoothing) / denominator
                                     for url in urls for status in statuses}
        self._conditional_probabilities = {}
        for url, counts in conditional_counts.items():
            denominator = sum(counts.values()) + self.smoothing * len(statuses)
            self._conditional_probabilities[url] = {
                status: (counts[status] + self.smoothing) / denominator for status in statuses
            }
        self._conditional_probabilities[UNKNOWN_CATEGORY] = {
            status: 1.0 / len(statuses) for status in statuses
        }
        self._url_entropy_bits = self._entropy(self._url_probabilities)
        self._status_entropy_bits = self._entropy(self._status_probabilities)
        self._entropy_bits_per_request = (
            self._entropy(self._pair_probabilities) if self.mode == "joint" else
            self._url_entropy_bits + sum(url_counts[url] / event_count * self._entropy(probabilities)
                                         for url, probabilities in self._conditional_probabilities.items()
                                         if url in url_counts) if self.mode == "status_given_url" else
            self._url_entropy_bits + self._status_entropy_bits
        )
        self._fitted = True
        return self

    def score_events(self, events: Iterable[Mapping[str, object]]) -> IndependentRequestScore:
        self._require_fitted()
        materialized = list(events)
        if not materialized:
            raise ValueError("cannot score an empty request session")
        url_costs: list[float] = []
        status_costs: list[float] = []
        unknown_urls: list[int] = []
        unknown_statuses: list[int] = []
        for index, event in enumerate(materialized):
            url_group, status_category = self._features(event)
            if url_group not in self._url_counts:
                unknown_urls.append(index)
                url_group = UNKNOWN_CATEGORY
            if status_category not in self._status_counts:
                unknown_statuses.append(index)
                status_category = UNKNOWN_CATEGORY
            if self.mode == "joint":
                url_costs.append(-math.log2(self._pair_probabilities[(url_group, status_category)]))
                status_costs.append(0.0)
            elif self.mode == "status_given_url":
                url_costs.append(-math.log2(self._url_probabilities[url_group]))
                conditional = self._conditional_probabilities[url_group]
                status_costs.append(-math.log2(conditional.get(status_category, conditional[UNKNOWN_CATEGORY])))
            else:
                url_costs.append(-math.log2(self._url_probabilities[url_group]))
                status_costs.append(-math.log2(self._status_probabilities[status_category]))
        log_probability = -sum(url_costs) - sum(status_costs)
        information_score = -log_probability / len(materialized)
        initial_probability = 2.0 ** (-(url_costs[0] + status_costs[0]))
        values = (log_probability, information_score, initial_probability)
        if any(not math.isfinite(value) for value in values) or initial_probability <= 0:
            raise ArithmeticError("independent request score is not finite")
        return IndependentRequestScore(
            log_probability_bits=log_probability,
            information_score=information_score,
            event_count=len(materialized),
            initial_probability=initial_probability,
            url_surprisal_bits=tuple(url_costs),
            status_surprisal_bits=tuple(status_costs),
            unknown_url_indices=tuple(unknown_urls),
            unknown_status_indices=tuple(unknown_statuses),
        )

    def to_dict(self) -> dict[str, object]:
        self._require_fitted()
        return {
            "smoothing": self.smoothing,
            "mode": self.mode,
            "unknown_category": UNKNOWN_CATEGORY,
            "training_event_count": self._training_event_count,
            "url_counts": self._url_counts,
            "status_counts": self._status_counts,
            "url_probabilities": self._url_probabilities,
            "status_probabilities": self._status_probabilities,
            "pair_probabilities": {f"{url}\u001f{status}": value for (url, status), value in self._pair_probabilities.items()},
            "conditional_probabilities": self._conditional_probabilities,
            "url_entropy_bits": self._url_entropy_bits,
            "status_entropy_bits": self._status_entropy_bits,
            "entropy_bits_per_request": self.entropy_bits_per_request,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "IndependentMarginalModel":
        model = cls(smoothing=float(data["smoothing"]), mode=str(data.get("mode", "independent")))
        model._url_counts = {str(k): int(v) for k, v in dict(data["url_counts"]).items()}  # type: ignore[arg-type]
        model._status_counts = {str(k): int(v) for k, v in dict(data["status_counts"]).items()}  # type: ignore[arg-type]
        model._url_probabilities = {str(k): float(v) for k, v in dict(data["url_probabilities"]).items()}  # type: ignore[arg-type]
        model._status_probabilities = {str(k): float(v) for k, v in dict(data["status_probabilities"]).items()}  # type: ignore[arg-type]
        model._pair_probabilities = {tuple(k.split("\u001f", 1)): float(v)
                                     for k, v in dict(data.get("pair_probabilities", {})).items()}
        model._conditional_probabilities = {str(url): {str(k): float(v) for k, v in dict(values).items()}
                                            for url, values in dict(data.get("conditional_probabilities", {})).items()}
        model._training_event_count = int(data["training_event_count"])
        model._url_entropy_bits = float(data["url_entropy_bits"])
        model._status_entropy_bits = float(data["status_entropy_bits"])
        model._entropy_bits_per_request = float(data.get("entropy_bits_per_request",
                                                          model._url_entropy_bits + model._status_entropy_bits))
        if (UNKNOWN_CATEGORY not in model._url_probabilities
                or UNKNOWN_CATEGORY not in model._status_probabilities
                or not model._valid_probability_table(model._url_probabilities)
                or not model._valid_probability_table(model._status_probabilities)
                or model._training_event_count <= 0
                or not math.isfinite(model._url_entropy_bits)
                or not math.isfinite(model._status_entropy_bits)):
            raise ValueError("serialized independent marginal model is invalid")
        model._fitted = True
        return model

    @staticmethod
    def _features(event: Mapping[str, object]) -> tuple[str, str]:
        url_group = str(event.get("url_group") or "unknown").strip() or "unknown"
        status_category = str(event.get("status_category") or "").strip()
        if not status_category:
            status_category = EventEncoder._status_category(event.get("status"))
        return url_group, status_category or "unknown"

    def _smoothed_probabilities(self, counts: Counter[str], total: int) -> dict[str, float]:
        vocabulary = set(counts) | {UNKNOWN_CATEGORY}
        denominator = total + self.smoothing * len(vocabulary)
        return {item: (counts[item] + self.smoothing) / denominator for item in vocabulary}

    @staticmethod
    def _entropy(probabilities: Mapping[str, float]) -> float:
        return -sum(probability * math.log2(probability) for probability in probabilities.values())

    @staticmethod
    def _valid_probability_table(probabilities: Mapping[str, float]) -> bool:
        return (bool(probabilities)
                and all(math.isfinite(value) and value > 0 for value in probabilities.values())
                and abs(sum(probabilities.values()) - 1.0) <= 1e-9)

    def _require_fitted(self) -> None:
        if not self._fitted:
            raise RuntimeError("fit the IndependentMarginalModel before accessing learned probabilities")
