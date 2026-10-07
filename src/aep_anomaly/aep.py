"""AEP deviation scoring and validation-quantile thresholding."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class AEPScore:
    information_score: float
    entropy_rate: float
    aep_deviation: float
    anomalous: bool


class AEPDetector:
    """Compare normalized self-information with a Markov entropy rate."""

    def __init__(self, quantile: float = 0.99) -> None:
        if not math.isfinite(quantile) or not 0 <= quantile <= 1:
            raise ValueError("quantile must be a finite number between 0 and 1")
        self.quantile = float(quantile)
        self.threshold: float | None = None

    def fit_threshold(self, validation_information_scores: Iterable[float], entropy_rate: float) -> float:
        """Learn the AEP deviation cutoff from validation information scores."""
        entropy_rate = self._finite(entropy_rate, "entropy_rate")
        deviations = [
            abs(self._finite(score, "validation information score") - entropy_rate)
            for score in validation_information_scores
        ]
        if not deviations:
            raise ValueError("at least one validation information score is required")
        self.threshold = self._quantile(deviations, self.quantile)
        return self.threshold

    def score(self, information_score: float, entropy_rate: float) -> AEPScore:
        """Return AEP deviation and whether it exceeds the learned cutoff."""
        if self.threshold is None:
            raise RuntimeError("fit the AEP threshold before scoring")
        information_score = self._finite(information_score, "information_score")
        entropy_rate = self._finite(entropy_rate, "entropy_rate")
        deviation = abs(information_score - entropy_rate)
        return AEPScore(
            information_score=information_score,
            entropy_rate=entropy_rate,
            aep_deviation=deviation,
            anomalous=deviation > self.threshold,
        )

    @staticmethod
    def _quantile(values: list[float], quantile: float) -> float:
        ordered = sorted(values)
        position = quantile * (len(ordered) - 1)
        lower = math.floor(position)
        upper = math.ceil(position)
        fraction = position - lower
        return ordered[lower] * (1 - fraction) + ordered[upper] * fraction

    @staticmethod
    def _finite(value: float, name: str) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a finite number") from exc
        if not math.isfinite(parsed):
            raise ValueError(f"{name} must be a finite number")
        return parsed
