"""Kernel density estimation for normalized self-information scores."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable

from scipy.stats import gaussian_kde


@dataclass(frozen=True)
class DensityScore:
    density: float
    anomaly_score: float
    anomalous: bool | None


class InformationScoreDensity:
    """Fit KDE to normal information scores and score unseen values."""

    def __init__(self, bandwidth: str | float = "scott", epsilon: float = 1e-12,
                 quantile: float = 0.99) -> None:
        if isinstance(bandwidth, str):
            if bandwidth not in {"scott", "silverman"}:
                raise ValueError("bandwidth must be 'scott', 'silverman', or a positive finite number")
        elif not (
            isinstance(bandwidth, (int, float)) and math.isfinite(bandwidth) and bandwidth > 0
        ):
            raise ValueError("bandwidth must be 'scott', 'silverman', or a positive finite number")
        if not math.isfinite(epsilon) or epsilon <= 0:
            raise ValueError("epsilon must be a finite value greater than zero")
        if not math.isfinite(quantile) or not 0 <= quantile <= 1:
            raise ValueError("quantile must be a finite number between 0 and 1")
        self.bandwidth = bandwidth
        self.epsilon = float(epsilon)
        self.quantile = float(quantile)
        self.threshold: float | None = None
        self._kde: gaussian_kde | None = None

    def fit(self, normal_information_scores: Iterable[float]) -> "InformationScoreDensity":
        """Fit the KDE using finite normal-window information scores."""
        values = [self._finite(value, "normal information score") for value in normal_information_scores]
        if len(values) < 2:
            raise ValueError("at least two normal information scores are required to fit KDE")
        if max(values) == min(values):
            raise ValueError("normal information scores must have non-zero variance for KDE")
        try:
            self._kde = gaussian_kde(values, bw_method=self.bandwidth)
        except (ValueError, ArithmeticError) as exc:
            raise ValueError(f"could not fit KDE to the supplied information scores: {exc}") from exc
        self.threshold = None
        return self

    def fit_threshold(self, validation_information_scores: Iterable[float]) -> float:
        """Learn an anomaly-score cutoff from validation scores."""
        self._require_fitted()
        anomaly_scores = [self._score_value(value) for value in validation_information_scores]
        if not anomaly_scores:
            raise ValueError("at least one validation information score is required")
        ordered = sorted(anomaly_scores)
        position = self.quantile * (len(ordered) - 1)
        lower = math.floor(position)
        upper = math.ceil(position)
        fraction = position - lower
        self.threshold = ordered[lower] * (1 - fraction) + ordered[upper] * fraction
        return self.threshold

    def score(self, information_score: float) -> DensityScore:
        """Return estimated density, negative log-density, and optional decision."""
        value = self._finite(information_score, "information_score")
        density = self._density(value)
        anomaly_score = -math.log(density + self.epsilon)
        if not math.isfinite(anomaly_score):
            raise ArithmeticError("calculated density anomaly score is not finite")
        return DensityScore(
            density=density,
            anomaly_score=anomaly_score,
            anomalous=None if self.threshold is None else anomaly_score > self.threshold,
        )

    def _score_value(self, information_score: float) -> float:
        value = self._finite(information_score, "validation information score")
        density = self._density(value)
        return -math.log(density + self.epsilon)

    def _density(self, value: float) -> float:
        self._require_fitted()
        density = float(self._kde([value])[0])  # type: ignore[misc]
        if not math.isfinite(density) or density < 0:
            raise ArithmeticError("KDE returned an invalid density")
        return density

    def _require_fitted(self) -> None:
        if self._kde is None:
            raise RuntimeError("fit the KDE before scoring information values")

    @staticmethod
    def _finite(value: float, name: str) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a finite number") from exc
        if not math.isfinite(parsed):
            raise ValueError(f"{name} must be a finite number")
        return parsed
