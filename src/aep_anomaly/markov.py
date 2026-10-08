"""First-order Markov modeling for discrete event-state sequences."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Hashable, Iterable

import numpy as np


State = Hashable


@dataclass(frozen=True)
class TransitionDetail:
    """Probability details for one step in a scored sequence."""

    from_state: State | None
    to_state: State
    probability: float
    kind: str


@dataclass(frozen=True)
class MarkovSequenceScore:
    """Log-probability and normalized self-information for a sequence."""

    log_probability_bits: float
    information_score: float
    event_count: int
    initial_probability: float
    transition_probabilities: tuple[float, ...]
    least_probable_transitions: tuple[TransitionDetail, ...]


class MarkovModel:
    """Fit and score a smoothed first-order Markov chain.

    States are any hashable values. For this project, request states can be
    tuples of ``(method, normalized_uri, status_class)``.
    """

    def __init__(self, smoothing: float = 0.5, stationary_tolerance: float = 1e-12) -> None:
        if not math.isfinite(smoothing) or smoothing <= 0:
            raise ValueError("smoothing must be a finite value greater than zero")
        if not math.isfinite(stationary_tolerance) or stationary_tolerance <= 0:
            raise ValueError("stationary_tolerance must be finite and greater than zero")
        self.smoothing = float(smoothing)
        self.stationary_tolerance = stationary_tolerance
        self._fitted = False

    @property
    def states(self) -> tuple[State, ...]:
        self._require_fitted()
        return self._states

    @property
    def entropy_rate_bits(self) -> float:
        self._require_fitted()
        return self._entropy_rate_bits

    @property
    def stationary_distribution(self) -> dict[State, float]:
        self._require_fitted()
        return dict(zip(self._states, self._stationary_probabilities))

    @property
    def initial_probabilities(self) -> dict[State, float]:
        self._require_fitted()
        return dict(self._initial_probabilities)

    @property
    def transition_probabilities(self) -> dict[State, dict[State, float]]:
        self._require_fitted()
        return {state: dict(row) for state, row in self._transition_probabilities.items()}

    def fit(self, sequences: Iterable[Iterable[State]]) -> "MarkovModel":
        """Estimate probabilities from one or more independent sequences."""
        self._fitted = False
        materialized: list[list[State]] = []
        all_states: set[State] = set()
        for sequence in sequences:
            events = list(sequence)
            if not events:
                continue
            for state in events:
                try:
                    hash(state)
                except TypeError as exc:
                    raise TypeError(f"Markov states must be hashable; got {state!r}") from exc
                all_states.add(state)
            materialized.append(events)
        if not materialized:
            raise ValueError("at least one non-empty training sequence is required")

        # Stable ordering makes matrix and serialized diagnostic output repeatable.
        self._states = tuple(sorted(all_states, key=repr))
        state_count = len(self._states)
        initial_counts: Counter[State] = Counter(sequence[0] for sequence in materialized)
        initial_total = sum(initial_counts.values())
        self._initial_probabilities = {
            state: (initial_counts[state] + self.smoothing)
            / (initial_total + self.smoothing * state_count)
            for state in self._states
        }

        transition_counts: dict[State, Counter[State]] = {
            state: Counter() for state in self._states
        }
        for sequence in materialized:
            for from_state, to_state in zip(sequence, sequence[1:]):
                transition_counts[from_state][to_state] += 1

        self._transition_probabilities = {}
        for from_state in self._states:
            row_total = sum(transition_counts[from_state].values())
            denominator = row_total + self.smoothing * state_count
            self._transition_probabilities[from_state] = {
                to_state: (transition_counts[from_state][to_state] + self.smoothing) / denominator
                for to_state in self._states
            }

        self._stationary_probabilities = self._calculate_stationary_distribution()
        self._entropy_rate_bits = -sum(
            stationary_probability
            * sum(
                probability * math.log2(probability)
                for probability in self._transition_probabilities[state].values()
                if probability > 0
            )
            for state, stationary_probability in zip(self._states, self._stationary_probabilities)
        )
        if not math.isfinite(self._entropy_rate_bits):
            raise ArithmeticError("calculated entropy rate is not finite")
        self._fitted = True
        return self

    def score_sequence(self, sequence: Iterable[State]) -> MarkovSequenceScore:
        """Score a sequence in log space; unseen states raise ``ValueError``."""
        self._require_fitted()
        events = list(sequence)
        if not events:
            raise ValueError("cannot score an empty sequence")
        unknown = [state for state in events if state not in self._initial_probabilities]
        if unknown:
            unique_unknown = list(dict.fromkeys(unknown))
            raise ValueError(f"sequence contains states not observed during fit: {unique_unknown!r}")

        initial_probability = self._initial_probabilities[events[0]]
        log_probability = math.log2(initial_probability)
        details: list[TransitionDetail] = []
        transition_probabilities: list[float] = []
        for from_state, to_state in zip(events, events[1:]):
            probability = self._transition_probabilities[from_state][to_state]
            if not math.isfinite(probability) or probability <= 0:
                raise ArithmeticError("transition probability is not finite and positive")
            transition_probabilities.append(probability)
            details.append(TransitionDetail(from_state, to_state, probability, "transition"))
            log_probability += math.log2(probability)

        information_score = -log_probability / len(events)
        if not math.isfinite(log_probability) or not math.isfinite(information_score):
            raise ArithmeticError("sequence score is not finite")
        least_probable = tuple(sorted(details, key=lambda detail: detail.probability)[:5])
        return MarkovSequenceScore(
            log_probability_bits=log_probability,
            information_score=information_score,
            event_count=len(events),
            initial_probability=initial_probability,
            transition_probabilities=tuple(transition_probabilities),
            least_probable_transitions=least_probable,
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible representation of a fitted model."""
        self._require_fitted()
        if any(not isinstance(state, tuple) or not all(isinstance(part, str) for part in state)
               for state in self._states):
            raise TypeError("JSON model persistence supports tuple-of-string request states")
        return {
            "smoothing": self.smoothing,
            "states": [list(state) for state in self._states],
            "initial_probabilities": [self._initial_probabilities[state] for state in self._states],
            "transition_probabilities": [
                [self._transition_probabilities[source][target] for target in self._states]
                for source in self._states
            ],
            "stationary_probabilities": list(self._stationary_probabilities),
            "entropy_rate_bits": self._entropy_rate_bits,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "MarkovModel":
        """Reconstruct a fitted model saved by :meth:`to_dict`."""
        states = tuple(tuple(str(part) for part in state) for state in data["states"])  # type: ignore[arg-type]
        initial = data["initial_probabilities"]
        matrix = data["transition_probabilities"]
        stationary = data["stationary_probabilities"]
        if not states or len(initial) != len(states) or len(matrix) != len(states):  # type: ignore[arg-type]
            raise ValueError("invalid serialized Markov model dimensions")
        model = cls(smoothing=float(data["smoothing"]))
        model._states = states
        model._initial_probabilities = {state: float(initial[index]) for index, state in enumerate(states)}  # type: ignore[index]
        model._transition_probabilities = {
            source: {target: float(matrix[i][j]) for j, target in enumerate(states)}  # type: ignore[index]
            for i, source in enumerate(states)
        }
        model._stationary_probabilities = tuple(float(value) for value in stationary)  # type: ignore[arg-type]
        model._entropy_rate_bits = float(data["entropy_rate_bits"])
        if (not math.isfinite(model._entropy_rate_bits)
                or any(not math.isfinite(value) or value <= 0 for value in model._initial_probabilities.values())
                or len(model._stationary_probabilities) != len(states)):
            raise ValueError("serialized Markov model contains invalid probabilities")
        model._fitted = True
        return model

    def _calculate_stationary_distribution(self) -> tuple[float, ...]:
        state_count = len(self._states)
        transition_matrix = np.array(
            [
                [self._transition_probabilities[from_state][to_state] for to_state in self._states]
                for from_state in self._states
            ],
            dtype=float,
        )
        # Solve pi P = pi with sum(pi) = 1. Replacing one dependent equation
        # avoids the slow oscillatory convergence of power iteration for
        # nearly deterministic periodic chains.
        system = transition_matrix.T - np.eye(state_count)
        system[-1, :] = 1.0
        target = np.zeros(state_count, dtype=float)
        target[-1] = 1.0
        try:
            distribution = np.linalg.solve(system, target)
        except np.linalg.LinAlgError as exc:
            raise ArithmeticError("could not solve for the stationary distribution") from exc
        if not np.all(np.isfinite(distribution)) or np.any(distribution < -1e-10):
            raise ArithmeticError("stationary distribution contains invalid probabilities")
        distribution = np.maximum(distribution, 0.0)
        total = float(np.sum(distribution))
        if not math.isfinite(total) or total <= 0:
            raise ArithmeticError("stationary distribution cannot be normalized")
        distribution /= total
        residual = float(np.max(np.abs(distribution @ transition_matrix - distribution)))
        if residual > max(self.stationary_tolerance * 100, 1e-9):
            raise ArithmeticError("stationary distribution solution did not converge")
        return tuple(float(value) for value in distribution)

    def _require_fitted(self) -> None:
        if not self._fitted:
            raise RuntimeError("fit the MarkovModel before accessing learned probabilities")
