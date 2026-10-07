"""Deterministic conversion of HTTP request fields into Markov states."""

from __future__ import annotations

from .route_normalizer import RouteNormalizer


EventState = tuple[str, str, str]


class EventEncoder:
    """Encode requests as ``(method, normalized_uri, status_class)`` tuples."""

    def __init__(self, route_normalizer: RouteNormalizer | None = None) -> None:
        self.route_normalizer = route_normalizer or RouteNormalizer()

    def encode(self, method: str | None, uri: str | None, status: object) -> EventState:
        """Return a stable state; unavailable or invalid values become ``unknown``."""
        normalized_method = str(method).strip().upper() if method is not None else ""
        normalized_method = normalized_method or "unknown"

        normalized_uri = self.route_normalizer.normalize(uri)
        status_class = self._status_class(status)
        return normalized_method, normalized_uri, status_class

    @staticmethod
    def _status_class(status: object) -> str:
        if isinstance(status, bool):
            return "unknown"
        try:
            text = str(status).strip()
            if len(text) != 3 or not text.isascii() or not text.isdigit():
                return "unknown"
            code = int(text)
        except (TypeError, ValueError, OverflowError):
            return "unknown"
        if 100 <= code <= 599:
            return f"{code // 100}xx"
        return "unknown"
