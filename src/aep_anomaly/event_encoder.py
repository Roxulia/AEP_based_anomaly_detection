"""Deterministic conversion of HTTP request fields into Markov states."""

from __future__ import annotations

import hashlib
import json

from .route_grouper import RouteGrouper
from .route_normalizer import RouteNormalizer
from .state_types import EventState, StateDescription, StateId


STATE_ENCODING_VERSION = 4


class EventEncoder:
    """Create stable opaque state IDs and separate human-readable descriptions."""

    def __init__(self, route_normalizer: RouteNormalizer | None = None,
                 route_grouper: RouteGrouper | None = None) -> None:
        self.route_normalizer = route_normalizer or RouteNormalizer()
        self.route_grouper = route_grouper or RouteGrouper()

    def describe(self, method: str | None, uri: str | None, status: object) -> StateDescription:
        """Extract the interpretable state dimensions from an HTTP request."""
        normalized_method = str(method).strip().upper() if method is not None else ""
        normalized_method = normalized_method or "unknown"

        normalized_uri = self.route_normalizer.normalize(uri)
        url_group = self.route_grouper.group(normalized_uri)
        status_category = self._status_category(status)
        return {"method": normalized_method, "url_group": url_group,
                "status_category": status_category}

    @staticmethod
    def state_id(description: StateDescription) -> StateId:
        """Return a deterministic opaque ID for a normalized state description."""
        canonical = json.dumps(description, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return f"state-v{STATE_ENCODING_VERSION}:{digest}"

    def encode_with_description(self, method: str | None, uri: str | None,
                                status: object) -> tuple[StateId, StateDescription]:
        description = self.describe(method, uri, status)
        return self.state_id(description), description

    def encode(self, method: str | None, uri: str | None, status: object) -> StateId:
        """Return the deterministic ID; use ``describe`` for display metadata."""
        return self.encode_with_description(method, uri, status)[0]

    @classmethod
    def _status_category(cls, status: object) -> str:
        """Retain useful HTTP outcome distinctions while grouping similar codes."""
        status_class = cls.status_class(status)
        if status_class == "unknown":
            return "unknown"
        code = int(str(status).strip())
        if 200 <= code <= 299:
            return "success"
        if 300 <= code <= 399:
            return "redirect"
        if code in {401, 403}:
            return "auth_failure"
        if code == 404:
            return "not_found"
        if code == 429:
            return "rate_limited"
        if 400 <= code <= 499:
            return "client_error"
        if 500 <= code <= 599:
            return "server_error"
        return "informational"

    @staticmethod
    def status_class(status: object) -> str:
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
