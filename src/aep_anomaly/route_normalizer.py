"""Conservative normalization of dynamic identifiers in request URIs."""

from __future__ import annotations

import re
from urllib.parse import urlsplit


_UUID_SEGMENT = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_LONG_NUMERIC_ID = re.compile(r"^[0-9]{6,}$")
_PLACEHOLDER = re.compile(r"^\{[^{}]+\}$")


class RouteNormalizer:
    """Remove URI query/fragment data and normalize clear identifier segments.

    Static numeric segments, route casing, extensions, and slash structure are
    preserved. Dynamic `{parameter}` segments, UUIDs, and numeric segments of
    six or more digits become ``:id``.
    """

    def normalize(self, uri: str | None) -> str:
        """Return a canonical path while retaining meaningful route details."""
        if uri is None or not str(uri).strip():
            return "unknown"

        raw_uri = str(uri).strip()
        try:
            path = urlsplit(raw_uri).path
        except ValueError:
            # Malformed bracketed URLs are still useful as route text. Remove
            # query/fragment suffixes without discarding the rest of the path.
            path = re.split(r"[?#]", raw_uri, maxsplit=1)[0]
        if not path:
            return "unknown"

        normalized_segments = []
        for segment in path.split("/"):
            if _PLACEHOLDER.fullmatch(segment) or _UUID_SEGMENT.fullmatch(segment) or _LONG_NUMERIC_ID.fullmatch(segment):
                normalized_segments.append(":id")
            else:
                normalized_segments.append(segment)

        normalized = "/".join(normalized_segments)
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized or "/"
