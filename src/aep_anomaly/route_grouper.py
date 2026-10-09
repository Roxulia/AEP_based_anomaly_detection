"""Deterministic route-family grouping without probe-intent assumptions."""

from __future__ import annotations

class RouteGrouper:
    """Group normalized URLs into stable route families.

    API routes retain their API namespace and resource name. Other routes retain
    their first two path segments; single-segment routes remain distinct. Route
    legitimacy is decided only by the explicit application endpoint allowlist in
    preprocessing; this grouper does not infer probe intent.
    """

    def group(self, normalized_uri: str | None) -> str:
        if normalized_uri is None or not str(normalized_uri).strip() or normalized_uri == "unknown":
            return "unknown"
        path = str(normalized_uri).split("?", 1)[0].split("#", 1)[0]
        segments = [segment for segment in path.strip("/").split("/")
                    if segment and segment != ":id"]
        if not segments:
            return "root"
        if segments[0].lower() == "api" and len(segments) >= 3:
            return ".".join(segment.lower() for segment in segments[:3])
        if len(segments) >= 2:
            return ".".join(segment.lower() for segment in segments[:2])
        return f"route.{segments[0].lower()}"
