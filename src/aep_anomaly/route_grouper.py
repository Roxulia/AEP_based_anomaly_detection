"""Deterministic route-family and security-probe grouping."""

from __future__ import annotations

import re


_PROBE_RULES = (
    (re.compile(r"(?:^|/)\.env(?:$|/|\.)", re.IGNORECASE), "security_probe.credentials"),
    (re.compile(r"(?:^|/)\.aws(?:$|/)", re.IGNORECASE), "security_probe.credentials"),
    (re.compile(r"(?:^|/)\.git(?:$|/)", re.IGNORECASE), "security_probe.version_control"),
    (re.compile(r"(?:^|/)wp-admin(?:$|/)", re.IGNORECASE), "security_probe.cms_admin"),
    (re.compile(r"(?:^|/)etc/passwd(?:$|/)", re.IGNORECASE), "security_probe.system_file"),
    (re.compile(r"(?:^|/)\.\.(?:/|$)"), "security_probe.path_traversal"),
)


class RouteGrouper:
    """Group normalized URLs into stable route families.

    API routes retain their API namespace and resource name. Other routes retain
    their first two path segments; single-segment routes remain distinct. Known
    credential, source-control, CMS, system-file, and traversal probes receive
    dedicated groups so grouping does not hide common scan patterns.
    """

    def group(self, normalized_uri: str | None) -> str:
        if normalized_uri is None or not str(normalized_uri).strip() or normalized_uri == "unknown":
            return "unknown"
        path = str(normalized_uri).split("?", 1)[0].split("#", 1)[0]
        for pattern, group in _PROBE_RULES:
            if pattern.search(path):
                return group

        segments = [segment for segment in path.strip("/").split("/")
                    if segment and segment != ":id"]
        if not segments:
            return "root"
        if segments[0].lower() == "api" and len(segments) >= 3:
            return ".".join(segment.lower() for segment in segments[:3])
        if len(segments) >= 2:
            return ".".join(segment.lower() for segment in segments[:2])
        return f"route.{segments[0].lower()}"
