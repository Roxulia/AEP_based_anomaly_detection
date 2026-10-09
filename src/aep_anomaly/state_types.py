"""Data-processing contract for opaque request state identifiers."""

from __future__ import annotations

StateId = str
EventState = StateId
StateSequence = tuple[StateId, ...]
StateDescription = dict[str, str]
