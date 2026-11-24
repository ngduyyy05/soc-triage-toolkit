"""Data model shared by the parsers and report writers."""

from dataclasses import dataclass, field
from hashlib import sha256
import json


@dataclass(frozen=True, order=True)
class Indicator:
    """Canonical observable extracted from a log record."""

    kind: str
    value: str


@dataclass
class Alert:
    """One normalized record with analysis fields and an occurrence count."""

    log_format: str
    timestamp: str
    host: str
    event_code: str
    action: str
    message: str
    details: dict
    indicators: list[Indicator] = field(default_factory=list)
    occurrences: int = 1
    score: int = 0
    attack: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Hash source and record content independently of scoring or enrichment."""
        normalized = {
            "format": self.log_format,
            "timestamp": self.timestamp,
            "host": self.host,
            "event_code": self.event_code,
            "action": self.action,
            "message": self.message,
            "details": self.details,
        }
        payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        return sha256(payload.encode("utf-8")).hexdigest()
