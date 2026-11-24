"""Load declarative scoring rules and combine their matches per alert."""

from collections.abc import Iterable
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
import re

import yaml

from .model import Alert

MATCH_FIELDS = {"log_format", "event_code", "action", "host"}
TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")


@dataclass(frozen=True)
class Rule:
    """Award points and ATT&CK tags when every matching field agrees."""

    conditions: dict[str, str]
    points: int
    attack: tuple[str, ...]


def load_rules(path: Path | None) -> list[Rule]:
    """Load and validate the bundled policy or a user-supplied policy."""
    source = path or files("soc_triage").joinpath("risk.yml")
    contents = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(contents, dict) or not isinstance(contents.get("rules"), list):
        raise ValueError("Risk configuration requires a rules list")
    rules = []
    for index, item in enumerate(contents["rules"], 1):
        if not isinstance(item, dict) or set(item) - {"match", "points", "attack"}:
            raise ValueError(f"Invalid risk rule {index}")
        conditions = item.get("match")
        points = item.get("points")
        attack = item.get("attack", [])
        if not isinstance(conditions, dict) or not conditions or conditions.keys() - MATCH_FIELDS:
            raise ValueError(f"Risk rule {index} has invalid match fields")
        if any(type(value) not in (str, int) for value in conditions.values()):
            raise ValueError(f"Risk rule {index} requires scalar string or integer conditions")
        if type(points) is not int or not 0 <= points <= 100:
            raise ValueError(f"Risk rule {index} requires integer points from 0 to 100")
        if not isinstance(attack, list) or not all(isinstance(tag, str) and TECHNIQUE.fullmatch(tag) for tag in attack):
            raise ValueError(f"Risk rule {index} contains invalid ATT&CK IDs")
        rules.append(Rule({key: str(value) for key, value in conditions.items()}, points, tuple(attack)))
    return rules


def triage(alerts: Iterable[Alert], rules: list[Rule]) -> list[Alert]:
    """Deduplicate exact records and order them by descending capped score."""
    unique: dict[str, Alert] = {}
    for alert in alerts:
        fingerprint = alert.fingerprint
        if fingerprint in unique:
            unique[fingerprint].occurrences += 1
            continue
        tags: set[str] = set()
        for rule in rules:
            if all(getattr(alert, field) == value for field, value in rule.conditions.items()):
                alert.score = min(100, alert.score + rule.points)
                tags.update(rule.attack)
        alert.attack = sorted(tags)
        unique[fingerprint] = alert
    return sorted(unique.values(), key=lambda alert: (-alert.score, alert.timestamp, alert.fingerprint))
