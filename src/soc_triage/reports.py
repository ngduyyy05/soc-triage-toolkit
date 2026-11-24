"""Serialize normalized alerts and enrichment into analyst-facing reports."""

import csv
from dataclasses import asdict
import html
import json
from pathlib import Path
import re

from .model import Alert

COLUMNS = ("fingerprint", "log_format", "timestamp", "host", "event_code", "action",
           "message", "occurrences", "score", "attack", "indicators", "enrichment")


def _safe_csv(value: object) -> object:
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _markdown(value: str) -> str:
    normalized = " ".join(value.splitlines())
    return re.sub(r"([\\`*_{}\[\]()#+|!])", r"\\\1", html.escape(normalized))


def write_reports(directory: Path, alerts: list[Alert], intelligence: list[dict]) -> None:
    """Write structured alerts and a Markdown incident brief."""
    directory.mkdir(parents=True, exist_ok=True)
    records = [{"fingerprint": alert.fingerprint, **asdict(alert)} for alert in alerts]
    by_indicator = {(item["kind"], item["value"]): item for item in intelligence}
    for record, alert in zip(records, alerts):
        record["enrichment"] = [by_indicator[(ioc.kind, ioc.value)] for ioc in alert.indicators
                                if (ioc.kind, ioc.value) in by_indicator]
    with (directory / "alerts.json").open("w", encoding="utf-8") as file:
        json.dump({"alerts": records, "enrichment": intelligence}, file, indent=2, ensure_ascii=False)
        file.write("\n")
    with (directory / "alerts.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=COLUMNS)
        writer.writeheader()
        for record in records:
            row = {name: _safe_csv(record[name]) for name in COLUMNS}
            for name in ("attack", "indicators", "enrichment"):
                row[name] = json.dumps(record[name], ensure_ascii=False)
            writer.writerow(row)
    lines = ["# Incident triage report", "", f"Records read: {sum(a.occurrences for a in alerts)}  ",
             f"Unique records: {len(alerts)}  ", f"Indicators: {len({ioc for a in alerts for ioc in a.indicators})}",
             "", "## Prioritized records", "", "| Score | Occurrences | Time | Source | Event | ATT&CK |",
             "| --- | --- | --- | --- | --- | --- |"]
    for alert in alerts:
        label = alert.message or alert.event_code or alert.action
        source = " / ".join(filter(None, (alert.log_format, alert.host)))
        lines.append(f"| {alert.score} | {alert.occurrences} | {_markdown(alert.timestamp)} | "
                     f"{_markdown(source)} | {_markdown(label)} | {', '.join(alert.attack)} |")
    lines.extend(["", "## Indicators", "", "| Type | Value | Enrichment |", "| --- | --- | --- |"])
    for ioc in sorted({ioc for alert in alerts for ioc in alert.indicators}):
        result = by_indicator.get((ioc.kind, ioc.value))
        status = json.dumps(result.get("providers") or result.get("status")) if result else "not requested"
        lines.append(f"| {ioc.kind} | {_markdown(ioc.value)} | {_markdown(status)} |")
    (directory / "incident.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
