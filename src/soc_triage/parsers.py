"""Read JSON telemetry, Linux syslog authentication records and CSV exports."""

from collections.abc import Iterator
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import TextIO

from .indicators import extract_indicators
from .model import Alert

FORMATS = ("sysmon", "suricata", "auth", "csv")
SYSLOG = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\S*T\S+)\s+"
    r"(?P<host>\S+)\s+(?P<service>[^\s:\[]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)


def _records(file: TextIO) -> Iterator[dict]:
    start = file.tell()
    first = file.read(1)
    while first and first.isspace():
        first = file.read(1)
    file.seek(start)
    if first == "[":
        records = json.load(file)
        if not all(isinstance(record, dict) for record in records):
            raise ValueError("JSON array entries must be objects")
        yield from records
        return
    seen = False
    try:
        for line_number, line in enumerate(file, 1):
            if line.strip():
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError(f"JSON line {line_number} must be an object")
                seen = True
                yield record
    except json.JSONDecodeError as error:
        if seen:
            raise ValueError(f"Invalid JSON on line {line_number}: {error.msg}") from error
        # Also accept a single pretty-printed event export.
        file.seek(start)
        record = json.load(file)
        if not isinstance(record, dict):
            raise ValueError("Expected a JSON event object")
        yield record


def _event_data(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    if "Data" in value:
        fields = value["Data"]
        if isinstance(fields, dict):
            fields = [fields]
        if isinstance(fields, list):
            return {str(item.get("Name", item.get("@Name"))): item.get("Value", item.get("#text", ""))
                    for item in fields if isinstance(item, dict) and ("Name" in item or "@Name" in item)}
    return value


def _alert(log_format: str, timestamp: object, host: object, code: object,
           action: object, message: object, details: dict) -> Alert:
    def get_text(value: object) -> str:
        return "" if value is None else str(value)
    return Alert(log_format, get_text(timestamp), get_text(host), get_text(code),
                 get_text(action), get_text(message), details, extract_indicators(details))


def _sysmon(record: dict) -> Alert:
    winlog = record.get("winlog") or {}
    event = record.get("event") or {}
    event_wrapper = record.get("Event", record)
    system = event_wrapper.get("System") or {}
    data = _event_data(winlog.get("event_data") or event_wrapper.get("EventData")
                       or record.get("EventData"))
    source_time = system.get("TimeCreated") or {}
    if isinstance(source_time, dict):
        source_time = source_time.get("SystemTime", source_time.get("@SystemTime"))
    code = event.get("code") or winlog.get("event_id") or system.get("EventID") or record.get("EventID")
    if isinstance(code, dict):
        code = code.get("#text", code.get("Value"))
    host = record.get("host")
    if isinstance(host, dict):
        host = host.get("name", host.get("hostname"))
    action = event.get("action", "")
    if str(code) == "10" and str(data.get("TargetImage", "")).casefold().endswith("\\lsass.exe"):
        action = "lsass_access"
    return _alert("sysmon", record.get("@timestamp") or source_time or record.get("TimeCreated"),
                  host or winlog.get("computer_name") or system.get("Computer") or record.get("MachineName"),
                  code or record.get("Id"), action,
                  record.get("message") or data.get("CommandLine", ""),
                  {**record, "event_data": data})


def _suricata(record: dict) -> Alert:
    signature = record.get("alert") or {}
    http = record.get("http") or {}
    dns = record.get("dns") or {}
    message = signature.get("signature") or http.get("hostname") or dns.get("rrname", "")
    return _alert("suricata", record.get("timestamp"), record.get("host"),
                  signature.get("signature_id"), record.get("event_type"), message, record)


def _auth(file: TextIO, year: int) -> Iterator[Alert]:
    for line_number, line in enumerate(file, 1):
        if not line.strip():
            continue
        match = SYSLOG.fullmatch(line.rstrip("\r\n"))
        if not match:
            raise ValueError(f"Unsupported auth.log syntax on line {line_number}")
        timestamp = match["timestamp"]
        if timestamp[0].isalpha():
            timestamp = datetime.strptime(f"{year} {timestamp}", "%Y %b %d %H:%M:%S").isoformat()
        message = match["message"]
        action = match["service"]
        if action == "sshd":
            if message.startswith(("Failed ", "Invalid user ")):
                action = "ssh_failure"
            elif message.startswith("Accepted "):
                action = "ssh_success"
        yield _alert("auth", timestamp, match["host"], "", action, message,
                     {"service": match["service"], "message": message})


def _csv(file: TextIO) -> Iterator[Alert]:
    reader = csv.DictReader(file, strict=True)
    names = reader.fieldnames
    if not names or any(not name for name in names) or len(set(names)) != len(names):
        raise ValueError("CSV requires distinct, nonempty column names")
    for row in reader:
        if None in row or None in row.values():
            raise ValueError(f"CSV row {reader.line_num} does not match the header")
        yield _alert("csv", row.get("timestamp"), row.get("host"), row.get("event_code"),
                     row.get("action"), row.get("message"), row)


def parse(path: Path, log_format: str, auth_year: int | None = None) -> Iterator[Alert]:
    """Read one UTF-8 input, reporting malformed data with its source file."""
    with path.open(encoding="utf-8-sig", newline="") as file:
        try:
            if log_format == "auth":
                yield from _auth(file, auth_year or datetime.now(timezone.utc).year)
            elif log_format == "csv":
                yield from _csv(file)
            else:
                parser = {"sysmon": _sysmon, "suricata": _suricata}[log_format]
                for record in _records(file):
                    yield parser(record)
        except (ValueError, TypeError, AttributeError, csv.Error) as error:
            raise ValueError(f"{path.name}: {error}") from error
