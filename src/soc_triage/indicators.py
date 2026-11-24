"""Extract and canonicalize common SOC observables from structured records."""

from collections.abc import Iterator
from ipaddress import ip_address
import re
from urllib.parse import urlsplit

from .model import Indicator

URL = re.compile(r"https?://[^\s<>\"']+", re.I)
DOMAIN = re.compile(r"(?<![\w.@-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])", re.I)
IP = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])|(?<![\w:/])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*(?!\w)", re.I)
HASH = re.compile(r"\b(?:[a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
STRUCTURAL_FIELDS = {"image", "parentimage", "sourceimage", "targetimage", "process.executable",
                     "filename", "computer", "hostname", "computername", "host", "provider"}
FILE_SUFFIXES = {"exe", "dll", "ps1", "bat", "cmd", "log", "txt", "json", "csv", "xml", "zip", "evtx"}


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key.casefold() not in STRUCTURAL_FIELDS:
                yield from _strings(item)


def _host(value: str) -> Indicator | None:
    hostname = value.strip("[]").rstrip(".").lower()
    try:
        return Indicator("ip", str(ip_address(hostname)))
    except ValueError:
        if len(hostname) <= 253 and DOMAIN.fullmatch(hostname):
            return Indicator("domain", hostname)
        return None


def extract_indicators(record: dict) -> list[Indicator]:
    """Return distinct IPs, domains, HTTP(S) URLs and hex digests."""
    found: set[Indicator] = set()
    for value in _strings(record):
        for match in URL.finditer(value):
            url = match.group().rstrip(".,;!?)}")
            try:
                parsed = urlsplit(url)
                host = _host(parsed.hostname or "")
                port = parsed.port
            except ValueError:
                continue
            if host and parsed.username is None and port != 0:
                # Query strings and fragments can contain credentials or session IDs.
                authority = host.value
                if host.kind == "ip" and ":" in authority:
                    authority = f"[{authority}]"
                if port is not None:
                    authority = f"{authority}:{port}"
                found.add(Indicator("url", parsed._replace(netloc=authority, query="", fragment="").geturl()))
                found.add(host)
        text = URL.sub(" ", value)
        for match in IP.finditer(text):
            host = _host(match.group().rstrip("."))
            if host and host.kind == "ip":
                found.add(host)
        for match in DOMAIN.finditer(text):
            domain = match.group().lower()
            if domain.rsplit(".", 1)[1] not in FILE_SUFFIXES:
                found.add(Indicator("domain", domain))
        for match in HASH.finditer(text):
            found.add(Indicator("hash", match.group().lower()))
    return sorted(found)
