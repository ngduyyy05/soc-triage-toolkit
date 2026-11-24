"""Look up public indicators with fixed provider endpoints and optional keys."""

from collections.abc import Callable, Iterable, Mapping
from ipaddress import ip_address
import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .model import Indicator

Requester = Callable[[Request], dict]
LOCAL_DOMAIN_SUFFIXES = (".test", ".example", ".invalid", ".localhost", ".local", ".internal", ".onion", ".arpa")
EXAMPLE_DOMAINS = ("example.com", "example.org", "example.net")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Prevent API credentials from following a redirect."""
        return None


def _request(request: Request) -> dict:
    with build_opener(_NoRedirect()).open(request, timeout=10) as response:
        return json.load(response)


def _public(indicator: Indicator) -> bool:
    if indicator.kind == "ip":
        address = ip_address(indicator.value)
        return address.is_global and not address.is_multicast and not address.is_reserved
    domain = indicator.value
    return (not domain.endswith(LOCAL_DOMAIN_SUFFIXES)
            and not any(domain == base or domain.endswith("." + base) for base in EXAMPLE_DOMAINS))


def _fetch(provider: str, request: Request, requester: Requester) -> dict:
    try:
        contents = requester(request)["data"]
        if provider == "virustotal":
            stats = contents["attributes"]["last_analysis_stats"]
            data = {field: stats[field] for field in ("malicious", "suspicious", "harmless", "undetected")
                    if field in stats}
        else:
            data = {field: contents[field] for field in ("abuseConfidenceScore", "totalReports") if field in contents}
        if not data or not all(type(value) is int and value >= 0 for value in data.values()):
            return {"status": "invalid_response"}
        return {"status": "ok", **data}
    except HTTPError as error:
        return {"status": "http_error", "code": error.code}
    except (URLError, TimeoutError, OSError):
        return {"status": "network_error"}
    except (KeyError, TypeError, ValueError):
        return {"status": "invalid_response"}


def enrich(indicators: Iterable[Indicator], env: Mapping[str, str],
           requester: Requester = _request) -> list[dict]:
    """Return per-provider status and reputation for each distinct public observable."""
    results = []
    for indicator in sorted(set(indicators)):
        if indicator.kind not in {"ip", "domain"}:
            continue
        result = {"kind": indicator.kind, "value": indicator.value, "providers": {}}
        results.append(result)
        if not _public(indicator):
            result["status"] = "skipped_nonpublic"
            continue
        providers = result["providers"]
        vt_key = env.get("VIRUSTOTAL_API_KEY")
        if vt_key:
            resource = "ip_addresses" if indicator.kind == "ip" else "domains"
            url = f"https://www.virustotal.com/api/v3/{resource}/{quote(indicator.value, safe='')}"
            providers["virustotal"] = _fetch("virustotal", Request(url, headers={"x-apikey": vt_key}), requester)
        else:
            providers["virustotal"] = {"status": "missing_key"}
        if indicator.kind == "ip":
            abuse_key = env.get("ABUSEIPDB_API_KEY")
            if abuse_key:
                query = urlencode({"ipAddress": indicator.value, "maxAgeInDays": 90})
                request = Request(f"https://api.abuseipdb.com/api/v2/check?{query}",
                                  headers={"Key": abuse_key, "Accept": "application/json"})
                providers["abuseipdb"] = _fetch("abuseipdb", request, requester)
            else:
                providers["abuseipdb"] = {"status": "missing_key"}
    return results
