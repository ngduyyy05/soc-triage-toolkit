"""Regression tests for supported exports, enrichment and the CLI."""

import csv
import json
from pathlib import Path
from urllib.error import HTTPError

import pytest

from soc_triage.cli import main
from soc_triage.enrichment import enrich
from soc_triage.indicators import extract_indicators
from soc_triage.model import Indicator
from soc_triage.parsers import parse
from soc_triage.scoring import load_rules, triage

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_cli_reads_all_formats_and_writes_reports(tmp_path, capsys):
    args = ["--auth-year", "2025", "--output", str(tmp_path)]
    for log_format, filename in [
        ("sysmon", "sysmon.jsonl"), ("sysmon", "sysmon-export.json"),
        ("suricata", "eve.jsonl"), ("auth", "auth.log"), ("csv", "events.csv"),
    ]:
        args.extend(("--input", log_format, str(SAMPLES / filename)))
    assert main(args) == 0
    assert "Read 7 records; wrote 6 unique records" in capsys.readouterr().out
    report = json.loads((tmp_path / "alerts.json").read_text(encoding="utf-8"))
    assert report["enrichment"] == []
    first = report["alerts"][0]
    assert (first["score"], first["occurrences"]) == (35, 2)
    assert any(a["attack"] == ["T1110.001"] for a in report["alerts"])
    assert any(a["attack"] == ["T1003.001"] for a in report["alerts"])
    assert any({"kind": "domain", "value": "lookup.example.test"} in a["indicators"] for a in report["alerts"])
    with (tmp_path / "alerts.csv").open(encoding="utf-8", newline="") as file:
        assert len(list(csv.DictReader(file))) == 6
    assert "Unique records: 6" in (tmp_path / "incident.md").read_text(encoding="utf-8")


def test_enrichment_both_providers_and_domain(monkeypatch):
    calls = []

    def response(request):
        calls.append(request)
        if request.host == "api.abuseipdb.com":
            return {"data": {"abuseConfidenceScore": 19, "totalReports": 2}}
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 2}}}}

    env = {"ABUSEIPDB_API_KEY": "mock-only", "VIRUSTOTAL_API_KEY": "mock-only"}
    monkeypatch.setattr("soc_triage.enrichment._public", lambda _: True)
    ip = Indicator("ip", "192.0.2.5")
    data = enrich([ip, ip, Indicator("domain", "lookup.example.test")], env, requester=response)
    assert len(calls) == 3
    assert calls[0].full_url.endswith("/domains/lookup.example.test")
    assert calls[1].get_header("X-apikey") == "mock-only"
    assert "ipAddress=192.0.2.5" in calls[2].full_url
    assert data[1]["providers"]["abuseipdb"]["totalReports"] == 2


def test_enrichment_statuses(monkeypatch):
    def error(request):
        raise HTTPError(request.full_url, 429, "rate limit", None, None)

    ip = Indicator("ip", "192.0.2.5")
    domain = Indicator("domain", "lookup.example.test")
    assert all(record["status"] == "skipped_nonpublic" for record in enrich([ip, domain], {}))
    monkeypatch.setattr("soc_triage.enrichment._public", lambda _: True)
    records = enrich([domain], {"VIRUSTOTAL_API_KEY": "mock-only"}, requester=error)
    assert records[0]["providers"]["virustotal"] == {"status": "http_error", "code": 429}
    assert enrich([domain], {})[0]["providers"] == {
        "virustotal": {"status": "missing_key"}
    }


def test_indicator_validation():
    result = extract_indicators({"message": "HTTPS://DEMO.EXAMPLE.TEST/get?private=1, "
                                    "2001:db8::7; 999.40.0.1 and utility.exe"})
    assert Indicator("ip", "2001:db8::7") in result
    assert Indicator("domain", "demo.example.test") in result
    assert Indicator("url", "https://demo.example.test/get") in result
    assert len(result) == 3


def test_risk_yaml_override(tmp_path):
    path = tmp_path / "risk.yml"
    path.write_text("rules:\n  - match: {log_format: auth}\n    points: 60\n"
                    "  - match: {action: ssh_failure}\n    points: 60\n    attack: [T1110.001]\n")
    records = triage(parse(SAMPLES / "auth.log", "auth", 2025), load_rules(path))
    assert [(record.score, record.attack) for record in records] == [(100, ["T1110.001"]), (60, [])]
    path.write_text("rules: unexpected")
    with pytest.raises(ValueError, match="rules list"):
        load_rules(path)


@pytest.mark.parametrize(("log_format", "contents"), [("sysmon", '[{"ok":1}, false]'), ("csv", "a,b\n1"),
                                                      ("auth", "ordinary text")])
def test_malformed_input_fails_without_writing_reports(tmp_path, capsys, log_format, contents):
    path = tmp_path / "bad-input.txt"
    path.write_text(contents, encoding="utf-8")
    out = tmp_path / "out"
    assert main(["--input", log_format, str(path), "--output", str(out)]) == 1
    assert "bad-input.txt" in capsys.readouterr().err
    assert not out.exists()
