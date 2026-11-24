"""Command-line interface for offline triage and opt-in enrichment."""

import argparse
from collections.abc import Sequence
import os
from pathlib import Path
import sys

import yaml

from .enrichment import enrich
from .parsers import FORMATS, parse
from .reports import write_reports
from .scoring import load_rules, triage


def _year(value: str) -> int:
    year = int(value)
    if not 1 <= year <= 9999:
        raise argparse.ArgumentTypeError("year must be between 1 and 9999")
    return year


def main(argv: Sequence[str] | None = None) -> int:
    """Read each declared input, then write JSON, CSV and Markdown reports."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", nargs=2, metavar=("FORMAT", "PATH"), action="append", required=True,
                        help="repeat for additional inputs (sysmon, suricata, auth, csv)")
    parser.add_argument("--output", required=True, type=Path, help="directory for the three reports")
    parser.add_argument("--risk-config", type=Path, help="custom YAML scoring rules")
    parser.add_argument("--auth-year", type=_year, metavar="YEAR",
                        help="year for traditional syslog (defaults to the current UTC year)")
    parser.add_argument("--enrich", action="store_true", help="send public IPs and domains to configured providers")
    args = parser.parse_args(argv)
    for log_format, _ in args.input:
        if log_format not in FORMATS:
            parser.error(f"unknown input format {log_format!r}; choose from {', '.join(FORMATS)}")
    try:
        rules = load_rules(args.risk_config)
        alerts = triage((alert for log_format, path in args.input
                         for alert in parse(Path(path), log_format, args.auth_year)), rules)
        indicators = {indicator for alert in alerts for indicator in alert.indicators}
        intelligence = enrich(indicators, os.environ) if args.enrich else []
        write_reports(args.output, alerts, intelligence)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"soc-triage: {error}", file=sys.stderr)
        return 1
    total = sum(alert.occurrences for alert in alerts)
    print(f"Read {total} records; wrote {len(alerts)} unique records and {len(indicators)} indicators.")
    print(f"Reports: {args.output / 'alerts.json'}, {args.output / 'alerts.csv'}, {args.output / 'incident.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
