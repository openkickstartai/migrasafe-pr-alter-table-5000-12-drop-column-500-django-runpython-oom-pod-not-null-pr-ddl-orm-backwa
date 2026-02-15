#!/usr/bin/env python3
"""MigraSafe CLI — scan migration files for risky DDL operations."""
import json
import sys

import click
from rich.console import Console
from rich.table import Table

from migrasafe import analyze_file, risk_label

console = Console()
COLORS = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}


@click.command("migrasafe")
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--threshold", "-t", default=30, help="Block if total risk score >= threshold")
@click.option("--format", "-f", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--no-django", is_flag=True, help="Disable Django-specific rules")
def main(paths, threshold, fmt, no_django):
    """Analyze database migration files for dangerous operations."""
    if not paths:
        console.print("[yellow]Usage: python cli.py <migration_files...>[/]")
        sys.exit(0)
    all_findings, total = [], 0
    for p in paths:
        r = analyze_file(p, include_django=not no_django)
        all_findings.extend(r.findings)
        total += r.total_score
    if fmt == "json":
        data = [{"rule": f.rule_id, "severity": f.severity.name, "line": f.line,
                 "message": f.message, "score": f.score, "remediation": f.remediation}
                for f in all_findings]
        click.echo(json.dumps({"findings": data, "total_score": total,
                               "passed": total < threshold}, indent=2))
        sys.exit(0 if total < threshold else 1)
    if all_findings:
        tbl = Table(title="\U0001f6e1  MigraSafe Analysis", show_lines=True)
        for col, st, kw in [("Rule", "cyan", {}), ("Severity", "bold", {}),
                             ("Ln", "", {"justify": "right"}), ("Issue", "", {}),
                             ("Pts", "", {"justify": "right"})]:
            tbl.add_column(col, style=st, **kw)
        for f in all_findings:
            c = COLORS[f.severity.name]
            tbl.add_row(f.rule_id, f"[{c}]{f.severity.name}[/]",
                        str(f.line), f.message, str(f.score))
        console.print(tbl)
        console.print("\n[dim]Remediations:[/]")
        for f in all_findings:
            console.print(f"  [cyan]{f.rule_id}[/]: {f.remediation}")
    label = risk_label(total)
    c = COLORS[label]
    console.print(f"\n  Risk Score: [{c}]{total}[/] ({label}) | Threshold: {threshold}")
    if total >= threshold:
        console.print(f"  [red bold]\u2717 BLOCKED[/] \u2014 score {total} >= {threshold}\n")
        sys.exit(1)
    console.print(f"  [green bold]\u2713 PASSED[/] \u2014 score {total} < {threshold}\n")


if __name__ == "__main__":
    main()
