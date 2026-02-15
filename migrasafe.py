"""MigraSafe — Database migration risk analysis engine."""
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    score: int
    line: int
    message: str
    sql_snippet: str
    remediation: str


@dataclass
class AnalysisResult:
    file_path: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def total_score(self) -> int:
        return sum(f.score for f in self.findings)


RULES = [
    ("MS001", Severity.CRITICAL, 40,
     r"ALTER\s+TABLE\s+\S+\s+ADD\s+(?:COLUMN\s+)?\w+\s+\w+[^;]*\bNOT\s+NULL\b(?![^;]*\bDEFAULT\b)",
     "ADD NOT NULL column without DEFAULT — fails on non-empty tables",
     "Add DEFAULT value or split: add nullable -> backfill -> SET NOT NULL"),
    ("MS002", Severity.HIGH, 30,
     r"ALTER\s+TABLE\s+\S+\s+DROP\s+COLUMN\s+\w+",
     "DROP COLUMN is backward-incompatible; running code may still reference it",
     "Expand-contract: stop reading -> deploy -> drop in later migration"),
    ("MS003", Severity.HIGH, 25,
     r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)",
     "CREATE INDEX without CONCURRENTLY locks the table for writes",
     "Use CREATE INDEX CONCURRENTLY to avoid blocking writes"),
    ("MS004", Severity.HIGH, 30,
     r"ALTER\s+TABLE\s+\S+\s+RENAME\s+COLUMN\s+\w+",
     "RENAME COLUMN is backward-incompatible; old code uses old name",
     "Add new column -> copy data -> update code -> drop old column"),
    ("MS005", Severity.CRITICAL, 50,
     r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?\w+",
     "DROP TABLE causes irreversible data loss",
     "Ensure all services stopped using table; consider renaming first"),
    ("MS006", Severity.HIGH, 35,
     r"ALTER\s+TABLE\s+\S+\s+ALTER\s+COLUMN\s+\w+\s+(?:SET\s+DATA\s+)?TYPE",
     "ALTER COLUMN TYPE may cause full table rewrite and lock",
     "Use expand-contract or ensure cast is safe (e.g. varchar->text)"),
    ("MS007", Severity.MEDIUM, 20,
     r"ALTER\s+TABLE\s+\S+\s+ADD\s+(?:CONSTRAINT\s+\w+\s+)?UNIQUE",
     "ADD UNIQUE constraint requires full table scan and lock",
     "Create UNIQUE INDEX CONCURRENTLY first, then ADD CONSTRAINT USING INDEX"),
    ("MS101", Severity.MEDIUM, 20,
     r"RunPython\s*\(\s*\w+\s*\)",
     "RunPython without reverse function makes migration irreversible",
     "Add reverse: RunPython(forward, reverse) or RunPython(forward, RunPython.noop)"),
]


def analyze_sql(sql: str, file_path: str = "<stdin>", include_django: bool = True) -> AnalysisResult:
    result = AnalysisResult(file_path=file_path)
    active = [r for r in RULES if include_django or not r[0].startswith("MS1")]
    for rule_id, severity, score, pattern, message, remediation in active:
        for match in re.finditer(pattern, sql, re.IGNORECASE | re.MULTILINE):
            line = sql[:match.start()].count("\n") + 1
            snippet = match.group(0).strip()[:80]
            result.findings.append(Finding(
                rule_id, severity, score, line, message, snippet, remediation
            ))
    return result


def analyze_file(path: str, include_django: bool = True) -> AnalysisResult:
    content = Path(path).read_text(encoding="utf-8")
    return analyze_sql(content, file_path=path, include_django=include_django)


def risk_label(score: int) -> str:
    if score >= 50:
        return "CRITICAL"
    if score >= 30:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"
