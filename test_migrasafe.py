"""Comprehensive tests for MigraSafe migration risk analyzer."""
import pytest
from hypothesis import given, strategies as st
from migrasafe import analyze_sql, AnalysisResult, Severity, risk_label


class TestMS001NotNullWithoutDefault:
    def test_detects_not_null_no_default(self):
        r = analyze_sql("ALTER TABLE users ADD COLUMN email VARCHAR(255) NOT NULL;")
        assert any(f.rule_id == "MS001" for f in r.findings)
        assert r.total_score >= 40

    def test_allows_not_null_with_default(self):
        r = analyze_sql("ALTER TABLE users ADD COLUMN email VARCHAR(255) NOT NULL DEFAULT '';")
        assert not any(f.rule_id == "MS001" for f in r.findings)


class TestMS002DropColumn:
    def test_detects_drop_column(self):
        r = analyze_sql("ALTER TABLE users DROP COLUMN legacy_field;")
        assert any(f.rule_id == "MS002" for f in r.findings)
        assert r.findings[0].severity == Severity.HIGH


class TestMS003CreateIndex:
    def test_blocks_non_concurrent_index(self):
        r = analyze_sql("CREATE INDEX idx_email ON users (email);")
        assert any(f.rule_id == "MS003" for f in r.findings)

    def test_allows_concurrent_index(self):
        r = analyze_sql("CREATE INDEX CONCURRENTLY idx_email ON users (email);")
        assert not any(f.rule_id == "MS003" for f in r.findings)

    def test_blocks_unique_non_concurrent(self):
        r = analyze_sql("CREATE UNIQUE INDEX idx_uniq ON users (email);")
        assert any(f.rule_id == "MS003" for f in r.findings)


class TestMS004RenameColumn:
    def test_detects_rename(self):
        r = analyze_sql("ALTER TABLE users RENAME COLUMN old_name TO new_name;")
        assert any(f.rule_id == "MS004" for f in r.findings)


class TestMS005DropTable:
    def test_detects_drop_table(self):
        r = analyze_sql("DROP TABLE old_users;")
        assert any(f.rule_id == "MS005" for f in r.findings)
        assert r.total_score >= 50

    def test_detects_drop_table_if_exists(self):
        r = analyze_sql("DROP TABLE IF EXISTS old_users;")
        assert any(f.rule_id == "MS005" for f in r.findings)


class TestMS006AlterColumnType:
    def test_detects_type_change(self):
        r = analyze_sql("ALTER TABLE users ALTER COLUMN age SET DATA TYPE bigint;")
        assert any(f.rule_id == "MS006" for f in r.findings)

    def test_detects_short_type_syntax(self):
        r = analyze_sql("ALTER TABLE users ALTER COLUMN age TYPE bigint;")
        assert any(f.rule_id == "MS006" for f in r.findings)


class TestMS101DjangoRunPython:
    def test_detects_irreversible_runpython(self):
        r = analyze_sql("RunPython(populate_data)")
        assert any(f.rule_id == "MS101" for f in r.findings)

    def test_skips_django_when_disabled(self):
        r = analyze_sql("RunPython(populate_data)", include_django=False)
        assert not any(f.rule_id.startswith("MS1") for f in r.findings)


class TestScoring:
    def test_safe_sql_scores_zero(self):
        r = analyze_sql("SELECT 1; INSERT INTO logs VALUES (1);")
        assert r.total_score == 0
        assert len(r.findings) == 0

    def test_multiple_issues_accumulate(self):
        sql = "ALTER TABLE t DROP COLUMN a;\nDROP TABLE t;\nCREATE INDEX i ON t(c);"
        r = analyze_sql(sql)
        assert r.total_score >= 105
        assert len(r.findings) >= 3

    def test_line_numbers_tracked(self):
        sql = "SELECT 1;\nDROP TABLE users;"
        r = analyze_sql(sql)
        assert r.findings[0].line == 2


class TestRiskLabel:
    @pytest.mark.parametrize("score,expected", [
        (0, "LOW"), (14, "LOW"), (15, "MEDIUM"), (29, "MEDIUM"),
        (30, "HIGH"), (49, "HIGH"), (50, "CRITICAL"), (999, "CRITICAL"),
    ])
    def test_labels(self, score, expected):
        assert risk_label(score) == expected


class TestPropertyBased:
    @given(st.text(min_size=0, max_size=500))
    def test_never_crashes_on_arbitrary_input(self, sql):
        r = analyze_sql(sql)
        assert isinstance(r, AnalysisResult)
        assert r.total_score >= 0

    @given(st.lists(st.sampled_from([
        "ALTER TABLE t ADD COLUMN c INT NOT NULL;",
        "ALTER TABLE t DROP COLUMN c;",
        "CREATE INDEX i ON t(c);",
        "DROP TABLE t;",
        "SELECT 1;",
    ]), min_size=1, max_size=8))
    def test_score_non_negative_for_combinations(self, stmts):
        r = analyze_sql("\n".join(stmts))
        assert r.total_score >= 0
        assert all(f.score > 0 for f in r.findings)
