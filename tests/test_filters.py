"""Pure ingress-filter matching and validation tests (no database required)."""
from __future__ import annotations

from ringdown.filters import (
    CompiledIngressFilter,
    FilterValidationError,
    IngressFilterSet,
    historical_predicate,
    validate_filter_spec,
)


def _row(**overrides):
    row = {
        "id": 1,
        "name": "test",
        "match_type": "substring",
        "pattern": "Routine Job",
        "source_glob": None,
        "program_glob": None,
        "case_sensitive": False,
        "filter_order": 100,
    }
    row.update(overrides)
    return row


def _event(**overrides):
    event = {
        "source": "database",
        "program": "systemd",
        "body": "Finished routine job successfully.",
    }
    event.update(overrides)
    return event


def test_substring_defaults_to_case_insensitive():
    ingress_filter = CompiledIngressFilter.from_row(_row())
    assert ingress_filter.matches(_event())


def test_case_sensitive_substring_and_scopes():
    ingress_filter = CompiledIngressFilter.from_row(_row(
        pattern="routine job", case_sensitive=True,
        source_glob="data*", program_glob="system?"))
    assert ingress_filter.matches(_event())
    assert not ingress_filter.matches(_event(body="Finished ROUTINE JOB successfully."))
    assert not ingress_filter.matches(_event(source="maildir"))
    assert not ingress_filter.matches(_event(program="CRON"))


def test_re2_regex_matches_without_backtracking_features():
    ingress_filter = CompiledIngressFilter.from_row(_row(
        match_type="regex", pattern=r"phpsessionclean\.(service|timer)",
        case_sensitive=False))
    assert ingress_filter.matches(_event(body="Finished PHPSESSIONCLEAN.service"))
    assert not ingress_filter.matches(_event(body="unrelated"))


def test_re2_rejects_lookaround():
    try:
        validate_filter_spec(
            name="bad", match_type="regex", pattern=r"foo(?=bar)")
    except FilterValidationError as exc:
        assert "invalid RE2" in str(exc)
    else:
        raise AssertionError("RE2 lookaround should be rejected")


def test_validation_rejects_ambiguous_or_inconsistent_globs():
    for source_glob in ("db,mail", "db host", "db[12]"):
        try:
            validate_filter_spec(
                name="bad glob", match_type="substring", pattern="noise",
                source_glob=source_glob)
        except FilterValidationError:
            pass
        else:
            raise AssertionError(f"glob {source_glob!r} should be rejected")


def test_validation_rejects_wrong_json_scalar_types():
    for kwargs in (
        {"name": 7, "case_sensitive": False, "filter_order": 100},
        {"name": "typed", "case_sensitive": "false", "filter_order": 100},
        {"name": "typed", "case_sensitive": False, "filter_order": True},
    ):
        try:
            validate_filter_spec(
                name=kwargs["name"], match_type="substring", pattern="noise",
                case_sensitive=kwargs["case_sensitive"], filter_order=kwargs["filter_order"])
        except FilterValidationError:
            pass
        else:
            raise AssertionError(f"invalid scalar types should be rejected: {kwargs}")


def test_first_match_wins_and_drop_stats_do_not_retain_bodies():
    filter_set = IngressFilterSet(pool=None)
    filter_set._filters = [
        CompiledIngressFilter.from_row(_row(id=4, name="first", pattern="routine")),
        CompiledIngressFilter.from_row(_row(id=5, name="second", pattern="job")),
    ]
    accepted, dropped = filter_set.partition([
        _event(source="database"),
        _event(source="maildir", body="important"),
        _event(source="database"),
    ])
    assert [event["body"] for event in accepted] == ["important"]
    assert dropped == {(4, "database"): 2}
    assert all("routine" not in str(key).lower() for key in dropped)


def test_php_session_cleanup_seed_shapes():
    service = CompiledIngressFilter.from_row(_row(
        id=40, name="PHP session cleanup lifecycle", match_type="regex",
        pattern=(r"^(?:Starting phpsessionclean\.service - Clean php session files\.\.\.|"
                 r"Finished phpsessionclean\.service - Clean php session files\.|"
                 r"phpsessionclean\.service: Deactivated successfully\.)$"),
        program_glob="systemd"))
    cron = CompiledIngressFilter.from_row(_row(
        id=50, pattern="/usr/lib/php/sessionclean", program_glob="CRON"))
    for body in (
        "Finished phpsessionclean.service - Clean php session files.",
        "phpsessionclean.service: Deactivated successfully.",
        "Starting phpsessionclean.service - Clean php session files...",
    ):
        assert service.matches(_event(program="systemd", body=body))
    assert cron.matches(_event(
        program="CRON",
        body="(root) CMD ( [ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean)"))
    assert not service.matches(_event(
        program="systemd",
        body="phpsessionclean.service: Failed with result 'exit-code'."))


def test_existing_rsyslog_cron_seed_shapes():
    debian_sa1 = CompiledIngressFilter.from_row(_row(
        id=20, pattern="debian-sa1", program_glob="CRON"))
    sysstat_service = CompiledIngressFilter.from_row(_row(
        id=25, pattern="sysstat-collect", program_glob="CRON"))
    pam_session = CompiledIngressFilter.from_row(_row(
        id=30, pattern="pam_unix(cron:session): session ", program_glob="CRON"))

    assert debian_sa1.matches(_event(
        program="CRON", body="(root) CMD (/usr/lib/sysstat/debian-sa1 1 1)"))
    assert sysstat_service.matches(_event(
        program="CRON", body="(root) CMD (systemctl start sysstat-collect.service)"))
    assert pam_session.matches(_event(
        program="CRON", body="pam_unix(cron:session): session opened for user root"))
    assert not sysstat_service.matches(_event(
        program="systemd", body="sysstat-collect.service: Failed with result 'exit-code'"))


def test_historical_predicate_binds_operator_values():
    spec = validate_filter_spec(
        name="php", match_type="substring", pattern="100% literal",
        source_glob="db*", program_glob="system?", case_sensitive=False)
    sql, params = historical_predicate(spec, alias="e")
    assert "100% literal" not in sql
    assert "db*" not in sql
    assert "strpos(lower(e.body), lower(%s))" in sql
    assert "e.source LIKE %s" in sql
    assert params == ["100% literal", "db%", "system_"]
