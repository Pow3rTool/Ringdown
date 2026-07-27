"""Database-backed ingress filtering for the collector hot path.

Filters are global infrastructure policy, not alert rules: the first enabled
filter that matches an event drops it before template mining, persistence,
semantic evaluation, and alert routing.  The collector keeps the filter set in
memory and reloads it through Postgres LISTEN/NOTIFY, so matching performs no
per-line database I/O.

Regular expressions use RE2 rather than Python ``re``.  An ingress expression
runs against every received line; using a linear-time engine keeps a malformed
or adversarial pattern from wedging the single collector loop.
"""
from __future__ import annotations

import fnmatch
from collections import Counter
from dataclasses import dataclass
from typing import Any

import re2

from . import db

MATCH_TYPES = {"substring", "regex"}
MAX_PATTERN_LEN = 512
MAX_NAME_LEN = 120
MAX_GLOB_LEN = 255
MAX_PREVIEW_LIMIT = 200
MAX_PURGE_BATCH = 100_000


class FilterValidationError(ValueError):
    """An operator-supplied filter is invalid."""


def _text(value: Any, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise FilterValidationError(f"{field} must be text.")
    return value.strip()


def _clean_glob(value: str, field: str) -> str:
    value = _text(value, field)
    if len(value) > MAX_GLOB_LEN:
        raise FilterValidationError(f"{field} is too long ({len(value)} > {MAX_GLOB_LEN}).")
    if "," in value:
        raise FilterValidationError(
            f"{field} is one glob, not a comma-separated list; create separate filters instead.")
    if any(ch.isspace() for ch in value):
        raise FilterValidationError(f"{field} cannot contain whitespace.")
    # The historical SQL preview/purge path deliberately supports the same small
    # glob language as the hot path: '*' and '?'.  Reject bracket expressions so
    # a live match can never disagree with its historical preview.
    if "[" in value or "]" in value:
        raise FilterValidationError(f"{field} supports only '*' and '?' wildcards.")
    return value


def compile_regex(pattern: str, *, case_sensitive: bool):
    options = re2.Options()
    options.case_sensitive = bool(case_sensitive)
    options.log_errors = False
    try:
        return re2.compile(pattern, options=options)
    except Exception as exc:
        raise FilterValidationError(f"invalid RE2 pattern: {exc}") from exc


def validate_filter_spec(
    *,
    name: str,
    match_type: str,
    pattern: str,
    source_glob: str = "",
    program_glob: str = "",
    case_sensitive: bool = False,
    filter_order: int = 100,
) -> dict[str, Any]:
    """Normalize and validate a filter definition for every write surface."""
    name = _text(name, "name")
    match_type = _text(match_type, "match_type").lower()
    pattern = _text(pattern, "pattern")
    if not isinstance(case_sensitive, bool):
        raise FilterValidationError("case_sensitive must be a boolean.")
    if not name:
        raise FilterValidationError("name is required.")
    if len(name) > MAX_NAME_LEN:
        raise FilterValidationError(f"name is too long ({len(name)} > {MAX_NAME_LEN}).")
    if match_type not in MATCH_TYPES:
        raise FilterValidationError("match_type must be 'substring' or 'regex'.")
    if not pattern:
        raise FilterValidationError("pattern is required.")
    if len(pattern) > MAX_PATTERN_LEN:
        raise FilterValidationError(
            f"pattern is too long ({len(pattern)} > {MAX_PATTERN_LEN}).")
    if isinstance(filter_order, bool):
        raise FilterValidationError("filter_order must be an integer.")
    try:
        filter_order = int(filter_order)
    except (TypeError, ValueError) as exc:
        raise FilterValidationError("filter_order must be an integer.") from exc
    if not 0 <= filter_order <= 1_000_000:
        raise FilterValidationError("filter_order must be between 0 and 1000000.")
    source_glob = _clean_glob(source_glob, "source_glob")
    program_glob = _clean_glob(program_glob, "program_glob")
    if match_type == "regex":
        compile_regex(pattern, case_sensitive=case_sensitive)
    return {
        "name": name,
        "match_type": match_type,
        "pattern": pattern,
        "source_glob": source_glob,
        "program_glob": program_glob,
        "case_sensitive": case_sensitive,
        "filter_order": filter_order,
    }


@dataclass(frozen=True)
class CompiledIngressFilter:
    id: int
    name: str
    match_type: str
    pattern: str
    source_glob: str
    program_glob: str
    case_sensitive: bool
    filter_order: int
    regex: Any = None

    @classmethod
    def from_row(cls, row: dict) -> CompiledIngressFilter:
        match_type = row["match_type"]
        case_sensitive = bool(row["case_sensitive"])
        rx = (compile_regex(row["pattern"], case_sensitive=case_sensitive)
              if match_type == "regex" else None)
        return cls(
            id=int(row["id"]),
            name=row["name"],
            match_type=match_type,
            pattern=row["pattern"],
            source_glob=row.get("source_glob") or "",
            program_glob=row.get("program_glob") or "",
            case_sensitive=case_sensitive,
            filter_order=int(row.get("filter_order") or 0),
            regex=rx,
        )

    def matches(self, event: dict) -> bool:
        source = event.get("source") or ""
        program = event.get("program") or ""
        if self.source_glob and not fnmatch.fnmatchcase(source, self.source_glob):
            return False
        if self.program_glob and not fnmatch.fnmatchcase(program, self.program_glob):
            return False
        body = event.get("body") or ""
        if self.match_type == "regex":
            return self.regex.search(body) is not None
        if self.case_sensitive:
            return self.pattern in body
        return self.pattern.casefold() in body.casefold()


class IngressFilterSet:
    """Enabled filters compiled and ordered for the collector."""

    def __init__(self, pool):
        self._pool = pool
        self._filters: list[CompiledIngressFilter] = []
        self._rejected: list[str] = []

    def __len__(self) -> int:
        return len(self._filters)

    @property
    def rejected(self) -> list[str]:
        return self._rejected

    async def reload(self) -> None:
        rows = await db.fetch(
            self._pool,
            "SELECT id, name, match_type, pattern, source_glob, program_glob, "
            "case_sensitive, filter_order FROM ingress_filters "
            "WHERE enabled ORDER BY filter_order, id")
        compiled, rejected = [], []
        for row in rows:
            try:
                compiled.append(CompiledIngressFilter.from_row(row))
            except (FilterValidationError, KeyError) as exc:
                rejected.append(f"filter {row.get('id', '?')} ({row.get('name', '?')}): {exc}")
        self._filters = compiled
        self._rejected = rejected

    def match(self, event: dict) -> CompiledIngressFilter | None:
        for ingress_filter in self._filters:
            if ingress_filter.matches(event):
                return ingress_filter
        return None

    def partition(self, events: list[dict]) -> tuple[list[dict], Counter]:
        """Return accepted events and first-match drop counts keyed by filter/source."""
        accepted: list[dict] = []
        dropped: Counter = Counter()
        for event in events:
            matched = self.match(event)
            if matched is None:
                accepted.append(event)
            else:
                dropped[(matched.id, event.get("source") or "?")] += 1
        return accepted, dropped


def _like_glob_clause(column: str, value: str) -> tuple[str, list]:
    """Translate the restricted (* and ?) glob language to bound SQL LIKE."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    escaped = escaped.replace("*", "%").replace("?", "_")
    return f"{column} LIKE %s ESCAPE E'\\\\'", [escaped]


def historical_predicate(spec: dict, *, alias: str = "events") -> tuple[str, list]:
    """SQL predicate equivalent to live matching, with every value bound."""
    validate_filter_spec(
        name=spec["name"],
        match_type=spec["match_type"],
        pattern=spec["pattern"],
        source_glob=spec.get("source_glob") or "",
        program_glob=spec.get("program_glob") or "",
        case_sensitive=bool(spec.get("case_sensitive")),
        filter_order=spec.get("filter_order", 100),
    )
    clauses, params = [], []
    body = f"{alias}.body"
    if spec["match_type"] == "substring":
        if spec.get("case_sensitive"):
            clauses.append(f"strpos({body}, %s) > 0")
        else:
            clauses.append(f"strpos(lower({body}), lower(%s)) > 0")
    else:
        clauses.append(f"{body} {'~' if spec.get('case_sensitive') else '~*'} %s")
    params.append(spec["pattern"])
    if spec.get("source_glob"):
        clause, values = _like_glob_clause(f"{alias}.source", spec["source_glob"])
        clauses.append(clause)
        params.extend(values)
    if spec.get("program_glob"):
        clause, values = _like_glob_clause(f"coalesce({alias}.program, '')", spec["program_glob"])
        clauses.append(clause)
        params.extend(values)
    return " AND ".join(clauses), params


async def list_filters(pool, *, include_disabled: bool = True) -> list[dict]:
    where = "" if include_disabled else "WHERE f.enabled"
    return await db.fetch(
        pool,
        "SELECT f.id, f.name, f.match_type, f.pattern, f.source_glob, f.program_glob, "
        "f.case_sensitive, f.filter_order, f.enabled, f.created_by, f.created_by_upn, "
        "f.created_at, f.updated_at, COALESCE(sum(s.matched), 0)::bigint AS dropped, "
        "max(s.last_matched) AS last_matched "
        "FROM ingress_filters f LEFT JOIN ingress_filter_stats s ON s.filter_id = f.id "
        f"{where} GROUP BY f.id ORDER BY f.filter_order, f.id")


async def get_filter(pool, filter_id: int) -> dict | None:
    return await db.fetchone(
        pool,
        "SELECT id, name, match_type, pattern, source_glob, program_glob, case_sensitive, "
        "filter_order, enabled, created_by, created_by_upn, created_at, updated_at "
        "FROM ingress_filters WHERE id = %s",
        (int(filter_id),))


async def preview_filter(pool, spec: dict, *, limit: int = 20) -> dict:
    """Count and sample historical matches under a bounded statement timeout."""
    predicate, params = historical_predicate(spec, alias="e")
    limit = min(max(int(limit or 20), 1), MAX_PREVIEW_LIMIT)
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute("SET LOCAL statement_timeout = '15s'")
        await cur.execute(f"SELECT count(*) AS n FROM events e WHERE {predicate}", params)
        total = (await cur.fetchone())["n"]
        await cur.execute(
            "SELECT e.id, e.ts, e.source, e.severity_text, e.program, e.body "
            f"FROM events e WHERE {predicate} ORDER BY e.ts DESC LIMIT %s",
            params + [limit])
        sample = await cur.fetchall()
    return {"would_match": total, "sample": sample, "limit": limit}


async def purge_filter(pool, spec: dict, *, batch_size: int = 50_000) -> dict:
    """Delete at most one bounded batch of historical matches.

    PostgreSQL can reuse the freed pages after ordinary VACUUM, but returning the
    space to the operating system requires a later partition rewrite/VACUUM FULL.
    """
    predicate, params = historical_predicate(spec, alias="e")
    batch_size = min(max(int(batch_size or 50_000), 1), MAX_PURGE_BATCH)
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute("SET LOCAL lock_timeout = '3s'")
        await cur.execute("SET LOCAL statement_timeout = '60s'")
        await cur.execute(
            "WITH doomed AS MATERIALIZED ("
            f"  SELECT e.id, e.ts FROM events e WHERE {predicate} LIMIT %s"
            "), deleted AS ("
            "  DELETE FROM events e USING doomed d WHERE e.id = d.id AND e.ts = d.ts "
            "  RETURNING e.id"
            ") SELECT count(*) AS n FROM deleted",
            params + [batch_size])
        deleted = (await cur.fetchone())["n"]
    return {
        "deleted": deleted,
        "batch_size": batch_size,
        "batch_limit_reached": deleted == batch_size,
        "storage_note": (
            "Rows are gone and PostgreSQL can reuse their pages after VACUUM; shrinking partition "
            "files on disk requires a separately scheduled rewrite/VACUUM FULL."),
    }
