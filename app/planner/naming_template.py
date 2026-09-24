"""Token-substitution template engine for naming.yaml patterns.

Patterns use <UPPER_SNAKE_CASE> placeholders (e.g. "H_<IP_ADDRESS>"). This
is the single place that turns a naming.yaml pattern string plus real
request values into an actual FortiGate object/policy name — used by
app.planner.standards.object_name()/policy_name() so that an admin editing
a pattern in naming.yaml (via the Admin UI or by hand) changes what CLI
actually gets generated, not just what's displayed.
"""

from __future__ import annotations

import re

from app.planner.models import PlannerDataError

TOKEN_PATTERN_RE = re.compile(r"<([A-Z_]+)>")


class NamingTemplateError(PlannerDataError):
    """A naming.yaml pattern could not be rendered."""

    def __init__(self, detail: str) -> None:
        super().__init__("naming_template", detail)


def render(pattern: str | None, **tokens: str) -> str:
    """Substitute <TOKEN> placeholders in `pattern` with `tokens` values.

    Raises NamingTemplateError if `pattern` is empty/None, or references a
    token not present in `tokens` — never silently emits a partial name.
    """
    if not pattern:
        raise NamingTemplateError("pattern is empty or missing")

    referenced = set(TOKEN_PATTERN_RE.findall(pattern))
    missing = referenced - set(tokens)
    if missing:
        raise NamingTemplateError(
            f"pattern {pattern!r} references undefined token(s): "
            f"{', '.join(sorted(missing))}"
        )

    def _sub(match: re.Match) -> str:
        return str(tokens[match.group(1)])

    return TOKEN_PATTERN_RE.sub(_sub, pattern)
