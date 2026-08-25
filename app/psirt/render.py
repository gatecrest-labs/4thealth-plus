"""Render a PsirtAssessment as a self-contained HTML report.

Pure deterministic templating — no LLM involved. Jinja2 autoescaping
(Flask's default) handles HTML-escaping every advisory/finding field, so
values that end up in the report (which may originate from a pasted email)
can never inject markup into the page.
"""

from __future__ import annotations

import datetime

from flask import render_template


def render_psirt_html(assessment: dict) -> str:
    return render_template(
        "psirt_report.html",
        advisory=assessment["advisory"],
        findings=assessment["findings"],
        out_of_scope_products=assessment["out_of_scope_products"],
        priority=assessment["priority"],
        priority_rationale=assessment["priority_rationale"],
        kev_hit=assessment["kev_hit"],
        warnings=assessment["warnings"],
        generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
