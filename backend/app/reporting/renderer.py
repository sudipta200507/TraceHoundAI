"""Jinja2 report renderer (Phase 10) — formatting only, no analysis.

Uses the bundled templates/ directory. Templates receive a fully prepared
ReportContext and perform loops/conditionals only; all security logic lives
in report_builder.py. The renderer never calls models, tools, or scanners.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from backend.app.reporting.report_builder import ReportContext


def templates_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(templates_dir())),
        undefined=StrictUndefined,
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_report(context: ReportContext) -> str:
    return _environment().get_template("report.md.j2").render(ctx=context)


def render_appendix(context: ReportContext) -> str:
    """Full raw inventories (appendix) from the same validated context."""
    return _environment().get_template("appendix.md.j2").render(ctx=context)


def write_report(context: ReportContext, path: str | Path) -> Path:
    from backend.app.reporting.validator import validate_report_context

    problems = validate_report_context(context)
    if problems:
        raise ValueError("report validation failed: " + "; ".join(problems))
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(context), encoding="utf-8")
    return out


def write_appendix(context: ReportContext, path: str | Path) -> Path:
    """Write the technical appendix (same context, no validation gate — it
    is a verbatim inventory dump, not an assessment)."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_appendix(context), encoding="utf-8")
    return out


def write_inventory_json(document: dict, path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return out


def write_endpoints_csv(rows: list[list[str]], path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.StringIO()
    # lineterminator="\n": Path.write_text translates to os.linesep on
    # Windows — the csv default "\r\n" would otherwise become "\r\r\n".
    csv.writer(buffer, lineterminator="\n").writerows(rows)
    out.write_text(buffer.getvalue(), encoding="utf-8")
    return out
