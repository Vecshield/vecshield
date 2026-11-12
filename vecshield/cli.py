"""VecShield CLI — a local PII safety gate for AI pipelines.

    vecshield detect <file-or-text>
    vecshield ingest-check <file-or-dir>
    vecshield training-check <dataset-dir>
    vecshield redact-preview <file-or-text>

Every command runs locally, emits JSON with --json (for CI), and exits 2 when a
policy failure is detected so it can gate a pipeline or a build.
"""

from __future__ import annotations

import json as _json
import os
import sys

import rich_click as click
from rich.markup import escape
from rich.table import Table

from vecshield import __version__
from vecshield.cli_output import SEV_STYLE, glyph, make_console, prepare_stdio
from vecshield.models import Chunk, Severity

console = make_console()

_FAIL_ON = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _read_input(target: str) -> str:
    """A CLI argument is either a path to a text file or a literal string."""
    if os.path.isfile(target):
        with open(target, encoding="utf-8", errors="replace") as f:
            return f.read()
    return target


def _classifier(no_nlp: bool):
    from vecshield.classify import RegexClassifier, default_classifier

    return RegexClassifier() if no_nlp else default_classifier(use_nlp=True)


@click.group()
@click.version_option(__version__, package_name="vecshield")
def cli() -> None:
    """PII safety gate for AI ingestion and training pipelines."""
    prepare_stdio()


# --------------------------------------------------------------------------- #
# detect                                                                       #
# --------------------------------------------------------------------------- #
@cli.command()
@click.argument("target")
@click.option(
    "--no-nlp", is_flag=True, help="Regex-only (disable the Presidio NLP layer)."
)
@click.option("--fail-on-pii", is_flag=True, help="Exit 2 if any PII is detected.")
@click.option("--json", "json_out", is_flag=True, help="Emit JSON instead of a table.")
def detect(target, no_nlp, fail_on_pii, json_out) -> None:
    """Detect PII/PHI/PCI/secrets in a file or a literal string."""
    from vecshield import check_text

    text = _read_input(target)
    result = check_text(text, use_nlp=not no_nlp)

    if json_out:
        click.echo(_json.dumps(result.to_dict(), indent=2))
    else:
        if result.has_pii:
            console.print(
                f"[error]PII detected[/] — label [bold]{escape(str(result.label))}[/], "
                f"confidence {result.confidence:.0%}"
            )
            table = Table(show_lines=False)
            for c in ("Label", "Detector", "Preview"):
                table.add_column(c, overflow="fold")
            for span in result.spans:
                table.add_row(
                    escape(str(span.get("label", result.label))),
                    escape(str(span.get("detector", "-"))),
                    escape(str(span.get("preview", ""))),
                )
            console.print(table)
        else:
            console.print(f"[ok]{glyph('ok')} No PII detected.[/]")

    if fail_on_pii and result.has_pii:
        sys.exit(2)


# --------------------------------------------------------------------------- #
# ingest-check                                                                 #
# --------------------------------------------------------------------------- #
@cli.command(name="ingest-check")
@click.argument("target")
@click.option(
    "--text-field", default=None, help="Record field holding the text (jsonl/csv)."
)
@click.option(
    "--format", "fmt", default=None, help="Force a format reader (jsonl/csv/text/...)."
)
@click.option(
    "--no-nlp", is_flag=True, help="Regex-only (disable the Presidio NLP layer)."
)
@click.option(
    "--fail-on",
    type=click.Choice(list(_FAIL_ON)),
    default="high",
    help="Exit 2 when a finding at or above this severity is blocked.",
)
@click.option("--json", "json_out", is_flag=True, help="Emit JSON instead of a table.")
def ingest_check(target, text_field, fmt, no_nlp, fail_on, json_out) -> None:
    """Gate a file, JSONL, or directory of chunks before they are embedded.

    A literal string is also accepted and treated as a single chunk.
    """
    from vecshield import check_chunks

    block_severity = _FAIL_ON[fail_on]
    chunks = _load_chunks(target, text_field=text_field, fmt=fmt)
    report = check_chunks(chunks, use_nlp=not no_nlp, block_severity=block_severity)

    if json_out:
        click.echo(_json.dumps(report.to_dict(), indent=2))
    else:
        console.print(
            f"\n[bold]Ingest gate[/] — {report.total} chunk(s), "
            f"[bad]{len(report.blocked_chunks)} blocked[/], "
            f"[ok]{len(report.allowed_chunks)} allowed[/], "
            f"PII density {report.pii_density:.1%}"
        )
        _render_findings(report.findings)

    if report.blocked:
        sys.exit(2)


# --------------------------------------------------------------------------- #
# training-check                                                               #
# --------------------------------------------------------------------------- #
@cli.command(name="training-check")
@click.argument("dataset_path")
@click.option(
    "--no-nlp", is_flag=True, help="Regex-only (disable the Presidio NLP layer)."
)
@click.option(
    "--max-records", default=None, type=int, help="Cap records scanned per dataset."
)
@click.option(
    "--fail-on",
    type=click.Choice(list(_FAIL_ON)),
    default="high",
    help="Exit 2 when a finding at or above this severity is found.",
)
@click.option("--json", "json_out", is_flag=True, help="Emit JSON instead of a table.")
def training_check(dataset_path, no_nlp, max_records, fail_on, json_out) -> None:
    """Scan a local training/fine-tuning dataset directory for sensitive data."""
    from vecshield import check_dataset

    if not os.path.isdir(dataset_path):
        console.print(f"[error]Not a directory:[/] {escape(dataset_path)}")
        sys.exit(1)

    report = check_dataset(dataset_path, use_nlp=not no_nlp, max_records=max_records)

    if json_out:
        click.echo(_json.dumps(report.to_dict(), indent=2))
    else:
        console.print(
            f"\n[bold]Training-data scan[/] — {report.records_scanned} record(s) "
            f"scanned, [bad]{report.sensitive_records} sensitive[/] "
            f"({report.density:.1%}), top severity "
            f"[bold]{report.max_severity.upper()}[/]"
        )
        _render_finding_dicts(report.findings)

    threshold = _FAIL_ON[fail_on]
    top = Severity(report.max_severity)
    if report.has_pii and top.rank >= threshold.rank:
        sys.exit(2)


# --------------------------------------------------------------------------- #
# redact-preview                                                              #
# --------------------------------------------------------------------------- #
@cli.command(name="redact-preview")
@click.argument("target")
@click.option(
    "--no-nlp", is_flag=True, help="Regex-only (disable the Presidio NLP layer)."
)
@click.option("--json", "json_out", is_flag=True, help="Emit JSON instead of raw text.")
def redact_preview(target, no_nlp, json_out) -> None:
    """Show what a file or string looks like with PII spans masked."""
    from vecshield import redact_text

    text = _read_input(target)
    redacted = redact_text(text, use_nlp=not no_nlp)

    if json_out:
        click.echo(
            _json.dumps({"original_chars": len(text), "redacted": redacted}, indent=2)
        )
    else:
        console.print(redacted, markup=False, highlight=False, soft_wrap=True)


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #
def _load_chunks(target, *, text_field, fmt) -> list[Chunk]:
    """Turn a directory, a file, or a literal string into a list of Chunks."""
    from vecshield.datasources import build_datasource

    if os.path.isdir(target):
        source = build_datasource(
            "local", path=target, text_field=text_field, format=fmt
        )
        chunks: list[Chunk] = []
        with source:
            for ds in source.describe().datasets:
                chunks.extend(source.iter_records(ds.name))
        return chunks

    if os.path.isfile(target):
        from vecshield.datasources.base import format_for
        from vecshield.datasources.formats import read_records

        with open(target, "rb") as f:
            data = f.read()
        detected = fmt or format_for(target)
        if detected == "unknown":
            detected = "text"
        out: list[Chunk] = []
        for i, (text, meta) in enumerate(
            read_records(detected, data, text_field=text_field)
        ):
            out.append(
                Chunk(
                    id=f"{os.path.basename(target)}#{i}",
                    collection=os.path.basename(target),
                    text=text,
                    metadata=dict(meta),
                )
            )
        return out

    # Treat as a literal string.
    return [Chunk(id="0", collection="cli", text=target)]


def _render_findings(findings) -> None:
    if not findings:
        console.print(f"[ok]{glyph('ok')} No blocking findings.[/]")
        return
    table = Table(title="Blocked findings", show_lines=True)
    for c in ("Severity", "Category", "Finding"):
        table.add_column(c, overflow="fold")
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        style = SEV_STYLE.get(f.severity, "")
        table.add_row(f"[{style}]{f.severity.value.upper()}[/]", escape(str(f.category)),
                      escape(f.title))
    console.print(table)


def _render_finding_dicts(findings) -> None:
    if not findings:
        console.print(f"[ok]{glyph('ok')} No findings.[/]")
        return
    table = Table(title="Findings", show_lines=True)
    for c in ("Severity", "Dataset", "Finding"):
        table.add_column(c, overflow="fold")
    for f in sorted(
        findings, key=lambda x: -_FAIL_ON.get(x["severity"], Severity.INFO).rank
    ):
        sev = Severity(f["severity"])
        style = SEV_STYLE.get(sev, "")
        table.add_row(
            f"[{style}]{sev.value.upper()}[/]",
            escape(f.get("collection") or "-"),
            escape(f["title"]),
        )
    console.print(table)


if __name__ == "__main__":
    cli()
