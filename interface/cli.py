"""
interface/cli.py — Sentinel Fusion command-line interface.

Install once with:
    pip install -e .

Then run from anywhere:
    sentinel --help
    sentinel status
    sentinel run --nra scan.json --winlog events.json --report
    sentinel alerts --status open
    sentinel cases create --title "SSH Brute Force" --severity high
    sentinel intel 185.220.101.45

Without installation, invoke directly:
    python -m interface.cli --help
"""

from __future__ import annotations

from typing import Optional

import typer

from interface._state import set_db
from interface.banner import print_banner
from interface.commands import alerts, cases, events, intel, pipeline, purge, runs, scores, status, watch
from interface.output import console

app = typer.Typer(
    name="sentinel",
    help="Sentinel Fusion — SOC Detection & Correlation Platform.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
)

# ── Register subcommand groups ────────────────────────────────────────────────

app.add_typer(status.app,   name="status",   invoke_without_command=True)
app.add_typer(pipeline.app, name="run",      invoke_without_command=True)
app.add_typer(events.app,   name="events",   invoke_without_command=True)
app.add_typer(alerts.app,   name="alerts",   invoke_without_command=True)
app.add_typer(cases.app,    name="cases",    invoke_without_command=True)
app.add_typer(scores.app,   name="scores",   invoke_without_command=True)
app.add_typer(intel.app,    name="intel",    invoke_without_command=True)
app.add_typer(runs.app,     name="runs",     invoke_without_command=True)
app.add_typer(purge.app,    name="purge",    invoke_without_command=True)
app.add_typer(watch.app,    name="watch",    invoke_without_command=True)


# ── Global options ─────────────────────────────────────────────────────────────

@app.callback()
def main(
    db:     Optional[str] = typer.Option(
                None, "--db",
                envvar="SENTINEL_DB",
                help="SQLite database path. Overrides SENTINEL_DB env var.",
                show_default=False,
            ),
    banner: bool          = typer.Option(
                False, "--banner", "-b",
                help="Print the Sentinel Fusion banner before running.",
                is_eager=True,
            ),
) -> None:
    """
    [bold cyan]Sentinel Fusion[/bold cyan] — SOC Detection & Correlation Platform.

    All commands connect directly to the SQLite database — no API server required.
    Use --db to point at a specific database file, or set SENTINEL_DB.
    """
    if banner:
        print_banner(console)
    set_db(db)


# ── Module entrypoint ──────────────────────────────────────────────────────────

def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
