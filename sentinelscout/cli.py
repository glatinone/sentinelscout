"""SentinelScout CLI — Typer-powered."""
import asyncio
import sys
import time
import os

# Force UTF-8 on Windows
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinelscout import __version__
from sentinelscout.models import AnalysisReport, Severity
from sentinelscout.sources import BaseSource, Source
from sentinelscout.sources.cve import CVESource
from sentinelscout.sources.github import GitHubAdvSource
from sentinelscout.sources.virustotal import VirusTotalSource
from sentinelscout.sources.alienvault import AlienVaultSource
from sentinelscout.sources.shodan import ShodanSource
from sentinelscout.analyzer import analyze
from sentinelscout import config

app = typer.Typer(add_completion=False, help="🛡️ SentinelScout — Multi-source OSINT aggregator")
console = Console()


def _severity_color(sev: Severity) -> str:
    return {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "unknown": "dim"}.get(sev.value, "dim")


def _score_icon(score: int) -> str:
    if score >= 80:
        return "🚨 CRITICAL"
    if score >= 60:
        return "🔴 HIGH"
    if score >= 40:
        return "🟡 MEDIUM"
    if score >= 20:
        return "🟢 LOW"
    return "⚪ SAFE"


async def _query(indicator: str, sources_filter: list[str] | None) -> AnalysisReport:
    all_sources: list[BaseSource] = [
        VirusTotalSource(),
        AlienVaultSource(),
        ShodanSource(),
        CVESource(),
        GitHubAdvSource(),
    ]

    if sources_filter:
        all_sources = [s for s in all_sources if s.source.value in sources_filter or s.name in sources_filter]

    tasks = [s.query(indicator) for s in all_sources]
    results = await asyncio.gather(*tasks)

    report = AnalysisReport(indicator=indicator, sources=list(results))
    all_scores = [r.score() for r in results if r.found]
    report.threat_score = max(all_scores) if all_scores else 0

    # AI analysis
    report = await analyze(report)

    return report


def _print_report(report: AnalysisReport):
    console.print(Panel(f"[bold cyan]Query:[/bold cyan] {report.indicator}  [dim]({len(report.sources)} sources)[/dim]", expand=False))
    console.print()

    t = Table(show_header=True, header_style="bold magenta", box=None, pad_edge=False)
    t.add_column("Source", style="bold")
    t.add_column("Status", justify="center")
    t.add_column("Severity", justify="center")
    t.add_column("Result", max_width=60)

    for r in report.sources:
        color = _severity_color(r.severity)
        status = "[+]" if r.found else "[!]"
        sev = r.severity.value.upper() if r.severity != Severity.UNKNOWN else "N/A"
        result = r.summary or ("Not found" if not r.found else "")
        t.add_row(r.source.value.replace("_", " ").title(), status, f"[{color}]{sev}[/{color}]", result)

    console.print(t)
    console.print()

    # AI Summary
    if report.ai_summary:
        score_color = "green" if report.threat_score < 40 else "yellow" if report.threat_score < 70 else "red"
        console.print(Panel(
            f"[bold]🤖 AI Analysis[/bold]\n[dim]{report.ai_summary}[/dim]\n\n[bold]Threat Score: [{score_color}]{report.threat_score}/100[/{score_color}] {_score_icon(report.threat_score)}",
            border_style="cyan",
            expand=False,
        ))


@app.command()
def query(
    indicator: str = typer.Argument(..., help="Domain, IP, or file hash to query"),
    source: str | None = typer.Option(None, "--source", "-s", help="Specific source to use (virustotal, alienvault, shodan, cve, github_adv)"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI analysis"),
):
    """Query an IOC across all configured sources."""
    sources_filter = [source] if source else None
    start = time.time()

    try:
        report = asyncio.run(_query(indicator, sources_filter))
        if no_ai:
            report.ai_summary = ""
        _print_report(report)
        elapsed = time.time() - start
        console.print(f"\n[dim]Completed in {elapsed:.2f}s[/dim]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")
        raise typer.Exit(1)


@app.command()
def sources():
    """List available sources and their status."""
    t = Table(show_header=True, header_style="bold magenta", box=None)
    t.add_column("Source")
    t.add_column("Type")
    t.add_column("API Required")
    t.add_column("Config Status")

    rows = [
        ("virustotal",   "Domain/IP/Hash", "Yes",     "OK configured" if config.VIRUSTOTAL_API_KEY else "MISSING key"),
        ("alienvault",   "IP/Domain/Hash", "Yes",     "OK configured" if config.ALIENVAULT_API_KEY else "MISSING key"),
        ("shodan",       "IP only",         "Yes",     "OK configured" if config.SHODAN_API_KEY else "MISSING key"),
        ("cve",          "Vulnerabilities", "No",      "always available"),
        ("github_adv",   "Advisories",      "No",      "always available"),
    ]
    for row in rows:
        t.add_row(*row)
    console.print(t)


@app.command()
def version():
    """Show version."""
    console.print(f"SentinelScout v{__version__}")


if __name__ == "__main__":
    app()