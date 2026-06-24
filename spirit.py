import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "spirit"))

import click
import subprocess
import re
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich import box
from rich.rule import Rule
from rich.columns import Columns
from core import Engine
from git.audit_log import log_push_attempt, get_audit_log, get_audit_summary
from storage.cache import get_cached_scan, save_scan_cache, invalidate_cache

console = Console()

BANNER = """
[bold cyan]
 ░██████╗██████╗░██╗██████╗░██╗████████╗ ░█████╗░██╗░░░░░██╗
 ██╔════╝██╔══██╗██║██╔══██╗██║╚══██╔══╝ ██╔══██╗██║░░░░░██║
 ╚█████╗░██████╔╝██║██████╔╝██║░░░██║░░░ ██║░░╚═╝██║░░░░░██║
 ░╚═══██╗██╔═══╝░██║██╔══██╗██║░░░██║░░░ ██║░░██╗██║░░░░░██║
 ██████╔╝██║░░░░░██║██║░░██║██║░░░██║░░░ ╚█████╔╝███████╗██║
 ╚═════╝░╚═╝░░░░░╚═╝╚═╝░░╚═╝╚═╝░░░╚═╝░░░ ╚════╝░╚══════╝╚═╝
[/bold cyan]
[dim cyan]  Real-Time Dependency Security Intelligence for Banking[/dim cyan]
[dim]  Team DrunkenDevs[/dim]
"""


def print_banner():
    console.print(BANNER, justify="center")
    console.print(Rule(style="cyan"))


def get_zone_style(zone):
    if zone == "SAFE":
        return "bold green", "✅", "green"
    elif zone == "WARNING":
        return "bold yellow", "⚠️ ", "yellow"
    else:
        return "bold red", "🚨", "red"


def display_score(score):
    style, icon, color = get_zone_style(score.zone)
    panels = [
        Panel(f"[bold]{score.config_score}/100[/bold]", title="[cyan]Config Safety[/cyan]", border_style="cyan", width=20),
        Panel(f"[bold]{score.cve_score}/100[/bold]", title="[cyan]CVE Exposure[/cyan]", border_style="cyan", width=20),
        Panel(f"[bold]{score.trust_score}/100[/bold]", title="[cyan]Trust Score[/cyan]", border_style="cyan", width=20),
        Panel(f"[bold]{score.freshness_score}/100[/bold]", title="[cyan]Freshness[/cyan]", border_style="cyan", width=20),
        Panel(f"[bold]{score.phantom_score}/100[/bold]", title="[cyan]Phantom Risk[/cyan]", border_style="cyan", width=20),
    ]
    console.print(Columns(panels, equal=True, expand=True))
    console.print()
    console.print(Panel(
        Align.center(f"[{style}]{icon} {score.total}/100 -- {score.zone} {icon}[/{style}]"),
        title="[bold white]Security Fingerprint[/bold white]",
        border_style=color,
        padding=(1, 4),
    ))


def display_findings(findings):
    if not findings:
        console.print(Panel(
            Align.center("[bold green]✅ No vulnerabilities detected. Codebase is secure.[/bold green]"),
            border_style="green",
        ))
        return
    console.print()
    console.print(Rule("[bold red]Security Findings[/bold red]", style="red"))
    console.print()
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan",
                  border_style="cyan", row_styles=["", "dim"], padding=(0, 1))
    table.add_column("Severity", width=12)
    table.add_column("Library", width=14)
    table.add_column("File", width=35)
    table.add_column("Line", width=6, justify="center")
    table.add_column("Issue", width=50)
    table.add_column("Fix", width=35)
    severity_styles = {
        "critical": ("red", "🔴 CRITICAL"),
        "high": ("orange3", "🟠 HIGH"),
        "medium": ("yellow", "🟡 MEDIUM"),
        "low": ("blue", "🔵 LOW"),
    }
    for f in findings:
        color, label = severity_styles.get(f.severity, ("white", f.severity.upper()))
        table.add_row(
            f"[{color}]{label}[/{color}]",
            f"[bold]{f.library}[/bold]",
            f"[dim]{f.file}[/dim]",
            f"[cyan]{f.line}[/cyan]",
            f.message,
            f"[green]{f.fix or 'Review manually'}[/green]",
        )
    console.print(table)


def run_git_command(args, cwd=None):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def run_scan_cached(path, force=False):
    """
    Central scan function used by all commands.
    Returns report from cache if files unchanged, otherwise runs full scan.
    """
    abs_path = os.path.abspath(path)

    if not force:
        cached = get_cached_scan(abs_path)
        if cached:
            report = Engine(abs_path)._deserialize_report(cached)
            console.print("[dim] Using cached scan — files unchanged[/dim]")
            return report

    engine = Engine(abs_path)
    report = engine.run()
    save_scan_cache(abs_path, engine._serialize_report(report))
    return report


def get_fix_rules():
    return {
        "bcrypt": [
            {
                "pattern": r"(\.hashSync\s*\([^,]+,\s*)([0-9]+)(\s*\))",
                "replacement": r"\g<1>12\g<3>",
                "description": "bcrypt rounds -> 12",
                "validate": lambda old, new: "12" in new,
            },
            {
                "pattern": r"(\.hash\s*\([^,]+,\s*)([0-9]+)(\s*[,)])",
                "replacement": r"\g<1>12\g<3>",
                "description": "bcrypt hash rounds -> 12",
                "validate": lambda old, new: "12" in new,
            },
        ],
        "jwt": [
            {
                "pattern": r'algorithm\s*:\s*["\']none["\']',
                "replacement": "algorithm: 'HS256'",
                "description": "JWT algorithm -> HS256",
                "validate": lambda old, new: "HS256" in new,
            },
            {
                "pattern": r"algorithm\s*:\s*`none`",
                "replacement": "algorithm: 'HS256'",
                "description": "JWT algorithm -> HS256",
                "validate": lambda old, new: "HS256" in new,
            },
        ],
        "axios": [
            {
                "pattern": r"rejectUnauthorized\s*:\s*false",
                "replacement": "rejectUnauthorized: true",
                "description": "axios TLS validation -> enabled",
                "validate": lambda old, new: "rejectUnauthorized: true" in new,
            },
            {
                "pattern": r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']0["\']',
                "replacement": 'NODE_TLS_REJECT_UNAUTHORIZED = "1"',
                "description": "TLS rejection -> enabled",
                "validate": lambda old, new: '"1"' in new,
            },
        ],
        "mongoose": [
            {
                "pattern": r"strict\s*:\s*false",
                "replacement": "strict: true",
                "description": "mongoose strict:false -> strict:true",
                "validate": lambda old, new: "strict: true" in new,
            }
        ],
        "express": [
            {
                "pattern": r'(cors\s*\(\s*\{[^}]*origin\s*:\s*)["\']?\*["\']?',
                "replacement": r"\g<1>'https://yourdomain.com'",
                "description": "express CORS wildcard -> specific origin",
                "validate": lambda old, new: "yourdomain" in new,
            }
        ],
        "lodash": [
            {
                "pattern": r"lodash\.merge\s*\(\s*\{\s*\}\s*,\s*(req\.\w+|req\.body)\s*\)",
                "replacement": r"Object.assign({}, \1)",
                "description": "lodash.merge with user input -> Object.assign (safe)",
                "validate": lambda old, new: "Object.assign" in new,
            },
            {
                "pattern": r"lodash\.merge\s*\(\s*\{\s*\}\s*,\s*(\w+)\s*\)",
                "replacement": r"Object.assign({}, \1)",
                "description": "lodash.merge -> Object.assign",
                "validate": lambda old, new: "Object.assign" in new,
            },
        ],
    }


@click.group()
def cli():
    """
    \b
    ███████╗██████╗ ██╗██████╗ ██╗████████╗ ██████╗██╗     ██╗
    ██╔════╝██╔══██╗██║██╔══██╗██║╚══██╔══╝██╔════╝██║     ██║
    ███████╗██████╔╝██║██████╔╝██║   ██║   ██║     ██║     ██║
    ╚════██║██╔═══╝ ██║██╔══██╗██║   ██║   ██║     ██║     ██║
    ███████║██║     ██║██║  ██║██║   ██║   ╚██████╗███████╗██║
    ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝    ╚═════╝╚══════╝╚═╝

    \b
    Real-Time Dependency Security Intelligence for Banking
    Team DrunkenDevs

    \b
    COMMANDS:
      scan          Full security scan of a project
      fix           Auto-remediate detected vulnerabilities
      push          Security-gated git commit and push
      diff          Scan only files changed since last commit
      watch         Watch for changes and scan every 5 saves
      report        Generate HTML/JSON security report
      audit         View push attempt audit trail
      licenses      Check dependency license compliance
      install-hooks Install SpiritCLI as git pre-push hook

    \b
    EXAMPLES:
      spirit scan demo_apps/vulnerable_bank_app
      spirit scan demo_apps/vulnerable_bank_app --fresh
      spirit fix demo_apps/vulnerable_bank_app
      spirit push demo_apps/vulnerable_bank_app -m "deploy"
      spirit push demo_apps/vulnerable_bank_app --force
      spirit diff demo_apps/secure_bank_app
      spirit watch demo_apps/vulnerable_bank_app
      spirit report demo_apps/vulnerable_bank_app --html
      spirit audit demo_apps/vulnerable_bank_app
      spirit licenses demo_apps/vulnerable_bank_app
      spirit install-hooks demo_apps/vulnerable_bank_app

    \b
    SECURITY ZONES:
      SAFE        71-100  Push allowed
      WARNING     36-70   Acknowledgement required
      QUARANTINE  0-35    Push blocked

    \b
    CACHE:
      Results cached per directory. Auto-invalidated when files change.
      Use --fresh flag on scan to force a new scan.
    """
    pass


@cli.command()
@click.argument("path", default=".")
@click.option("--fresh", is_flag=True, help="Force fresh scan, bypass cache")
def scan(path, fresh):
    """Run a full security scan — CVE, config, phantom, freshness, trust"""
    print_banner()
    console.print(f"\n[cyan]Target:[/cyan] [bold]{path}[/bold]")
    console.print()
    with console.status(
        "[cyan]Scanning dependencies and configurations...[/cyan]", spinner="dots"
    ):
        report = run_scan_cached(path, force=fresh)
    console.print(f"[dim]Scanned {len(report.dependencies)} dependencies[/dim]")
    console.print()
    display_score(report.score)
    display_findings(report.findings)
    console.print()
    console.print(Rule(style="cyan"))
    console.print(f"[dim]Scan complete -- {report.timestamp}[/dim]", justify="center")


@cli.command()
@click.argument("path", default=".")
@click.option("--message", "-m", default=None, help="Commit message")
@click.option("--force", "-f", is_flag=True, help="Bypass security gate (logged)")
def push(path, message, force):
    """Security-gated git add, commit and push with 3-zone enforcement"""
    print_banner()
    abs_path = os.path.abspath(path)

    if force:
        console.print("[red]⚠ FORCE PUSH ACTIVATED — Security gate bypassed[/red]")
        confirmed = click.confirm(
            "This bypasses all security checks and will be logged. Are you sure?",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]Force push cancelled.[/yellow]")
            return
        if not message:
            message = click.prompt("Commit message", default="force push")
        try:
            subprocess.run(["git", "add", "."], cwd=abs_path, check=True)
            status = run_git_command(["git", "status", "--porcelain"], cwd=abs_path)
            if status.stdout.strip():
                subprocess.run(["git", "commit", "-m", message], cwd=abs_path, check=True)
            else:
                console.print("[dim]Nothing to commit[/dim]")
            result = run_git_command(["git", "push", "--force"], cwd=abs_path)
            if result.returncode == 0:
                console.print("[yellow]⚠ Force push successful — security was bypassed[/yellow]")
                console.print("[yellow]This action has been logged for audit.[/yellow]")
            elif "No configured push destination" in result.stderr:
                console.print("[yellow]⚠ Committed — no remote configured[/yellow]")
            else:
                console.print(f"[red]Push failed: {result.stderr}[/red]")
            log_push_attempt(abs_path, 0, "FORCE_PUSH", "FORCE_PUSH", message)
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Git error: {e}[/red]")
        return

    if not os.path.exists(os.path.join(abs_path, ".git")):
        console.print("[yellow]Git not initialized in this directory.[/yellow]")
        init = click.confirm("Initialize git repository?", default=True)
        if init:
            subprocess.run(["git", "init"], cwd=abs_path, check=True)
            console.print("[green]✓ Git initialized.[/green]")
        else:
            console.print("[red]Aborted.[/red]")
            return

    console.print(f"\n[cyan]Running security scan on[/cyan] [bold]{path}[/bold]...")
    with console.status("[cyan]Scanning...[/cyan]", spinner="dots"):
        report = run_scan_cached(path)  # uses cache

    score = report.score.total
    zone = report.score.zone
    critical_findings = [
        f for f in report.findings
        if f.severity == "critical" and f.file != "package.json"
    ]
    display_score(report.score)

    if zone == "QUARANTINE" or critical_findings:
        console.print(Panel(
            Align.center(
                f"[bold red]🚫 PUSH BLOCKED[/bold red]\n\n"
                f"[red]Score: {score}/100 — QUARANTINE[/red]\n\n"
                f"[yellow]Critical findings must be fixed before pushing.\n"
                f"Run [cyan]spirit fix {path}[/cyan] to auto-remediate\n"
                f"Or use [cyan]spirit push --force[/cyan] to bypass (logged)[/yellow]"
            ),
            title="[red]Security Gate — Push Rejected[/red]",
            border_style="red", padding=(1, 4),
        ))
        console.print("\n[red]Critical Findings:[/red]")
        for f in critical_findings:
            console.print(f"  [red]●[/red] [bold]{f.library}[/bold] — {f.message}")
        log_push_attempt(abs_path, score, zone, "BLOCKED")
        return

    elif zone == "WARNING":
        console.print(Panel(
            Align.center(
                f"[bold yellow]⚠ PUSH WARNING[/bold yellow]\n\n"
                f"[yellow]Score: {score}/100 — WARNING[/yellow]\n\n"
                f"[dim]Developer acknowledgement required.[/dim]"
            ),
            title="[yellow]Security Gate — Review Required[/yellow]",
            border_style="yellow", padding=(1, 4),
        ))
        console.print("\n[yellow]Active Findings:[/yellow]")
        for f in report.findings[:5]:
            console.print(f"  [yellow]●[/yellow] [bold]{f.library}[/bold] — {f.message[:70]}")
        confirmed = click.confirm(
            "\nI have reviewed all findings and accept the risk. Proceed with push?",
            default=False,
        )
        if not confirmed:
            console.print("[red]Push cancelled.[/red]")
            console.print(f"[yellow]Tip: Run [cyan]spirit fix {path}[/cyan] to fix issues first[/yellow]")
            log_push_attempt(abs_path, score, zone, "CANCELLED")
            return
        log_push_attempt(abs_path, score, zone, "WARNING_ACCEPTED", message or "")
        console.print("[yellow]Push proceeding with acknowledged risk.[/yellow]")

    else:
        console.print(Panel(
            Align.center(
                f"[bold green]✅ PUSH APPROVED[/bold green]\n\n"
                f"[green]Score: {score}/100 — SAFE[/green]\n\n"
                f"[dim]All security checks passed.[/dim]"
            ),
            title="[green]Security Gate — Approved[/green]",
            border_style="green", padding=(1, 4),
        ))

    if not message:
        message = click.prompt("\nCommit message", default="security-verified commit")

    try:
        console.print("\n[cyan]Running git add .[/cyan]")
        subprocess.run(["git", "add", "."], cwd=abs_path, check=True)
        status = run_git_command(["git", "status", "--porcelain"], cwd=abs_path)
        if status.stdout.strip():
            console.print(f"[cyan]Committing: {message}[/cyan]")
            subprocess.run(["git", "commit", "-m", message], cwd=abs_path, check=True)
        else:
            console.print("[dim]Nothing new to commit[/dim]")
        console.print("[cyan]Pushing to remote...[/cyan]")
        result = run_git_command(["git", "push"], cwd=abs_path)
        if result.returncode == 0:
            log_push_attempt(abs_path, score, zone, "APPROVED", message)
            console.print(Panel(
                Align.center(
                    f"[bold green]✅ Push Successful[/bold green]\n\n"
                    f"[green]Score: {score}/100 — {zone}[/green]"
                ),
                border_style="green", padding=(1, 4),
            ))
        elif "No configured push destination" in result.stderr:
            log_push_attempt(abs_path, score, zone, "APPROVED", message)
            console.print(Panel(
                Align.center(
                    f"[bold yellow]✅ Committed Successfully[/bold yellow]\n\n"
                    f"[yellow]Score: {score}/100 — {zone}[/yellow]\n\n"
                    f"[dim]No remote configured — add with: git remote add origin <url>[/dim]"
                ),
                border_style="yellow", padding=(1, 4),
            ))
        else:
            console.print(f"[red]Push failed: {result.stderr}[/red]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Git error: {e}[/red]")


@cli.command()
@click.argument("path", default=".")
def fix(path):
    """Auto-remediate config issues and offer package upgrades"""
    print_banner()

    # use cache for initial scan — instant if files unchanged
    with console.status("[cyan]Loading scan results...[/cyan]", spinner="dots"):
        report = run_scan_cached(path)

    fixable = [
        f for f in report.findings
        if f.library in ["bcrypt", "jwt", "axios", "mongoose", "express", "lodash"]
        and f.file != "package.json"
        and os.path.exists(f.file)
    ]

    cve_findings = [
        f for f in report.findings
        if f.file == "package.json" and ("GHSA" in f.message or "CVE" in f.message)
    ]

    if not fixable and not cve_findings:
        console.print(Panel(
            Align.center(
                "[bold green]✅ No fixable issues found.[/bold green]\n\n"
                "[dim]All dependencies are clean.[/dim]"
            ),
            border_style="green",
        ))
        return

    console.print()
    console.print(Rule("[bold cyan]Auto-Remediation Engine[/bold cyan]", style="cyan"))
    console.print(
        f"\n[bold]Found [red]{len(fixable)}[/red] config issues "
        f"and [red]{len(cve_findings)}[/red] CVE findings[/bold]\n"
    )

    fix_rules = get_fix_rules()

    # ── PART 1: CONFIG FIXES ────────────────────────────────
    files_to_fix = {}
    for finding in fixable:
        if finding.file not in files_to_fix:
            files_to_fix[finding.file] = []
        files_to_fix[finding.file].append(finding)

    total_fixed = 0
    total_skipped = 0
    total_failed = 0

    for filepath, findings in files_to_fix.items():
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                original = f.read()

            modified = original
            applied_fixes = []
            failed_fixes = []

            for finding in findings:
                lib = finding.library
                if lib not in fix_rules:
                    continue
                fix_applied = False
                for rule in fix_rules[lib]:
                    try:
                        new_content = re.sub(
                            rule["pattern"], rule["replacement"],
                            modified, flags=re.IGNORECASE,
                        )
                        if new_content != modified:
                            if rule["validate"](modified, new_content):
                                applied_fixes.append(rule["description"])
                                modified = new_content
                                fix_applied = True
                                break
                            else:
                                failed_fixes.append(f"{lib} — validation failed")
                    except re.error as e:
                        failed_fixes.append(f"{lib} — regex error: {e}")
                if not fix_applied and lib in fix_rules:
                    failed_fixes.append(f"{lib} — pattern not matched (manual fix needed)")

            if applied_fixes:
                from remediation.diff_viewer import DiffViewer
                viewer = DiffViewer()
                viewer.show(original, modified, filepath)

            if applied_fixes or failed_fixes:
                content_lines = []
                if applied_fixes:
                    content_lines.append("[green]Fixes to apply:[/green]")
                    for fix in applied_fixes:
                        content_lines.append(f"  [green]+[/green] {fix}")
                if failed_fixes:
                    content_lines.append("")
                    content_lines.append("[yellow]Could not auto-fix:[/yellow]")
                    for fail in failed_fixes:
                        content_lines.append(f"  [yellow]![/yellow] {fail}")
                console.print(Panel(
                    "\n".join(content_lines),
                    title=f"[cyan]{filepath}[/cyan]",
                    border_style="cyan",
                ))

            if applied_fixes:
                if click.confirm(f"Apply {len(applied_fixes)} fix(es) to {filepath}?"):
                    backup_path = filepath + ".spirit.bak"
                    with open(backup_path, "w", encoding="utf-8") as f:
                        f.write(original)
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(modified)
                    console.print(
                        f"  [green]✅ Fixed {filepath}[/green] "
                        f"[dim](backup: {backup_path})[/dim]\n"
                    )
                    total_fixed += len(applied_fixes)
                else:
                    console.print(f"  [yellow]⏭ Skipped {filepath}[/yellow]\n")
                    total_skipped += len(applied_fixes)

            if failed_fixes:
                total_failed += len(failed_fixes)

        except PermissionError:
            console.print(f"[red]Permission denied: {filepath}[/red]")
            total_failed += 1
        except UnicodeDecodeError:
            console.print(f"[red]Cannot read file (encoding issue): {filepath}[/red]")
            total_failed += 1
        except Exception as e:
            console.print(f"[red]Unexpected error fixing {filepath}: {e}[/red]")
            total_failed += 1

    console.print()
    console.print(Panel(
        f"[green]Fixed: {total_fixed}[/green]   "
        f"[yellow]Skipped: {total_skipped}[/yellow]   "
        f"[red]Failed: {total_failed}[/red]",
        title="[cyan]Config Remediation Summary[/cyan]",
        border_style="cyan",
    ))

    # ── PART 2: PACKAGE UPGRADES ────────────────────────────
    if cve_findings:
        console.print()
        console.print(Rule("[bold cyan]Package Upgrade Engine[/bold cyan]", style="cyan"))

        from remediation.upgrade_engine import UpgradeEngine
        upgrade_engine = UpgradeEngine()

        with console.status("[cyan]Fetching latest versions...[/cyan]", spinner="dots"):
            plan = upgrade_engine.generate_upgrade_plan(report.dependencies, cve_findings)

        if not plan:
            console.print("[green]✅ No package upgrades needed.[/green]")
        else:
            table = Table(box=box.ROUNDED, show_header=True,
                          header_style="bold cyan", border_style="cyan")
            table.add_column("Package", width=18)
            table.add_column("Current", width=12)
            table.add_column("Recommended", width=14)
            table.add_column("Latest", width=12)
            table.add_column("Reason", width=35)

            for item in plan:
                table.add_row(
                    f"[bold]{item['package']}[/bold]",
                    f"[red]{item['current']}[/red]",
                    f"[green]{item['recommended']}[/green]",
                    f"[dim]{item['latest']}[/dim]",
                    f"[dim]{item['reason'][:35]}[/dim]",
                )
            console.print(table)

            pkg_json_path = os.path.join(path, "package.json")
            if os.path.exists(pkg_json_path):
                console.print()
                upgrade_all = click.confirm(
                    f"Upgrade {len(plan)} package(s) in package.json?", default=False
                )
                if upgrade_all:
                    upgraded = 0
                    for item in plan:
                        success = upgrade_engine.apply_upgrade(
                            pkg_json_path, item["package"], item["recommended"]
                        )
                        if success:
                            console.print(
                                f"  [green]✅ {item['package']}[/green] "
                                f"[red]{item['current']}[/red] → "
                                f"[green]{item['recommended']}[/green]"
                            )
                            upgraded += 1
                        else:
                            console.print(f"  [red]✗ {item['package']} — update failed[/red]")

                    console.print(Panel(
                        Align.center(
                            f"[green]✅ {upgraded}/{len(plan)} packages "
                            f"upgraded in package.json[/green]\n\n"
                            f"[dim]Run [cyan]npm install[/cyan] to apply changes[/dim]\n"
                            f"[dim]Backup: package.json.spirit.bak[/dim]"
                        ),
                        title="[cyan]Upgrade Complete[/cyan]",
                        border_style="cyan", padding=(1, 4),
                    ))
                else:
                    console.print("[yellow]Package upgrades skipped.[/yellow]")

    # ── PART 3: RESCAN (always fresh after fix) ─────────────
    if total_fixed > 0:
        # invalidate cache — files changed
        invalidate_cache(path)

        console.print()
        console.print(Rule("[cyan]Rescanning...[/cyan]", style="cyan"))
        with console.status("[cyan]Verifying fixes...[/cyan]", spinner="dots"):
            report2 = run_scan_cached(path, force=True)  # force fresh

        _, icon, color = get_zone_style(report2.score.zone)
        console.print(Panel(
            Align.center(
                f"{icon} [bold]Score: [{color}]{report2.score.total}/100 "
                f"-- {report2.score.zone}[/{color}][/bold] {icon}\n\n"
                f"[dim]Findings remaining: {len(report2.findings)}[/dim]\n\n"
                f"[dim]Backup files created with .spirit.bak extension[/dim]"
            ),
            title="[bold green]Remediation Complete[/bold green]",
            border_style="green", padding=(1, 4),
        ))
    else:
        console.print("[yellow]No config fixes applied.[/yellow]")


@cli.command()
@click.argument("path", default=".")
def diff(path):
    """Scan only files changed since last commit — fast incremental check"""
    print_banner()
    from git.diff_scanner import DiffScanner

    console.print(f"[cyan]Scanning changed files in[/cyan] [bold]{path}[/bold]...")

    scanner = DiffScanner()
    findings, changed_files = scanner.scan_diff(path)

    if not changed_files:
        console.print(Panel(
            Align.center("[yellow]No changed files detected.[/yellow]"),
            border_style="yellow",
        ))
        return

    console.print(f"\n[cyan]Changed files ({len(changed_files)}):[/cyan]")
    for f in changed_files:
        console.print(f"  [dim]→[/dim] {f}")
    console.print()

    if not findings:
        console.print(Panel(
            Align.center("[bold green]✅ No security issues in changed files[/bold green]"),
            border_style="green",
        ))
        return

    console.print(Rule("[bold red]Issues in Changed Files[/bold red]", style="red"))
    table = Table(box=box.ROUNDED, show_header=True,
                  header_style="bold cyan", border_style="cyan")
    table.add_column("Severity", width=12)
    table.add_column("Library", width=14)
    table.add_column("File", width=40)
    table.add_column("Line", width=6)
    table.add_column("Issue", width=50)
    table.add_column("Fix", width=30)
    severity_styles = {
        "critical": ("red", "🔴 CRITICAL"),
        "high": ("orange3", "🟠 HIGH"),
        "medium": ("yellow", "🟡 MEDIUM"),
        "low": ("blue", "🔵 LOW"),
    }
    for f in findings:
        color, label = severity_styles.get(f.severity, ("white", f.severity.upper()))
        table.add_row(
            f"[{color}]{label}[/{color}]",
            f"[bold]{f.library}[/bold]",
            f"[dim]{f.file}[/dim]",
            f"[cyan]{f.line}[/cyan]",
            f.message,
            f"[green]{f.fix or 'Review manually'}[/green]",
        )
    console.print(table)
    console.print(f"\n[red]⚠ {len(findings)} issue(s) found in changed files[/red]")
    console.print(f"[yellow]Run [cyan]spirit fix {path}[/cyan] to auto-remediate[/yellow]")


@cli.command()
@click.argument("path", default=".")
def watch(path):
    """Watch for file changes and scan every 5 saves"""
    print_banner()
    console.print(f"[cyan]Watching[/cyan] [bold]{path}[/bold] for changes...")
    console.print("[dim]Scans changed files every 5 saves — Press Ctrl+C to stop[/dim]\n")

    from git.diff_scanner import DiffScanner

    class SpiritWatcher(FileSystemEventHandler):
        def __init__(self):
            self.save_count = 0
            self.scanning = False
            self.scanner = DiffScanner()
            self.last_event = {}

        def on_modified(self, event):
            if event.is_directory:
                return
            if not event.src_path.endswith((".js", ".ts", ".py", ".json")):
                return
            if self.scanning:
                return
            now = time.time()
            last = self.last_event.get(event.src_path, 0)
            if now - last < 1.0:
                return
            self.last_event[event.src_path] = now

            self.save_count += 1
            remaining = 5 - self.save_count
            console.print(
                f"[dim]Save detected ({self.save_count}/5) — "
                f"{remaining} more save(s) until next scan[/dim]"
            )

            if self.save_count >= 5:
                self.scanning = True
                self.save_count = 0
                self.last_event = {}
                console.print(f"\n[cyan]5 saves reached — scanning changed files...[/cyan]")
                try:
                    findings, changed_files = self.scanner.scan_diff(path)
                    if not changed_files:
                        console.print("[dim]No changed files detected[/dim]")
                    else:
                        console.print(f"[dim]Scanned {len(changed_files)} changed file(s)[/dim]")
                        if findings:
                            console.print(f"[red]⚠ {len(findings)} issue(s) found:[/red]")
                            for f in findings:
                                severity_color = {
                                    "critical": "red", "high": "orange3",
                                    "medium": "yellow", "low": "blue",
                                }.get(f.severity, "white")
                                console.print(
                                    f"  [{severity_color}]●[/{severity_color}] "
                                    f"[bold]{f.library}[/bold] — {f.message[:60]}"
                                )
                            console.print(
                                f"[yellow]Run [cyan]spirit fix {path}[/cyan] to auto-remediate[/yellow]"
                            )
                        else:
                            console.print("[green]✅ No issues in changed files[/green]")
                except Exception as e:
                    console.print(f"[red]Scan error: {e}[/red]")

                console.print(Rule(style="dim"))
                console.print("[dim]Watching again — next scan after 5 saves[/dim]\n")
                self.scanning = False

    observer = Observer()
    observer.schedule(SpiritWatcher(), path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        console.print("\n[cyan]Watch stopped.[/cyan]")
    observer.join()


@cli.command()
@click.argument("path", default=".")
@click.option("--json", "export_json", is_flag=True, help="Export JSON report")
@click.option("--html", "export_html", is_flag=True, help="Export HTML report")
def report(path, export_json, export_html):
    """Generate terminal, HTML, and JSON security reports with trend analysis"""
    print_banner()
    from reporting import ReportGenerator, HTMLExporter, JSONExporter

    console.print(f"[cyan]Generating report for[/cyan] [bold]{path}[/bold]...")
    with console.status("[cyan]Scanning...[/cyan]", spinner="dots"):
        scan_report = run_scan_cached(path)  # uses cache

    generator = ReportGenerator()
    report_data = generator.generate(scan_report, path)

    trend = report_data["trend"]
    trend_color = "green" if trend == "IMPROVING" else "red" if trend == "DEGRADING" else "yellow"

    display_score(scan_report.score)
    console.print(f"\nTrend: [{trend_color}]{trend}[/{trend_color}]")
    console.print(f"Total findings: {len(report_data['findings'])}")

    console.print("\n[cyan]Scan History:[/cyan]")
    for h in report_data["history"]:
        h_color = "green" if h["zone"] == "SAFE" else "yellow" if h["zone"] == "WARNING" else "red"
        console.print(
            f"  [{h_color}]{h['score']:>6}/100 {h['zone']:<12}[/{h_color}] "
            f"{h['timestamp'][:19]}"
        )

    if export_html:
        exporter = HTMLExporter()
        path_out = exporter.export(report_data)
        console.print(f"\n[green]HTML report saved:[/green] {path_out}")

    if export_json:
        exporter = JSONExporter()
        path_out = exporter.export(report_data)
        console.print(f"\n[green]JSON report saved:[/green] {path_out}")


@cli.command()
@click.argument("path", default=".")
@click.option("--all", "show_all", is_flag=True, help="Show all paths")
def audit(path, show_all):
    """View complete push audit trail — approved, blocked, force pushes"""
    print_banner()

    target = None if show_all else os.path.abspath(path)
    logs = get_audit_log(path=target, limit=20)
    summary = get_audit_summary(path=target)

    if not logs:
        console.print("[yellow]No audit records found. Run spirit push first.[/yellow]")
        return

    approved = summary.get("APPROVED", 0)
    blocked = summary.get("BLOCKED", 0)
    force = summary.get("FORCE_PUSH", 0)
    warned = summary.get("WARNING_ACCEPTED", 0)
    cancelled = summary.get("CANCELLED", 0)

    console.print(Panel(
        f"[green]Approved: {approved}[/green]   "
        f"[yellow]Warned: {warned}[/yellow]   "
        f"[red]Blocked: {blocked}[/red]   "
        f"[red]Force Push: {force}[/red]   "
        f"[dim]Cancelled: {cancelled}[/dim]",
        title="[cyan]Push Audit Summary[/cyan]",
        border_style="cyan",
    ))
    console.print()

    table = Table(box=box.ROUNDED, show_header=True,
                  header_style="bold cyan", border_style="cyan")
    table.add_column("Timestamp", width=20)
    table.add_column("Score", width=10)
    table.add_column("Zone", width=12)
    table.add_column("Action", width=18)
    table.add_column("User", width=12)
    table.add_column("Message", width=30)

    action_colors = {
        "APPROVED": "green", "WARNING_ACCEPTED": "yellow",
        "BLOCKED": "red", "FORCE_PUSH": "red", "CANCELLED": "dim",
    }
    zone_colors = {
        "SAFE": "green", "WARNING": "yellow",
        "QUARANTINE": "red", "FORCE_PUSH": "red",
    }

    for row in logs:
        _, score, zone, action, message, user, timestamp = row
        action_color = action_colors.get(action, "white")
        zone_color = zone_colors.get(zone, "white")
        table.add_row(
            f"[dim]{timestamp[:19]}[/dim]",
            f"[bold]{score}/100[/bold]",
            f"[{zone_color}]{zone}[/{zone_color}]",
            f"[{action_color}]{action}[/{action_color}]",
            f"[dim]{user}[/dim]",
            f"[dim]{message[:30] if message else '—'}[/dim]",
        )
    console.print(table)

    if force > 0:
        console.print(f"\n[red]⚠ {force} force push(es) detected — security was bypassed[/red]")


@cli.command("install-hooks")
@click.argument("path", default=".")
def install_hooks(path):
    """Install SpiritCLI as git pre-push hook in target repository"""
    abs_path = os.path.abspath(path)
    git_dir = os.path.join(abs_path, ".git")

    if not os.path.exists(git_dir):
        console.print("[red]No git repository found. Run git init first.[/red]")
        return

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, "pre-push")
    spirit_py = os.path.abspath("spirit.py")

    hook_content = f"""#!/bin/sh
echo "SpiritCLI: Running security scan before push..."
python "{spirit_py}" scan "{abs_path}"
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "SpiritCLI: Security scan failed. Push blocked."
    exit 1
fi
echo "SpiritCLI: Security check passed. Proceeding with push."
exit 0
"""
    with open(hook_path, "w") as f:
        f.write(hook_content)
    try:
        os.chmod(hook_path, 0o755)
    except Exception:
        pass

    console.print(Panel(
        f"[green]✓ Git hook installed[/green]\n\n"
        f"[dim]Location: {hook_path}[/dim]\n\n"
        f"Every [cyan]git push[/cyan] in [bold]{path}[/bold] will now "
        f"automatically run a SpiritCLI security scan.",
        title="[green]Hook Installed Successfully[/green]",
        border_style="green", padding=(1, 2),
    ))


@cli.command()
@click.argument("path", default=".")
def licenses(path):
    """Check dependency license compliance"""
    print_banner()
    console.print(f"[cyan]Checking licenses for[/cyan] [bold]{path}[/bold]...")

    with console.status("[cyan]Scanning licenses...[/cyan]", spinner="dots"):
        engine = Engine(path)
        engine.dependencies = engine._collect_dependencies()
        from integrations.license_api import LicenseChecker
        checker = LicenseChecker()
        results = checker.check_all(engine.dependencies)
        score = checker.compute_score(results)

    color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
    console.print(Panel(
        Align.center(f"[bold {color}]{score}/100 License Compliance[/bold {color}]"),
        border_style=color, padding=(1, 4),
    ))

    table = Table(box=box.ROUNDED, show_header=True,
                  header_style="bold cyan", border_style="cyan")
    table.add_column("Package", width=20)
    table.add_column("Version", width=12)
    table.add_column("License", width=20)
    table.add_column("Status", width=12)

    status_styles = {
        "safe": ("green", "✅ SAFE"),
        "review": ("yellow", "⚠ REVIEW"),
        "dangerous": ("red", "❌ DANGEROUS"),
        "unknown": ("dim", "? UNKNOWN"),
    }

    for r in results:
        color, label = status_styles.get(r["status"], ("white", r["status"]))
        table.add_row(
            f"[bold]{r['package']}[/bold]",
            f"[dim]{r['version']}[/dim]",
            r["license"],
            f"[{color}]{label}[/{color}]",
        )
    console.print(table)

    dangerous = [r for r in results if r["status"] == "dangerous"]
    if dangerous:
        console.print(
            f"\n[red]⚠ {len(dangerous)} incompatible license(s) detected — "
            f"legal review required[/red]"
        )
@cli.command()
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def reset(confirm):
    """Reset all scan history, audit logs and cache"""
    print_banner()

    if not confirm:
        confirmed = click.confirm(
            "This will delete all scan history, audit logs, and cache. Are you sure?",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]Reset cancelled.[/yellow]")
            return

    import sqlite3
    from storage.cache import clear_all_cache

    # clear cache file
    clear_all_cache()
    console.print("[green]✓ Cache cleared[/green]")

    # clear database — IF EXISTS prevents crash on missing tables
    db_path = os.path.join("spirit", "storage", "scans.db")
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM scans WHERE 1=1")
        conn.execute("DROP TABLE IF EXISTS vulnerabilities")
        conn.execute("DROP TABLE IF EXISTS audit_log")
        conn.execute("DROP TABLE IF EXISTS force_pushes")
        conn.execute("DELETE FROM sqlite_sequence WHERE 1=1")
        conn.commit()
        conn.close()
        console.print("[green]✓ Database cleared[/green]")
    else:
        console.print("[dim]No database found — nothing to clear[/dim]")

    console.print(Panel(
        Align.center("[bold green]✅ Reset complete — fresh start[/bold green]"),
        border_style="green",
    ))
if __name__ == "__main__":
    cli()