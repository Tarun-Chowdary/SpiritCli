import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'spirit'))

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box
from rich.rule import Rule
from rich.columns import Columns
from core import Engine

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
    
    # score breakdown panels
    panels = [
        Panel(
            f"[bold]{score.config_score}/100[/bold]",
            title="[cyan]Config Safety[/cyan]",
            border_style="cyan",
            width=20
        ),
        Panel(
            f"[bold]{score.cve_score}/100[/bold]",
            title="[cyan]CVE Exposure[/cyan]",
            border_style="cyan",
            width=20
        ),
        Panel(
            f"[bold]{score.trust_score}/100[/bold]",
            title="[cyan]Trust Score[/cyan]",
            border_style="cyan",
            width=20
        ),
        Panel(
            f"[bold]{score.freshness_score}/100[/bold]",
            title="[cyan]Freshness[/cyan]",
            border_style="cyan",
            width=20
        ),
        Panel(
            f"[bold]{score.phantom_score}/100[/bold]",
            title="[cyan]Phantom Risk[/cyan]",
            border_style="cyan",
            width=20
        ),
    ]
    
    console.print(Columns(panels, equal=True, expand=True))
    console.print()
    
    # main score
    console.print(Panel(
        Align.center(
            f"[{style}]{icon} {score.total}/100 -- {score.zone} {icon}[/{style}]"
        ),
        title="[bold white]Security Fingerprint[/bold white]",
        border_style=color,
        padding=(1, 4)
    ))

def display_findings(findings):
    if not findings:
        console.print(Panel(
            Align.center("[bold green]✅ No vulnerabilities detected. Codebase is secure.[/bold green]"),
            border_style="green"
        ))
        return
    
    console.print()
    console.print(Rule("[bold red]Security Findings[/bold red]", style="red"))
    console.print()
    
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        row_styles=["", "dim"],
        padding=(0, 1)
    )
    
    table.add_column("  Severity", width=12)
    table.add_column("Library", width=14)
    table.add_column("File", width=35)
    table.add_column("Line", width=6, justify="center")
    table.add_column("Issue", width=50)
    table.add_column("Fix", width=35)
    
    severity_styles = {
        "critical": ("red", "🔴 CRITICAL"),
        "high":     ("orange3", "🟠 HIGH"),
        "medium":   ("yellow", "🟡 MEDIUM"),
        "low":      ("blue", "🔵 LOW")
    }
    
    for f in findings:
        color, label = severity_styles.get(f.severity, ("white", f.severity.upper()))
        table.add_row(
            f"[{color}]{label}[/{color}]",
            f"[bold]{f.library}[/bold]",
            f"[dim]{f.file}[/dim]",
            f"[cyan]{f.line}[/cyan]",
            f.message,
            f"[green]{f.fix or 'Review manually'}[/green]"
        )
    
    console.print(table)

@click.group()
def cli():
    """SpiritCLI -- Real-Time Dependency Security Intelligence"""
    pass

@cli.command()
@click.argument('path', default='.')
def scan(path):
    """Run a full security scan"""
    print_banner()
    
    console.print(f"\n[cyan]Target:[/cyan] [bold]{path}[/bold]")
    console.print()
    
    with console.status(
        "[cyan]Scanning dependencies and configurations...[/cyan]",
        spinner="dots"
    ):
        engine = Engine(path)
        report = engine.run()
    
    console.print(f"[dim]Scanned {len(report.dependencies)} dependencies[/dim]")
    console.print()
    
    display_score(report.score)
    display_findings(report.findings)
    
    console.print()
    console.print(Rule(style="cyan"))
    console.print(
        f"[dim]Scan complete -- {report.timestamp}[/dim]",
        justify="center"
    )

@cli.command()
@click.argument('path', default='.')
def push(path):
    """Run push enforcement check"""
    print_banner()
    
    with console.status(
        "[cyan]Running security gate check...[/cyan]",
        spinner="dots"
    ):
        engine = Engine(path)
        report = engine.run()
    
    score = report.score.total
    zone = report.score.zone
    findings = report.findings
    critical = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]
    
    console.print()
    
    if zone == "QUARANTINE":
        console.print(Panel(
            Align.center(
                f"[bold red]🚨 PUSH BLOCKED 🚨[/bold red]\n\n"
                f"[red]Score: {score}/100 -- QUARANTINE[/red]\n\n"
                f"[white]Critical findings: [red]{len(critical)}[/red][/white]\n"
                f"[white]High findings: [orange3]{len(high)}[/orange3][/white]\n\n"
                f"[dim]Fix all critical findings before pushing.\n"
                f"Run [cyan]spirit fix {path}[/cyan] to auto-remediate.[/dim]"
            ),
            title="[bold red]SECURITY GATE -- REJECTED[/bold red]",
            border_style="red",
            padding=(1, 4)
        ))
        
        if critical:
            console.print()
            console.print(Rule("[red]Critical Issues[/red]", style="red"))
            for f in critical:
                console.print(
                    f"  [red]🔴[/red] [bold]{f.library}[/bold] -- "
                    f"{f.message} "
                    f"[dim]({f.file}:{f.line})[/dim]"
                )
        raise SystemExit(1)
    
    elif zone == "WARNING":
        console.print(Panel(
            Align.center(
                f"[bold yellow]⚠️  PUSH WARNING ⚠️ [/bold yellow]\n\n"
                f"[yellow]Score: {score}/100 -- WARNING[/yellow]\n\n"
                f"[white]Critical: [red]{len(critical)}[/red]  "
                f"High: [orange3]{len(high)}[/orange3][/white]\n\n"
                f"[dim]Developer acknowledgement required.[/dim]"
            ),
            title="[bold yellow]SECURITY GATE -- REVIEW REQUIRED[/bold yellow]",
            border_style="yellow",
            padding=(1, 4)
        ))
        
        if critical:
            console.print()
            console.print(Rule("[yellow]Critical Findings[/yellow]", style="yellow"))
            for f in critical:
                console.print(
                    f"  [red]🔴[/red] [bold]{f.library}[/bold] -- "
                    f"{f.message} "
                    f"[dim]({f.file}:{f.line})[/dim]"
                )
        
        console.print()
        confirmed = click.confirm(
            "I have reviewed all findings and accept the risk",
            default=False
        )
        
        if confirmed:
            console.print(Panel(
                Align.center("[yellow]Push proceeding with acknowledged risk.[/yellow]"),
                border_style="yellow"
            ))
        else:
            console.print(Panel(
                Align.center("[red]Push cancelled by developer.[/red]"),
                border_style="red"
            ))
            raise SystemExit(1)
    
    else:
        console.print(Panel(
            Align.center(
                f"[bold green]✅ PUSH APPROVED ✅[/bold green]\n\n"
                f"[green]Score: {score}/100 -- SAFE[/green]\n\n"
                f"[dim]No critical findings detected.\n"
                f"Codebase meets security standards.[/dim]"
            ),
            title="[bold green]SECURITY GATE -- APPROVED[/bold green]",
            border_style="green",
            padding=(1, 4)
        ))

@cli.command()
@click.argument('path', default='.')
def fix(path):
    """Run auto-remediation"""
    print_banner()
    
    with console.status(
        "[cyan]Scanning for fixable issues...[/cyan]",
        spinner="dots"
    ):
        engine = Engine(path)
        report = engine.run()
    
    if not report.findings:
        console.print(Panel(
            Align.center("[bold green]✅ No issues found. Nothing to fix.[/bold green]"),
            border_style="green"
        ))
        return
    
    console.print()
    console.print(Rule("[bold cyan]Auto-Remediation Engine[/bold cyan]", style="cyan"))
    console.print(f"\n[bold]Found [red]{len(report.findings)}[/red] fixable issues[/bold]\n")
    
    fixes = {
        "bcrypt": {
            "pattern": r'(\.hashSync\s*\([^,]+,\s*)(\d+)(\))',
            "replacement": r'\g<1>12\g<3>',
            "description": "bcrypt rounds 4 -> 12"
        },
        "jwt": {
            "pattern": r'algorithm\s*:\s*["\']none["\']',
            "replacement": "algorithm: 'HS256'",
            "description": "JWT algorithm none -> HS256"
        },
        "axios": {
            "pattern": r'rejectUnauthorized\s*:\s*false',
            "replacement": "rejectUnauthorized: true",
            "description": "axios rejectUnauthorized false -> true"
        }
    }
    
    import re
    files_to_fix = {}
    for finding in report.findings:
        if finding.file not in files_to_fix:
            files_to_fix[finding.file] = []
        files_to_fix[finding.file].append(finding)
    
    for filepath, findings in files_to_fix.items():
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                original = f.read()
            
            modified = original
            applied_fixes = []
            
            for finding in findings:
                lib = finding.library
                if lib in fixes:
                    fix_info = fixes[lib]
                    new_content = re.sub(
                        fix_info["pattern"],
                        fix_info["replacement"],
                        modified
                    )
                    if new_content != modified:
                        applied_fixes.append(fix_info["description"])
                        modified = new_content
            
            if applied_fixes:
                console.print(Panel(
                    "\n".join([f"  [green]+[/green] {fix}" for fix in applied_fixes]),
                    title=f"[cyan]{filepath}[/cyan]",
                    border_style="cyan"
                ))
                
                if click.confirm(f"Apply fixes to {filepath}?"):
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(modified)
                    console.print(f"  [green]✅ Fixed {filepath}[/green]\n")
                else:
                    console.print(f"  [yellow]⏭  Skipped {filepath}[/yellow]\n")
                    
        except Exception as e:
            console.print(f"[red]Error fixing {filepath}: {e}[/red]")
    
    console.print()
    console.print(Rule("[cyan]Rescanning...[/cyan]", style="cyan"))
    
    with console.status("[cyan]Verifying fixes...[/cyan]", spinner="dots"):
        engine2 = Engine(path)
        report2 = engine2.run()
    
    style, icon, color = get_zone_style(report2.score.zone)
    console.print(Panel(
        Align.center(
            f"{icon} [bold]Score: [{color}]{report2.score.total}/100 "
            f"-- {report2.score.zone}[/{color}][/bold] {icon}\n\n"
            f"[dim]Findings remaining: {len(report2.findings)}[/dim]"
        ),
        title="[bold green]Remediation Complete[/bold green]",
        border_style="green",
        padding=(1, 4)
    ))

@cli.command()
@click.argument('path', default='.')
def watch(path):
    """Watch for file changes and scan incrementally"""
    print_banner()
    console.print(f"[cyan]Watching[/cyan] [bold]{path}[/bold] for changes...")
    console.print("[dim]Press Ctrl+C to stop[/dim]")

@cli.command()
@click.argument('path', default='.')
@click.option('--json', 'export_json', is_flag=True, help='Export JSON report')
@click.option('--html', 'export_html', is_flag=True, help='Export HTML report')
def report(path, export_json, export_html):
    """Generate security report"""
    import sys
    sys.path.insert(0, 'spirit')
    
    from core import Engine
    from reporting import ReportGenerator, HTMLExporter, JSONExporter
    
    console.print(f"[cyan]Generating report for[/cyan] [bold]{path}[/bold]...")
    
    engine = Engine(path)
    scan_report = engine.run()
    
    generator = ReportGenerator()
    report_data = generator.generate(scan_report, path)
    
    # always show terminal summary
    score = report_data["score"]["total"]
    zone = report_data["score"]["zone"]
    trend = report_data["trend"]
    
    zone_color = "green" if zone == "SAFE" else "yellow" if zone == "WARNING" else "red"
    trend_color = "green" if trend == "IMPROVING" else "red" if trend == "DEGRADING" else "yellow"
    
    console.print(f"\n[bold {zone_color}]{score}/100 — {zone}[/bold {zone_color}]")
    console.print(f"Trend: [{trend_color}]{trend}[/{trend_color}]")
    console.print(f"Total findings: {len(report_data['findings'])}")
    
    # scan history
    console.print("\n[cyan]Scan History:[/cyan]")
    for h in report_data["history"]:
        h_color = "green" if h["zone"] == "SAFE" else "yellow" if h["zone"] == "WARNING" else "red"
        console.print(f"  [{h_color}]{h['score']:>6}/100 {h['zone']:<12}[/{h_color}] {h['timestamp'][:19]}")
    
    # export if requested
    if export_html:
        exporter = HTMLExporter()
        path_out = exporter.export(report_data)
        console.print(f"\n[green]HTML report saved:[/green] {path_out}")
    
    if export_json:
        exporter = JSONExporter()
        path_out = exporter.export(report_data)
        console.print(f"\n[green]JSON report saved:[/green] {path_out}")

if __name__ == '__main__':
    cli()