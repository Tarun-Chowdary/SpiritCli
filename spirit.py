import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'spirit'))

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from core import Engine

console = Console()

@click.group()
def cli():
    """SpiritCLI — Real-Time Dependency Security Intelligence"""
    pass

@cli.command()
@click.argument('path', default='.')
def scan(path):
    """Run a full security scan"""
    console.print(Panel(
        f"[bold cyan]SpiritCLI[/bold cyan] scanning [bold]{path}[/bold]",
        box=box.DOUBLE
    ))
    with console.status("[cyan]Scanning...[/cyan]", spinner="dots"):
        engine = Engine(path)
    report = engine.run()
    
    # score color
    if report.score.zone == "SAFE":
        color = "green"
    elif report.score.zone == "WARNING":
        color = "yellow"
    else:
        color = "red"
    
    # score panel
    console.print(Panel(
        f"[bold {color}]{report.score.total}/100 — {report.score.zone}[/bold {color}]\n\n"
        f"Config Safety:  {report.score.config_score}/100\n"
        f"CVE Exposure:   {report.score.cve_score}/100\n"
        f"Trust Score:    {report.score.trust_score}/100\n"
        f"Freshness:      {report.score.freshness_score}/100\n"
        f"Phantom Risk:   {report.score.phantom_score}/100",
        title="Security Fingerprint"
    ))
    
    # findings table
    if report.findings:
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
        table.add_column("Severity", width=10)
        table.add_column("Library", width=12)
        table.add_column("File", width=30)
        table.add_column("Line", width=6)
        table.add_column("Message", width=60)
        
        for f in report.findings:
            color = {
                "critical": "red",
                "high": "orange3",
                "medium": "yellow",
                "low": "blue"
            }.get(f.severity, "white")
            
            table.add_row(
                f"[{color}]{f.severity.upper()}[/{color}]",
                f.library,
                f.file,
                str(f.line),
                f.message
            )
        
        console.print("\n[bold]Findings:[/bold]")
        console.print(table)
    else:
        console.print("\n[green]No findings detected. Codebase looks clean.[/green]")
    
    # summary
    console.print(f"\n[cyan]Scanned:[/cyan] {len(report.dependencies)} dependencies across {path}")

@cli.command()
@click.argument('path', default='.')
def watch(path):
    """Watch for file changes and scan incrementally"""
    console.print(f"[cyan]Watching[/cyan] [bold]{path}[/bold]...")

@cli.command()
@click.argument('path', default='.')
def push(path):
    """Run push enforcement check"""
    with console.status("[cyan]Running security check before push...[/cyan]", spinner="dots"):
        engine = Engine(path)
        report = engine.run()
    
    score = report.score.total
    zone = report.score.zone
    findings = report.findings
    
    critical = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]
    
    if zone == "QUARANTINE":
        console.print(Panel(
            f"[bold red]PUSH BLOCKED[/bold red]\n\n"
            f"Score: {score}/100 -- QUARANTINE\n\n"
            f"Critical findings: {len(critical)}\n"
            f"High findings: {len(high)}\n\n"
            f"Fix all critical findings before pushing.\n"
            f"Run [cyan]spirit fix {path}[/cyan] to auto-remediate.",
            title="[red]PUSH REJECTED[/red]",
            border_style="red"
        ))
        raise SystemExit(1)
    
    elif zone == "WARNING":
        console.print(Panel(
            f"[yellow]Score: {score}/100 -- WARNING[/yellow]\n\n"
            f"Active findings:\n"
            f"  Critical: {len(critical)}\n"
            f"  High: {len(high)}\n\n"
            f"Review findings before pushing.",
            title="[yellow]PUSH WARNING[/yellow]",
            border_style="yellow"
        ))
        
        if critical:
            console.print("\n[bold red]Critical findings that need attention:[/bold red]")
            for f in critical:
                console.print(f"  [red]--[/red] {f.library} | {f.message} | {f.file}:{f.line}")
        
        confirmed = click.confirm(
            "\nI have reviewed all findings and accept the risk",
            default=False
        )
        
        if confirmed:
            console.print("[yellow]Push proceeding with acknowledged risk.[/yellow]")
        else:
            console.print("[red]Push cancelled.[/red]")
            raise SystemExit(1)
    
    else:
        console.print(Panel(
            f"[bold green]Score: {score}/100 -- SAFE[/bold green]\n\n"
            f"No critical findings detected.\n"
            f"Codebase is secure.",
            title="[green]PUSH APPROVED[/green]",
            border_style="green"
        ))

@cli.command()
@click.argument('path', default='.')
def fix(path):
    """Run auto-remediation"""
    with console.status("[cyan]Scanning for fixable issues...[/cyan]", spinner="dots"):
        engine = Engine(path)
        report = engine.run()
    
    if not report.findings:
        console.print("[green]No issues found. Nothing to fix.[/green]")
        return
    
    console.print(f"\n[bold]Found {len(report.findings)} fixable issues[/bold]\n")
    
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
                # show diff
                console.print(f"\n[bold cyan]File: {filepath}[/bold cyan]")
                for fix_desc in applied_fixes:
                    console.print(f"  [green]+[/green] {fix_desc}")
                
                # ask confirmation
                if click.confirm(f"\nApply {len(applied_fixes)} fix(es) to {filepath}?"):
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(modified)
                    console.print(f"[green]Fixed {filepath}[/green]")
                else:
                    console.print(f"[yellow]Skipped {filepath}[/yellow]")
                    
        except Exception as e:
            console.print(f"[red]Error fixing {filepath}: {e}[/red]")
    
    # rescan to show improvement
    console.print("\n[cyan]Rescanning to show improvement...[/cyan]")
    with console.status("[cyan]Rescanning...[/cyan]", spinner="dots"):
        engine2 = Engine(path)
        report2 = engine2.run()
    
    console.print(Panel(
        f"[bold green]Score after fix: {report2.score.total}/100 -- {report2.score.zone}[/bold green]\n"
        f"Findings remaining: {len(report2.findings)}",
        title="[green]Fix Complete[/green]",
        border_style="green"
    ))

@cli.command()
def report():
    """Generate security report"""
    console.print("[cyan]Generating report...[/cyan]")

if __name__ == '__main__':
    cli()