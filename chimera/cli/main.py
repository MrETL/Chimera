"""Command-line interface for Chimera."""

import click
import json
from rich.console import Console
from rich.table import Table

from chimera.core.kernel import ChimeraKernel
from chimera.core.attack_registry import AttackRegistry

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Chimera - Unified AI Offensive Framework."""
    pass


@cli.command()
@click.argument("target_uri")
@click.option("--attack", "-a", multiple=True, help="Specific attack(s) to run (can be repeated).")
@click.option("--list-attacks", is_flag=True, help="List available attacks and exit.")
@click.option("--output", "-o", help="Output file for report.")
@click.option("--format", "-f", type=click.Choice(["json", "markdown"]), default="json", help="Report format.")
def scan(target_uri, attack, list_attacks, output, format):
    """Scan a target model with specified attacks."""
    if list_attacks:
        _list_attacks()
        return
    
    kernel = ChimeraKernel()
    attacks = list(attack) if attack else None
    
    console.print(f"[bold green]🔍 Scanning target: {target_uri}[/bold green]")
    results = kernel.scan_target(target_uri, attacks=attacks)
    
    # Display summary
    _display_summary(results)
    
    # Generate and save report
    report = kernel.generate_report(results, format=format)
    if output:
        with open(output, "w") as f:
            f.write(report)
        console.print(f"[green]Report saved to {output}[/green]")
    else:
        console.print(report)


@cli.command()
def list_attacks():
    """List all available attack modules."""
    _list_attacks()


def _list_attacks():
    """Display all registered attacks."""
    table = Table(title="Available Attacks")
    table.add_column("Name", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Description", style="green")
    
    for name in AttackRegistry.list_attacks():
        attack_cls = AttackRegistry.get_attack(name)
        if attack_cls:
            table.add_row(
                name,
                attack_cls.category.value,
                attack_cls.description
            )
    
    console.print(table)


def _display_summary(results):
    """Display a summary table of results."""
    table = Table(title="Scan Results Summary")
    table.add_column("Attack", style="cyan")
    table.add_column("Success", style="bold")
    table.add_column("Confidence", style="yellow")
    table.add_column("MITRE", style="blue")
    
    for r in results:
        success_text = "[green]✓[/green]" if r.success else "[red]✗[/red]"
        table.add_row(
            r.attack_name,
            success_text,
            f"{r.confidence:.2f}",
            r.mitre_technique or "N/A"
        )
    
    console.print(table)


if __name__ == "__main__":
    cli()
