"""
ctfkit.cli.main
Main CLI entrypoint for ctfkit.
"""

from __future__ import annotations
import shutil
import click
from rich.table import Table
from ctfkit import __version__
from ctfkit.cli.crypto_cli import crypto_group
from ctfkit.cli.formatters import console, print_banner


@click.group()
@click.version_option(version=__version__, prog_name="ctfkit")
def cli():
    """ctfkit - Modular CTF Cryptanalysis & Automation Toolkit."""
    pass


@cli.command(name="doctor")
def doctor_cmd():
    """Inspect environment, installed Python crypto packages, and system binaries."""
    print_banner(f"CTFKIT ENVIRONMENT DIAGNOSTICS v{__version__}")

    table = Table(title="Dependency Status")
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Tier", style="magenta")
    table.add_column("Status", style="bold")
    table.add_column("Notes", style="dim")

    # Python core packages
    modules_to_check = [
        ("rich", "UI", True),
        ("Crypto", "Core AES/Block (pycryptodome)", True),
        ("sympy", "Number Theory", False),
        ("gmpy2", "C Fast Math (gmpy2)", False),
        ("z3", "SMT Solver (z3-solver)", False),
        ("requests", "FactorDB API", False),
    ]

    for mod_name, label, is_core in modules_to_check:
        try:
            __import__(mod_name)
            table.add_row(f"{label}", "Python", "[green]INSTALLED[/green]", f"Available ({mod_name})")
        except ImportError:
            status = "[yellow]OPTIONAL (MISSING)[/yellow]" if not is_core else "[red]CORE (MISSING)[/red]"
            table.add_row(f"{label}", "Python", status, "Fallback in effect")

    # External binaries
    binaries_to_check = [
        ("sage", "SageMath (Lattice & Coppersmith)"),
        ("hashcat", "Hashcat GPU Cracker"),
        ("john", "John the Ripper"),
    ]

    for bin_name, label in binaries_to_check:
        path = shutil.which(bin_name)
        if path:
            table.add_row(label, "Binary", "[green]FOUND[/green]", path)
        else:
            table.add_row(label, "Binary", "[dim]NOT FOUND[/dim]", "Optional external tool")

    console.print(table)


# Register subcommand groups
cli.add_command(crypto_group)


if __name__ == "__main__":
    cli()
