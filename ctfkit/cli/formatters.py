"""
ctfkit.cli.formatters
Cross-platform terminal presentation (UTF-8 and Windows CP1252 safe).
"""

from __future__ import annotations
import sys
import json
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree
from rich.text import Text
from ctfkit.core.artifacts import TransformationStep
from ctfkit.crypto.pipeline import PipelineNode

# Ensure stdout and stderr use UTF-8 where possible
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(highlight=False)


def print_banner(title: str = "CTFKIT CRYPTO EXPERT TOOLKIT") -> None:
    banner = Text(f"[=] {title} [=]", style="bold cyan")
    console.print(Panel(banner, border_style="cyan"))


def print_flag_recovered(flag: str) -> None:
    text = Text(f"[★] FLAG RECOVERED: {flag}", style="bold green on black")
    console.print(Panel(text, border_style="green", expand=False))


def print_transformation_tree(history: List[TransformationStep], initial_label: str = "Input Data") -> None:
    tree = Tree(f"[bold yellow]{initial_label}[/bold yellow]")
    current = tree
    for step in history:
        param_str = f" [dim]{json.dumps(step.parameters)}[/dim]" if step.parameters else ""
        current = current.add(f"[bold cyan]Step {step.depth}:[/bold cyan] [green]{step.codec_name}[/green]{param_str}")
    console.print(tree)


def print_analysis_node(node: PipelineNode) -> None:
    if node.flag_found:
        print_flag_recovered(node.flag_found)

    console.print("\n[bold cyan]Transformation Pathway:[/bold cyan]")
    print_transformation_tree(node.history)

    console.print(f"\n[dim]Final Payload ({len(node.payload)} bytes):[/dim]")
    try:
        preview = node.payload.decode("utf-8")
        console.print(Panel(preview, title="Decoded Plaintext", border_style="blue"))
    except Exception:
        hex_preview = node.payload.hex()[:256]
        console.print(Panel(hex_preview, title="Binary / Hex Output", border_style="blue"))
