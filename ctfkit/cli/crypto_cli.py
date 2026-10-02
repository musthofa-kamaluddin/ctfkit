"""
ctfkit.cli.crypto_cli
Click CLI command group for the expert cryptanalysis suite.
"""

from __future__ import annotations
import sys
import json
from pathlib import Path
from typing import Optional
import click
from ctfkit.core.config import get_config
from ctfkit.core.flags import FlagDetector, KnownPlaintextOracle
from ctfkit.core.artifacts import RSAParameters
from ctfkit.crypto.pipeline import RecursiveDecodePipeline
from ctfkit.crypto.xor.single_byte import SingleByteXORSolver
from ctfkit.crypto.xor.multi_byte import RepeatingKeyXORSolver
from ctfkit.crypto.xor.known_plaintext import KnownPlaintextXORSolver
from ctfkit.crypto.classical.caesar import CaesarSolver
from ctfkit.crypto.classical.vigenere import VigenereSolver
from ctfkit.crypto.classical.affine import AffineSolver
from ctfkit.crypto.classical.transposition import RailFenceSolver
from ctfkit.crypto.rsa.attacks import RSAAutomatedTriage
from ctfkit.crypto.aes.ecb_analyzer import detect_ecb_mode
from ctfkit.crypto.prng.mt19937 import MT19937Cloner
from ctfkit.cli.formatters import (
    console,
    print_banner,
    print_flag_recovered,
    print_analysis_node
)


def read_input_data(target: str, auto_unhex: bool = True) -> bytes:
    """Reads input from direct string, local file path, or stdin ('-') with optional auto-unhexing."""
    if target == "-":
        raw = sys.stdin.buffer.read()
    else:
        p = Path(target)
        if p.is_file():
            raw = p.read_bytes()
        else:
            raw = target.encode("utf-8")

    if auto_unhex:
        clean = b"".join(raw.split()).replace(b"0x", b"").replace(b"0X", b"")
        if len(clean) >= 4 and len(clean) % 2 == 0:
            try:
                unhexed = bytes.fromhex(clean.decode("ascii"))
                if len(unhexed) > 0:
                    return unhexed
            except Exception:
                pass
    return raw


@click.group(name="crypto")
def crypto_group():
    """Expert CTF Cryptanalysis and Automation Suite."""
    pass


@crypto_group.command(name="auto")
@click.argument("target", required=True)
@click.option("--flag-prefix", default=None, help="Target flag prefix (e.g. HackToday26{)")
@click.option("--depth", default=8, type=int, help="Maximum recursive search depth")
@click.option("--beam-width", default=5, type=int, help="Beam search width")
@click.option("--json-out", is_flag=True, help="Emit JSON formatted results")
def auto_cmd(target: str, flag_prefix: Optional[str], depth: int, beam_width: int, json_out: bool):
    """Recursively analyze and decode ciphertext DAG searching for flags."""
    cfg = get_config()
    if flag_prefix:
        cfg.set_flag_prefix(flag_prefix)

    detector = FlagDetector(cfg)
    raw_data = read_input_data(target)

    if not json_out:
        print_banner(f"RECURSIVE DECODE PIPELINE [Depth: {depth}, Beam: {beam_width}]")
        console.print(f"[bold]Target Flag Prefix:[/bold] [green]{cfg.competition.flag_prefix}[/green]")

    pipeline = RecursiveDecodePipeline(config=cfg, detector=detector, max_depth=depth, beam_width=beam_width)
    node = pipeline.run(raw_data)

    if json_out:
        result = {
            "success": node is not None and node.flag_found is not None,
            "flag": node.flag_found if node else None,
            "depth": node.depth if node else 0,
            "pathway": [step.codec_name for step in node.history] if node else [],
            "payload_hex": node.payload.hex() if node else ""
        }
        click.echo(json.dumps(result, indent=2))
    else:
        if node:
            print_analysis_node(node)
        else:
            console.print("[bold red][!] No valid transformation branch could be solved.[/bold red]")


@crypto_group.command(name="xor")
@click.argument("target", required=True)
@click.option("--flag-prefix", default=None, help="Target flag prefix")
@click.option("--mode", type=click.Choice(["auto", "single", "repeating", "known"]), default="auto")
@click.option("--key-len", default="2-16", help="Key length range for repeating XOR (e.g. 2-16)")
def xor_cmd(target: str, flag_prefix: Optional[str], mode: str, key_len: str):
    """Break XOR ciphers: Single-byte, Repeating-key, or Known-Plaintext."""
    cfg = get_config()
    if flag_prefix:
        cfg.set_flag_prefix(flag_prefix)

    detector = FlagDetector(cfg)
    raw_data = read_input_data(target)
    print_banner("XOR CRYPTANALYSIS ENGINE")

    # 1. Known Plaintext Check
    if mode in ("auto", "known"):
        oracle = KnownPlaintextOracle(cfg)
        solver = KnownPlaintextXORSolver(oracle, detector)
        res = solver.solve(raw_data)
        if res and res[0].flag_found:
            print_flag_recovered(res[0].flag_found)
            console.print(f"[bold green]Recovered Key:[/bold green] {res[0].key_candidate!r}")
            return

    # 2. Single-byte XOR
    if mode in ("auto", "single"):
        s_solver = SingleByteXORSolver(detector)
        s_res = s_solver.solve(raw_data, top_k=3)
        if s_res and s_res[0].flag_found:
            print_flag_recovered(s_res[0].flag_found)
            console.print(f"[bold green]Single-byte Key:[/bold green] 0x{s_res[0].key:02x}")
            return

    # 3. Repeating-key XOR
    if mode in ("auto", "repeating"):
        r_solver = RepeatingKeyXORSolver(detector)
        parts = [int(p.strip()) for p in key_len.split("-")]
        min_l, max_l = parts[0], parts[1] if len(parts) > 1 else parts[0]
        r_res = r_solver.solve(raw_data, min_len=min_l, max_len=max_l)
        if r_res:
            best = r_res[0]
            if best.flag_found:
                print_flag_recovered(best.flag_found)
            console.print(f"[bold green]Recovered Key:[/bold green] {best.key!r} (Length: {best.key_length})")
            console.print(f"[dim]Plaintext:[/dim] {best.plaintext.decode('utf-8', errors='ignore')[:128]}...")


@crypto_group.command(name="rsa")
@click.option("-n", type=str, default=None, help="Modulus n (decimal or hex)")
@click.option("-e", type=str, default=None, help="Public exponent e (defaults to 65537 if omitted)")
@click.option("-c", type=str, default=None, help="Ciphertext c (decimal or hex)")
@click.option("--file", "param_file", type=click.Path(exists=True), default=None, help="JSON file containing parameters")
@click.option("--flag-prefix", default=None, help="Target flag prefix")
def rsa_cmd(n: Optional[str], e: Optional[str], c: Optional[str], param_file: Optional[str], flag_prefix: Optional[str]):
    """Execute automated RSA mathematical attacks (Wiener, Fermat, Small e, etc.)."""
    cfg = get_config()
    if flag_prefix:
        cfg.set_flag_prefix(flag_prefix)

    detector = FlagDetector(cfg)
    print_banner("RSA AUTOMATED TRIAGE ENGINE")

    params_dict = {}
    if param_file:
        content = Path(param_file).read_text()
        params_dict = json.loads(content)

    if n:
        params_dict["n"] = n
    if e:
        params_dict["e"] = e
    elif "e" not in params_dict:
        params_dict["e"] = 65537
    if c:
        params_dict["c"] = c

    rsa_params = RSAParameters.from_dict(params_dict)
    if not rsa_params.is_solvable_direct():
        console.print("[bold red][!] Error: Parameters n, e, and c must be provided.[/bold red]")
        return

    triage = RSAAutomatedTriage(detector)
    res = triage.audit(rsa_params)
    if res:
        console.print(f"[bold green][★] Solved via attack:[/bold green] {res.attack_name}")
        if res.flag_found:
            print_flag_recovered(res.flag_found)
        else:
            console.print(f"[bold]Plaintext bytes:[/bold] {res.plaintext_bytes!r}")
            try:
                console.print(f"[bold]Plaintext text:[/bold] {res.plaintext_bytes.decode('utf-8')}")
            except Exception:
                pass
        if res.d:
            console.print(f"[dim]Private exponent d: {res.d}[/dim]")
    else:
        console.print("[bold red][!] None of the standard algebraic attacks succeeded.[/bold red]")


@crypto_group.command(name="classical")
@click.argument("cipher_type", type=click.Choice(["rot", "vigenere", "affine", "railfence"]))
@click.argument("target", required=True)
@click.option("--flag-prefix", default=None, help="Target flag prefix")
def classical_cmd(cipher_type: str, target: str, flag_prefix: Optional[str]):
    """Solve classical ciphers: ROT/Caesar, Vigenere, Affine, Rail Fence."""
    cfg = get_config()
    if flag_prefix:
        cfg.set_flag_prefix(flag_prefix)

    detector = FlagDetector(cfg)
    raw_data = read_input_data(target)
    print_banner(f"CLASSICAL CIPHER SOLVER: {cipher_type.upper()}")

    if cipher_type == "rot":
        res = CaesarSolver(detector).solve(raw_data)
        if res:
            if res[0].flag_found:
                print_flag_recovered(res[0].flag_found)
            console.print(f"[bold green]Best Shift:[/bold green] {res[0].shift}")
            console.print(f"[bold]Plaintext:[/bold] {res[0].plaintext}")

    elif cipher_type == "vigenere":
        res = VigenereSolver(detector, KnownPlaintextOracle(cfg)).solve(raw_data)
        if res:
            if res[0].flag_found:
                print_flag_recovered(res[0].flag_found)
            console.print(f"[bold green]Recovered Key:[/bold green] {res[0].key} (Length: {res[0].key_length})")
            console.print(f"[bold]Plaintext:[/bold] {res[0].plaintext}")

    elif cipher_type == "affine":
        res = AffineSolver(detector).solve(raw_data)
        if res:
            if res[0].flag_found:
                print_flag_recovered(res[0].flag_found)
            console.print(f"[bold green]Keys:[/bold green] a={res[0].a}, b={res[0].b}")
            console.print(f"[bold]Plaintext:[/bold] {res[0].plaintext}")

    elif cipher_type == "railfence":
        res = RailFenceSolver(detector).solve(raw_data)
        if res:
            if res[0].flag_found:
                print_flag_recovered(res[0].flag_found)
            console.print(f"[bold green]Rails:[/bold green] {res[0].rails}")
            console.print(f"[bold]Plaintext:[/bold] {res[0].plaintext}")
