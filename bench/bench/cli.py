"""Click CLI for vmsifter-bench."""

from pathlib import Path

import click

from bench.backends import get_backend, list_backends
from bench.diff import diff as run_diff
from bench.runner import run as run_backend


@click.group()
def main() -> None:
    """vmsifter-bench — replay instruction catalogs through decoder/emulator backends."""


@main.command()
@click.option("-i", "--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("-b", "--backend", "backend_name", required=True, type=str)
@click.option("--exec-mode", type=click.Choice(["32", "64"]), default="64", show_default=True)
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("."), show_default=True)
@click.option("-o", "--output", "output_file", type=click.Path(path_type=Path), default=None,
              help="Explicit output file path (overrides --output-dir).")
def run(
    input_path: Path,
    backend_name: str,
    exec_mode: str,
    output_dir: Path,
    output_file: Path | None,
) -> None:
    """Run a backend on an instruction catalog CSV."""
    mode = int(exec_mode)

    if output_file is None:
        output_file = output_dir / f"results_{backend_name}.csv"

    click.echo(f"Backend: {backend_name} | Mode: {mode}-bit | Input: {input_path}")
    with get_backend(backend_name, exec_mode=mode) as backend:
        run_backend(input_path, backend, mode, output_file)
    click.echo(f"Output: {output_file}")


@main.command()
@click.argument("left", type=click.Path(exists=True, path_type=Path))
@click.argument("right", type=click.Path(exists=True, path_type=Path))
@click.option("--on", "columns", default="valid,length,exit_type", show_default=True,
              help="Comma-separated columns to compare.")
@click.option("-o", "--output", "output_path", type=click.Path(path_type=Path), default=None,
              help="Output file (default: stdout).")
def diff(left: Path, right: Path, columns: str, output_path: Path | None) -> None:
    """Compare two result CSVs and output differing rows."""
    compare_cols = [c.strip() for c in columns.split(",")]
    count = run_diff(left, right, output_path, compare_cols)
    click.echo(f"{count} differing row(s)", err=True)


@main.command("backends")
def backends_cmd() -> None:
    """List registered backends."""
    names = list_backends()
    if not names:
        click.echo("No backends available.")
        return
    for name in names:
        backend = get_backend(name, exec_mode=64)
        click.echo(f"  {name} ({backend.kind})")
