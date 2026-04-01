"""Click CLI for vmsifter-bench."""

import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from bench.diff import diff as run_diff
from bench.docker_runtime import list_backends, run_backend_in_docker, validate_backend_in_docker
from bench.normalize import normalize_campaign_dir


def _format_byte_count(value: int) -> str:
    if value < 1000:
        return f"{value}B"

    suffixes = ("KB", "MB", "GB", "TB", "PB", "EB")
    scaled = float(value)
    for suffix in suffixes:
        scaled /= 1000.0
        if scaled < 1000.0:
            return f"{scaled:.1f}{suffix}"

    return f"{scaled:.1f}{suffix}"


class CompactByteCountColumn(ProgressColumn):
    def render(self, task) -> str:
        total = task.total
        if isinstance(total, (int, float)) and not isinstance(total, bool):
            return f"{_format_byte_count(int(task.completed))}/{_format_byte_count(int(total))}"
        return _format_byte_count(int(task.completed))


@click.group()
@click.option("--debug", "-d", is_flag=True, default=False, help="Enable debug logging.")
@click.pass_context
def main(ctx: click.Context, debug: bool) -> None:
    """vmsifter-bench — replay instruction catalogs through decoder/emulator backends."""
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )


@main.command()
@click.option("-i", "--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("-b", "--backend", "backend_name", required=True, type=str)
@click.option("--exec-mode", type=click.Choice(["32", "64"]), default="64", show_default=True)
@click.option("-j", "--workers", type=click.IntRange(min=1), default=1, show_default=True)
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("."), show_default=True)
@click.option("-o", "--output", "output_file", type=click.Path(path_type=Path), default=None,
              help="Explicit output file path (overrides --output-dir).")
def run(
    input_path: Path,
    backend_name: str,
    exec_mode: str,
    workers: int,
    output_dir: Path,
    output_file: Path | None,
) -> None:
    """Build and run a backend container on an instruction catalog CSV."""
    mode = int(exec_mode)

    if output_file is None:
        output_file = output_dir / f"results_{backend_name}.csv"

    click.echo(f"Backend: {backend_name} | Mode: {mode}-bit | Workers: {workers} | Input: {input_path}")
    try:
        run_backend_in_docker(input_path, backend_name, mode, output_file, workers=workers)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Output: {output_file}")


@main.command()
@click.option("-i", "--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("-b", "--backend", "backend_name", required=True, type=str)
@click.option("--exec-mode", type=click.Choice(["32", "64"]), default="64", show_default=True)
@click.option("-j", "--workers", type=click.IntRange(min=1), default=1, show_default=True)
@click.option("-o", "--output", "output_path", type=click.Path(path_type=Path), default=None,
              help="Optional JSON file to write discrepant rows to.")
def validate(input_path: Path, backend_name: str, exec_mode: str, workers: int, output_path: Path | None) -> None:
    """Validate an input CSV against a backend without writing a results file."""
    mode = int(exec_mode)
    click.echo(f"Backend: {backend_name} | Mode: {mode}-bit | Workers: {workers} | Input: {input_path}")
    try:
        validate_backend_in_docker(input_path, backend_name, mode, output_path=output_path, workers=workers)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo("Validation succeeded.")


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


@main.command()
@click.argument("campaign_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
def normalize(campaign_dir: Path) -> None:
    """Merge sharded campaign CSVs into unified files."""
    progress: Progress | None = None
    task_ids: dict[str, TaskID] = {}
    progress_callback = None

    if sys.stderr.isatty():
        progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            CompactByteCountColumn(),
            TimeElapsedColumn(),
            TextColumn("eta"),
            TimeRemainingColumn(compact=True, elapsed_when_finished=True),
            transient=True,
            console=Console(stderr=True),
        )
        progress.start()

        def render_progress(name: str, current: int, total: int) -> None:
            task_id = task_ids.get(name)
            if task_id is None:
                label = name.replace("_", " ")
                task_id = progress.add_task(f"Normalizing {label}", total=total)
                task_ids[name] = task_id
            progress.update(task_id, completed=current, total=total)

        progress_callback = render_progress

    try:
        outputs = normalize_campaign_dir(campaign_dir, progress_callback=progress_callback)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        if progress is not None:
            progress.stop()

    for output_path in outputs.values():
        click.echo(f"Normalized: {output_path}")


@main.command("backends")
def backends_cmd() -> None:
    """List available containerized backends."""
    names = list_backends()
    if not names:
        click.echo("No backends available.")
        return
    for name in names:
        click.echo(f"  {name}")
