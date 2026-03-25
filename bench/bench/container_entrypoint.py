"""In-container entrypoint for running a single backend locally."""

import argparse
from pathlib import Path

from bench.backends import get_backend
from bench.runner import run as run_backend
from bench.validator import VALIDATION_DISCREPANCY_EXIT_CODE, validate as validate_backend


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run bench logic inside a container.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a backend and write a results CSV.")
    run_parser.add_argument("--input", dest="input_path", type=Path, required=True)
    run_parser.add_argument("--output", dest="output_path", type=Path, required=True)
    run_parser.add_argument("--backend", dest="backend_name", required=True)
    run_parser.add_argument("--exec-mode", dest="exec_mode", type=int, choices=(32, 64), required=True)
    run_parser.add_argument("--progress-socket", dest="progress_socket", type=Path, default=None)
    run_parser.add_argument("--byte-start", dest="byte_start", type=int, default=None)
    run_parser.add_argument("--byte-end", dest="byte_end", type=int, default=None)

    validate_parser = subparsers.add_parser("validate", help="Validate input rows against a backend.")
    validate_parser.add_argument("--input", dest="input_path", type=Path, required=True)
    validate_parser.add_argument("--output", dest="output_path", type=Path, default=None)
    validate_parser.add_argument("--backend", dest="backend_name", required=True)
    validate_parser.add_argument("--exec-mode", dest="exec_mode", type=int, choices=(32, 64), required=True)
    validate_parser.add_argument("--progress-socket", dest="progress_socket", type=Path, default=None)
    validate_parser.add_argument("--byte-start", dest="byte_start", type=int, default=None)
    validate_parser.add_argument("--byte-end", dest="byte_end", type=int, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with get_backend(args.backend_name, exec_mode=args.exec_mode) as backend:
        if args.command == "run":
            run_backend(
                args.input_path,
                backend,
                args.exec_mode,
                args.output_path,
                progress_socket=args.progress_socket,
                byte_start=args.byte_start,
                byte_end=args.byte_end,
            )
            return

        summary = validate_backend(
            args.input_path,
            backend,
            args.output_path,
            progress_socket=args.progress_socket,
            byte_start=args.byte_start,
            byte_end=args.byte_end,
        )
        if summary.discrepant_rows:
            raise SystemExit(VALIDATION_DISCREPANCY_EXIT_CODE)


if __name__ == "__main__":
    main()
