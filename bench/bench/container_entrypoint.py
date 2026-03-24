"""In-container entrypoint for running a single backend locally."""

import argparse
from pathlib import Path

from bench.backends import get_backend
from bench.runner import run as run_backend
from bench.validator import validate as validate_backend


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run bench logic inside a container.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a backend and write a results CSV.")
    run_parser.add_argument("--input", dest="input_path", type=Path, required=True)
    run_parser.add_argument("--output", dest="output_path", type=Path, required=True)
    run_parser.add_argument("--backend", dest="backend_name", required=True)
    run_parser.add_argument("--exec-mode", dest="exec_mode", type=int, choices=(32, 64), required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate input rows against a backend.")
    validate_parser.add_argument("--input", dest="input_path", type=Path, required=True)
    validate_parser.add_argument("--backend", dest="backend_name", required=True)
    validate_parser.add_argument("--exec-mode", dest="exec_mode", type=int, choices=(32, 64), required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with get_backend(args.backend_name, exec_mode=args.exec_mode) as backend:
        if args.command == "run":
            run_backend(args.input_path, backend, args.exec_mode, args.output_path)
            return

        summary = validate_backend(args.input_path, backend)
        if summary.discrepant_rows:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
