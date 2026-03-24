"""In-container entrypoint for running a single backend locally."""

import argparse
from pathlib import Path

from bench.backends import get_backend
from bench.runner import run as run_backend


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a bench backend inside a container.")
    parser.add_argument("--input", dest="input_path", type=Path, required=True)
    parser.add_argument("--output", dest="output_path", type=Path, required=True)
    parser.add_argument("--backend", dest="backend_name", required=True)
    parser.add_argument("--exec-mode", dest="exec_mode", type=int, choices=(32, 64), required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with get_backend(args.backend_name, exec_mode=args.exec_mode) as backend:
        run_backend(args.input_path, backend, args.exec_mode, args.output_path)


if __name__ == "__main__":
    main()
