"""Real Docker-backed XED validation regression tests."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import docker
import pytest
from docker.errors import DockerException

from bench.docker_runtime import (
    build_backend_image,
    validate_backend_container,
    validate_backend_containers_parallel,
)

pytestmark = pytest.mark.docker_integration

FIXTURES_DIR = Path(__file__).parent / "data"
XED_DISCREPANCY_CSV = FIXTURES_DIR / "xed_validate_discrepancies.csv"


@pytest.fixture(scope="session")
def docker_client():
    try:
        client = docker.from_env()
        client.ping()
    except DockerException as exc:
        pytest.skip(f"Docker daemon is unavailable: {exc}")
    yield client
    client.close()


@pytest.fixture(scope="session")
def built_xed_image(docker_client):
    build_backend_image("xed", client=docker_client)
    return docker_client


def _expected_insns(path: Path) -> list[str]:
    with open(path, newline="", encoding="ascii") as stream:
        return [row["insn"] for row in csv.DictReader(stream)]


def _assert_failure_payload(output_path: Path, expected_insns: list[str]) -> None:
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert [entry["reference"]["insn"] for entry in payload] == expected_insns
    assert all(entry["report"]["comparable"] is True for entry in payload)
    assert all(len(entry["report"]["issues"]) == 1 for entry in payload)
    assert all(entry["report"]["issues"][0]["field"] == "length" for entry in payload)


def test_validate_backend_container_reports_real_xed_discrepancies(
    tmp_path: Path,
    built_xed_image,
):
    output_path = tmp_path / "xed.failures.single.json"
    expected_insns = _expected_insns(XED_DISCREPANCY_CSV)

    with pytest.raises(RuntimeError, match="Validation found discrepancies"):
        validate_backend_container(
            "xed",
            XED_DISCREPANCY_CSV,
            64,
            output_path=output_path,
            client=built_xed_image,
        )

    _assert_failure_payload(output_path, expected_insns)


def test_validate_backend_containers_parallel_reports_real_xed_discrepancies_with_8_workers(
    tmp_path: Path,
    built_xed_image,
):
    output_path = tmp_path / "xed.failures.parallel.json"
    expected_insns = _expected_insns(XED_DISCREPANCY_CSV)

    with pytest.raises(RuntimeError, match="Validation found discrepancies"):
        validate_backend_containers_parallel(
            "xed",
            XED_DISCREPANCY_CSV,
            64,
            output_path=output_path,
            workers=8,
            client=built_xed_image,
        )

    _assert_failure_payload(output_path, expected_insns)
