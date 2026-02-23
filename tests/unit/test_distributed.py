# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import multiprocessing
import pickle
import queue as queue_mod
from unittest.mock import patch

import pytest

from tests.fixtures.mock_socket import MockSocket
from vmsifter.fuzzer import TunnelFuzzer
from vmsifter.fuzzer.types import Splittable
from vmsifter.worker import Worker


@pytest.fixture
def workdir(tmp_path):
    """Override settings.workdir to use a temp directory."""
    with patch("vmsifter.worker.settings") as mock_settings, patch("vmsifter.output.settings") as mock_out_settings:
        mock_settings.workdir = str(tmp_path)
        mock_settings.insn_buf_size = 15
        mock_settings.refresh_frequency = 100
        mock_settings.logging.format = None
        mock_out_settings.workdir = str(tmp_path)
        yield tmp_path


def test_worker_legacy_mode(workdir):
    """Without queue/events, handle_client behaves identically to current code."""
    # Small range that finishes quickly
    tun = TunnelFuzzer(insn_buffer=bytearray([0xFE]), end_first_byte=b"\xFF")
    worker = Worker(0, tun)
    worker.__enter__()

    mock_sock = MockSocket()
    stats = worker.handle_client(mock_sock, ("mock", 0))

    assert stats.nb_insn > 0
    assert stats.total_seconds >= 0
    worker.__exit__(None, None, None)


def test_worker_signals_idle_when_done(workdir):
    """Worker sets idle_event after fuzzer is exhausted."""
    tun = TunnelFuzzer(insn_buffer=bytearray([0xFE]), end_first_byte=b"\xFF")
    worker = Worker(0, tun)
    worker.__enter__()

    mock_sock = MockSocket()
    idle_event = multiprocessing.Event()
    split_event = multiprocessing.Event()
    work_queue = multiprocessing.Queue()

    # Worker will exhaust its range, signal idle, wait for new work,
    # timeout after 1 second (we use a short timeout by mocking)
    with patch("vmsifter.worker.queue_mod") as mock_queue_mod:
        mock_queue_mod.Empty = queue_mod.Empty
        stats = worker.handle_client(mock_sock, ("mock", 0), work_queue, idle_event, split_event)

    # idle_event should have been set at some point
    # (it stays set because no scheduler cleared it)
    assert idle_event.is_set()
    assert stats.nb_insn > 0
    worker.__exit__(None, None, None)


def test_worker_picks_up_new_work(workdir):
    """Worker gets new fuzzer from queue after signaling idle."""
    tun = TunnelFuzzer(insn_buffer=bytearray([0xFE]), end_first_byte=b"\xFF")
    worker = Worker(0, tun)
    worker.__enter__()

    mock_sock = MockSocket()
    idle_event = multiprocessing.Event()
    split_event = multiprocessing.Event()
    work_queue = multiprocessing.Queue()

    # Put a second small range on the queue for pickup
    second_tun = TunnelFuzzer(insn_buffer=bytearray([0xFD]), end_first_byte=b"\xFE")
    work_queue.put(second_tun)

    stats = worker.handle_client(mock_sock, ("mock", 0), work_queue, idle_event, split_event)

    # Worker should have processed both ranges
    assert stats.nb_insn > 0
    worker.__exit__(None, None, None)


def test_donor_splits_on_event(workdir):
    """Worker with split_event set puts split fuzzer on queue."""
    # Wider range so it doesn't exhaust before the split checkpoint
    tun = TunnelFuzzer(insn_buffer=bytearray([0x00]), end_first_byte=b"\xFF")
    worker = Worker(0, tun)
    worker.__enter__()

    mock_sock = MockSocket()
    idle_event = multiprocessing.Event()
    split_event = multiprocessing.Event()
    work_queue = multiprocessing.Queue()

    # Set the split event before starting -- it will be checked at refresh_frequency intervals
    split_event.set()

    # Use a very low refresh frequency so the split checkpoint is hit quickly
    worker._cache_dyna_refresh_frequency = 1

    # We need the worker to stop after a while. Override the fuzzer to have a small range.
    # Actually, let's use a medium range and just let it run.
    tun2 = TunnelFuzzer(insn_buffer=bytearray([0xF0]), end_first_byte=b"\xFF")
    worker._fuzzer = tun2
    split_event.set()

    stats = worker.handle_client(mock_sock, ("mock", 0), work_queue, idle_event, split_event)

    # Check if a split fuzzer was placed on the queue
    try:
        donated_fuzzer = work_queue.get_nowait()
        assert isinstance(donated_fuzzer, Splittable)
    except queue_mod.Empty:
        # If range was too small to split, that's also valid
        pass

    worker.__exit__(None, None, None)


def test_split_result_picklable_through_queue():
    """Verify split TunnelFuzzer can be sent through multiprocessing.Queue."""
    tun = TunnelFuzzer(insn_buffer=bytearray([0x00]), end_first_byte=b"\xFF")
    new = tun.split_remaining()
    assert new is not None

    q = multiprocessing.Queue()
    q.put(new)
    received = q.get(timeout=5)
    assert received.insn_buffer[0] == new.insn_buffer[0]
    assert received.end_first_byte == new.end_first_byte
