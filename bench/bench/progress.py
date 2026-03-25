"""Progress reporting helpers shared between host and container code."""

from __future__ import annotations

import json
import logging
import socket
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def decode_progress_line(line: str) -> dict[str, object]:
    """Parse one newline-delimited JSON progress update."""
    payload = json.loads(line)
    if not isinstance(payload, dict):
        raise ValueError("Progress payload must be a JSON object")
    return payload


class ByteCountingTextReader:
    """Iterate over a text file while tracking the number of bytes consumed."""

    def __init__(self, path: Path, *, encoding: str = "utf-8") -> None:
        self.path = path
        self.encoding = encoding
        self.bytes_read = 0
        self._stream = None

    def __enter__(self) -> "ByteCountingTextReader":
        self._stream = open(self.path, "rb")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __iter__(self) -> "ByteCountingTextReader":
        return self

    def __next__(self) -> str:
        line = self.readline()
        if line == "":
            raise StopIteration
        return line

    def readline(self) -> str:
        """Read one line, updating the consumed-byte counter."""
        if self._stream is None:
            raise ValueError("I/O operation on closed file")

        chunk = self._stream.readline()
        if not chunk:
            return ""

        self.bytes_read += len(chunk)
        return chunk.decode(self.encoding)

    def close(self) -> None:
        """Close the wrapped file if it is open."""
        if self._stream is None:
            return
        try:
            self._stream.close()
        finally:
            self._stream = None


class ProgressReporter:
    """Send throttled progress updates over an optional Unix socket."""

    def __init__(
        self,
        socket_path: Path | None,
        *,
        phase: str,
        every: int = 100,
        min_interval: float = 0.1,
    ) -> None:
        self.socket_path = socket_path
        self.phase = phase
        self.every = every
        self.min_interval = min_interval
        self._socket: socket.socket | None = None
        self._last_current = -1
        self._last_sent_at = 0.0

    def __enter__(self) -> "ProgressReporter":
        if self.socket_path is None:
            return self

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(str(self.socket_path))
        except OSError:
            logger.debug("Progress socket %s is unavailable", self.socket_path, exc_info=True)
            try:
                sock.close()
            except UnboundLocalError:
                pass
            return self

        self._socket = sock
        self.report(0, force=True)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def report(self, current: int, *, force: bool = False, done: bool = False) -> None:
        """Send a progress update if the channel is available and not throttled."""
        if self._socket is None:
            return

        now = time.monotonic()
        should_send = force or done
        if not should_send:
            delta = current - self._last_current
            should_send = delta >= self.every or now - self._last_sent_at >= self.min_interval
        if not should_send:
            return

        payload = {
            "phase": self.phase,
            "current": current,
            "done": done,
        }
        try:
            self._socket.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        except OSError:
            logger.debug("Failed to send progress update to %s", self.socket_path, exc_info=True)
            self.close()
            return

        self._last_current = current
        self._last_sent_at = now

    def close(self) -> None:
        """Close the progress channel if it is open."""
        if self._socket is None:
            return
        try:
            self._socket.close()
        finally:
            self._socket = None
