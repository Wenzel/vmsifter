import signal
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import List, Optional, Type

from vmsifter.config import InjectorType, settings
from vmsifter.injector.types import AbstractInjector


class XedInjector(AbstractInjector):
    def __init__(self, socket_path: Path, pinned_cpu: int):
        super().__init__(socket_path, pinned_cpu)
        self._proc: Optional[subprocess.Popen] = None

    @staticmethod
    def get_type() -> InjectorType:
        return InjectorType.XED

    def _safe_enter(self):
        super()._safe_enter()
        cmdline = self._build_proc_cmdline()
        self.logger.debug("Starting XED injector: %s", " ".join(cmdline))
        self._proc = self._ex.enter_context(subprocess.Popen(cmdline, stdout=None, stderr=subprocess.STDOUT))
        return self

    def __exit__(
        self, __exc_type: Optional[Type[BaseException]], __exc_value: Optional[BaseException], __traceback
    ) -> None:
        self.logger.debug("Cleaning up !")
        # send SIGKILL to injector
        # pypy: with SIGINT the injector doesn't terminate somehow
        if self._proc is not None:
            with suppress(ProcessLookupError):
                self._proc.send_signal(signal.SIGKILL)
        ret = super().__exit__(__exc_type, __exc_value, __traceback)
        self.logger.debug("Cleanup done")
        return ret

    def _build_proc_cmdline(self) -> List[str]:
        return [
            settings.injector.xed.injector_path,
            "--socket",
            str(self._socket_path),
            "--insn-buf-size",
            f"{settings.insn_buf_size}",
            "--pin-cpu",
            str(self._pinned_cpu),
            "--mode",
            settings.x86.exec_mode,
        ]
