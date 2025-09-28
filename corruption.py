#!/usr/bin/env python3

import logging
import subprocess
from typing import List
import time


def _build_proc_cmdline() -> List[str]:
    cmd = [
        "sudo",
        "ping",
        "google.com"
    ]

    return cmd


# setup_logging(debug_enabled=True)
logging.basicConfig(level=logging.INFO)
logging.info("Starting injector")
cmd = _build_proc_cmdline()
proc = subprocess.Popen(cmd, stdout=None, stderr=subprocess.STDOUT)
# accept injector client
logging.info("Accept injector socket")
# cli_sock, cli_addr = self._sock.accept()
cli_sock, cli_addr = None, None
# create Worker
logging.info("Injector connected from %s", cli_addr)


for i in range(5):
    time.sleep(1)
    logging.info("Message %s: proc.status = %s", i, proc.poll())
proc.terminate()
