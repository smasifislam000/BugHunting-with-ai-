"""
monitoring/scheduler.py
-----------------------
Simple interval-based scheduler.
Runs a job every N hours, used for continuous monitoring.
"""

import time
import threading
from typing import Callable, Optional

from core.logger import get_logger, info, ok, warn

log = get_logger("scheduler")


def run_every(interval_seconds: int, job: Callable,
              run_immediately: bool = True,
              stop_event: Optional[threading.Event] = None):
    """
    Runs job every interval_seconds until stop_event is set.
    """
    if stop_event is None:
        stop_event = threading.Event()

    if run_immediately:
        try:
            job()
        except Exception as e:
            log.debug(f"job failed: {e}")

    while not stop_event.is_set():
        stop_event.wait(interval_seconds)
        if stop_event.is_set():
            break
        try:
            info("scheduler: running job")
            job()
            ok("scheduler: job done")
        except Exception as e:
            warn(f"scheduler job failed: {e}")


if __name__ == "__main__":
    def example():
        print("tick")

    try:
        run_every(5, example)
    except KeyboardInterrupt:
        pass
