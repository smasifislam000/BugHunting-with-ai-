"""
core/error_recovery.py
----------------------
Error isolation utilities.
Wraps any function so failures don't stop the scan.
"""

import time
import functools
import traceback
from pathlib import Path
from typing import Callable, Any, Optional, Type, Tuple
from datetime import datetime

from core.logger import get_logger, warn, err

log = get_logger("error_recovery")


# ─────────────────────────────────────────
# Error log file
# ─────────────────────────────────────────
_ERROR_LOG = Path("logs/errors.log")


def _log_error(where: str, exc: BaseException, tb: str = "") -> None:
    try:
        _ERROR_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(_ERROR_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n[{datetime.utcnow().isoformat()}] {where}\n")
            f.write(f"{type(exc).__name__}: {exc}\n")
            if tb:
                f.write(tb[:4000] + "\n")
    except Exception:
        pass


# ─────────────────────────────────────────
# Decorator: safe_call
# ─────────────────────────────────────────
def safe_call(default: Any = None,
              retries: int = 0,
              retry_delay: float = 1.0,
              retry_on: Tuple[Type[BaseException], ...] = (Exception,),
              log_traceback: bool = False):
    """
    Decorator that catches all exceptions and returns default.
    Optional retry on specified exceptions.

    Usage:
        @safe_call(default=[], retries=2)
        def get_subdomains(domain): ...
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last_exc: Optional[BaseException] = None
            for attempt in range(retries + 1):
                try:
                    return fn(*args, **kwargs)
                except retry_on as e:
                    last_exc = e
                    if attempt < retries:
                        log.debug(
                            f"{fn.__name__} failed (attempt {attempt+1}): {e}"
                        )
                        time.sleep(retry_delay * (2 ** attempt))
                        continue
                    # Final failure
                    warn(f"{fn.__name__} failed after {retries+1} attempts: {e}")
                    _log_error(
                        fn.__qualname__, e,
                        traceback.format_exc() if log_traceback else ""
                    )
                    return default
                except Exception as e:
                    warn(f"{fn.__name__} unexpected error: {e}")
                    _log_error(
                        fn.__qualname__, e,
                        traceback.format_exc() if log_traceback else ""
                    )
                    return default
            return default
        return wrapper
    return decorator


# ─────────────────────────────────────────
# Context manager: ignore_errors
# ─────────────────────────────────────────
class ignore_errors:
    """
    Context manager that swallows exceptions.

    Usage:
        with ignore_errors():
            risky_operation()
    """
    def __init__(self, where: str = "context", reraise: bool = False,
                 log_traceback: bool = False):
        self.where = where
        self.reraise = reraise
        self.log_traceback = log_traceback

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            return False
        if issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
            return False
        warn(f"[{self.where}] {exc_type.__name__}: {exc_val}")
        if self.log_traceback:
            _log_error(
                self.where, exc_val,
                "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
            )
        return not self.reraise


# ─────────────────────────────────────────
# Retry helper
# ─────────────────────────────────────────
def retry(fn: Callable, *args,
          attempts: int = 3,
          delay: float = 1.0,
          backoff: float = 2.0,
          on_error: Optional[Callable[[Exception, int], None]] = None,
          **kwargs) -> Optional[Any]:
    """
    Call fn with retries. Returns None on final failure.
    """
    current_delay = delay
    for i in range(attempts):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if on_error:
                try:
                    on_error(e, i)
                except Exception:
                    pass
            log.debug(f"retry {i+1}/{attempts} for {fn.__name__}: {e}")
            if i < attempts - 1:
                time.sleep(current_delay)
                current_delay *= backoff
    _log_error(fn.__qualname__, Exception("retry exhausted"))
    return None


# ─────────────────────────────────────────
# Module runner with isolation
# ─────────────────────────────────────────
def run_module_safely(module_name: str,
                      run_fn: Callable,
                      domain: str,
                      output_root: str = "results",
                      scan_id: Optional[int] = None) -> dict:
    """
    Run a module function with full isolation.
    Returns:
        {"module": name, "ok": bool, "result": ..., "error": ...}
    """
    start = time.time()
    try:
        try:
            result = run_fn(domain=domain, output_root=output_root,
                            scan_id=scan_id)
        except TypeError:
            # Some modules don't accept scan_id
            result = run_fn(domain=domain, output_root=output_root)
        return {
            "module": module_name,
            "ok": True,
            "result": result,
            "duration_sec": round(time.time() - start, 2),
        }
    except KeyboardInterrupt:
        raise
    except Exception as e:
        _log_error(f"module:{module_name}", e, traceback.format_exc())
        warn(f"Module '{module_name}' failed: {e}")
        return {
            "module": module_name,
            "ok": False,
            "error": f"{type(e).__name__}: {e}",
            "duration_sec": round(time.time() - start, 2),
        }


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Error recovery helpers")
    p.add_argument("--test", action="store_true")
    args = p.parse_args()

    if args.test:
        @safe_call(default="fallback", retries=2, retry_delay=0.1)
        def boom():
            raise ValueError("intentional error")

        print("safe_call:", boom())

        with ignore_errors(where="test-ctx"):
            raise RuntimeError("swallowed")

        print("done")
