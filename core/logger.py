"""
core/logger.py
--------------
Centralized logging with color + file output.
Graceful: never crashes if log dir missing.
"""

import os
import sys
import logging
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────
# ANSI Color Codes
# ─────────────────────────────────────────
class C:
    RED     = '\033[1;31m'
    GREEN   = '\033[1;32m'
    YELLOW  = '\033[1;33m'
    BLUE    = '\033[1;34m'
    MAGENTA = '\033[1;35m'
    CYAN    = '\033[1;36m'
    WHITE   = '\033[1;37m'
    GREY    = '\033[0;90m'
    BOLD    = '\033[1m'
    END     = '\033[0m'


# ─────────────────────────────────────────
# Custom Formatter with Colors
# ─────────────────────────────────────────
class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG:    C.GREY,
        logging.INFO:     C.CYAN,
        logging.WARNING:  C.YELLOW,
        logging.ERROR:    C.RED,
        logging.CRITICAL: C.RED + C.BOLD,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, C.WHITE)
        time_str = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        level = record.levelname.ljust(8)
        return f"{C.GREY}[{time_str}]{C.END} {color}{level}{C.END} {record.getMessage()}"


# ─────────────────────────────────────────
# Logger Factory
# ─────────────────────────────────────────
_loggers = {}

def get_logger(name: str = "dream", log_dir: str = "logs") -> logging.Logger:
    """
    Get or create a logger.
    Writes to console (colored) + file (plain).
    """
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Avoid duplicate handlers on re-import
    if logger.handlers:
        _loggers[name] = logger
        return logger

    # ── Console Handler ──
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(ColorFormatter())
    logger.addHandler(console)

    # ── File Handler (best-effort) ──
    try:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        log_file = Path(log_dir) / f"{name}_{datetime.now().strftime('%Y%m%d')}.log"
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)
    except Exception:
        # File logging failed — not fatal
        pass

    _loggers[name] = logger
    return logger


# ─────────────────────────────────────────
# Convenience Print Helpers
# ─────────────────────────────────────────
def banner(text: str):
    line = "═" * (len(text) + 4)
    print(f"\n{C.BLUE}{line}{C.END}")
    print(f"{C.BLUE}  {text}{C.END}")
    print(f"{C.BLUE}{line}{C.END}\n")


def ok(msg):    print(f"{C.GREEN}[✓]{C.END} {msg}")
def info(msg):  print(f"{C.CYAN}[*]{C.END} {msg}")
def warn(msg):  print(f"{C.YELLOW}[!]{C.END} {msg}")
def err(msg):   print(f"{C.RED}[✗]{C.END} {msg}")
def skip(msg):  print(f"{C.GREY}[~]{C.END} {msg}")