import datetime
import sys


def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


_LEVEL_COLORS = {
    "INFO":     "\033[1;34m",   # bold blue
    "WARNING":  "\033[1;33m",   # bold yellow
    "ERROR":    "\033[1;31m",   # bold red
    "CRITICAL": "\033[1;91m",   # bold bright red
    "DEBUG":    "\033[0;90m",   # dark grey
    "SUCCESS":  "\033[1;92m",   # bold bright green
}
_TS_COLOR = "\033[0;36m"        # cyan — timestamp digits only
_RESET = "\033[0m"


def _log(level: str, msg: str, *, err: bool = False) -> None:
    fd = sys.stderr if err else sys.stdout
    if fd.isatty():
        ts  = f"[{_TS_COLOR}{_ts()}{_RESET}]"
        color = _LEVEL_COLORS.get(level, "")
        tag = f"[{color}{level}{_RESET}]"
    else:
        ts  = f"[{_ts()}]"
        tag = f"[{level}]"
    print(f"{ts} {tag} {msg}", file=fd, flush=True)


def _hi(text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[1;92m{text}\033[0m"
    return text


def _sep() -> None:
    print("  " + "─" * 56)
