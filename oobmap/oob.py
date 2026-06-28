import json
import threading
import time
from pathlib import Path


class InteractshLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self.offset = self.path.stat().st_size if self.path.exists() else 0
        self._lock = threading.Lock()

    def contains(self, token: str) -> bool:
        return self.find_any({token: token}) is not None

    def find_any(self, token_map: dict[str, str]) -> str | None:
        if not self.path.exists():
            return None
        with self._lock:
            with self.path.open("r", encoding="utf-8", errors="ignore") as handle:
                handle.seek(self.offset)
                for line in handle:
                    raw = line.lower()
                    for token in token_map:
                        if token.lower() in raw:
                            return token
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    raw = json.dumps(event).lower()
                    for token in token_map:
                        if token.lower() in raw:
                            return token
        return None

    def wait_any(self, token_map: dict[str, str], timeout: float) -> str | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            token = self.find_any(token_map)
            if token:
                return token
            time.sleep(0.5)
        return None

    def scan_direct(self, prefix: str) -> str | None:
        """Scan for a DNS entry whose hostname is <hex_labels>.<prefix>.<domain>.
        Hex may be split across multiple dot-separated labels for long values.
        Returns the decoded value or None."""
        if not self.path.exists():
            return None
        marker = f".{prefix}."
        with self._lock:
            with self.path.open("r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.offset)
                for line in f:
                    lo = line.lower()
                    if marker not in lo:
                        continue
                    idx = lo.find(marker)
                    # walk back over hex chars AND dots (multi-label support)
                    start = idx - 1
                    while start >= 0 and lo[start] in "0123456789abcdef.":
                        start -= 1
                    raw = lo[start + 1:idx]
                    hex_part = raw.replace(".", "")  # join split labels
                    if len(hex_part) >= 2 and len(hex_part) % 2 == 0:
                        try:
                            return bytes.fromhex(hex_part).decode("utf-8", errors="replace")
                        except ValueError:
                            pass
        return None

    def find_direct(self, prefix: str, timeout: float) -> str | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = self.scan_direct(prefix)
            if result is not None:
                return result
            time.sleep(0.5)
        return None


class MultiInteractshLog:
    def __init__(self, paths: list[str]):
        self._logs = [InteractshLog(p) for p in paths]

    def find_any(self, token_map: dict[str, str]) -> str | None:
        for log in self._logs:
            result = log.find_any(token_map)
            if result:
                return result
        return None

    def wait_any(self, token_map: dict[str, str], timeout: float) -> str | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = self.find_any(token_map)
            if result:
                return result
            time.sleep(0.5)
        return None

    def find_direct(self, prefix: str, timeout: float) -> str | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for log in self._logs:
                result = log.scan_direct(prefix)
                if result is not None:
                    return result
            time.sleep(0.5)
        return None
