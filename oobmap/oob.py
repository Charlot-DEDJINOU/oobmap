import json
import time
from pathlib import Path


class InteractshLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self.offset = self.path.stat().st_size if self.path.exists() else 0

    def contains(self, token: str) -> bool:
        return self.find_any({token: token}) is not None

    def find_any(self, token_map: dict[str, str]) -> str | None:
        if not self.path.exists():
            return None

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
