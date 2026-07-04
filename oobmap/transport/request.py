from dataclasses import dataclass


@dataclass(frozen=True)
class RawRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes

    @property
    def host(self) -> str:
        for name, value in self.headers:
            if name.lower() == "host":
                return value
        raise ValueError("raw request has no Host header")

    def header_value(self, wanted: str) -> str | None:
        for name, value in self.headers:
            if name.lower() == wanted.lower():
                return value
        return None


@dataclass(frozen=True)
class InjectionPoint:
    name: str
    place: str
    value: str


def parse_raw_request(path: str) -> RawRequest:
    with open(path, "rb") as handle:
        raw = handle.read()
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    lines = head.decode("iso-8859-1").splitlines()
    if not lines:
        raise ValueError("empty request file")

    parts = lines[0].split()
    if len(parts) != 3:
        raise ValueError(f"invalid request line: {lines[0]!r}")
    method, target, version = parts

    headers = []
    for line in lines[1:]:
        if not line.strip():
            continue
        name, colon, value = line.partition(":")
        if not colon:
            raise ValueError(f"invalid header line: {line!r}")
        headers.append((name.strip(), value.strip()))

    return RawRequest(method=method, target=target, version=version, headers=headers, body=body)
