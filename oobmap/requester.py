import http.client
import ssl
from dataclasses import dataclass, replace
from urllib.parse import parse_qsl, quote_plus, unquote_plus, urlencode, urlsplit, urlunsplit


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


def split_cookie(header: str) -> list[tuple[str, str]]:
    cookies = []
    for part in header.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            cookies.append((key, value))
    return cookies


def join_cookie(cookies: list[tuple[str, str]]) -> str:
    return "; ".join(f"{key}={value}" for key, value in cookies)


def with_header(req: RawRequest, header_name: str, value: str) -> RawRequest:
    headers = []
    done = False
    for name, old in req.headers:
        if name.lower() == header_name.lower():
            headers.append((name, value))
            done = True
        else:
            headers.append((name, old))
    if not done:
        headers.append((header_name, value))
    return replace(req, headers=headers)


def inject(req: RawRequest, name: str, value: str, place: str = "auto") -> RawRequest:
    if place == "marker":
        return inject_marker(req, value)
    if place in ("auto", "cookie"):
        cookie = req.header_value("Cookie")
        if cookie:
            cookies = split_cookie(cookie)
            for index, (key, old) in enumerate(cookies):
                if key == name:
                    cookies[index] = (key, quote_plus(value))
                    return with_header(req, "Cookie", join_cookie(cookies))
        if place == "cookie":
            raise ValueError(f"cookie not found: {name}")

    if place in ("auto", "query"):
        split = urlsplit(req.target)
        params = parse_qsl(split.query, keep_blank_values=True)
        for index, (key, old) in enumerate(params):
            if key == name:
                params[index] = (key, value)
                target = urlunsplit((split.scheme, split.netloc, split.path, urlencode(params), split.fragment))
                return replace(req, target=target)
        if place == "query":
            raise ValueError(f"query parameter not found: {name}")

    if place in ("auto", "body"):
        ctype = req.header_value("Content-Type") or ""
        if req.body and "application/x-www-form-urlencoded" in ctype.lower():
            decoded = req.body.decode("utf-8", errors="replace")
            params = parse_qsl(decoded, keep_blank_values=True)
            for index, (key, old) in enumerate(params):
                if key == name:
                    params[index] = (key, value)
                    body = urlencode(params).encode()
                    updated = with_header(req, "Content-Length", str(len(body)))
                    return replace(updated, body=body)
        if place == "body":
            raise ValueError(f"body parameter not found: {name}")

    if place in ("auto", "header"):
        for header, old in req.headers:
            if header.lower() == name.lower():
                return with_header(req, header, value)
        if place == "header":
            raise ValueError(f"header not found: {name}")

    raise ValueError(f"injection point not found: {name}")


def current_value(req: RawRequest, name: str, place: str = "auto") -> str:
    if place == "marker":
        return ""
    if place in ("auto", "cookie"):
        cookie = req.header_value("Cookie")
        if cookie:
            for key, value in split_cookie(cookie):
                if key == name:
                    return unquote_plus(value)
        if place == "cookie":
            raise ValueError(f"cookie not found: {name}")

    if place in ("auto", "query"):
        split = urlsplit(req.target)
        for key, value in parse_qsl(split.query, keep_blank_values=True):
            if key == name:
                return value
        if place == "query":
            raise ValueError(f"query parameter not found: {name}")

    if place in ("auto", "body"):
        ctype = req.header_value("Content-Type") or ""
        if req.body and "application/x-www-form-urlencoded" in ctype.lower():
            decoded = req.body.decode("utf-8", errors="replace")
            for key, value in parse_qsl(decoded, keep_blank_values=True):
                if key == name:
                    return value
        if place == "body":
            raise ValueError(f"body parameter not found: {name}")

    if place in ("auto", "header"):
        value = req.header_value(name)
        if value is not None:
            return value
        if place == "header":
            raise ValueError(f"header not found: {name}")

    raise ValueError(f"injection point not found: {name}")


def injection_points(req: RawRequest, level: int = 1) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []

    split = urlsplit(req.target)
    for key, value in parse_qsl(split.query, keep_blank_values=True):
        points.append(InjectionPoint(key, "query", value))

    ctype = req.header_value("Content-Type") or ""
    if req.body and "application/x-www-form-urlencoded" in ctype.lower():
        decoded = req.body.decode("utf-8", errors="replace")
        for key, value in parse_qsl(decoded, keep_blank_values=True):
            points.append(InjectionPoint(key, "body", value))

    if level >= 2:
        cookie = req.header_value("Cookie")
        if cookie:
            for key, value in split_cookie(cookie):
                points.append(InjectionPoint(key, "cookie", unquote_plus(value)))

    if level >= 3:
        common = {"user-agent", "referer", "x-forwarded-for", "x-real-ip"}
        for key, value in req.headers:
            if key.lower() in common:
                points.append(InjectionPoint(key, "header", value))

    if level >= 5:
        seen = {(point.place, point.name.lower()) for point in points}
        skip = {"host", "content-length", "cookie"}
        for key, value in req.headers:
            marker = ("header", key.lower())
            if key.lower() not in skip and marker not in seen:
                points.append(InjectionPoint(key, "header", value))

    return points


def inject_marker(req: RawRequest, value: str) -> RawRequest:
    changed = False
    target = req.target
    if "*" in target:
        target = target.replace("*", quote_plus(value), 1)
        changed = True

    headers = []
    for name, old in req.headers:
        if "*" in old and not changed:
            headers.append((name, old.replace("*", quote_plus(value), 1)))
            changed = True
        else:
            headers.append((name, old))

    body = req.body
    if b"*" in body and not changed:
        body = body.replace(b"*", quote_plus(value).encode(), 1)
        changed = True

    if not changed:
        raise ValueError("marker '*' not found in request")
    return replace(req, target=target, headers=headers, body=body)


def send(req: RawRequest, force_ssl: bool = False, timeout: float = 10.0) -> tuple[int, bytes]:
    host = req.host
    scheme = "https" if force_ssl else "http"
    port = 443 if force_ssl else 80
    if ":" in host and not host.startswith("["):
        host_only, raw_port = host.rsplit(":", 1)
        if raw_port.isdigit():
            host = host_only
            port = int(raw_port)

    target = req.target
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlsplit(target)
        scheme = parsed.scheme
        host = parsed.hostname or host
        port = parsed.port or (443 if scheme == "https" else 80)
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, parsed.fragment))

    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    kwargs = {"timeout": timeout}
    if scheme == "https":
        kwargs["context"] = ssl.create_default_context()
    conn = conn_cls(host, port, **kwargs)
    headers = {name: value for name, value in req.headers if name.lower() not in ("host", "content-length")}
    headers["Host"] = req.host
    if req.body:
        headers["Content-Length"] = str(len(req.body))
    conn.request(req.method, target, body=req.body or None, headers=headers)
    response = conn.getresponse()
    body = response.read()
    status = response.status
    conn.close()
    return status, body
