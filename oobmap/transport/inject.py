import json
from dataclasses import replace
from urllib.parse import parse_qsl, quote_plus, unquote_plus, urlencode, urlsplit, urlunsplit

from .request import RawRequest, InjectionPoint
from .cookies import split_cookie, join_cookie
from .json_path import _json_get, _json_set, _json_leaf_paths
from .headers import with_header, with_first_header


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
                return with_first_header(req, header, value)
        if place == "header":
            raise ValueError(f"header not found: {name}")

    if place in ("auto", "json"):
        ctype = req.header_value("Content-Type") or ""
        if req.body and "application/json" in ctype.lower():
            try:
                obj = json.loads(req.body.decode("utf-8"))
                _json_get(obj, name)
                new_obj = _json_set(obj, name, value)
                body = json.dumps(new_obj, separators=(",", ":")).encode("utf-8")
                updated = with_header(req, "Content-Length", str(len(body)))
                return replace(updated, body=body)
            except (json.JSONDecodeError, KeyError, IndexError, ValueError):
                pass
        if place == "json":
            raise ValueError(f"json injection point not found: {name}")

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

    if place in ("auto", "json"):
        ctype = req.header_value("Content-Type") or ""
        if req.body and "application/json" in ctype.lower():
            try:
                obj = json.loads(req.body.decode("utf-8"))
                return str(_json_get(obj, name))
            except (json.JSONDecodeError, KeyError, IndexError, ValueError):
                pass
        if place == "json":
            raise ValueError(f"json injection point not found: {name}")

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

    ctype = req.header_value("Content-Type") or ""
    if req.body and "application/json" in ctype.lower():
        try:
            obj = json.loads(req.body.decode("utf-8"))
            for path, value in _json_leaf_paths(obj):
                points.append(InjectionPoint(path, "json", value))
        except json.JSONDecodeError:
            pass

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


def send(req: RawRequest, force_ssl: bool = False, timeout: float = 10.0,
         proxy: str | None = None, verify_ssl: bool = True) -> tuple[int, bytes]:
    import urllib.request
    import urllib.error
    import ssl as _ssl

    host = req.host
    scheme = "https" if force_ssl else "http"

    target = req.target
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        scheme = parsed.scheme
        host = parsed.netloc or host
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, parsed.fragment))
    else:
        path = target

    url = f"{scheme}://{host}{path}"

    handlers: list = []
    handlers.append(urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}
    ))

    if not verify_ssl:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    headers_dict = {
        name: value
        for name, value in req.headers
        if name.lower() not in ("host", "content-length")
    }
    ureq = urllib.request.Request(url, data=req.body or None,
                                  headers=headers_dict, method=req.method)
    ureq.add_unredirected_header("Host", req.host)
    if req.body:
        ureq.add_unredirected_header("Content-Length", str(len(req.body)))

    try:
        with opener.open(ureq, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() or b""
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc.reason)) from exc
