from urllib.parse import urlsplit, urlunsplit

from .request import RawRequest


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
