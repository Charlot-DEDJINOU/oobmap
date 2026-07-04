from dataclasses import replace

from .request import RawRequest


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


def with_first_header(req: RawRequest, header_name: str, value: str) -> RawRequest:
    headers = []
    done = False
    for name, old in req.headers:
        if not done and name.lower() == header_name.lower():
            headers.append((name, value))
            done = True
        else:
            headers.append((name, old))
    if not done:
        headers.append((header_name, value))
    return replace(req, headers=headers)
