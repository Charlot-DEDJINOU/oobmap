def split_cookie(header: str) -> list[tuple[str, str]]:
    cookies = []
    for part in header.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            cookies.append((key, value))
    return cookies


def join_cookie(cookies: list[tuple[str, str]]) -> str:
    return "; ".join(f"{key}={value}" for key, value in cookies)
