import datetime
import string
import sys

from .. import __version__
from ..core.actions import check, dump, enum, extract
from ..core.detection import _detect_dbms
from ..payloads import PROFILES
from ..tamper import TAMPERS
from ..utils.logging import _log
from .parser import make_parser


DEFAULT_ALPHABET = string.ascii_lowercase + string.digits
ENUM_ALPHABET = string.ascii_letters + string.digits + " _-.:/@()[]{}+,;=<>|"

_ENUM_KEYS = ("dbs", "banner", "current_user", "current_db", "tables", "columns")


def _validate_action_flags(args, is_enum: bool) -> None:
    if getattr(args, "check", False) and (args.expr or is_enum):
        raise SystemExit("--check cannot be combined with --expr/--dump/enum flags")


def run(args) -> int:
    if getattr(args, "enum_all", False):
        args.dbs = args.banner = args.current_user = args.current_db = True

    if not getattr(args, "request", None):
        raise SystemExit("the following argument is required: -r/--request")

    if not getattr(args, "domain", None) or not getattr(args, "log", None):
        missing = "--domain" if not getattr(args, "domain", None) else "--log"
        _log("WARNING", f"{missing} is required", err=True)
        _log("INFO",
             "launch interactsh client first:\n\n"
             "    interactsh-client -json -o interactsh.jsonl\n\n"
             "  then run oobmap with:\n"
             "    --domain <your-cid>.oast.site --log interactsh.jsonl",
             err=True)
        raise SystemExit(1)

    if not args.dbms:
        args.dbms = _detect_dbms(args)
        if not args.dbms:
            raise SystemExit(
                "could not auto-detect DBMS — no OOB callback from any profile "
                "(all engines and their variants were tried). Check outbound "
                "DNS/HTTP egress and your --domain/--log setup; some variants "
                "also need target-side prerequisites (e.g. mssql-openrowset "
                "needs 'Ad Hoc Distributed Queries' enabled). If the injection "
                "point has trailing SQL, add --payload-suffix. Or specify "
                "--dbms explicitly."
            )
    elif args.dbms not in PROFILES:
        raise SystemExit(
            f"[ERROR] unknown --dbms value: '{args.dbms}'. "
            f"Valid profiles: {', '.join(sorted(PROFILES))}. "
            "Aliases accepted: sqlite, postgres, oracle, sqlserver, mariadb."
        )

    is_enum = any(getattr(args, k, False) for k in _ENUM_KEYS) or getattr(args, "dump", False)
    _validate_action_flags(args, is_enum)
    if args.alphabet is None:
        args.alphabet = ENUM_ALPHABET if is_enum else DEFAULT_ALPHABET
    if args.max_len is None:
        args.max_len = 120 if is_enum else 40

    if args.expr:
        return extract(args)
    if args.dump:
        return dump(args)
    if is_enum:
        return enum(args)
    return check(args)


_ART = [
    "     ___  ___  ___  __  __   _   ___",
    "    / _ \\/ _ \\| _ )|  \\/  | /_\\ | _ \\",
    "   | (_) | (_) | _ \\ |\\/| |/ _ \\|  _/",
    f"    \\___/ \\___/|___/_|  |_/_/ \\_\\_|    {{v{__version__}}}",
]
_SUBTITLE = "    OOB blind SQLi extractor — powered by interactsh"


def _banner() -> str:
    if sys.stdout.isatty():
        c  = "\033[1;36m"   # bold cyan  — logo
        v  = "\033[1;33m"   # bold yellow — version tag
        s  = "\033[0;37m"   # light grey  — subtitle
        r  = "\033[0m"
        art = "\n".join(
            # color the version tag separately on the last art line
            line.replace(f"{{v{__version__}}}", f"{r}{v}{{v{__version__}}}{r}{c}")
            .join([c, r])
            for line in _ART
        )
        return f"\n{art}\n\n{s}{_SUBTITLE}{r}\n"
    return "\n" + "\n".join(_ART) + f"\n\n{_SUBTITLE}\n"


def _starting_line() -> str:
    now = datetime.datetime.now()
    ts   = now.strftime("%H:%M:%S")
    date = now.strftime("%Y-%m-%d")
    if sys.stdout.isatty():
        star = "\033[1;36m[*]\033[0m"
    else:
        star = "[*]"
    return f"{star} starting @ {ts} /{date}/\n"


def _ending_line() -> str:
    now = datetime.datetime.now()
    ts   = now.strftime("%H:%M:%S")
    date = now.strftime("%Y-%m-%d")
    if sys.stdout.isatty():
        star = "\033[1;36m[*]\033[0m"
    else:
        star = "[*]"
    return f"\n{star} ending @ {ts} /{date}/\n"


def list_tampers(args) -> int:
    for name, (_, description) in sorted(TAMPERS.items()):
        print(f"{name:<22} {description}")
    return 0


def profiles(args) -> int:
    for name in sorted(PROFILES):
        profile = PROFILES[name]
        print(f"{name:16} {profile.description}")
        print(f"{'':16} {profile.comment}")
    return 0


def main(argv=None):
    print(_banner(), end="", flush=True)
    parser = make_parser()
    args = parser.parse_args(argv)
    if args.command is None and not getattr(args, "request", None):
        parser.print_help()
        return 0
    print(_starting_line(), flush=True)
    try:
        rc = args.func(args)
        print(_ending_line(), flush=True)
        return rc
    except KeyboardInterrupt:
        print(_ending_line(), flush=True)
        _log("WARNING", "Interrupted", err=True)
        return 130
