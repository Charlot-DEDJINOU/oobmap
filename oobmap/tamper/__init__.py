from typing import Callable

from .encoding import hex_encode_strings, double_url_encode, url_encode
from .encoding_extra import (
    apostrophemask,
    apostrophenullencode,
    appendnullbyte,
    base64encode,
    charunicodeencode,
    charunicodeescape,
    decentities,
    hexentities,
    htmlencode,
    overlongutf8,
    overlongutf8more,
    percentage,
    unmagicquotes,
    escapequotes,
    hex2char,
)
from .whitespace import inline_comments, space_to_random_blank
from .whitespace_extra import (
    bluecoat,
    commentbeforeparentheses,
    multiplespaces,
    space2dash,
    space2hash,
    space2morecomment,
    space2morehash,
    space2mssqlblank,
    space2mssqlhash,
    space2mysqlblank,
    space2mysqldash,
    space2plus,
)
from .keywords import randomize_case, between_comments
from .keywords_extra import (
    versionedkeywords,
    versionedmorekeywords,
    halfversionedmorekeywords,
    modsecurityversioned,
    modsecurityzeroversioned,
    randomcomments,
    lowercase,
    uppercase,
    luanginx,
    luanginxmore,
)
from .rewrites import if2case, ord2ascii, sp_password

TAMPERS: dict[str, tuple[Callable[[str], str], str]] = {
    "inline-comments":    (inline_comments,       "Replace spaces with /**/"),
    "randomize-case":     (randomize_case,        "Randomly capitalize SQL keywords"),
    "between-comments":   (between_comments,      "Split keywords mid-word: SEL/**/ECT"),
    "hex-encode-strings": (hex_encode_strings,    "Convert 'string' literals to 0x hex"),
    "double-url-encode":  (double_url_encode,     "Double URL-encode the full payload"),
    "url-encode":         (url_encode,            "URL-encode the full payload once"),
    "space2randomblank":  (space_to_random_blank, "Replace spaces with a random whitespace character (tab/newline/etc.)"),
    "if2case":            (if2case,               "Rewrite IF(cond,then,else) as CASE WHEN (cond) THEN (then) ELSE (else) END"),
    "ord2ascii":          (ord2ascii,             "Replace ORD() calls with ASCII() (MySQL)"),
    "sp_password":        (sp_password,           "Append 'sp_password' to hide the query from MSSQL logs"),
    "apostrophemask":       (apostrophemask,       "Replace ' with its UTF-8 fullwidth equivalent"),
    "apostrophenullencode": (apostrophenullencode, "Replace ' with the illegal double-encoding %00%27"),
    "appendnullbyte":       (appendnullbyte,       "Append a %00 null byte to the end of the payload"),
    "base64encode":         (base64encode,         "Base64-encode the entire payload"),
    "charunicodeencode":    (charunicodeencode,    "Unicode-URL-encode every character as %uXXXX"),
    "charunicodeescape":    (charunicodeescape,    "Unicode-escape every character as \\uXXXX"),
    "decentities":          (decentities,          "HTML decimal-encode every character: &#NN;"),
    "hexentities":          (hexentities,          "HTML hex-encode every character: &#xHH;"),
    "htmlencode":           (htmlencode,           "HTML decimal-encode non-alphanumeric characters"),
    "overlongutf8":         (overlongutf8,         "Overlong-UTF8-encode non-alphanumeric characters"),
    "overlongutf8more":     (overlongutf8more,     "Overlong-UTF8-encode every character"),
    "percentage":           (percentage,           "Prefix every character with a literal %"),
    "unmagicquotes":        (unmagicquotes,        "Replace ' with %bf%27 and append -- to neutralize residue"),
    "escapequotes":         (escapequotes,         "Backslash-escape ' and \""),
    "hex2char":             (hex2char,             "Rewrite 0x<hex> literals as CONCAT(CHAR(...),...)"),
    "bluecoat":              (bluecoat,               "Replace the space after a keyword with a random blank, then '=' with ' LIKE '"),
    "commentbeforeparentheses": (commentbeforeparentheses, "Prepend /**/ before every ("),
    "multiplespaces":        (multiplespaces,         "Wrap AND/OR/SELECT/WHERE/UNION with extra spaces"),
    "space2dash":            (space2dash,             "Replace spaces with -- plus a random string and newline"),
    "space2hash":            (space2hash,             "Replace spaces with # plus a random string and newline (MySQL)"),
    "space2morecomment":     (space2morecomment,      "Replace spaces with /**_**/ (MySQL)"),
    "space2morehash":        (space2morehash,         "Replace spaces with # plus a longer random string and newline (MySQL)"),
    "space2mssqlblank":      (space2mssqlblank,       "Replace spaces with a random blank token (%09/%0a/%0b/%0c/%0d)"),
    "space2mssqlhash":       (space2mssqlhash,        "Replace spaces with # plus a newline"),
    "space2mysqlblank":      (space2mysqlblank,       "Replace spaces with a random blank token (MySQL)"),
    "space2mysqldash":       (space2mysqldash,        "Replace spaces with -- plus a newline (MySQL)"),
    "space2plus":            (space2plus,             "Replace spaces with +"),
    "versionedkeywords":         (versionedkeywords,         "Wrap SELECT/FROM/WHERE/AND/OR/UNION individually in /*! ... */ (MySQL)"),
    "versionedmorekeywords":     (versionedmorekeywords,     "Wrap a broader keyword set individually in /*! ... */ (MySQL)"),
    "halfversionedmorekeywords": (halfversionedmorekeywords, "Prepend /*! before each keyword, close once at the end (MySQL)"),
    "modsecurityversioned":      (modsecurityversioned,      "Wrap the whole payload in /*! ... */ (MySQL)"),
    "modsecurityzeroversioned":  (modsecurityzeroversioned,  "Wrap the whole payload in /*!00000 ... */ (MySQL)"),
    "randomcomments":            (randomcomments,            "Insert /**/ at a random position within common keywords"),
    "lowercase":                 (lowercase,                 "Lowercase common SQL keywords"),
    "uppercase":                 (uppercase,                 "Uppercase common SQL keywords"),
    "luanginx":                  (luanginx,                  "Append trailing padding to bypass Lua-Nginx/Cloudflare body-size WAF checks"),
    "luanginxmore":              (luanginxmore,               "Same as luanginx with larger padding"),
}


def apply_tampers(payload: str, names: list[str]) -> str:
    for name in names:
        fn, _ = TAMPERS[name]
        payload = fn(payload)
    return payload


# Tampers whose SQL rewriting only works for specific DBMS dialects.
# hex-encode-strings relies on bare 0x<hex> literal syntax, only valid in MySQL/MSSQL.
_HEX_ENCODE_COMPATIBLE_DBMS = {"mysql", "mysql-stacked", "mssql", "mssql-cmdshell"}

# sp_password only has an effect against MSSQL (its log-redaction behavior is
# MSSQL-specific); it's a harmless no-op elsewhere, not a syntax break.
_SP_PASSWORD_COMPATIBLE_DBMS = {"mssql", "mssql-cmdshell"}

# The 5 versioned-comment tampers rely on MySQL's /*! ... */ executable-comment
# syntax; on every other engine /* ... */ is a standard comment, so the wrapped
# keyword text is silently stripped from the parsed query.
_VERSIONED_COMMENT_TAMPERS = {
    "versionedkeywords", "versionedmorekeywords", "halfversionedmorekeywords",
    "modsecurityversioned", "modsecurityzeroversioned",
}
_VERSIONED_COMMENT_COMPATIBLE_DBMS = {"mysql", "mysql-stacked"}


def tamper_warnings(tamper_names: list[str], dbms: str | None) -> list[str]:
    """Return human-readable warnings for tamper/DBMS combinations known to
    break query syntax. Advisory only — callers print these and continue;
    this function never raises and never blocks execution."""
    warnings = []
    if "hex-encode-strings" in tamper_names and dbms and dbms not in _HEX_ENCODE_COMPATIBLE_DBMS:
        warnings.append(
            "tamper 'hex-encode-strings' emits bare 0x<hex> literals, valid "
            f"only in MySQL/MSSQL — likely to break query syntax for --dbms {dbms}."
        )
    if "sp_password" in tamper_names and dbms and dbms not in _SP_PASSWORD_COMPATIBLE_DBMS:
        warnings.append(
            "tamper 'sp_password' only hides queries from MSSQL logs — "
            f"has no effect for --dbms {dbms}."
        )
    used_versioned_comment_tampers = set(tamper_names) & _VERSIONED_COMMENT_TAMPERS
    if used_versioned_comment_tampers and dbms and dbms not in _VERSIONED_COMMENT_COMPATIBLE_DBMS:
        for name in sorted(used_versioned_comment_tampers):
            warnings.append(
                f"tamper '{name}' relies on MySQL's /*! ... */ executable-comment "
                f"syntax — the wrapped keyword is silently stripped as a plain "
                f"comment for --dbms {dbms}, likely to break query syntax."
            )
    return warnings


__all__ = ["TAMPERS", "apply_tampers", "tamper_warnings"]
