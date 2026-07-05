import unittest
from oobmap.tamper import apply_tampers, TAMPERS, tamper_warnings
from oobmap.tamper.rewrites import if2case, ord2ascii, sp_password
from oobmap.tamper.encoding_extra import (
    apostrophemask,
    apostrophenullencode,
    appendnullbyte,
    base64encode,
    escapequotes,
    percentage,
    decentities,
    hexentities,
    htmlencode,
)


class TamperTests(unittest.TestCase):
    def test_inline_comments_replaces_spaces(self):
        result = apply_tampers("SELECT id FROM users", ["inline-comments"])
        self.assertEqual(result, "SELECT/**/id/**/FROM/**/users")

    def test_inline_comments_no_spaces_remain(self):
        result = apply_tampers("a b c", ["inline-comments"])
        self.assertNotIn(" ", result)

    def test_randomize_case_contains_keyword_chars(self):
        result = apply_tampers("SELECT 1", ["randomize-case"])
        self.assertIn("select", result.lower())

    def test_between_comments_splits_select(self):
        result = apply_tampers("SELECT 1", ["between-comments"])
        self.assertNotIn("SELECT", result)
        self.assertIn("/**/", result)

    def test_hex_encode_admin(self):
        result = apply_tampers("username='admin'", ["hex-encode-strings"])
        self.assertNotIn("'admin'", result)
        self.assertIn("61646d696e", result)

    def test_hex_encode_empty_string(self):
        result = apply_tampers("val=''", ["hex-encode-strings"])
        self.assertIn("0x", result)

    def test_double_url_encode_encodes_space(self):
        result = apply_tampers("a b", ["double-url-encode"])
        self.assertIn("%25", result)

    def test_chained_order(self):
        result = apply_tampers("SELECT 1", ["inline-comments", "hex-encode-strings"])
        self.assertNotIn(" ", result)

    def test_unknown_tamper_raises(self):
        with self.assertRaises(KeyError):
            apply_tampers("SELECT 1", ["not-a-tamper"])

    def test_empty_list_is_noop(self):
        self.assertEqual(apply_tampers("SELECT 1", []), "SELECT 1")

    def test_url_encode_encodes_space(self):
        result = apply_tampers("a b", ["url-encode"])
        self.assertIn("%20", result)

    def test_url_encode_is_single_pass(self):
        result = apply_tampers("a b", ["url-encode"])
        self.assertNotIn("%2520", result)

    def test_space2randomblank_no_literal_spaces_remain(self):
        result = apply_tampers("SELECT id FROM users", ["space2randomblank"])
        self.assertNotIn(" ", result)

    def test_space2randomblank_preserves_length(self):
        original = "SELECT id FROM users"
        result = apply_tampers(original, ["space2randomblank"])
        self.assertEqual(len(result), len(original))

    def test_space2randomblank_only_replaces_spaces(self):
        original = "SELECT id FROM users"
        result = apply_tampers(original, ["space2randomblank"])
        non_space_original = original.replace(" ", "")
        non_space_result = "".join(c for c in result if c not in "\t\n\x0b\x0c\r")
        self.assertEqual(non_space_original, non_space_result)

    def test_if2case_via_apply_tampers(self):
        result = apply_tampers("IF(1=1,2,3)", ["if2case"])
        self.assertEqual(result, "CASE WHEN (1=1) THEN (2) ELSE (3) END")

    def test_ord2ascii_via_apply_tampers(self):
        result = apply_tampers("ORD('A')", ["ord2ascii"])
        self.assertEqual(result, "ASCII('A')")

    def test_sp_password_via_apply_tampers(self):
        result = apply_tampers("SELECT 1-- -", ["sp_password"])
        self.assertEqual(result, "SELECT 1-- - sp_password")

    def test_all_ten_tampers_registered(self):
        expected = {"inline-comments", "randomize-case", "between-comments",
                    "hex-encode-strings", "double-url-encode",
                    "url-encode", "space2randomblank",
                    "if2case", "ord2ascii", "sp_password"}
        self.assertEqual(set(TAMPERS.keys()), expected)


class TamperWarningsTests(unittest.TestCase):
    def test_hex_encode_strings_warns_for_postgres(self):
        warnings = tamper_warnings(["hex-encode-strings"], "postgres-program")
        self.assertEqual(len(warnings), 1)
        self.assertIn("hex-encode-strings", warnings[0])

    def test_hex_encode_strings_warns_for_sqlite(self):
        warnings = tamper_warnings(["hex-encode-strings"], "sqlite-http")
        self.assertEqual(len(warnings), 1)

    def test_hex_encode_strings_warns_for_oracle(self):
        warnings = tamper_warnings(["hex-encode-strings"], "oracle-http")
        self.assertEqual(len(warnings), 1)

    def test_hex_encode_strings_no_warning_for_mysql(self):
        self.assertEqual(tamper_warnings(["hex-encode-strings"], "mysql"), [])

    def test_hex_encode_strings_no_warning_for_mysql_stacked(self):
        self.assertEqual(tamper_warnings(["hex-encode-strings"], "mysql-stacked"), [])

    def test_hex_encode_strings_no_warning_for_mssql(self):
        self.assertEqual(tamper_warnings(["hex-encode-strings"], "mssql"), [])

    def test_hex_encode_strings_no_warning_for_mssql_cmdshell(self):
        self.assertEqual(tamper_warnings(["hex-encode-strings"], "mssql-cmdshell"), [])

    def test_hex_encode_strings_no_warning_when_dbms_none(self):
        self.assertEqual(tamper_warnings(["hex-encode-strings"], None), [])

    def test_no_warning_without_hex_encode_strings_in_chain(self):
        self.assertEqual(tamper_warnings(["randomize-case"], "postgres-program"), [])

    def test_no_warning_for_empty_chain(self):
        self.assertEqual(tamper_warnings([], "postgres-program"), [])

    def test_sp_password_warns_for_mysql(self):
        warnings = tamper_warnings(["sp_password"], "mysql")
        self.assertEqual(len(warnings), 1)
        self.assertIn("sp_password", warnings[0])

    def test_sp_password_no_warning_for_mssql(self):
        self.assertEqual(tamper_warnings(["sp_password"], "mssql"), [])

    def test_sp_password_no_warning_for_mssql_cmdshell(self):
        self.assertEqual(tamper_warnings(["sp_password"], "mssql-cmdshell"), [])

    def test_sp_password_no_warning_when_dbms_none(self):
        self.assertEqual(tamper_warnings(["sp_password"], None), [])


class If2CaseTests(unittest.TestCase):
    def test_simple_ternary(self):
        result = if2case("IF(1=1,2,3)")
        self.assertEqual(result, "CASE WHEN (1=1) THEN (2) ELSE (3) END")

    def test_nested_function_calls_in_arguments(self):
        payload = "IF(LENGTH(h)>62,CONCAT('.',MID(h,63,62)),'')"
        result = if2case(payload)
        self.assertEqual(
            result,
            "CASE WHEN (LENGTH(h)>62) THEN (CONCAT('.',MID(h,63,62))) ELSE ('') END",
        )

    def test_no_match_passthrough(self):
        self.assertEqual(if2case("SELECT 1"), "SELECT 1")

    def test_malformed_arg_count_left_untouched(self):
        self.assertEqual(if2case("IF(1,2)"), "IF(1,2)")

    def test_nested_if_inside_then_argument(self):
        result = if2case("IF(1,IF(2,3,4),5)")
        self.assertEqual(
            result,
            "CASE WHEN (1) THEN (CASE WHEN (2) THEN (3) ELSE (4) END) ELSE (5) END",
        )

    def test_case_insensitive_match(self):
        result = if2case("if(1,2,3)")
        self.assertEqual(result, "CASE WHEN (1) THEN (2) ELSE (3) END")

    def test_multiple_occurrences(self):
        result = if2case("IF(1,2,3) AND IF(4,5,6)")
        self.assertEqual(
            result,
            "CASE WHEN (1) THEN (2) ELSE (3) END AND CASE WHEN (4) THEN (5) ELSE (6) END",
        )


class Ord2AsciiTests(unittest.TestCase):
    def test_replaces_ord_call(self):
        self.assertEqual(ord2ascii("ORD('A')"), "ASCII('A')")

    def test_case_insensitive(self):
        self.assertEqual(ord2ascii("ord('a')"), "ASCII('a')")

    def test_noop_without_match(self):
        self.assertEqual(ord2ascii("SELECT 1"), "SELECT 1")

    def test_word_boundary_prevents_false_match(self):
        self.assertEqual(ord2ascii("COORD(1)"), "COORD(1)")


class SpPasswordTests(unittest.TestCase):
    def test_appends_sp_password(self):
        self.assertEqual(sp_password("SELECT 1-- -"), "SELECT 1-- - sp_password")

    def test_appends_to_empty_string(self):
        self.assertEqual(sp_password(""), " sp_password")


class EncodingExtraBasicTests(unittest.TestCase):
    def test_apostrophemask_replaces_quote(self):
        self.assertEqual(apostrophemask("O'Brien"), "O%EF%BC%87Brien")

    def test_apostrophenullencode_replaces_quote(self):
        self.assertEqual(apostrophenullencode("a'b"), "a%00%27b")

    def test_appendnullbyte_appends_at_end(self):
        self.assertEqual(appendnullbyte("SELECT 1"), "SELECT 1%00")

    def test_base64encode_encodes_payload(self):
        self.assertEqual(base64encode("admin"), "YWRtaW4=")

    def test_escapequotes_escapes_single_quote(self):
        self.assertEqual(escapequotes("a'b"), "a\\'b")

    def test_escapequotes_escapes_double_quote(self):
        self.assertEqual(escapequotes('a"b'), 'a\\"b')

    def test_percentage_prefixes_each_char(self):
        self.assertEqual(percentage("AB"), "%A%B")


class HtmlEntityTests(unittest.TestCase):
    def test_decentities_encodes_every_character(self):
        self.assertEqual(decentities("Ab"), "&#65;&#98;")

    def test_hexentities_encodes_every_character(self):
        self.assertEqual(hexentities("'"), "&#x27;")

    def test_htmlencode_skips_alphanumeric(self):
        self.assertEqual(htmlencode("Ab1'"), "Ab1&#39;")

    def test_htmlencode_encodes_all_when_no_alnum(self):
        self.assertEqual(htmlencode("' "), "&#39;&#32;")
