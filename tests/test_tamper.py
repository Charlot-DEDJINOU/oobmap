import unittest
from oobmap.tamper import apply_tampers, TAMPERS


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

    def test_all_seven_tampers_registered(self):
        expected = {"inline-comments", "randomize-case", "between-comments",
                    "hex-encode-strings", "double-url-encode",
                    "url-encode", "space2randomblank"}
        self.assertEqual(set(TAMPERS.keys()), expected)
