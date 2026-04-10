import unittest

from seceventmonitor.utils.affected_versions import (
    deserialize_affected_entries,
    matches_affected_filters,
    parse_affected_versions_text,
)


class AffectedVersionTest(unittest.TestCase):
    def test_matches_version_range_from_display_text(self) -> None:
        entries = parse_affected_versions_text("[应用] openssl: >= 3.0.0, < 3.0.8")

        self.assertTrue(matches_affected_filters(entries, product_keyword="openssl", version_keyword="3.0.6"))
        self.assertFalse(matches_affected_filters(entries, product_keyword="openssl", version_keyword="3.0.8"))
        self.assertFalse(matches_affected_filters(entries, product_keyword="nginx", version_keyword="3.0.6"))

    def test_deserialize_falls_back_to_display_text(self) -> None:
        entries = deserialize_affected_entries("", "[应用] nginx: 1.25.3")

        self.assertTrue(matches_affected_filters(entries, product_keyword="nginx", version_keyword="1.25.3"))
        self.assertFalse(matches_affected_filters(entries, product_keyword="nginx", version_keyword="1.25.4"))


if __name__ == "__main__":
    unittest.main()
