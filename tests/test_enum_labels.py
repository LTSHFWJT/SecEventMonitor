import unittest

from seceventmonitor.utils.enum_labels import enum_label


class EnumLabelTest(unittest.TestCase):
    def test_maps_vuln_status_to_chinese(self) -> None:
        self.assertEqual(enum_label("vuln_status", "Awaiting Analysis"), "待分析")
        self.assertEqual(enum_label("vuln_status", "Analyzed"), "已分析")

    def test_maps_cvss_enums_to_chinese(self) -> None:
        self.assertEqual(enum_label("base_severity", "CRITICAL"), "严重")
        self.assertEqual(enum_label("attack_vector", "NETWORK"), "网络")
        self.assertEqual(enum_label("user_interaction", "PASSIVE"), "被动")
        self.assertEqual(enum_label("scope", "UNCHANGED"), "未改变")
        self.assertEqual(enum_label("availability_impact", "HIGH"), "高")


if __name__ == "__main__":
    unittest.main()
