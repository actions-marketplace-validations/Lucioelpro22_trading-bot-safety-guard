import tempfile
import unittest
from pathlib import Path

from src.audit import scan


class AuditTests(unittest.TestCase):
    def scan_text(self, name: str, text: str, max_leverage: float = 5):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / name).write_text(text, encoding="utf-8")
            return scan(root, True, True, max_leverage)

    def test_detects_secret_without_echoing_value(self):
        findings = self.scan_text("bot.py", 'API_KEY="1234567890abcdefghijklmnop"')
        self.assertEqual(findings[0].rule, "possible-secret")
        self.assertNotIn("1234567890", findings[0].message)

    def test_allows_placeholder(self):
        self.assertEqual(self.scan_text(".env.example", "API_KEY=your_api_key_here"), [])

    def test_detects_live_endpoint_without_demo(self):
        findings = self.scan_text("client.py", 'BASE_URL = "https://api.bybit.com"')
        self.assertTrue(any(item.rule == "live-endpoint" for item in findings))

    def test_allows_live_and_demo_selection_in_same_client(self):
        text = 'LIVE = "https://api.bybit.com"\nDEMO = "https://api-demo.bybit.com"'
        self.assertEqual(self.scan_text("client.py", text), [])

    def test_detects_excessive_leverage(self):
        findings = self.scan_text("risk.yaml", "max_leverage: 20")
        self.assertTrue(any(item.rule == "excessive-leverage" for item in findings))


if __name__ == "__main__":
    unittest.main()
