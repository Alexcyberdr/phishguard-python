import unittest
from phishing_detector import analyze

class DetectorTests(unittest.TestCase):
    def test_normal(self):
        self.assertEqual(analyze("Meeting tomorrow")["score"], 0)
    def test_case(self):
        self.assertEqual(analyze("URGENT")["score"], 20)
    def test_high(self):
        self.assertEqual(analyze("Urgent verify account password")["risk"], "high")
    def test_repeat(self):
        self.assertEqual(analyze("password password")["score"], 25)
    def test_boundary(self):
        self.assertEqual(analyze("passwordless")["score"], 0)

    def test_http(self):
        self.assertEqual(analyze("http://example.com")["url_score"], 15)
    def test_https_unknown(self):
        self.assertEqual(analyze("https://example.com")["urls"][0]["status"], "reputation_unknown")
    def test_ip_executable(self):
        self.assertEqual(analyze("http://192.0.2.15/login.exe")["url_score"], 80)
    def test_multiline(self):
        self.assertEqual(analyze("urgent\npassword")["text_score"], 45)
    def test_duplicate_urls(self):
        self.assertEqual(len(analyze("http://example.com http://example.com")["urls"]), 1)
    def test_invalid_port(self):
        self.assertEqual(analyze("http://example.com:99999")["urls"][0]["status"], "invalid")
    def test_punycode_userinfo(self):
        self.assertEqual(analyze("https://user@xn--bcher-kva.example")["url_score"], 45)
    def test_shortener(self):
        self.assertEqual(analyze("https://bit.ly/example")["url_score"], 15)

if __name__ == "__main__":
    unittest.main()
