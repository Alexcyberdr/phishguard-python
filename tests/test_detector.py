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

if __name__ == "__main__":
    unittest.main()
