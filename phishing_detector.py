"""Offline heuristic email analysis; not a production security filter."""
import re

RULES = {"password": 25, "urgent": 20, "verify": 20, "account": 10,
         "gift card": 25, "click here": 15}

def analyze(email):
    matches = [word for word in RULES if re.search(r"\b" + re.escape(word) + r"\b", email.lower())]
    score = min(100, sum(RULES[word] for word in matches))
    return {"score": score, "risk": "high" if score >= 60 else "medium" if score >= 25 else "low", "matches": matches}

if __name__ == "__main__":
    print(analyze(input("Paste a sample email: ")))
