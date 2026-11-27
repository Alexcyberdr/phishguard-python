# PhishGuard Python

Educational phishing detection and email risk analysis prototype.

## Features
- Offline keyword matching with case normalization and word boundaries.
- Weighted risk score (0–100), matched indicators and risk classification.
- Five interactive Python training missions with XP and feedback.
- Five automated unit test cases.

## Run
```sh
python3 phishing_detector.py
python3 -m unittest discover -s tests -v
```
Open `index.html` locally in a browser to play the training game.

## Example
`Urgent verify account password` produces a score of 75 and high risk. This is an illustrative example, not an execution log.

## Limitations
Keyword rules can miss phishing and flag legitimate emails. Scores are heuristic, not probabilities. No URL reputation, header authentication, grammar analysis or live email integration is implemented. Do not rely on this tool to decide whether an email is safe.

## Roadmap
Add URL parsing, email header analysis, synthetic datasets and evaluation of false positives and false negatives.

## License
MIT. See LICENSE.
