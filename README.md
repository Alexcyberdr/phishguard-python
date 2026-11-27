# PhishGuard Python

Educational open-source phishing analysis prototype (v0.2), developed with AI assistance.

## Features
- English and Spanish weighted keyword and phrase detection.
- Offline HTTP(S) URL extraction and static analysis: unencrypted HTTP, IP literals, long URLs, known shorteners, Punycode, embedded user information, sensitive URL terms and executable extensions.
- Multiline email input, JSON output, separate text and URL scores.
- Five interactive Python training missions (open index.html locally).
- Automated unit tests.

## Usage
Requires Python 3; no external packages or API keys.

```sh
git clone https://github.com/Alexcyberdr/phishguard-python.git
cd phishguard-python
python3 phishing_detector.py
```

Paste the email subject and body, then press Ctrl-D on macOS/Linux (Ctrl-Z then Enter on Windows). Alternatively:
```sh
python3 phishing_detector.py < email.txt
python3 -m unittest discover -s tests -v
```

## Scoring
The combined score is the text score plus the highest individual URL score, capped at 100. URL text is excluded from keyword scoring. Low: 0–24; medium: 25–59; high: 60–100. These weights are illustrative heuristics, not probabilities.

Example: http://192.0.2.15/login.exe has an expected URL score of 80 (HTTP 15, IP 25, sensitive term 10, executable extension 30).

## Safety and limitations
No links are visited and no external requests are made. HTTPS does not establish trust. URL reputation remains unknown; no live reputation, sender authentication or attachment scanning is implemented. Text-based URL extraction is not a full HTML or EML parser and may miss obfuscated links. Reports can contain sensitive URLs: keep them private. Do not rely on a low score as evidence of safety. Tests are provided; execution results are not claimed here.

## License
MIT. See LICENSE.
