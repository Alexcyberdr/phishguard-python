"""Offline bilingual heuristic email analysis; not a production security filter."""
import re
import unicodedata
import ipaddress
from urllib.parse import urlsplit, unquote

RULES = {"password": 25, "urgent": 20, "verify": 20, "account": 10,
         "gift card": 25, "click here": 15}

GROUPS = {
    "urgency": (15, "immediate action|act now|final notice|last chance|within 24 hours|as soon as possible|time sensitive|acción inmediata|actúa ahora|último aviso|última oportunidad|vence hoy"),
    "credentials": (35, "send your password|verify your password|confirm your pin|enter your credentials|share your verification code|one time password|security code|reset your password|verify your identity|confirm your identity|login credentials|social security number|verificar contraseña|enviar contraseña|confirma tu pin|código de verificación|código de seguridad|verifica tu identidad|restablecer contraseña|número de seguro social"),
    "threats": (25, "account suspended|account locked|account disabled|unusual activity|unauthorized login|security alert|account will be closed|service interruption|cuenta suspendida|cuenta bloqueada|actividad inusual|acceso no autorizado|alerta de seguridad|cuenta será cerrada"),
    "finance": (25, "wire transfer|bank details|update payment information|payment failed|overdue invoice|refund pending|direct deposit change|payment instructions|transferencia bancaria|datos bancarios|actualizar datos bancarios|pago rechazado|factura vencida|reembolso pendiente"),
    "prizes": (25, "lottery winner|claim your prize|you have won|free gift|guaranteed returns|unclaimed funds|advance fee|premio ganado|reclama tu premio|has ganado|regalo gratis|ganancias garantizadas"),
    "impersonation": (10, "it support|security department|help desk|payroll department|technical support|customer support|soporte técnico|departamento de seguridad|recursos humanos"),
    "secrecy": (20, "do not tell anyone|keep this confidential|do not contact|personal favor|keep this secret|no le digas a nadie|mantén esto en secreto|favor personal"),
    "crypto": (30, "seed phrase|private key|wallet recovery|crypto giveaway|frase semilla|clave privada|recuperar billetera"),
    "links": (15, "click the link|open the attachment|scan the qr code|download the attachment|haz clic aquí|abre el archivo adjunto|escanea el código qr|descarga el archivo"),
    "spanish": (20, "urgente|contraseña|verificar|tarjeta de regalo|actualiza tu cuenta|confirma tus datos"),
}
for weight, phrases in GROUPS.values():
    RULES.update({phrase: weight for phrase in phrases.split("|")})

def normalize(text):
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())

def analyze_text(email):
    normalized = normalize(email)
    candidates = []
    for phrase, weight in RULES.items():
        for match in re.finditer(r"\b" + re.escape(normalize(phrase)) + r"\b", normalized):
            candidates.append((match.start(), match.end(), phrase, weight))
    # Prefer longer phrases over overlapping individual words.
    selected = []
    for start, end, phrase, weight in sorted(candidates, key=lambda x: (-(x[1]-x[0]), -x[3], x[0])):
        if not any(start < b and end > a for a, b, _, _ in selected):
            selected.append((start, end, phrase, weight))
    matches = list(dict.fromkeys(p for _, _, p, _ in sorted(selected)))
    score = min(100, sum(RULES[p] for p in matches))
    return {"score": score, "risk": "high" if score >= 60 else "medium" if score >= 25 else "low", "matches": matches}


URL_PATTERN = re.compile(r'https?://[^\s<>"\x27]+', re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly"}

def analyze_url(url):
    indicators = {}
    try:
        parts = urlsplit(url)
        host = parts.hostname
        if not host or parts.scheme.lower() not in {"http", "https"}:
            raise ValueError("Invalid HTTP(S) URL")
        _ = parts.port
    except ValueError:
        return {"url": url, "status": "invalid", "score": 0, "indicators": {}}
    if parts.scheme.lower() == "http":
        indicators["unencrypted_http"] = 15
    try:
        ipaddress.ip_address(host)
        indicators["ip_literal"] = 25
    except ValueError:
        pass
    if len(url) > 150:
        indicators["long_url"] = 10
    if host.lower().rstrip(".") in SHORTENERS:
        indicators["shortener"] = 15
    if any(label.startswith("xn--") for label in host.lower().split(".")):
        indicators["punycode"] = 20
    if parts.username is not None or parts.password is not None:
        indicators["userinfo"] = 25
    path = unquote(parts.path)
    if re.search(r"login|verify|password", path + "?" + unquote(parts.query), re.I):
        indicators["sensitive_terms"] = 10
    if re.search(r"\.(exe|scr|bat|msi|cmd|ps1)$", path, re.I):
        indicators["executable_extension"] = 30
    return {"url": url, "status": "reputation_unknown",
            "score": min(100, sum(indicators.values())), "indicators": indicators}

def analyze(email):
    urls = list(dict.fromkeys(m.group().rstrip(".,;!?)]}") for m in URL_PATTERN.finditer(email)))
    text_result = analyze_text(URL_PATTERN.sub(" ", email))
    results = [analyze_url(url) for url in urls]
    url_score = max((item["score"] for item in results), default=0)
    score = min(100, text_result["score"] + url_score)
    return {"score": score, "risk": "high" if score >= 60 else "medium" if score >= 25 else "low",
            "matches": text_result["matches"], "text_score": text_result["score"],
            "url_score": url_score, "urls": results}

if __name__ == "__main__":
    import sys
    import json
    if sys.stdin.isatty():
        print("Paste email content, then press Ctrl-D on macOS/Linux (Ctrl-Z then Enter on Windows).", file=sys.stderr)
    print(json.dumps(analyze(sys.stdin.read()), indent=2, ensure_ascii=False))
