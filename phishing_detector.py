"""Offline bilingual heuristic email analysis; not a production security filter."""
import re
import unicodedata

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

def analyze(email):
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

if __name__ == "__main__":
    print(analyze(input("Paste a sample email: ")))
