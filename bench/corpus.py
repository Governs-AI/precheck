# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Span-annotated PII corpus generator for the precheck detection benchmark.

Ground truth is produced at generation time: templates carry `{slot}` markers,
and the renderer records the exact character offsets each slot occupies in the
rendered string. No post-hoc annotation, no human labelling, no ambiguity.

Design notes
------------
* Deterministic — a fixed seed produces byte-identical corpora, so before/after
  runs are directly comparable.
* No new runtime dependencies. Value pools are hand-built per locale rather than
  pulled from Faker so that the generator stays inside the existing dependency
  set and locale realism is explicit and reviewable.
* Difficulty tiers mirror the axes on which off-the-shelf detectors are known to
  degrade (REDACT, arXiv:2606.19881): high-sensitivity entity families, partial
  disclosure, and obfuscated surface forms.
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

SEED = 20260811

LANGUAGES = ["en", "es", "fr", "de", "zh"]

TIERS = [
    "plain",  # standard prose, well-formed entities
    "high_sensitivity",  # names, addresses, medical + national identifiers
    "partial",  # partial disclosure (last-4, initials, year-only DOB)
    "obfuscated",  # spaced / spelled-out / separator-mangled surface forms
    "structured",  # PII inside nested JSON tool arguments
    "clean",  # no PII at all — over-redaction control
]


@dataclass
class Span:
    start: int
    end: int
    type: str
    value: str


@dataclass
class Item:
    id: str
    lang: str
    tier: str
    text: str
    spans: List[Span] = field(default_factory=list)
    tool: str = "chat"

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# Value pools
# ---------------------------------------------------------------------------

PERSONS = {
    "en": [
        "John Smith",
        "Maria Garcia",
        "Robert Johnson",
        "Sarah Chen",
        "David Miller",
    ],
    "es": [
        "Juan Martínez",
        "Lucía Fernández",
        "Carlos Ruiz",
        "Ana Torres",
        "Miguel Ortega",
    ],
    "fr": [
        "Jean Dupont",
        "Marie Lefèvre",
        "Pierre Moreau",
        "Claire Rousseau",
        "Luc Bernard",
    ],
    "de": [
        "Hans Müller",
        "Anna Schmidt",
        "Peter Wagner",
        "Julia Becker",
        "Thomas Fischer",
    ],
    "zh": ["张伟", "王芳", "李娜", "刘强", "陈静"],
}

LOCATIONS = {
    "en": [
        "1600 Pennsylvania Avenue, Washington DC",
        "42 Baker Street, London",
        "500 Market St, San Francisco",
    ],
    "es": [
        "Calle Gran Vía 28, Madrid",
        "Avenida Diagonal 405, Barcelona",
        "Plaza Mayor 7, Salamanca",
    ],
    "fr": [
        "12 Rue de Rivoli, Paris",
        "3 Avenue Jean Médecin, Nice",
        "8 Quai Saint-Vincent, Lyon",
    ],
    "de": [
        "Unter den Linden 5, Berlin",
        "Maximilianstraße 13, München",
        "Reeperbahn 22, Hamburg",
    ],
    "zh": [
        "北京市朝阳区建国路88号",
        "上海市浦东新区世纪大道100号",
        "广州市天河区天河路299号",
    ],
}

ORG_DOMAINS = ["acme.com", "globex.io", "initech.co", "umbrella-health.org"]

EMAIL_LOCALS = ["j.smith", "m.garcia", "contact", "a.torres", "h.mueller"]

PHONES = {
    "en": ["415-555-0132", "(202) 555-0177", "+1 415 555 0199"],
    "es": ["+34 612 34 56 78", "912 345 678"],
    "fr": ["+33 6 12 34 56 78", "01 42 68 53 00"],
    "de": ["+49 151 23456789", "030 123456"],
    "zh": ["+86 138 0013 8000", "010-12345678"],
}

# All Luhn-valid: a detector that gates on the checksum (as Presidio does) must
# not be penalised for rejecting a number that was never a card in the first place.
CARDS = ["4532015112830366", "5425233430109903", "4111 1111 1111 1111"]

IBANS = [
    "DE89370400440532013000",
    "FR1420041010050500013M02606",
    "ES9121000418450200051332",
]

SSNS = ["123-45-6789", "078-05-1120"]

IPS = ["192.168.14.203", "10.0.42.7", "203.0.113.51"]

# Synthetic, and deliberately test-prefixed rather than live-prefixed: a
# live-prefixed literal trips GitHub push protection even when the value is
# fabricated. The detection pattern covers both prefixes, so the fixture still
# exercises the vendor-prefixed-with-internal-underscore shape.
API_KEYS = [
    "sk_test_BENCHFIXTURE0000000000000",
    "AKIABENCHFIXTUREEXAMPLE0",
]

JWTS = [
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
]

MRNS = ["MRN: 4457812", "Medical Record Number: A-9928134"]
NPIS = ["NPI: 1234567893"]
DEAS = ["DEA: BM1234563"]
MEMBER_IDS = ["Member ID: HX-88213904"]
DOBS = ["DOB: 04/17/1982", "Date of Birth: 11/02/1975"]
CVVS = ["CVV: 831"]
EXPIRIES = ["exp: 04/28"]

# Templates: {slot} markers are replaced and their offsets recorded.
TEMPLATES: Dict[str, Dict[str, List[str]]] = {
    "en": {
        "plain": [
            "Please email {EMAIL_ADDRESS} about the invoice.",
            "Call me back on {PHONE_NUMBER} after 3pm.",
            "Charge the card {CREDIT_CARD} for the annual plan.",
            "The server at {IP_ADDRESS} is refusing connections.",
            "Wire the retainer to {IBAN_CODE} by Friday.",
            "Our staging key is {API_KEY} — rotate it tonight.",
            "Auth header carries {JWT_TOKEN} on every call.",
            "His social is {US_SSN}, needed for the I-9.",
        ],
        "high_sensitivity": [
            "Patient {PERSON} lives at {LOCATION} and is due for a follow-up.",
            "Dr. {PERSON} prescribed medication for patient {PERSON}.",
            "Ship the settlement cheque to {PERSON} at {LOCATION}.",
            "{PERSON} filed the complaint; contact them at {EMAIL_ADDRESS}.",
            "Chart for {PERSON} — {US_MEDICAL_RECORD_NUMBER}, {US_DATE_OF_BIRTH}.",
            "Prescriber {PERSON}, {US_NPI}, {US_DEA}.",
            "Claim submitted by {PERSON} under {US_HEALTH_MEMBER_ID}.",
        ],
        "partial": [
            "The card ending in 0366 belongs to J. S. — confirm before charging.",
            "Patient initials M.G., born 1982, seen last Tuesday.",
            "Reach the account holder on the number ending 0132.",
            "SSN last four is 6789 for the applicant from Ohio.",
        ],
        "obfuscated": [
            "Reach him at j dot smith at acme dot com when you can.",
            "Contact: j . s m i t h @ a c m e . c o m",
            "Card number four five three two 0151 1283 0366.",
            "Phone: four one five, five five five, zero one three two.",
        ],
        "clean": [
            "The deployment finished at 14:32 UTC with no errors.",
            "Version 4.2.1 ships the new retry policy for webhooks.",
            "Acme Corporation reported quarterly revenue above forecast.",
            "Ticket 123-45 was closed as a duplicate of 678-90.",
            "The build agent uses 8 vCPUs and 32 GB of memory.",
        ],
    },
    "es": {
        "plain": [
            "Por favor escribe a {EMAIL_ADDRESS} sobre la factura.",
            "Llámame al {PHONE_NUMBER} después de las tres.",
            "Cobra la tarjeta {CREDIT_CARD} del plan anual.",
            "Transfiere el anticipo a {IBAN_CODE} antes del viernes.",
        ],
        "high_sensitivity": [
            "El paciente {PERSON} vive en {LOCATION} y necesita revisión.",
            "La doctora {PERSON} atendió al paciente {PERSON} esta mañana.",
            "Envíen el cheque a {PERSON} en {LOCATION}.",
            "{PERSON} presentó la reclamación; su correo es {EMAIL_ADDRESS}.",
        ],
        "partial": [
            "La tarjeta terminada en 0366 pertenece a J. M. — confirmar antes de cobrar.",
            "Paciente con iniciales L. F., nacida en 1982.",
        ],
        "obfuscated": [
            "Su correo es j punto smith arroba acme punto com.",
            "Teléfono: seis uno dos, tres cuatro, cinco seis.",
        ],
        "clean": [
            "El despliegue terminó a las 14:32 UTC sin errores.",
            "La versión 4.2.1 incluye la nueva política de reintentos.",
        ],
    },
    "fr": {
        "plain": [
            "Merci d'écrire à {EMAIL_ADDRESS} au sujet de la facture.",
            "Rappelez-moi au {PHONE_NUMBER} après 15h.",
            "Débitez la carte {CREDIT_CARD} pour l'abonnement annuel.",
            "Virez les honoraires sur {IBAN_CODE} avant vendredi.",
        ],
        "high_sensitivity": [
            "Le patient {PERSON} habite au {LOCATION} et doit être revu.",
            "Le docteur {PERSON} a soigné le patient {PERSON} ce matin.",
            "Envoyez le chèque à {PERSON} au {LOCATION}.",
            "{PERSON} a déposé la plainte ; son courriel est {EMAIL_ADDRESS}.",
        ],
        "partial": [
            "La carte se terminant par 0366 appartient à J. D. — à confirmer.",
            "Patiente aux initiales M. L., née en 1982.",
        ],
        "obfuscated": [
            "Son adresse est j point smith arobase acme point com.",
            "Téléphone : zéro six, douze, trente-quatre.",
        ],
        "clean": [
            "Le déploiement s'est terminé à 14h32 UTC sans erreur.",
            "La version 4.2.1 ajoute la politique de relance.",
        ],
    },
    "de": {
        "plain": [
            "Bitte schreiben Sie an {EMAIL_ADDRESS} wegen der Rechnung.",
            "Rufen Sie mich unter {PHONE_NUMBER} nach 15 Uhr zurück.",
            "Belasten Sie die Karte {CREDIT_CARD} für den Jahresplan.",
            "Überweisen Sie das Honorar auf {IBAN_CODE} bis Freitag.",
        ],
        "high_sensitivity": [
            "Der Patient {PERSON} wohnt in {LOCATION} und braucht eine Nachuntersuchung.",
            "Doktor {PERSON} behandelte heute den Patienten {PERSON}.",
            "Senden Sie den Scheck an {PERSON} in {LOCATION}.",
            "{PERSON} hat die Beschwerde eingereicht; E-Mail: {EMAIL_ADDRESS}.",
        ],
        "partial": [
            "Die Karte endend auf 0366 gehört H. M. — bitte bestätigen.",
            "Patientin mit den Initialen A. S., geboren 1982.",
        ],
        "obfuscated": [
            "Seine Adresse ist j punkt smith at acme punkt com.",
            "Telefon: null eins fünf eins, zwei drei vier.",
        ],
        "clean": [
            "Das Deployment endete um 14:32 UTC ohne Fehler.",
            "Version 4.2.1 bringt die neue Wiederholungsrichtlinie.",
        ],
    },
    "zh": {
        "plain": [
            "请发邮件到 {EMAIL_ADDRESS} 询问发票事宜。",
            "下午三点后请拨打 {PHONE_NUMBER} 联系我。",
            "请用银行卡 {CREDIT_CARD} 支付年费。",
        ],
        "high_sensitivity": [
            "患者 {PERSON} 住在 {LOCATION}，需要复诊。",
            "{PERSON} 医生今天为患者 {PERSON} 看诊。",
            "请把支票寄给 {PERSON}，地址是 {LOCATION}。",
            "{PERSON} 提交了投诉，邮箱是 {EMAIL_ADDRESS}。",
        ],
        "partial": [
            "尾号 0366 的卡属于张先生，扣款前请确认。",
            "患者姓名缩写 W.F.，1982 年出生。",
        ],
        "obfuscated": [
            "他的邮箱是 j 点 smith 艾特 acme 点 com。",
            "电话：一三八 零零一三 八零零零。",
        ],
        "clean": [
            "部署于 14:32 UTC 完成，没有报错。",
            "4.2.1 版本加入了新的重试策略。",
        ],
    },
}

SLOT_POOLS = {
    "PERSON": lambda rng, lang: rng.choice(PERSONS[lang]),
    "LOCATION": lambda rng, lang: rng.choice(LOCATIONS[lang]),
    "EMAIL_ADDRESS": lambda rng, lang: f"{rng.choice(EMAIL_LOCALS)}@{rng.choice(ORG_DOMAINS)}",
    "PHONE_NUMBER": lambda rng, lang: rng.choice(PHONES.get(lang, PHONES["en"])),
    "CREDIT_CARD": lambda rng, lang: rng.choice(CARDS),
    "IBAN_CODE": lambda rng, lang: rng.choice(IBANS),
    "US_SSN": lambda rng, lang: rng.choice(SSNS),
    "IP_ADDRESS": lambda rng, lang: rng.choice(IPS),
    "API_KEY": lambda rng, lang: rng.choice(API_KEYS),
    "JWT_TOKEN": lambda rng, lang: rng.choice(JWTS),
    "US_MEDICAL_RECORD_NUMBER": lambda rng, lang: rng.choice(MRNS),
    "US_NPI": lambda rng, lang: rng.choice(NPIS),
    "US_DEA": lambda rng, lang: rng.choice(DEAS),
    "US_HEALTH_MEMBER_ID": lambda rng, lang: rng.choice(MEMBER_IDS),
    "US_DATE_OF_BIRTH": lambda rng, lang: rng.choice(DOBS),
    "PCI_CVV": lambda rng, lang: rng.choice(CVVS),
    "PCI_EXPIRY": lambda rng, lang: rng.choice(EXPIRIES),
}

SLOT_RE = re.compile(r"\{([A-Z_]+)\}")

# Entity families, used to report high-sensitivity recall separately.
HIGH_SENSITIVITY = {
    "PERSON",
    "LOCATION",
    "US_SSN",
    "US_MEDICAL_RECORD_NUMBER",
    "US_NPI",
    "US_DEA",
    "US_HEALTH_MEMBER_ID",
    "US_DATE_OF_BIRTH",
}


def render(template: str, rng: random.Random, lang: str) -> Tuple[str, List[Span]]:
    """Fill {SLOT} markers, recording exact offsets of each filled value."""
    out: List[str] = []
    spans: List[Span] = []
    pos = 0
    cursor = 0
    for m in SLOT_RE.finditer(template):
        literal = template[cursor : m.start()]
        out.append(literal)
        pos += len(literal)

        entity = m.group(1)
        value = SLOT_POOLS[entity](rng, lang)
        spans.append(Span(start=pos, end=pos + len(value), type=entity, value=value))
        out.append(value)
        pos += len(value)
        cursor = m.end()

    tail = template[cursor:]
    out.append(tail)
    return "".join(out), spans


def _structured_items(
    rng: random.Random, lang: str, n: int, start_idx: int
) -> List[Item]:
    """PII nested inside JSON tool arguments at varying depth."""
    items: List[Item] = []
    for i in range(n):
        person = rng.choice(PERSONS[lang])
        email = f"{rng.choice(EMAIL_LOCALS)}@{rng.choice(ORG_DOMAINS)}"
        card = rng.choice(CARDS)
        depth = (i % 3) + 1

        leaf: Dict[str, Any] = {
            "customer_name": person,
            "contact_email": email,
            "payment": {"card_number": card},
        }
        payload: Dict[str, Any] = leaf
        for d in range(depth):
            payload = {f"level_{d}": payload}

        text = json.dumps(payload, ensure_ascii=False)
        spans: List[Span] = []
        for value, etype in (
            (person, "PERSON"),
            (email, "EMAIL_ADDRESS"),
            (card, "CREDIT_CARD"),
        ):
            idx = text.find(value)
            if idx >= 0:
                spans.append(
                    Span(start=idx, end=idx + len(value), type=etype, value=value)
                )

        items.append(
            Item(
                id=f"{lang}-structured-{start_idx + i:04d}",
                lang=lang,
                tier="structured",
                text=text,
                spans=spans,
                tool="db.query",
            )
        )
    return items


# Partial and obfuscated templates carry their PII inline rather than in slots;
# these tables give the ground-truth values the detector is expected to catch.
INLINE_TRUTH: Dict[str, List[Tuple[str, str]]] = {
    "The card ending in 0366 belongs to J. S. — confirm before charging.": [
        ("0366", "CREDIT_CARD")
    ],
    "Patient initials M.G., born 1982, seen last Tuesday.": [("M.G.", "PERSON")],
    "Reach the account holder on the number ending 0132.": [("0132", "PHONE_NUMBER")],
    "SSN last four is 6789 for the applicant from Ohio.": [("6789", "US_SSN")],
    "Reach him at j dot smith at acme dot com when you can.": [
        ("j dot smith at acme dot com", "EMAIL_ADDRESS")
    ],
    "Contact: j . s m i t h @ a c m e . c o m": [
        ("j . s m i t h @ a c m e . c o m", "EMAIL_ADDRESS")
    ],
    "Card number four five three two 0151 1283 0366.": [
        ("four five three two 0151 1283 0366", "CREDIT_CARD")
    ],
    "Phone: four one five, five five five, zero one three two.": [
        ("four one five, five five five, zero one three two", "PHONE_NUMBER")
    ],
    "La tarjeta terminada en 0366 pertenece a J. M. — confirmar antes de cobrar.": [
        ("0366", "CREDIT_CARD")
    ],
    "Paciente con iniciales L. F., nacida en 1982.": [("L. F.", "PERSON")],
    "Su correo es j punto smith arroba acme punto com.": [
        ("j punto smith arroba acme punto com", "EMAIL_ADDRESS")
    ],
    "Teléfono: seis uno dos, tres cuatro, cinco seis.": [
        ("seis uno dos, tres cuatro, cinco seis", "PHONE_NUMBER")
    ],
    "La carte se terminant par 0366 appartient à J. D. — à confirmer.": [
        ("0366", "CREDIT_CARD")
    ],
    "Patiente aux initiales M. L., née en 1982.": [("M. L.", "PERSON")],
    "Son adresse est j point smith arobase acme point com.": [
        ("j point smith arobase acme point com", "EMAIL_ADDRESS")
    ],
    "Téléphone : zéro six, douze, trente-quatre.": [
        ("zéro six, douze, trente-quatre", "PHONE_NUMBER")
    ],
    "Die Karte endend auf 0366 gehört H. M. — bitte bestätigen.": [
        ("0366", "CREDIT_CARD")
    ],
    "Patientin mit den Initialen A. S., geboren 1982.": [("A. S.", "PERSON")],
    "Seine Adresse ist j punkt smith at acme punkt com.": [
        ("j punkt smith at acme punkt com", "EMAIL_ADDRESS")
    ],
    "Telefon: null eins fünf eins, zwei drei vier.": [
        ("null eins fünf eins, zwei drei vier", "PHONE_NUMBER")
    ],
    "尾号 0366 的卡属于张先生，扣款前请确认。": [("0366", "CREDIT_CARD")],
    "患者姓名缩写 W.F.，1982 年出生。": [("W.F.", "PERSON")],
    "他的邮箱是 j 点 smith 艾特 acme 点 com。": [
        ("j 点 smith 艾特 acme 点 com", "EMAIL_ADDRESS")
    ],
    "电话：一三八 零零一三 八零零零。": [("一三八 零零一三 八零零零", "PHONE_NUMBER")],
}


def build(
    per_template: int = 6, languages: Optional[Iterable[str]] = None
) -> List[Item]:
    """Generate the corpus. Deterministic for a fixed SEED."""
    rng = random.Random(SEED)
    langs = list(languages or LANGUAGES)
    items: List[Item] = []
    counter = 0

    for lang in langs:
        tmpl_by_tier = TEMPLATES[lang]
        for tier in ["plain", "high_sensitivity", "clean"]:
            for template in tmpl_by_tier.get(tier, []):
                for _ in range(per_template):
                    text, spans = render(template, rng, lang)
                    items.append(
                        Item(
                            id=f"{lang}-{tier}-{counter:04d}",
                            lang=lang,
                            tier=tier,
                            text=text,
                            spans=spans,
                        )
                    )
                    counter += 1

        for tier in ["partial", "obfuscated"]:
            for template in tmpl_by_tier.get(tier, []):
                truth = INLINE_TRUTH.get(template, [])
                spans = []
                for value, etype in truth:
                    idx = template.find(value)
                    if idx >= 0:
                        spans.append(
                            Span(
                                start=idx, end=idx + len(value), type=etype, value=value
                            )
                        )
                items.append(
                    Item(
                        id=f"{lang}-{tier}-{counter:04d}",
                        lang=lang,
                        tier=tier,
                        text=template,
                        spans=spans,
                    )
                )
                counter += 1

        items.extend(_structured_items(rng, lang, per_template * 2, counter))
        counter += per_template * 2

    return items


def write_jsonl(items: List[Item], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for it in items:
            fh.write(json.dumps(it.to_json(), ensure_ascii=False) + "\n")


if __name__ == "__main__":  # pragma: no cover - manual invocation
    corpus = build()
    write_jsonl(corpus, "bench/corpus.jsonl")
    by_tier: Dict[str, int] = {}
    by_lang: Dict[str, int] = {}
    for it in corpus:
        by_tier[it.tier] = by_tier.get(it.tier, 0) + 1
        by_lang[it.lang] = by_lang.get(it.lang, 0) + 1
    print(f"{len(corpus)} items")
    print("by tier:", by_tier)
    print("by lang:", by_lang)
