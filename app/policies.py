import re
import time
import hashlib
from typing import Tuple, Any, Dict, List, Set, Optional
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_analyzer import RecognizerRegistry
from presidio_anonymizer.entities import OperatorConfig
from .settings import settings

# Fallback regex patterns for when Presidio is not available
EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[^@\s]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
PHONE = re.compile(r"\+?\d[\d\s\-\(\)]{7,}\d")
CARD = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

def luhn_ok(s: str) -> bool:
    """Luhn algorithm for credit card validation"""
    s = "".join(ch for ch in s if ch.isdigit())
    total = 0
    alt = False
    for d in reversed(s):
        n = ord(d) - 48
        if alt:
            n = (n * 2 - 9) if n * 2 > 9 else n * 2
        total += n
        alt = not alt
    return (total % 10) == 0

def _mask_email(s: str) -> str:
    return EMAIL.sub(lambda m: f"{m.group(1)[0]}***{m.group(2)}", s)

def _mask_phone(s: str) -> str:
    return PHONE.sub(lambda _: "+***-***-****", s)

def _mask_card(s: str) -> str:
    def repl(m):
        raw = re.sub(r"[^\d]", "", m.group(0))
        return "**** **** **** ****" if 13 <= len(raw) <= 19 and luhn_ok(raw) else m.group(0)
    return CARD.sub(repl, s)

SENSITIVE_KEYS = {"email", "phone", "ssn", "card", "cvv", "secret", "token", "apikey", "api_key"}

# Global Presidio instances
ANALYZER = None
ANONYMIZER = None
USE_PRESIDIO = settings.use_presidio if hasattr(settings, "use_presidio") else True

def build_presidio():
    """Initialize Presidio analyzer and anonymizer with custom recognizers"""
    try:
        # Initialize spaCy NLP engine with configured model and load it
        model_name = getattr(settings, "presidio_model", "en_core_web_sm")
        # Presidio 2.x expects a list of {lang_code, model_name}
        nlp_engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": model_name}])
        nlp_engine.load()
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(nlp_engine=nlp_engine)

        # Custom API key recognizer
        api_key_pattern = Pattern(name="API_KEY", regex=r"(?:sk|pk|AKIA|ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,40}", score=0.6)
        api_key_recognizer = PatternRecognizer(
            supported_entity="API_KEY",
            patterns=[api_key_pattern],
            context=["secret", "token", "apikey", "api_key", "bearer", "key"]
        )
        registry.add_recognizer(api_key_recognizer)

        # JWT token recognizer
        jwt_pattern = Pattern(name="JWT_TOKEN", regex=r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", score=0.8)
        jwt_recognizer = PatternRecognizer(
            supported_entity="JWT_TOKEN",
            patterns=[jwt_pattern],
            context=["token", "jwt", "bearer", "authorization"]
        )
        registry.add_recognizer(jwt_recognizer)

        # Override SSN recognizer to be more context-aware and exclude passwords
        ssn_pattern = Pattern(name="US_SSN", regex=r"\b(?!000|666|9\d{2})\d{3}[-]?(?!00)\d{2}[-]?(?!0000)\d{4}\b", score=0.8)
        ssn_recognizer = PatternRecognizer(
            supported_entity="US_SSN",
            patterns=[ssn_pattern],
            context=["ssn", "social", "security", "tax", "id", "number"],
            deny_list=["password", "pass", "pwd", "secret", "key", "token"]
        )
        registry.add_recognizer(ssn_recognizer)

        analyzer = AnalyzerEngine(registry=registry, nlp_engine=nlp_engine, supported_languages=["en"])
        anonymizer = AnonymizerEngine()
        return analyzer, anonymizer
    except Exception as e:
        print(f"Failed to initialize Presidio: {e}")
        return None, None

def init_presidio():
    """Initialize Presidio at module level"""
    global ANALYZER, ANONYMIZER, USE_PRESIDIO
    ANALYZER, ANONYMIZER = build_presidio()
    if ANALYZER is None:
        USE_PRESIDIO = False
        print("Falling back to regex-based PII detection")

# Initialize on import
init_presidio()

ANONYMIZE_OPERATORS = {
    "DEFAULT": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
    "CREDIT_CARD": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
    "PHONE_NUMBER": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
    "EMAIL_ADDRESS": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
    "IP_ADDRESS": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
    "IBAN_CODE": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
    "US_SSN": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
    "API_KEY": OperatorConfig("replace", {"new_value": "[REDACTED_API_KEY]"}),
    "JWT_TOKEN": OperatorConfig("replace", {"new_value": "[REDACTED_JWT]"}),
}

def entity_type_to_placeholder(entity_type: str) -> str:
    """Convert Presidio entity type to descriptive placeholder"""
    entity_mapping = {
        "EMAIL_ADDRESS": "<USER_EMAIL>",
        "PHONE_NUMBER": "<USER_PHONE>",
        "CREDIT_CARD": "<USER_CARD>",
        "US_SSN": "<USER_SSN>",
        "IP_ADDRESS": "<USER_IP>",
        "IBAN_CODE": "<USER_IBAN>",
        "API_KEY": "<API_KEY>",
        "JWT_TOKEN": "<JWT_TOKEN>",
    }
    return entity_mapping.get(entity_type, f"<USER_{entity_type}>")

def anonymize_text_presidio(text: str, field_name: str = "", entities: Optional[List[str]] = None) -> Tuple[str, List[str]]:
    """Anonymize text using Presidio"""
    if not USE_PRESIDIO or ANALYZER is None:
        return text, []
    
    ents = entities or list(ANONYMIZE_OPERATORS.keys())
    results = ANALYZER.analyze(text=text, entities=ents, language="en")
    if not results:
        return text, []
    
    # Filter out false positives
    filtered_results = []
    for r in results:
        if not is_false_positive(r.entity_type, field_name, text):
            filtered_results.append(r)
    
    if not filtered_results:
        return text, []
    
    # Create custom operators that use descriptive placeholders
    custom_ops = {}
    for r in filtered_results:
        entity_type = r.entity_type
        if entity_type in ["API_KEY", "JWT_TOKEN"]:
            # Use replace for these
            custom_ops[entity_type] = OperatorConfig("replace", {"new_value": entity_type_to_placeholder(entity_type)})
        else:
            # Use mask for PII
            custom_ops[entity_type] = OperatorConfig("replace", {"new_value": entity_type_to_placeholder(entity_type)})
    
    out = ANONYMIZER.anonymize(text=text, analyzer_results=filtered_results, operators=custom_ops).text
    reasons = sorted({f"pii.redacted:{r.entity_type.lower()}" for r in filtered_results})
    return out, reasons

def anonymize_text_regex(text: str) -> Tuple[str, List[str]]:
    """Fallback regex-based anonymization"""
    reasons = []
    redacted = text
    
    if EMAIL.search(text):
        redacted = _mask_email(redacted)
        reasons.append("pii.redacted:email")
    
    if PHONE.search(text):
        redacted = _mask_phone(redacted)
        reasons.append("pii.redacted:phone")
    
    if CARD.search(text):
        redacted = _mask_card(redacted)
        reasons.append("pii.redacted:card")
    
    return redacted, reasons

def is_password_field(field_name: str) -> bool:
    """Check if field name indicates a password field"""
    password_fields = {"password", "pass", "pwd", "secret", "key", "token", "auth"}
    return field_name.lower() in password_fields

def is_false_positive(entity_type: str, field_name: str, value: str) -> bool:
    """Check if a PII detection is likely a false positive based on field context"""
    field_lower = field_name.lower()
    
    # Password fields should not be detected as SSN
    if entity_type == "US_SSN" and is_password_field(field_name):
        return True
    
    # Common false positive patterns
    if entity_type == "US_SSN" and len(value) == 9 and value.isdigit():
        # Check if it looks like a simple password (repeated digits, sequential, etc.)
        if value == value[0] * len(value):  # All same digit
            return True
        if value in ["123456789", "987654321"]:  # Sequential
            return True
    
    return False

def redact_obj(obj: Any, reasons: Optional[Set[str]] = None, field_name: str = "") -> Tuple[Any, Set[str]]:
    """Recursively redact PII from JSON objects"""
    reasons = reasons or set()
    
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            vv, rr = redact_obj(v, reasons, k)
            out[k] = vv
            reasons |= rr
        
        # Note: Field-based redaction removed - Presidio handles both content and field detection
        # with better descriptive placeholders
        
        return out, reasons
    
    if isinstance(obj, list):
        out = []
        for v in obj:
            vv, rr = redact_obj(v, reasons)
            out.append(vv)
            reasons |= rr
        return out, reasons
    
    if isinstance(obj, str):
        # Handle password fields specifically
        if is_password_field(field_name):
            return "<PASSWORD>", {"field.redacted:password"}
        
        if USE_PRESIDIO and ANALYZER is not None:
            red, r = anonymize_text_presidio(obj, field_name)
        else:
            red, r = anonymize_text_regex(obj)
        
        if red != obj:
            reasons.update(r)
        return red, reasons
    
    return obj, reasons

# Policy configuration
DENY_TOOLS = {"python.exec", "bash.exec", "code.exec", "shell.exec"}
NET_SCOPES = ("net.",)
NET_TOOLS_PREFIX = ("web.", "http.", "fetch.", "request.")

def evaluate(tool: str, scope: Optional[str], payload: Dict, now: int) -> Dict:
    """Evaluate policy and return decision with optional payload transformation"""
    
    # 1) Hard deny for dangerous tools
    if tool in DENY_TOOLS:
        return {
            "decision": "deny",
            "reasons": ["blocked tool: code/exec"],
            "policy_id": "deny-exec",
            "ts": now
        }
    
    # 2) Redact for network scopes/tools
    if (scope or "").startswith(NET_SCOPES) or tool.startswith(NET_TOOLS_PREFIX):
        new_payload, reasons = redact_obj(payload)
        reasons = sorted(list(reasons))
        return {
            "decision": "transform",
            "payload": new_payload,
            "reasons": reasons or None,
            "policy_id": "net-redact-presidio" if USE_PRESIDIO else "net-redact-regex",
            "ts": now
        }
    
    # 3) Allow by default
    return {
        "decision": "allow",
        "payload": payload,
        "policy_id": "none",
        "ts": now
    }
