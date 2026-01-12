import re
import time
import hashlib
import yaml
import os
from copy import deepcopy
from typing import Tuple, Any, Dict, List, Set, Optional
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_analyzer import RecognizerRegistry
from presidio_anonymizer.entities import OperatorConfig
from .settings import settings
from .ocr import extract_text_from_image

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
    "DATE_TIME": OperatorConfig("replace", {"new_value": "[REDACTED_DATE]"}),
    "LOCATION": OperatorConfig("replace", {"new_value": "[REDACTED_LOCATION]"}),
    "PERSON": OperatorConfig("replace", {"new_value": "[REDACTED_PERSON]"}),
    "MEDICAL_LICENSE": OperatorConfig("replace", {"new_value": "[REDACTED_MEDICAL_ID]"}),
    "US_DRIVER_LICENSE": OperatorConfig("replace", {"new_value": "[REDACTED_DRIVER_LICENSE]"}),
    "CRYPTO": OperatorConfig("replace", {"new_value": "[REDACTED_CRYPTO_WALLET]"}),
    "URL": OperatorConfig("replace", {"new_value": "[REDACTED_URL]"}),
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
        "DATE_TIME": "<DATE>",
        "LOCATION": "<LOCATION>",
        "PERSON": "<PERSON_NAME>",
        "MEDICAL_LICENSE": "<MEDICAL_ID>",
        "US_DRIVER_LICENSE": "<DRIVER_LICENSE>",
        "CRYPTO": "<CRYPTO_WALLET>",
        "URL": "<URL>",
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
    field_lower = field_name.lower()
    return field_lower in password_fields or any(field in field_lower for field in password_fields)

def is_false_positive(entity_type: str, field_name: str, value: str) -> bool:
    """Check if a PII detection is likely a false positive based on field context"""
    field_lower = field_name.lower()
    
    # Password fields should not be detected as SSN
    if entity_type == "US_SSN" and is_password_field(field_name):
        return True
    
    # If the detected text is "password" or similar, it's likely a false positive for SSN
    if entity_type == "US_SSN" and value.lower() in ["password", "pwd", "pass"]:
        return True
    
    # Common false positive patterns - be more conservative
    if entity_type == "US_SSN" and len(value) == 9 and value.isdigit():
        # Only filter out obvious non-SSN patterns
        if value == value[0] * len(value):  # All same digit (e.g., "111111111")
            return True
        # Don't filter out sequential numbers as they could be real SSNs
    
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

# Tool access policy configuration with hot-reload
_POLICY_PATH = os.getenv("POLICY_FILE", os.path.join(os.path.dirname(__file__), "..", "policy.tool_access.yaml"))
_POLICY_CACHE: Dict[str, Any] = {}
_POLICY_MTIME = 0.0
TOKEN_SALT = os.getenv("PII_TOKEN_SALT", "default-salt-change-in-production")

def _load_policy() -> Dict[str, Any]:
    """Load policy with hot-reload support"""
    global _POLICY_CACHE, _POLICY_MTIME
    try:
        mtime = os.path.getmtime(_POLICY_PATH)
        if mtime != _POLICY_MTIME:
            with open(_POLICY_PATH, "r", encoding="utf-8") as f:
                _POLICY_CACHE = yaml.safe_load(f) or {}
            _POLICY_MTIME = mtime
    except FileNotFoundError:
        _POLICY_CACHE = {}
    except Exception as e:
        print(f"Failed to load policy file: {e}")
        _POLICY_CACHE = {}
    return _POLICY_CACHE

def get_policy() -> Dict[str, Any]:
    """Get current policy with hot-reload - cheap check every call"""
    return _load_policy()

def tokenize(value: str) -> str:
    """Create a stable token for PII values"""
    return f"pii_{hashlib.sha256((TOKEN_SALT + value).encode()).hexdigest()[:8]}"

def get_jsonpath(obj: Any, path: str) -> Any:
    """Get value from object using JSONPath-like syntax"""
    if not path.startswith("$."):
        return None
    
    parts = path[2:].split(".")
    current = obj
    
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    
    return current

def set_jsonpath(obj: Any, path: str, value: Any) -> None:
    """Set value in object using JSONPath-like syntax"""
    if not path.startswith("$."):
        return
    
    parts = path[2:].split(".")
    current = obj
    
    # Navigate to the parent of the target
    for part in parts[:-1]:
        if isinstance(current, dict):
            if part not in current:
                current[part] = {}
            current = current[part]
        else:
            return
    
    # Set the final value
    if isinstance(current, dict):
        current[parts[-1]] = value

def apply_tool_access_text(tool_name: str, findings: List[Dict], raw_text: str) -> Tuple[str, List[str]]:
    """Apply tool-specific PII access rules to raw text"""
    policy = get_policy()
    tool_access = policy.get("tool_access", {})
    
    cfg = tool_access.get(tool_name, {})
    allow_map = cfg.get("allow_pii", {})
    
    transformed_text = raw_text
    reasons = []
    
    # Process findings in reverse order to maintain correct indices
    for f in sorted(findings, key=lambda x: x["start"], reverse=True):
        pii_type = f.get("type", "")  # e.g., "PII:email_address"
        start = f.get("start", 0)
        end = f.get("end", 0)
        original_text = f.get("text", "")
        
        action = allow_map.get(pii_type)
        
        if action == "pass_through":
            reasons.append(f"pii.allowed:{pii_type}")
            continue
        elif action == "tokenize":
            tokenized_value = tokenize(original_text)
            transformed_text = transformed_text[:start] + tokenized_value + transformed_text[end:]
            reasons.append(f"pii.tokenized:{pii_type}")
        else:
            # Fall back to default redaction (mask/remove)
            if USE_PRESIDIO and ANALYZER is not None:
                redacted, _ = anonymize_text_presidio(original_text)
            else:
                redacted, _ = anonymize_text_regex(original_text)
            transformed_text = transformed_text[:start] + redacted + transformed_text[end:]
            reasons.append(f"pii.redacted:{pii_type}")
    
    return transformed_text, reasons

def apply_tool_access(tool_name: str, findings: List[Dict], payload_dict: Dict) -> Tuple[Dict, List[str]]:
    """Apply tool-specific PII access rules"""
    policy = get_policy()
    tool_access = policy.get("tool_access", {})
    defaults = policy.get("defaults", {})
    
    cfg = tool_access.get(tool_name, {})
    allow_map = cfg.get("allow_pii", {})
    
    transformed = deepcopy(payload_dict)
    reasons = []
    
    for f in findings:
        pii_cls = f.get("type", "")  # e.g., "PII:email"
        path = f.get("path", "")     # e.g., "$.payload.email"
        action = allow_map.get(pii_cls)
        
        if action == "pass_through":
            reasons.append(f"pii.allowed:{pii_cls}")
            continue
        elif action == "tokenize":
            original_value = get_jsonpath(payload_dict, path)
            if original_value is not None:
                tokenized_value = tokenize(str(original_value))
                set_jsonpath(transformed, path, tokenized_value)
                reasons.append(f"pii.tokenized:{pii_cls}")
        else:
            # Fall back to default redaction (mask/remove)
            original_value = get_jsonpath(payload_dict, path)
            if original_value is not None:
                # Use existing redaction logic
                if isinstance(original_value, str):
                    if USE_PRESIDIO and ANALYZER is not None:
                        redacted, _ = anonymize_text_presidio(original_value, "")
                    else:
                        redacted, _ = anonymize_text_regex(original_value)
                    set_jsonpath(transformed, path, redacted)
                else:
                    set_jsonpath(transformed, path, "<REDACTED>")
                reasons.append(f"pii.redacted:{pii_cls}")
    
    return transformed, reasons

# Policy configuration
DENY_TOOLS = {"python.exec", "bash.exec", "code.exec", "shell.exec"}
NET_SCOPES = ("net.",)
NET_TOOLS_PREFIX = ("web.", "http.", "fetch.", "request.")

def evaluate(tool: str, scope: Optional[str], raw_text: str, now: int, direction: str = "ingress") -> Dict:
    """Evaluate policy and return decision with optional payload transformation"""
    try:
        return _evaluate_policy(tool, scope, raw_text, now, direction)
    except Exception as e:
        # Handle errors based on ON_ERROR setting
        from .settings import settings
        error_behavior = settings.on_error
        
        if error_behavior == "block":
            return {
                "decision": "deny",
                "raw_text_out": raw_text,
                "reasons": ["precheck.error"],
                "policy_id": "error-handler",
                "ts": now
            }
        elif error_behavior == "pass":
            return {
                "decision": "pass_through",
                "reasons": ["precheck.bypass"],
                "policy_id": "error-handler",
                "ts": now
            }
        elif error_behavior == "best_effort":
            # Try regex fallback, else tokenize everything blindly
            try:
                if USE_PRESIDIO and ANALYZER is not None:
                    redacted_text, reasons = anonymize_text_presidio(raw_text)
                else:
                    redacted_text, reasons = anonymize_text_regex(raw_text)
                return {
                    "decision": "transform",
                    "raw_text_out": redacted_text,
                    "reasons": reasons or ["precheck.best_effort"],
                    "policy_id": "error-handler-regex",
                    "ts": now
                }
            except Exception:
                # Last resort: tokenize everything
                tokenized_text = tokenize(raw_text)
                return {
                    "decision": "transform",
                    "raw_text_out": tokenized_text,
                    "reasons": ["precheck.best_effort_tokenize"],
                    "policy_id": "error-handler-tokenize",
                    "ts": now
                }
        else:
            # Default to block
            return {
                "decision": "deny",
                "raw_text_out": raw_text,
                "reasons": ["precheck.error"],
                "policy_id": "error-handler",
                "ts": now
            }

def _evaluate_policy(tool: str, scope: Optional[str], raw_text: str, now: int, direction: str = "ingress") -> Dict:
    """
    Internal policy evaluation logic with explicit precedence rules for raw text processing.
    
    POLICY PRECEDENCE (highest to lowest priority):
    1. DENY_TOOLS: Hard deny for dangerous tools (python.exec, bash.exec, etc.)
    2. TOOL_SPECIFIC: Tool-specific rules in policy.tool_access.yaml
    3. GLOBAL_DEFAULTS: Global defaults for direction (ingress/egress)
    4. NETWORK_SCOPE: Network scope redaction (net.* scopes or web.* tools)
    5. SAFE_FALLBACK: Default redaction for all other cases
    
    Each level can override lower levels. Tool-specific rules take precedence
    over global defaults, which take precedence over network scope rules.
    """
    
    # PRECEDENCE LEVEL 1: Hard deny for dangerous tools
    if tool in DENY_TOOLS:
        return {
            "decision": "deny",
            "reasons": ["blocked tool: code/exec"],
            "policy_id": "deny-exec",
            "ts": now
        }
    
    # Load current policy (with hot-reload support)
    policy = get_policy()
    tool_access = policy.get("tool_access", {})
    defaults = policy.get("defaults", {})
    
    # PRECEDENCE LEVEL 2: Tool-specific access rules (highest priority for non-dangerous tools)
    if tool in tool_access and tool_access[tool].get("direction") == direction:
        # Run PII detection on raw text
        findings = []
        if USE_PRESIDIO and ANALYZER is not None:
            results = ANALYZER.analyze(text=raw_text, entities=list(ANONYMIZE_OPERATORS.keys()), language="en")
            for r in results:
                if not is_false_positive(r.entity_type, "", raw_text):
                    findings.append({
                        "type": f"PII:{r.entity_type.lower()}",
                        "start": r.start,
                        "end": r.end,
                        "score": r.score,
                        "text": raw_text[r.start:r.end]
                    })
        
        # Apply tool-specific transformations based on findings
        if findings:
            transformed_text, tool_reasons = apply_tool_access_text(tool, findings, raw_text)
            return {
                "decision": "transform",
                "raw_text_out": transformed_text,
                "reasons": tool_reasons,
                "policy_id": "tool-access",
                "ts": now
            }
        else:
            # No PII found, pass through
            return {
                "decision": "allow",
                "raw_text_out": raw_text,
                "policy_id": "tool-access",
                "ts": now
            }
    
    # PRECEDENCE LEVEL 3: Global defaults for this direction
    default_action = defaults.get(direction, {}).get("action", "redact")
    
    if default_action == "deny":
        return {
            "decision": "deny",
            "reasons": [f"default.{direction}.deny"],
            "policy_id": "defaults",
            "ts": now
        }
    elif default_action == "pass_through":
        return {
            "decision": "allow",
            "raw_text_out": raw_text,
            "reasons": [f"default.{direction}.pass_through"],
            "policy_id": "defaults",
            "ts": now
        }
    elif default_action == "tokenize":
        # Tokenize the entire text
        tokenized_text = tokenize(raw_text)
        return {
            "decision": "transform",
            "raw_text_out": tokenized_text,
            "reasons": [f"default.{direction}.tokenize"],
            "policy_id": "defaults",
            "ts": now
        }
    
    # PRECEDENCE LEVEL 4: Network scope redaction (net.* scopes or web.* tools)
    if (scope or "").startswith(NET_SCOPES) or tool.startswith(NET_TOOLS_PREFIX):
        if USE_PRESIDIO and ANALYZER is not None:
            redacted_text, reasons = anonymize_text_presidio(raw_text)
        else:
            redacted_text, reasons = anonymize_text_regex(raw_text)
        reasons = sorted(list(reasons))
        return {
            "decision": "transform",
            "raw_text_out": redacted_text,
            "reasons": reasons or None,
            "policy_id": "net-redact-presidio" if USE_PRESIDIO else "net-redact-regex",
            "ts": now
        }
    
    # PRECEDENCE LEVEL 5: Strict fallback (only block SSN and passwords)
    return _apply_strict_fallback(raw_text, now, None, None, None, None)

# NEW: Dynamic policy evaluation using payload-provided policies
def evaluate_with_payload_policy(
    tool: str, 
    scope: Optional[str], 
    raw_text: str, 
    now: int, 
    direction: str = "ingress",
    policy_config: Optional[Dict] = None,
    tool_config: Optional[Dict] = None,
    user_id: Optional[str] = None,
    budget_context: Optional[Dict] = None,
    image_data: Optional[str] = None
) -> Dict:
    """
    Evaluate policy using payload-provided configuration
    Falls back to static YAML if no policy_config provided
    """
    
    # Process image if present
    if image_data:
        extracted_text = extract_text_from_image(image_data)
        if extracted_text:
            if raw_text:
                raw_text += "\n\n[OCR EXTRACTED TEXT]\n" + extracted_text
            else:
                raw_text = "[OCR EXTRACTED TEXT]\n" + extracted_text
    
    if not policy_config:
        # Fallback to current YAML-based logic
        return evaluate(tool, scope, raw_text, now, direction)
    
    # Use payload-provided policy configuration
    return _evaluate_dynamic_policy(tool, scope, raw_text, now, direction, policy_config, tool_config, user_id, budget_context)

def _evaluate_dynamic_policy(
    tool: str, 
    scope: Optional[str], 
    raw_text: str, 
    now: int, 
    direction: str,
    policy_config: Dict,
    tool_config: Optional[Dict] = None,
    user_id: Optional[str] = None,
    budget_context: Optional[Dict] = None
) -> Dict:
    """Evaluate policy using dynamic configuration from payload"""
    
    try:
        # PRECEDENCE LEVEL 1: Hard deny for dangerous tools
        deny_tools = policy_config.get("deny_tools", ["python.exec", "bash.exec", "code.exec", "shell.exec"])
        if tool in deny_tools:
            return {
                "decision": "deny",
                "raw_text_out": raw_text,
                "reasons": ["blocked tool: code/exec"],
                "policy_id": "deny-exec",
                "ts": now
            }
        
        # PRECEDENCE LEVEL 2: Tool-specific access rules
        tool_access = policy_config.get("tool_access", {})
        
        # Try exact match first
        if tool in tool_access:
            tool_policy = tool_access[tool]
            tool_direction = tool_policy.get("direction")
            # Support "both" direction or exact match
            if tool_direction == direction or tool_direction == "both":
                return _apply_tool_specific_policy_dynamic(tool, raw_text, now, tool_policy, user_id, tool_config, policy_config, budget_context)
        
        # Try partial matching for MCP tools (e.g., "mcp.weather.current" matches "weather.current")
        for policy_tool, tool_policy in tool_access.items():
            if tool.endswith("." + policy_tool) or tool.endswith(policy_tool):
                tool_direction = tool_policy.get("direction")
                # Support "both" direction or exact match
                if tool_direction == direction or tool_direction == "both":
                    return _apply_tool_specific_policy_dynamic(tool, raw_text, now, tool_policy, user_id, tool_config, policy_config, budget_context)
        
        # PRECEDENCE LEVEL 3: Global defaults for this direction
        defaults = policy_config.get("defaults", {})
        default_action = defaults.get(direction, {}).get("action", "redact")
        return _apply_default_action_dynamic(default_action, raw_text, now, direction, policy_config, user_id, tool_config, budget_context)
        
    except Exception as e:
        # Handle errors based on policy configuration
        error_behavior = policy_config.get("on_error", "block")
        
        if error_behavior == "block":
            return {
                "decision": "deny",
                "raw_text_out": raw_text,
                "reasons": ["precheck.error"],
                "policy_id": "error-handler",
                "ts": now
            }
        elif error_behavior == "pass":
            return {
                "decision": "allow",
                "raw_text_out": raw_text,
                "reasons": ["precheck.bypass"],
                "policy_id": "error-handler",
                "ts": now
            }
        elif error_behavior == "best_effort":
            # Try regex fallback, else tokenize everything blindly
            try:
                if USE_PRESIDIO and ANALYZER is not None:
                    redacted_text, reasons = anonymize_text_presidio(raw_text)
                else:
                    redacted_text, reasons = anonymize_text_regex(raw_text)
                return {
                    "decision": "transform",
                    "raw_text_out": redacted_text,
                    "reasons": reasons or ["precheck.best_effort"],
                    "policy_id": "error-handler-regex",
                    "ts": now
                }
            except Exception:
                # Last resort: tokenize everything
                tokenized_text = tokenize(raw_text)
                return {
                    "decision": "transform",
                    "raw_text_out": tokenized_text,
                    "reasons": ["precheck.best_effort_tokenize"],
                    "policy_id": "error-handler-tokenize",
                    "ts": now
                }
        else:
            # Default to block
            return {
                "decision": "deny",
                "raw_text_out": raw_text,
                "reasons": ["precheck.error"],
                "policy_id": "error-handler",
                "ts": now
            }

def _apply_tool_specific_policy_dynamic(tool: str, raw_text: str, now: int, tool_policy: Dict, user_id: Optional[str] = None, tool_config: Optional[Dict] = None, policy_config: Optional[Dict] = None, budget_context: Optional[Dict] = None) -> Dict:
    """Apply tool-specific policy using dynamic configuration"""
    
    # Run PII detection on raw text
    findings = []
    if USE_PRESIDIO and ANALYZER is not None:
        results = ANALYZER.analyze(text=raw_text, entities=list(ANONYMIZE_OPERATORS.keys()), language="en")
        for r in results:
            if not is_false_positive(r.entity_type, "", raw_text):
                findings.append({
                    "type": f"PII:{r.entity_type.lower()}",
                    "start": r.start,
                    "end": r.end,
                    "score": r.score,
                    "text": raw_text[r.start:r.end]
                })
    

    import re
    ssn_patterns = [
        r'\b\d{3}-\d{2}-\d{4}\b',  # XXX-XX-XXXX with dashes
        r'\b(?!000|666|9\d{2})\d{3}[-]?(?!00)\d{2}[-]?(?!0000)\d{4}\b',  # With optional dashes
        r'\b(?!000|666|9\d{2})\d{9}\b'  # 9 digits without dashes (if context suggests SSN)
    ]
    
    # Check if text contains SSN-related context
    ssn_context = re.search(r'\b(ssn|social\s*security|tax\s*id|social\s*security\s*number)\b', raw_text, re.IGNORECASE)
    
    for pattern in ssn_patterns:
        for match in re.finditer(pattern, raw_text):
            # Check if this SSN overlaps with any existing finding
            overlaps = False
            for finding in findings:
                if not (match.end() <= finding["start"] or match.start() >= finding["end"]):
                    overlaps = True
                    break
            
            # Only add if no overlap and (has context or is in standard format)
            if not overlaps and (ssn_context or '-' in match.group()):
                # Check if it's already detected as US_SSN
                already_detected = False
                for finding in findings:
                    if finding["type"] == "PII:us_ssn" and finding["start"] == match.start():
                        already_detected = True
                        break
                
                if not already_detected:
                    findings.append({
                        "type": "PII:us_ssn",
                        "start": match.start(),
                        "end": match.end(),
                        "score": 0.9 if ssn_context else 0.7,
                        "text": match.group()
                    })
                    break  # Only add first match per pattern
    
    # Apply tool-specific transformations based on findings and allow_pii rules
    if findings:
        allow_pii = tool_policy.get("allow_pii", {})
        
        # Check if any PII type is set to "block" - if so, deny the entire request
        for finding in findings:
            pii_type = finding["type"]
            action = allow_pii.get(pii_type, "redact")
            if action == "block" or action == "deny":
                return {
                    "decision": "deny",
                    "raw_text_out": raw_text,
                    "reasons": [f"pii.blocked:{pii_type.replace('PII:', '')}"],
                    "policy_id": "tool-access",
                    "ts": now
                }
        
        # No blocking actions, apply transformations
        transformed_text, tool_reasons = apply_tool_access_text_dynamic(tool, findings, raw_text, allow_pii)
        return {
            "decision": "transform",
            "raw_text_out": transformed_text,
            "reasons": tool_reasons,
            "policy_id": "tool-access",
            "ts": now
        }
    else:
        # No PII found, check if tool has default action override
        action = tool_policy.get("action")
        if action == "deny" or action == "block":
            # Budget check not needed for deny/block actions
            return {
                "decision": "deny",
                "raw_text_out": raw_text,
                "reasons": ["tool-specific.block"],
                "policy_id": "tool-access",
                "ts": now
            }
        elif action == "tokenize":
            tokenized_text = tokenize(raw_text)
            return {
                "decision": "transform",
                "raw_text_out": tokenized_text,
                "reasons": ["tool-specific.tokenize"],
                "policy_id": "tool-access",
                "ts": now
            }
        elif action == "confirm":
            # Check budget first - budget overrides confirm
            if user_id and tool_config and policy_config and budget_context:
                budget_result = _check_budget_and_apply(user_id, tool, raw_text, tool_config, policy_config, budget_context, now)
                if budget_result:
                    return budget_result
            
            # If budget check passed, return confirm
            result = {
                "decision": "confirm",
                "raw_text_out": raw_text,
                "reasons": ["tool-specific.confirm"],
                "policy_id": "tool-access",
                "ts": now
            }
            
            # Add budget info if available
            if user_id and tool_config and policy_config and budget_context:
                result = _add_budget_info_to_result(result, user_id, tool, raw_text, tool_config, policy_config, budget_context)
            
            return result
        else:
            # Default: pass through - but check budget first if user_id provided
            result = {
                "decision": "allow",
                "raw_text_out": raw_text,
                "policy_id": "tool-access",
                "ts": now
            }
            
            # Check budget if user_id and tool_config provided
            if user_id and tool_config and policy_config and budget_context:
                budget_result = _check_budget_and_apply(user_id, tool, raw_text, tool_config, policy_config, budget_context, now)
                if budget_result:
                    return budget_result
                else:
                    # Add budget info to the result
                    result = _add_budget_info_to_result(result, user_id, tool, raw_text, tool_config, policy_config, budget_context)
            
            return result

def apply_tool_access_text_dynamic(tool: str, findings: List[Dict], raw_text: str, allow_pii: Dict[str, str]) -> Tuple[str, List[str]]:
    """Apply tool-specific text transformations using dynamic allow_pii rules"""
    
    transformed = raw_text
    reasons = []
    
    # Sort findings by start position (reverse order to maintain indices)
    findings_sorted = sorted(findings, key=lambda x: x["start"], reverse=True)
    
    for finding in findings_sorted:
        pii_type = finding["type"]
        start = finding["start"]
        end = finding["end"]
        original_text = finding["text"]
        
        # Check if this PII type is allowed for this tool
        action = allow_pii.get(pii_type, "redact")  # Default to redact if not specified
        
        if action == "pass_through":
            # Keep original text
            continue
        elif action == "tokenize":
            # Replace with token
            token = tokenize(original_text)
            transformed = transformed[:start] + token + transformed[end:]
            reasons.append(f"tokenized:{pii_type}")
        elif action == "redact":
            # Replace with placeholder
            placeholder = f"[{pii_type.upper()}]"
            transformed = transformed[:start] + placeholder + transformed[end:]
            reasons.append(f"redacted:{pii_type}")
        elif action == "deny":
            # This should be handled at a higher level, but just redact here
            placeholder = f"[{pii_type.upper()}]"
            transformed = transformed[:start] + placeholder + transformed[end:]
            reasons.append(f"redacted:{pii_type}")
    
    return transformed, reasons

def _apply_default_action_dynamic(action: str, raw_text: str, now: int, direction: str, policy_config: Dict, user_id: Optional[str] = None, tool_config: Optional[Dict] = None, budget_context: Optional[Dict] = None) -> Dict:
    """Apply default action using dynamic configuration"""
    
    if action == "deny":
        return {
            "decision": "deny",
            "raw_text_out": raw_text,
            "reasons": [f"default.{direction}.deny"],
            "policy_id": "defaults",
            "ts": now
        }
    elif action == "pass_through":
        return {
            "decision": "allow",
            "raw_text_out": raw_text,
            "reasons": [f"default.{direction}.pass_through"],
            "policy_id": "defaults",
            "ts": now
        }
    elif action == "tokenize":
        # Tokenize the entire text
        tokenized_text = tokenize(raw_text)
        return {
            "decision": "transform",
            "raw_text_out": tokenized_text,
            "reasons": [f"default.{direction}.tokenize"],
            "policy_id": "defaults",
            "ts": now
        }
    
    # PRECEDENCE LEVEL 4: Network scope redaction (net.* scopes or web.* tools)
    network_scopes = policy_config.get("network_scopes", ["net."])
    network_tools = policy_config.get("network_tools", ["web.", "http.", "fetch.", "request."])
    
    scope = policy_config.get("scope", "")
    tool = policy_config.get("tool", "")
    
    if (scope and any(scope.startswith(ns) for ns in network_scopes)) or any(tool.startswith(nt) for nt in network_tools):
        if USE_PRESIDIO and ANALYZER is not None:
            redacted_text, reasons = anonymize_text_presidio(raw_text)
        else:
            redacted_text, reasons = anonymize_text_regex(raw_text)
        reasons = sorted(list(reasons))
        return {
            "decision": "transform",
            "raw_text_out": redacted_text,
            "reasons": reasons or None,
            "policy_id": "net-redact-presidio" if USE_PRESIDIO else "net-redact-regex",
            "ts": now
        }

    # PRECEDENCE LEVEL 5: Strict fallback (only block SSN and passwords)
    return _apply_strict_fallback(raw_text, now, user_id, tool_config, policy_config, budget_context)

def _apply_strict_fallback(raw_text: str, now: int, user_id: Optional[str] = None, tool_config: Optional[Dict] = None, policy_config: Optional[Dict] = None, budget_context: Optional[Dict] = None) -> Dict:
    """Apply strict fallback policy - redact all PII types (email, phone, SSN, credit card, passwords, payment amounts, etc.)"""
    
    import re
    
    # Collect all PII findings from the original text
    all_findings = []
    
    # Detect standard PII types using Presidio or regex
    if USE_PRESIDIO and ANALYZER is not None:
        # Use Presidio to detect all standard PII types
        results = ANALYZER.analyze(text=raw_text, entities=list(ANONYMIZE_OPERATORS.keys()), language="en")
        for r in results:
            if not is_false_positive(r.entity_type, "", raw_text):
                all_findings.append({
                    "type": f"PII:{r.entity_type.lower()}",
                    "start": r.start,
                    "end": r.end,
                    "score": r.score,
                    "text": raw_text[r.start:r.end]
                })
    else:
        # Fallback regex detection for email, phone, card
        if EMAIL.search(raw_text):
            for match in EMAIL.finditer(raw_text):
                all_findings.append({
                    "type": "PII:email_address",
                    "start": match.start(),
                    "end": match.end(),
                    "score": 0.8,
                    "text": match.group()
                })
        if PHONE.search(raw_text):
            for match in PHONE.finditer(raw_text):
                all_findings.append({
                    "type": "PII:phone_number",
                    "start": match.start(),
                    "end": match.end(),
                    "score": 0.8,
                    "text": match.group()
                })
        if CARD.search(raw_text):
            for match in CARD.finditer(raw_text):
                raw_card = re.sub(r"[^\d]", "", match.group())
                if 13 <= len(raw_card) <= 19 and luhn_ok(raw_card):
                    all_findings.append({
                        "type": "PII:credit_card",
                        "start": match.start(),
                        "end": match.end(),
                        "score": 0.9,
                        "text": match.group()
                    })
    
    # Additionally detect passwords (not in Presidio) and payment amounts
    password_findings = []
    payment_findings = []
    
    # Password detection using regex
    password_pattern = r'\b(?:password|pwd|pass)\s*[:=]\s*\S+'
    for match in re.finditer(password_pattern, raw_text, re.IGNORECASE):
        # Check if this overlaps with any existing finding
        overlaps = False
        for finding in all_findings:
            if not (match.end() <= finding["start"] or match.start() >= finding["end"]):
                overlaps = True
                break
        if not overlaps:
            password_findings.append({
                "type": "PII:password",
                "start": match.start(),
                "end": match.end(),
                "score": 0.8,
                "text": match.group()
            })
    
    # Payment amount detection
    payment_pattern = r'\$\d+(?:\.\d{2})?|\b\d+(?:\.\d{2})?\s*(?:dollars?|USD|usd)\b|"(?:amount|price|cost)":\s*"?\d+(?:\.\d{2})?"?'
    for match in re.finditer(payment_pattern, raw_text, re.IGNORECASE):
        # Check if this overlaps with any existing finding
        overlaps = False
        for finding in all_findings:
            if not (match.end() <= finding["start"] or match.start() >= finding["end"]):
                overlaps = True
                break
        if not overlaps:
            payment_findings.append({
                "type": "PII:payment_amount",
                "start": match.start(),
                "end": match.end(),
                "score": 0.9,
                "text": match.group()
            })
    
    # Check budget for payment amounts if available
    if payment_findings and budget_context and policy_config:
        try:
            from .budget import (
                estimate_request_cost, 
                get_purchase_amount, 
                check_budget_with_context
            )
            # Get model from policy config or tool config
            model = policy_config.get("model", "gpt-4")
            if tool_config and "metadata" in tool_config:
                model = tool_config["metadata"].get("model", model)
            
            # Estimate costs
            estimated_llm_cost = estimate_request_cost(raw_text, model)
            
            # Extract purchase amount from text
            estimated_purchase = None
            for finding in payment_findings:
                try:
                    amount_match = re.search(r'(\d+(?:\.\d{2})?)', finding['text'])
                    if amount_match:
                        estimated_purchase = float(amount_match.group(1))
                        break
                except (ValueError, AttributeError):
                    continue
            
            # Fallback to tool metadata if no amount found in text
            if estimated_purchase is None and tool_config:
                estimated_purchase = get_purchase_amount(tool_config.get("metadata", {}))
            
            # Check budget using context
            budget_status, budget_info = check_budget_with_context(
                budget_context=budget_context,
                estimated_llm_cost=estimated_llm_cost,
                estimated_purchase=estimated_purchase
            )
            
            if not budget_status.allowed:
                # Budget exceeded, block the request
                return {
                    "decision": "deny",
                    "raw_text_out": raw_text,
                    "reasons": [f"budget_exceeded:{budget_status.reason}"],
                    "policy_id": "strict-fallback",
                    "ts": now
                }
        except Exception as e:
            # If budget check fails, continue with PII redaction
            pass
    
    # Add password and payment findings to all findings
    all_findings.extend(password_findings)
    all_findings.extend(payment_findings)
    
    # If any PII found, redact all of it
    if all_findings:
        # Sort findings by start position (reverse order for safe replacement)
        sorted_findings = sorted(all_findings, key=lambda x: x["start"], reverse=True)
        redacted_text = raw_text
        reasons = []
        
        for finding in sorted_findings:
            pii_type = finding["type"]
            start = finding["start"]
            end = finding["end"]
            
            # Determine placeholder based on type
            if pii_type == "PII:password":
                placeholder = "<PASSWORD>"
            elif pii_type == "PII:payment_amount":
                placeholder = "<PAYMENT_AMOUNT>"
            elif pii_type.startswith("PII:"):
                # Use entity type to get placeholder
                entity_type = pii_type.replace("PII:", "").upper()
                placeholder = entity_type_to_placeholder(entity_type)
            else:
                placeholder = "<REDACTED>"
            
            # Replace in text
            redacted_text = redacted_text[:start] + placeholder + redacted_text[end:]
            reasons.append(f"pii.redacted:{pii_type.replace('PII:', '')}")
        
        return {
            "decision": "transform",
            "raw_text_out": redacted_text,
            "reasons": sorted(set(reasons)),
            "policy_id": "strict-fallback",
            "ts": now
        }
    else:
        # No PII found - allow the request
        return {
            "decision": "allow",
            "raw_text_out": raw_text,
            "reasons": ["strict_fallback.allow"],
            "policy_id": "strict-fallback",
            "ts": now
        }

def _check_budget_and_apply(
    user_id: str, 
    tool: str, 
    raw_text: str, 
    tool_config: Dict, 
    policy_config: Dict, 
    budget_context: Optional[Dict],
    now: int
) -> Optional[Dict]:
    """Check budget and apply budget-based decisions"""
    
    try:
        from .budget import (
            estimate_request_cost, 
            get_purchase_amount, 
            check_budget_with_context,
            update_budget_after_decision
        )
        
        # Only check budget if budget_context is provided
        if not budget_context:
            return None
        
        # Get model from policy config or tool config
        model = policy_config.get("model", "gpt-4")
        if tool_config and "metadata" in tool_config:
            model = tool_config["metadata"].get("model", model)
        
        # Estimate costs
        estimated_llm_cost = estimate_request_cost(raw_text, model)
        estimated_purchase = get_purchase_amount(tool_config)
        
        # Only check budget if there's a purchase amount or if LLM cost is significant
        if estimated_purchase is None and estimated_llm_cost < 0.01:
            # No significant cost - just add budget info without blocking
            return None
        
        # Check budget using context from request
        budget_status, budget_info = check_budget_with_context(budget_context, estimated_llm_cost, estimated_purchase)
        
        # Determine decision based on budget
        if not budget_status.allowed:
            # Budget exceeded - deny the request
            return {
                "decision": "deny",
                "raw_text_out": raw_text,
                "reasons": ["budget_exceeded"],
                "policy_id": "budget-check",
                "ts": now,
                "budget_status": budget_status,
                "budget_info": budget_info
            }
        elif budget_status.reason == "budget_warning":
            # Budget warning - require confirmation
            return {
                "decision": "confirm",
                "raw_text_out": raw_text,
                "reasons": ["budget_warning"],
                "policy_id": "budget-check",
                "ts": now,
                "budget_status": budget_status,
                "budget_info": budget_info
            }
        else:
            # Budget OK - allow but include budget info
            # Note: We don't return here, let the normal policy flow continue
            # The budget info will be added to the final result
            return None
            
    except Exception as e:
        # If budget checking fails, log error but don't block the request
        print(f"Budget check failed: {e}")
        return None

def _add_budget_info_to_result(result: Dict, user_id: str, tool: str, raw_text: str, tool_config: Dict, policy_config: Dict, budget_context: Optional[Dict]) -> Dict:
    """Add budget information to policy evaluation result"""
    
    try:
        from .budget import estimate_request_cost, get_purchase_amount, check_budget_with_context
        
        # Only add budget info if budget_context is provided
        if not budget_context:
            return result
        
        # Get model from policy config or tool config
        model = policy_config.get("model", "gpt-4")
        if tool_config and "metadata" in tool_config:
            model = tool_config["metadata"].get("model", model)
        
        # Estimate costs
        estimated_llm_cost = estimate_request_cost(raw_text, model)
        estimated_purchase = get_purchase_amount(tool_config)
        
        # Only add budget info if there's a purchase amount or if LLM cost is significant
        if estimated_purchase is None and estimated_llm_cost < 0.01:
            # No significant cost - return result without budget info
            return result
        
        # Check budget using context from request
        budget_status, budget_info = check_budget_with_context(budget_context, estimated_llm_cost, estimated_purchase)
        
        # Add budget info to result
        result["budget_status"] = budget_status
        result["budget_info"] = budget_info
        
        # Add budget-related reasons
        if "reasons" not in result:
            result["reasons"] = []
        
        if budget_status.reason == "budget_ok":
            result["reasons"].append("budget_check_passed")
        elif budget_status.reason == "budget_warning":
            result["reasons"].append("budget_warning")
        elif budget_status.reason == "budget_exceeded":
            result["reasons"].append("budget_exceeded")
        
        return result
        
    except Exception as e:
        # If budget checking fails, return result without budget info
        print(f"Failed to add budget info: {e}")
        return result