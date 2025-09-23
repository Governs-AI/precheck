import pytest
import httpx
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    """Test health check endpoint"""
    response = client.get("/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["service"] == "governsai-precheck"
    assert "version" in data

def test_precheck_missing_api_key():
    """Test precheck endpoint without API key"""
    response = client.post("/u/testuser/v1/precheck", json={
        "tool": "web.fetch",
        "payload": {"url": "https://example.com"}
    })
    assert response.status_code == 401
    assert "missing api key" in response.json()["detail"]

def test_precheck_invalid_api_key():
    """Test precheck endpoint with invalid API key"""
    response = client.post("/u/testuser/v1/precheck", 
        json={"tool": "web.fetch", "payload": {"url": "https://example.com"}},
        headers={"X-Governs-Key": "invalid_key"}
    )
    assert response.status_code == 401
    assert "invalid api key" in response.json()["detail"]

def test_precheck_allow_tool():
    """Test precheck with allowed tool"""
    response = client.post("/u/testuser/v1/precheck",
        json={"tool": "web.fetch", "payload": {"url": "https://example.com"}},
        headers={"X-Governs-Key": "GAI_LOCAL_DEV_ABC"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "transform"  # Should transform due to web. prefix
    assert "payload" in data
    assert "policy_id" in data

def test_precheck_deny_exec_tool():
    """Test precheck with denied execution tool"""
    response = client.post("/u/testuser/v1/precheck",
        json={"tool": "python.exec", "payload": {"code": "print('hello')"}},
        headers={"X-Governs-Key": "GAI_LOCAL_DEV_ABC"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "deny"
    assert "blocked tool: code/exec" in data["reasons"]

def test_precheck_pii_redaction():
    """Test PII redaction in payload"""
    response = client.post("/u/testuser/v1/precheck",
        json={
            "tool": "web.fetch",
            "scope": "net.external",
            "payload": {
                "url": "https://example.com",
                "email": "test@example.com",
                "phone": "+1-555-123-4567",
                "data": "Contact us at support@company.com or call +1-800-555-0199"
            }
        },
        headers={"X-Governs-Key": "GAI_LOCAL_DEV_ABC"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "transform"
    assert "payload" in data
    
    # Check that PII was redacted
    payload = data["payload"]
    assert "email" in payload
    assert payload["email"] != "test@example.com"  # Should be redacted
    assert "phone" in payload
    assert payload["phone"] != "+1-555-123-4567"  # Should be redacted

def test_precheck_sensitive_field_redaction():
    """Test redaction of sensitive field names"""
    response = client.post("/u/testuser/v1/precheck",
        json={
            "tool": "web.fetch",
            "payload": {
                "url": "https://example.com",
                "api_key": "sk-1234567890abcdef",
                "secret": "my-secret-value",
                "normal_field": "this should not be redacted"
            }
        },
        headers={"X-Governs-Key": "GAI_LOCAL_DEV_ABC"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "transform"
    
    payload = data["payload"]
    assert payload["api_key"] == "[REDACTED]"
    assert payload["secret"] == "[REDACTED]"
    assert payload["normal_field"] == "this should not be redacted"

def test_precheck_allow_safe_tool():
    """Test precheck with safe tool that should be allowed"""
    response = client.post("/u/testuser/v1/precheck",
        json={"tool": "math.calculate", "payload": {"expression": "2 + 2"}},
        headers={"X-Governs-Key": "GAI_LOCAL_DEV_ABC"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"
    assert data["payload"] == {"expression": "2 + 2"}

def test_postcheck_endpoint():
    """Test postcheck endpoint"""
    response = client.post("/u/testuser/v1/postcheck",
        json={"tool": "web.fetch", "payload": {"url": "https://example.com"}},
        headers={"X-Governs-Key": "GAI_LOCAL_DEV_ABC"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "decision" in data
    assert "ts" in data
