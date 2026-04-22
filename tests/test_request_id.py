import re

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def test_health_has_request_id():
    response = client.get("/api/v1/health")

    assert "x-request-id" in response.headers
    assert UUID4_RE.match(response.headers["x-request-id"])


def test_request_id_is_unique_per_request():
    r1 = client.get("/api/v1/health")
    r2 = client.get("/api/v1/health")

    assert r1.headers["x-request-id"] != r2.headers["x-request-id"]
