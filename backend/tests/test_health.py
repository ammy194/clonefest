"""
Tests for the health endpoint.

These verify the most basic functionality: the server is running
and can respond to HTTP requests.
"""


async def test_health_returns_200(client):
    """GET /api/health should return 200 with status ok."""
    response = await client.get("/api/health")
    assert response.status_code == 200


async def test_health_returns_ok_status(client):
    """GET /api/health response body should contain status: ok."""
    response = await client.get("/api/health")
    data = response.json()
    assert data == {"status": "ok"}


async def test_health_is_get_only(client):
    """POST /api/health should not be allowed (405 Method Not Allowed)."""
    response = await client.post("/api/health")
    assert response.status_code == 405
