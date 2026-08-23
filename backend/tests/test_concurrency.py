import asyncio
from httpx import ASGITransport, AsyncClient
from app.db.session import get_db
from app.main import app


async def test_one_time_secret_concurrency(db_session):
    """Simulate two simultaneous requests consuming the same one-time secret."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create a one-time secret
        create_res = await client.post(
            "/api/secrets",
            json={
                "ciphertext": "Y29uY3VycmVudF9zZWNyZXQ=",
                "iv": "aXYxMjM0NTY3OA==",
                "secret_type": "text",
                "expires_in_seconds": 3600,
                "one_time": True,
            },
        )
        assert create_res.status_code == 201
        secret_id = create_res.json()["id"]

        # Concurrently issue two consume requests
        res1, res2 = await asyncio.gather(
            client.post(f"/api/secrets/{secret_id}/consume"),
            client.post(f"/api/secrets/{secret_id}/consume"),
        )

        status_codes = {res1.status_code, res2.status_code}
        # One request must succeed (200) and the other must fail (410)
        assert status_codes == {200, 410}

    app.dependency_overrides.clear()
