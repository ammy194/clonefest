from datetime import datetime, timedelta, timezone
from app.models.secret import Secret


def valid_payload(**overrides) -> dict:
    base = {
        "ciphertext": "dGVzdCBjaXBoZXJ0ZXh0",
        "iv": "dGVzdGl2MTIzNDU2",
        "secret_type": "text",
        "expires_in_seconds": 3600,
        "one_time": False,
        "password_protected": False,
    }
    base.update(overrides)
    return base


async def test_create_secret_success(client):
    response = await client.post("/api/secrets", json=valid_payload())
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert "expires_at" in data
    assert len(data["id"]) > 20


async def test_create_secret_one_time(client):
    response = await client.post("/api/secrets", json=valid_payload(one_time=True))
    assert response.status_code == 201


async def test_create_secret_password_protected(client):
    response = await client.post(
        "/api/secrets",
        json=valid_payload(
            password_protected=True,
            password_salt="c29tZXNhbHQ=",
            password_verifier="c29tZXZlcmlmaWVy",
        ),
    )
    assert response.status_code == 201


async def test_create_secret_invalid_type(client):
    response = await client.post("/api/secrets", json=valid_payload(secret_type="invalid_type"))
    assert response.status_code == 422


async def test_create_secret_negative_expiration(client):
    response = await client.post("/api/secrets", json=valid_payload(expires_in_seconds=-100))
    assert response.status_code == 422


async def test_create_secret_zero_expiration(client):
    response = await client.post("/api/secrets", json=valid_payload(expires_in_seconds=0))
    assert response.status_code == 422


async def test_create_secret_excessive_expiration(client):
    response = await client.post("/api/secrets", json=valid_payload(expires_in_seconds=999999))
    assert response.status_code == 422


async def test_create_secret_missing_ciphertext(client):
    payload = valid_payload()
    del payload["ciphertext"]
    response = await client.post("/api/secrets", json=payload)
    assert response.status_code == 422


async def test_create_secret_missing_iv(client):
    payload = valid_payload()
    del payload["iv"]
    response = await client.post("/api/secrets", json=payload)
    assert response.status_code == 422


async def test_create_secret_oversized_ciphertext(client):
    huge = "A" * 20_000_001
    response = await client.post("/api/secrets", json=valid_payload(ciphertext=huge))
    assert response.status_code == 422


async def test_create_secret_password_protected_missing_salt(client):
    response = await client.post(
        "/api/secrets",
        json=valid_payload(password_protected=True, password_verifier="c29tZXZlcmlmaWVy"),
    )
    assert response.status_code == 422


async def test_create_secret_all_types(client):
    for secret_type in ["text", "api_key", "password", "env", "json"]:
        response = await client.post("/api/secrets", json=valid_payload(secret_type=secret_type))
        assert response.status_code == 201, f"Failed for type: {secret_type}"


async def test_get_secret_success(client):
    create_resp = await client.post("/api/secrets", json=valid_payload())
    secret_id = create_resp.json()["id"]

    response = await client.get(f"/api/secrets/{secret_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["ciphertext"] == "dGVzdCBjaXBoZXJ0ZXh0"
    assert data["iv"] == "dGVzdGl2MTIzNDU2"
    assert data["secret_type"] == "text"
    assert data["one_time"] is False
    assert data["password_protected"] is False


async def test_get_secret_nonexistent(client):
    response = await client.get("/api/secrets/nonexistent_id_12345")
    assert response.status_code == 404


async def test_get_secret_expired(client, db_session):
    secret = Secret(
        id="expired_test_id",
        ciphertext="dGVzdA==",
        iv="dGVzdGl2",
        secret_type="text",
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        one_time=False,
        destroyed=False,
        password_protected=False,
        created_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    db_session.add(secret)
    await db_session.commit()

    response = await client.get("/api/secrets/expired_test_id")
    assert response.status_code == 410
    assert "expired" in response.json()["detail"].lower()


async def test_consume_secret_success(client):
    create_resp = await client.post("/api/secrets", json=valid_payload(one_time=True))
    secret_id = create_resp.json()["id"]

    consume_resp = await client.post(f"/api/secrets/{secret_id}/consume")
    assert consume_resp.status_code == 200
    assert consume_resp.json()["ciphertext"] == "dGVzdCBjaXBoZXJ0ZXh0"


async def test_consume_secret_double_consumption(client):
    create_resp = await client.post("/api/secrets", json=valid_payload(one_time=True))
    secret_id = create_resp.json()["id"]

    resp1 = await client.post(f"/api/secrets/{secret_id}/consume")
    assert resp1.status_code == 200

    resp2 = await client.post(f"/api/secrets/{secret_id}/consume")
    assert resp2.status_code == 410


async def test_consume_nonexistent_secret(client):
    response = await client.post("/api/secrets/does_not_exist/consume")
    assert response.status_code == 404


async def test_consume_already_destroyed(client):
    create_resp = await client.post("/api/secrets", json=valid_payload())
    secret_id = create_resp.json()["id"]
    await client.delete(f"/api/secrets/{secret_id}")

    response = await client.post(f"/api/secrets/{secret_id}/consume")
    assert response.status_code == 410


async def test_destroy_secret_success(client):
    create_resp = await client.post("/api/secrets", json=valid_payload())
    secret_id = create_resp.json()["id"]

    response = await client.delete(f"/api/secrets/{secret_id}")
    assert response.status_code == 204

    get_resp = await client.get(f"/api/secrets/{secret_id}")
    assert get_resp.status_code == 410


async def test_destroy_nonexistent_secret(client):
    response = await client.delete("/api/secrets/does_not_exist")
    assert response.status_code == 404


async def test_destroy_already_destroyed(client):
    create_resp = await client.post("/api/secrets", json=valid_payload())
    secret_id = create_resp.json()["id"]
    await client.delete(f"/api/secrets/{secret_id}")

    response = await client.delete(f"/api/secrets/{secret_id}")
    assert response.status_code == 410


async def test_create_response_no_encryption_key(client):
    response = await client.post("/api/secrets", json=valid_payload())
    data = response.json()
    assert set(data.keys()) == {"id", "expires_at", "creator_token"}
    assert "key" not in data


async def test_get_response_returns_ciphertext_not_plaintext(client):
    create_resp = await client.post("/api/secrets", json=valid_payload())
    secret_id = create_resp.json()["id"]

    response = await client.get(f"/api/secrets/{secret_id}")
    data = response.json()
    assert data["ciphertext"] == "dGVzdCBjaXBoZXJ0ZXh0"
    assert "plaintext" not in data


async def test_rate_limiting_trigger(client):
    for _ in range(10):
        res = await client.post("/api/secrets", json=valid_payload())
        assert res.status_code == 201

    # 11th request in same window should trigger 429
    res_limit = await client.post("/api/secrets", json=valid_payload())
    assert res_limit.status_code == 429


async def test_access_attempt_and_view_counting(client):
    create_resp = await client.post("/api/secrets", json=valid_payload(max_views=5))
    assert create_resp.status_code == 201
    secret_id = create_resp.json()["id"]

    # Initial GET should increment access_attempt_count
    get_resp = await client.get(f"/api/secrets/{secret_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["access_attempt_count"] == 1
    assert data["view_count"] == 0
    assert data["successful_view_count"] == 0

    # Consume should increment view_count and successful_view_count
    consume_resp = await client.post(f"/api/secrets/{secret_id}/consume")
    assert consume_resp.status_code == 200
    consume_data = consume_resp.json()
    assert consume_data["view_count"] == 1
    assert consume_data["successful_view_count"] == 1


async def test_failed_attempt_and_suspicious_activity_detection(client):
    create_resp = await client.post("/api/secrets", json=valid_payload())
    secret_id = create_resp.json()["id"]
    creator_token = create_resp.json()["creator_token"]

    # Report 2 failed attempts
    await client.post(f"/api/secrets/{secret_id}/failed-attempt", json={"reason": "Wrong password"})
    await client.post(f"/api/secrets/{secret_id}/failed-attempt", json={"reason": "Wrong password"})

    get_resp = await client.get(f"/api/secrets/{secret_id}")
    assert get_resp.json()["failed_attempts"] == 2
    assert get_resp.json()["has_suspicious_activity"] is False

    # 3rd failed attempt should trigger suspicious activity
    await client.post(f"/api/secrets/{secret_id}/failed-attempt", json={"reason": "Wrong password"})

    get_resp_after = await client.get(f"/api/secrets/{secret_id}")
    assert get_resp_after.json()["failed_attempts"] == 3
    assert get_resp_after.json()["has_suspicious_activity"] is True
    assert get_resp_after.json()["status"] == "suspicious"


async def test_lock_and_unlock_secret(client):
    create_resp = await client.post("/api/secrets", json=valid_payload())
    secret_id = create_resp.json()["id"]
    creator_token = create_resp.json()["creator_token"]

    # Lock the secret
    lock_resp = await client.post(f"/api/secrets/{secret_id}/lock", json={"creator_token": creator_token, "lock": True})
    assert lock_resp.status_code == 200
    assert lock_resp.json()["status"] == "locked"

    # Accessing locked secret should return 423
    get_locked = await client.get(f"/api/secrets/{secret_id}")
    assert get_locked.status_code == 423

    # Consuming locked secret should return 423
    consume_locked = await client.post(f"/api/secrets/{secret_id}/consume")
    assert consume_locked.status_code == 423

    # Unlock the secret
    unlock_resp = await client.post(f"/api/secrets/{secret_id}/lock", json={"creator_token": creator_token, "lock": False})
    assert unlock_resp.status_code == 200
    assert unlock_resp.json()["status"] == "unlocked"

    # Accessing unlocked secret should succeed
    get_unlocked = await client.get(f"/api/secrets/{secret_id}")
    assert get_unlocked.status_code == 200


async def test_update_secret_settings(client):
    create_resp = await client.post("/api/secrets", json=valid_payload(max_views=3, expires_in_seconds=3600))
    secret_id = create_resp.json()["id"]
    creator_token = create_resp.json()["creator_token"]

    patch_resp = await client.patch(
        f"/api/secrets/{secret_id}",
        json={"creator_token": creator_token, "max_views": 10, "expires_in_seconds": 7200, "one_time": False}
    )
    assert patch_resp.status_code == 200

    get_resp = await client.get(f"/api/secrets/{secret_id}")
    assert get_resp.json()["max_views"] == 10


async def test_security_events_timeline(client):
    create_resp = await client.post("/api/secrets", json=valid_payload())
    secret_id = create_resp.json()["id"]
    creator_token = create_resp.json()["creator_token"]

    # Perform actions
    await client.get(f"/api/secrets/{secret_id}")
    await client.post(f"/api/secrets/{secret_id}/consume")

    # Fetch events timeline
    events_resp = await client.post(f"/api/secrets/{secret_id}/events", json={"creator_token": creator_token})
    assert events_resp.status_code == 200
    events = events_resp.json()
    assert len(events) >= 2
    event_types = [e["event_type"] for e in events]
    assert "created" in event_types
    assert "access_attempt" in event_types


async def test_dashboard_overview(client):
    create1 = await client.post("/api/secrets", json=valid_payload(max_views=2))
    create2 = await client.post("/api/secrets", json=valid_payload(max_views=5))
    t1 = create1.json()["creator_token"]
    t2 = create2.json()["creator_token"]

    # Consume create1
    await client.post(f"/api/secrets/{create1.json()['id']}/consume")

    overview_resp = await client.post("/api/secrets/mine/overview", json={"creator_tokens": [t1, t2]})
    assert overview_resp.status_code == 200
    data = overview_resp.json()
    assert data["active_secrets"] >= 1
    assert data["total_views"] >= 1
    assert len(data["secrets"]) == 2
    assert len(data["recent_events"]) > 0


async def test_emergency_revoke_all(client):
    create1 = await client.post("/api/secrets", json=valid_payload())
    create2 = await client.post("/api/secrets", json=valid_payload())
    t1 = create1.json()["creator_token"]
    t2 = create2.json()["creator_token"]

    revoke_all_resp = await client.post("/api/secrets/emergency-revoke-all", json={"creator_tokens": [t1, t2]})
    assert revoke_all_resp.status_code == 200
    assert revoke_all_resp.json()["revoked_count"] == 2

    # Both should now return 410
    assert (await client.get(f"/api/secrets/{create1.json()['id']}")).status_code == 410
    assert (await client.get(f"/api/secrets/{create2.json()['id']}")).status_code == 410


async def test_views_and_failed_attempts_contract(client):
    """Locks in the exact "Views" / "Failed Attempts" contract the frontend
    relies on (VaultDrop Fix 2): a failed password attempt must never move
    the successful-view counters, and only /consume (called on an actual
    successful decryption) may increment them. access_attempt_count (bumped
    on every GET) is a separate, internal-only metric and must not be
    conflated with "Views".
    """
    create_resp = await client.post("/api/secrets", json=valid_payload(max_views=3))
    assert create_resp.status_code == 201
    secret_id = create_resp.json()["id"]

    # Fresh secret: no views, no failures yet.
    data = (await client.get(f"/api/secrets/{secret_id}")).json()
    assert data["successful_view_count"] == 0
    assert data["view_count"] == 0
    assert data["failed_attempts"] == 0

    # Two wrong-password attempts (this is what the frontend calls when
    # unwrapKeyWithPassword throws) must only bump failed_attempts.
    for _ in range(2):
        fail_resp = await client.post(
            f"/api/secrets/{secret_id}/failed-attempt",
            json={"reason": "Incorrect password attempt"},
        )
        assert fail_resp.status_code == 200

    data = (await client.get(f"/api/secrets/{secret_id}")).json()
    assert data["failed_attempts"] == 2
    assert data["successful_view_count"] == 0
    assert data["view_count"] == 0

    # A successful decryption calls /consume — this is the only thing that
    # should move the Views counters, and it must not touch failed_attempts.
    consume_resp = await client.post(f"/api/secrets/{secret_id}/consume")
    assert consume_resp.status_code == 200
    consume_data = consume_resp.json()
    assert consume_data["successful_view_count"] == 1
    assert consume_data["view_count"] == 1
    assert consume_data["failed_attempts"] == 2

    # A second successful decryption increments Views again.
    consume_resp_2 = await client.post(f"/api/secrets/{secret_id}/consume")
    assert consume_resp_2.status_code == 200
    assert consume_resp_2.json()["successful_view_count"] == 2
    assert consume_resp_2.json()["failed_attempts"] == 2


async def test_max_views_enforced_via_successful_consumes_only(client):
    """max_views must be enforced against successful accesses (consume calls),
    matching how the frontend now drives the Views counter for every secret
    (not just one-time ones). Wrong-password attempts must never consume a
    view slot.
    """
    create_resp = await client.post("/api/secrets", json=valid_payload(max_views=3))
    secret_id = create_resp.json()["id"]

    # Failed attempts must not eat into the view budget (they may still flag
    # the secret as suspicious once >= 3, which is separate, pre-existing
    # behavior unrelated to the view budget itself).
    for _ in range(2):
        await client.post(f"/api/secrets/{secret_id}/failed-attempt", json={"reason": "Wrong password"})
    data = (await client.get(f"/api/secrets/{secret_id}")).json()
    assert data["status"] == "active"
    assert data["successful_view_count"] == 0

    # Three successful accesses are allowed.
    for expected_count in (1, 2, 3):
        resp = await client.post(f"/api/secrets/{secret_id}/consume")
        assert resp.status_code == 200
        assert resp.json()["successful_view_count"] == expected_count

    # The 4th successful access must be blocked (secret burned after limit).
    blocked_resp = await client.post(f"/api/secrets/{secret_id}/consume")
    assert blocked_resp.status_code == 410

    # And a fresh GET after the limit is reached must also be blocked.
    get_after = await client.get(f"/api/secrets/{secret_id}")
    assert get_after.status_code == 410


async def test_unauthorized_creator_token_actions(client):
    create_resp = await client.post("/api/secrets", json=valid_payload())
    secret_id = create_resp.json()["id"]

    # Attempt lock with wrong token
    res1 = await client.post(f"/api/secrets/{secret_id}/lock", json={"creator_token": "wrong_token", "lock": True})
    assert res1.status_code == 401

    # Attempt patch with wrong token
    res2 = await client.patch(f"/api/secrets/{secret_id}", json={"creator_token": "wrong_token", "max_views": 5})
    assert res2.status_code == 401

    # Attempt revoke with wrong token
    res3 = await client.post(f"/api/secrets/{secret_id}/revoke", json={"creator_token": "wrong_token"})
    assert res3.status_code == 401

    # Attempt fetch events with wrong token
    res4 = await client.post(f"/api/secrets/{secret_id}/events", json={"creator_token": "wrong_token"})
    assert res4.status_code == 401

