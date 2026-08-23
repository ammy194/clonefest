from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.rate_limit import create_limiter, retrieve_limiter
from app.db.session import get_db
from app.schemas.secret import (
    DashboardOverviewResponse,
    EmergencyRevokeRequest,
    FailedAttemptRequest,
    SecretActivityResponse,
    SecretCreate,
    SecretCreateResponse,
    SecretEventResponse,
    SecretLockRequest,
    SecretMineRequest,
    SecretResponse,
    SecretRevokeRequest,
    SecretSettingsUpdateRequest,
)
from app.services.secret_service import SecretStatus, compute_secret_status, detect_anomaly, parse_client_env
from app.services import secret_service

router = APIRouter(prefix="/api")


def _raise_for_status(result: SecretStatus) -> None:
    """Map SecretStatus enum to the appropriate HTTP error."""
    if result == SecretStatus.NOT_FOUND:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")
    if result == SecretStatus.EXPIRED:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Secret has expired")
    if result == SecretStatus.DESTROYED:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Secret is no longer available")
    if result == SecretStatus.LOCKED:
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Secret is temporarily locked by owner")


@router.get("/health")
async def health_check():
    return {"status": "ok"}


@router.post("/secrets", response_model=SecretCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_secret(data: SecretCreate, request: Request, db: AsyncSession = Depends(get_db)):
    create_limiter.check(request)
    client_env = parse_client_env(request.headers.get("user-agent"))
    secret, creator_token = await secret_service.create_secret(db, data, client_env=client_env)
    return SecretCreateResponse(
        id=secret.id, 
        expires_at=secret.expires_at, 
        creator_token=creator_token
    )


@router.get("/secrets/{secret_id}", response_model=SecretResponse)
async def get_secret(secret_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    retrieve_limiter.check(request)
    client_env = parse_client_env(request.headers.get("user-agent"))
    result = await secret_service.get_secret(db, secret_id, client_env=client_env)
    if isinstance(result, SecretStatus):
        _raise_for_status(result)

    has_anomaly, _ = detect_anomaly(result)
    status_val = compute_secret_status(result)

    return SecretResponse(
        ciphertext=result.ciphertext, 
        iv=result.iv, 
        secret_type=result.secret_type,
        expires_at=result.expires_at, 
        one_time=result.one_time,
        max_views=result.max_views, 
        view_count=result.view_count,
        access_attempt_count=result.access_attempt_count,
        successful_view_count=result.successful_view_count,
        failed_attempts=result.failed_attempts,
        is_locked=result.is_locked,
        password_protected=result.password_protected,
        password_salt=result.password_salt, 
        password_verifier=result.password_verifier,
        file_name=result.file_name, 
        file_size=result.file_size, 
        file_type=result.file_type,
        status=status_val,
        has_anomaly=has_anomaly,
        has_suspicious_activity=result.has_suspicious_activity,
        suspicious_reason=result.suspicious_reason,
    )


@router.post("/secrets/{secret_id}/consume", response_model=SecretResponse)
async def consume_secret(secret_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    retrieve_limiter.check(request)
    client_env = parse_client_env(request.headers.get("user-agent"))
    result = await secret_service.consume_secret(db, secret_id, client_env=client_env)
    if isinstance(result, SecretStatus):
        _raise_for_status(result)

    has_anomaly, _ = detect_anomaly(result)
    status_val = compute_secret_status(result)

    return SecretResponse(
        ciphertext=result.ciphertext, 
        iv=result.iv, 
        secret_type=result.secret_type,
        expires_at=result.expires_at, 
        one_time=result.one_time,
        max_views=result.max_views, 
        view_count=result.view_count,
        access_attempt_count=result.access_attempt_count,
        successful_view_count=result.successful_view_count,
        failed_attempts=result.failed_attempts,
        is_locked=result.is_locked,
        password_protected=result.password_protected,
        password_salt=result.password_salt, 
        password_verifier=result.password_verifier,
        file_name=result.file_name, 
        file_size=result.file_size, 
        file_type=result.file_type,
        status=status_val,
        has_anomaly=has_anomaly,
        has_suspicious_activity=result.has_suspicious_activity,
        suspicious_reason=result.suspicious_reason,
    )


@router.post("/secrets/{secret_id}/failed-attempt", status_code=status.HTTP_200_OK)
async def record_failed_attempt(secret_id: str, data: FailedAttemptRequest, request: Request, db: AsyncSession = Depends(get_db)):
    retrieve_limiter.check(request)
    client_env = data.client_env or parse_client_env(request.headers.get("user-agent"))
    success = await secret_service.record_failed_attempt(db, secret_id, client_env=client_env, reason=data.reason)
    return {"recorded": success}


@router.delete("/secrets/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
async def destroy_secret(secret_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    client_env = parse_client_env(request.headers.get("user-agent"))
    result = await secret_service.destroy_secret(db, secret_id, client_env=client_env)
    if isinstance(result, SecretStatus):
        _raise_for_status(result)
    return None


@router.post("/secrets/mine", response_model=list[SecretActivityResponse])
async def get_my_secrets(data: SecretMineRequest, request: Request, db: AsyncSession = Depends(get_db)):
    retrieve_limiter.check(request)
    return await secret_service.get_my_secrets(db, data.creator_tokens)


@router.post("/secrets/mine/overview", response_model=DashboardOverviewResponse)
async def get_my_secrets_overview(data: SecretMineRequest, request: Request, db: AsyncSession = Depends(get_db)):
    retrieve_limiter.check(request)
    return await secret_service.get_my_secrets_overview(db, data.creator_tokens)


@router.post("/secrets/{secret_id}/events", response_model=list[SecretEventResponse])
async def get_secret_events(secret_id: str, data: SecretRevokeRequest, request: Request, db: AsyncSession = Depends(get_db)):
    retrieve_limiter.check(request)
    result = await secret_service.get_secret_events(db, secret_id, data.creator_token)
    if isinstance(result, SecretStatus):
        _raise_for_status(result)
    elif result is False:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid creator token")
    return result


@router.post("/secrets/{secret_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_secret(secret_id: str, data: SecretRevokeRequest, request: Request, db: AsyncSession = Depends(get_db)):
    retrieve_limiter.check(request)
    client_env = parse_client_env(request.headers.get("user-agent"))
    result = await secret_service.revoke_secret_by_creator_token(db, secret_id, data.creator_token, client_env=client_env)
    if isinstance(result, SecretStatus):
        _raise_for_status(result)
    elif result is False:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid creator token")
    return None


@router.post("/secrets/{secret_id}/lock", status_code=status.HTTP_200_OK)
async def lock_secret(secret_id: str, data: SecretLockRequest, request: Request, db: AsyncSession = Depends(get_db)):
    retrieve_limiter.check(request)
    client_env = parse_client_env(request.headers.get("user-agent"))
    result = await secret_service.toggle_lock_secret(db, secret_id, data.creator_token, lock=data.lock, client_env=client_env)
    if isinstance(result, SecretStatus):
        _raise_for_status(result)
    elif result is False:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid creator token")
    return {"status": "locked" if data.lock else "unlocked"}


@router.patch("/secrets/{secret_id}", status_code=status.HTTP_200_OK)
async def update_secret_settings(secret_id: str, data: SecretSettingsUpdateRequest, request: Request, db: AsyncSession = Depends(get_db)):
    retrieve_limiter.check(request)
    client_env = parse_client_env(request.headers.get("user-agent"))
    result = await secret_service.update_secret_settings(
        db, 
        secret_id, 
        data.creator_token, 
        max_views=data.max_views, 
        expires_in_seconds=data.expires_in_seconds, 
        one_time=data.one_time,
        client_env=client_env
    )
    if isinstance(result, SecretStatus):
        _raise_for_status(result)
    elif result is False:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid creator token")
    return {"status": "updated"}


@router.post("/secrets/emergency-revoke-all", status_code=status.HTTP_200_OK)
async def emergency_revoke_all_secrets(data: EmergencyRevokeRequest, request: Request, db: AsyncSession = Depends(get_db)):
    retrieve_limiter.check(request)
    client_env = parse_client_env(request.headers.get("user-agent"))
    count = await secret_service.emergency_revoke_all(db, data.creator_tokens, client_env=client_env)
    return {"revoked_count": count}

