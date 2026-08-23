import secrets
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta, timezone
from enum import Enum
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.secret import Secret, SecretEvent
from app.schemas.secret import (
    DashboardOverviewResponse,
    SecretActivityResponse,
    SecretCreate,
    SecretEventResponse,
    SecretStatusEnum,
)


class SecretStatus(str, Enum):
    """Distinguishes between not-found, expired, destroyed, and locked secrets."""
    NOT_FOUND = "not_found"
    EXPIRED = "expired"
    DESTROYED = "destroyed"
    LOCKED = "locked"


def _ensure_utc(dt: datetime) -> datetime:
    """SQLite returns naive datetimes, Postgres returns aware ones. This normalizes both."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def generate_secret_id() -> str:
    """32 random bytes -> base64url = 43 unpredictable characters."""
    return urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def generate_creator_token() -> str:
    """24 random bytes -> base64url = 32 character creator management key."""
    return urlsafe_b64encode(secrets.token_bytes(24)).rstrip(b"=").decode("ascii")


def parse_client_env(user_agent: str | None) -> str:
    """Privacy-preserving client environment parser.
    Extracts high-level browser and platform family without fingerprinting or storing personal data.
    """
    if not user_agent:
        return "Unknown Client"
    ua = user_agent.lower()
    
    # Detect platform
    platform = "Desktop"
    if "iphone" in ua or "ipad" in ua:
        platform = "iOS"
    elif "android" in ua:
        platform = "Android"
    elif "macintosh" in ua or "mac os" in ua:
        platform = "macOS"
    elif "windows" in ua:
        platform = "Windows"
    elif "linux" in ua:
        platform = "Linux"

    # Detect browser
    browser = "Browser"
    if "edg/" in ua or "edge/" in ua:
        browser = "Edge"
    elif "chrome/" in ua and "safari/" in ua and "edg" not in ua:
        browser = "Chrome"
    elif "safari/" in ua and "chrome" not in ua:
        browser = "Safari"
    elif "firefox/" in ua:
        browser = "Firefox"

    return f"{browser} ({platform})"


def compute_secret_status(secret: Secret, now: datetime | None = None) -> SecretStatusEnum:
    """Computes the deterministic status enum for a secret."""
    if now is None:
        now = datetime.now(timezone.utc)
    
    if secret.destroyed:
        if secret.one_time or secret.view_count >= secret.max_views:
            return SecretStatusEnum.BURNED
        return SecretStatusEnum.REVOKED
    
    if secret.is_locked:
        return SecretStatusEnum.LOCKED
        
    if now >= _ensure_utc(secret.expires_at):
        return SecretStatusEnum.EXPIRED
        
    if secret.has_suspicious_activity:
        return SecretStatusEnum.SUSPICIOUS
        
    return SecretStatusEnum.ACTIVE


def detect_anomaly(secret: Secret) -> tuple[bool, str | None]:
    """Lightweight rule-based anomaly detector for security awareness."""
    if secret.has_suspicious_activity:
        return True, secret.suspicious_reason or "Suspicious access patterns detected."
    if secret.failed_attempts >= 3:
        return True, f"Multiple failed access attempts detected ({secret.failed_attempts} attempts)."
    if secret.max_views > 1 and secret.view_count >= secret.max_views:
        return True, "Maximum view limit reached."
    return False, None


async def log_secret_event(
    db: AsyncSession,
    secret_id: str,
    event_type: str,
    status: str = "info",
    detail: str | None = None,
    client_env: str | None = None,
) -> SecretEvent:
    """Logs a security audit timeline event without plaintext or sensitive data."""
    now = datetime.now(timezone.utc)
    event = SecretEvent(
        secret_id=secret_id,
        event_type=event_type,
        status=status,
        detail=detail,
        client_env=client_env,
        created_at=now,
    )
    db.add(event)
    return event


async def create_secret(
    db: AsyncSession, 
    data: SecretCreate, 
    client_env: str | None = None
) -> tuple[Secret, str]:
    now = datetime.now(timezone.utc)
    creator_token = generate_creator_token()
    secret_id = generate_secret_id()
    
    # If one_time is set, max_views is strictly 1
    max_views = 1 if data.one_time else data.max_views

    secret = Secret(
        id=secret_id,
        ciphertext=data.ciphertext,
        iv=data.iv,
        secret_type=data.secret_type.value,
        expires_at=now + timedelta(seconds=data.expires_in_seconds),
        one_time=data.one_time,
        max_views=max_views,
        view_count=0,
        destroyed=False,
        is_locked=False,
        password_protected=data.password_protected,
        password_salt=data.password_salt,
        password_verifier=data.password_verifier,
        file_name=data.file_name,
        file_size=data.file_size,
        file_type=data.file_type,
        creator_token=creator_token,
        access_attempt_count=0,
        successful_view_count=0,
        failed_attempts=0,
        has_suspicious_activity=False,
        suspicious_reason=None,
        device_binding_hash=data.device_binding_hash,
        last_client_env=client_env,
        created_at=now,
    )
    db.add(secret)
    await db.flush()

    await log_secret_event(
        db,
        secret_id=secret_id,
        event_type="created",
        status="success",
        detail="Encrypted secret created with client-side zero-knowledge key",
        client_env=client_env,
    )

    await db.commit()
    await db.refresh(secret)
    return secret, creator_token


async def get_secret(
    db: AsyncSession, 
    secret_id: str, 
    client_env: str | None = None
) -> Secret | SecretStatus:
    """Returns the Secret if alive, or a SecretStatus explaining why it's unavailable.
    Records access attempt metrics and audit log.
    """
    now = datetime.now(timezone.utc)
    result = await db.execute(select(Secret).where(Secret.id == secret_id))
    secret = result.scalar_one_or_none()

    if secret is None:
        return SecretStatus.NOT_FOUND

    # Increment access attempt counter
    secret.access_attempt_count += 1
    secret.last_accessed_at = now
    if client_env:
        secret.last_client_env = client_env

    # Check destroyed
    if secret.destroyed:
        await log_secret_event(
            db,
            secret_id=secret_id,
            event_type="access_attempt",
            status="warning",
            detail="Access attempt on destroyed/burned secret",
            client_env=client_env,
        )
        # Repeated access to destroyed secret triggers suspicious flag
        if secret.access_attempt_count > (secret.successful_view_count + 2):
            secret.has_suspicious_activity = True
            secret.suspicious_reason = "Repeated access attempts on burned/destroyed secret."
            await log_secret_event(
                db,
                secret_id=secret_id,
                event_type="suspicious_activity",
                status="warning",
                detail="Multiple access attempts after secret was already burned",
                client_env=client_env,
            )
        await db.commit()
        return SecretStatus.DESTROYED

    # Check expired
    if now >= _ensure_utc(secret.expires_at):
        await log_secret_event(
            db,
            secret_id=secret_id,
            event_type="access_attempt",
            status="warning",
            detail="Access attempt on expired secret",
            client_env=client_env,
        )
        await db.commit()
        return SecretStatus.EXPIRED

    # Check locked
    if secret.is_locked:
        await log_secret_event(
            db,
            secret_id=secret_id,
            event_type="access_attempt",
            status="warning",
            detail="Access attempt blocked: Secret is locked by owner",
            client_env=client_env,
        )
        await db.commit()
        return SecretStatus.LOCKED

    # Check max views
    if secret.view_count >= secret.max_views:
        secret.destroyed = True
        await log_secret_event(
            db,
            secret_id=secret_id,
            event_type="burned",
            status="info",
            detail="Secret view limit reached",
            client_env=client_env,
        )
        await db.commit()
        return SecretStatus.DESTROYED

    # Normal valid access attempt
    await log_secret_event(
        db,
        secret_id=secret_id,
        event_type="access_attempt",
        status="info",
        detail="Secret link accessed and ciphertext retrieved",
        client_env=client_env,
    )
    await db.commit()
    await db.refresh(secret)
    return secret


async def consume_secret(
    db: AsyncSession, 
    secret_id: str, 
    client_env: str | None = None
) -> Secret | SecretStatus:
    """Atomically consume a secret view. Uses SELECT FOR UPDATE on Postgres to prevent race conditions."""
    now = datetime.now(timezone.utc)

    try:
        result = await db.execute(
            select(Secret).where(Secret.id == secret_id).with_for_update()
        )
    except Exception:
        # SQLite fallback (no FOR UPDATE support)
        result = await db.execute(select(Secret).where(Secret.id == secret_id))

    secret = result.scalar_one_or_none()

    if secret is None:
        return SecretStatus.NOT_FOUND
    if secret.destroyed:
        return SecretStatus.DESTROYED
    if secret.is_locked:
        return SecretStatus.LOCKED
    if now >= _ensure_utc(secret.expires_at):
        return SecretStatus.EXPIRED
    if secret.view_count >= secret.max_views:
        secret.destroyed = True
        await db.commit()
        return SecretStatus.DESTROYED

    # Increment atomic view count and successful views
    secret.view_count += 1
    secret.successful_view_count += 1
    secret.last_accessed_at = now
    if secret.viewed_at is None:
        secret.viewed_at = now
    if client_env:
        secret.last_client_env = client_env

    # Log successful decryption view event
    view_detail = f"Successfully decrypted in browser ({secret.view_count}/{secret.max_views} views)"
    if secret.one_time:
        view_detail = "Successfully decrypted in browser (one-time secret consumed)"

    await log_secret_event(
        db,
        secret_id=secret_id,
        event_type="view_success",
        status="success",
        detail=view_detail,
        client_env=client_env,
    )

    # Destroy if view limit reached or one_time
    if secret.one_time or secret.view_count >= secret.max_views:
        secret.destroyed = True
        await log_secret_event(
            db,
            secret_id=secret_id,
            event_type="burned",
            status="info",
            detail="Secret permanently burned after reading",
            client_env=client_env,
        )

    await db.commit()
    await db.refresh(secret)
    return secret


async def record_failed_attempt(
    db: AsyncSession, 
    secret_id: str, 
    client_env: str | None = None,
    reason: str | None = None
) -> bool:
    """Increments failed attempts counter and triggers suspicious activity detection."""
    now = datetime.now(timezone.utc)
    result = await db.execute(select(Secret).where(Secret.id == secret_id))
    secret = result.scalar_one_or_none()

    if secret is None or secret.destroyed:
        return False

    secret.failed_attempts += 1
    secret.last_accessed_at = now
    if client_env:
        secret.last_client_env = client_env

    fail_detail = reason or "Failed password attempt or decryption error"
    await log_secret_event(
        db,
        secret_id=secret_id,
        event_type="failed_attempt",
        status="failure",
        detail=f"{fail_detail} (Attempt #{secret.failed_attempts})",
        client_env=client_env,
    )

    # Trigger suspicious activity alert if >= 3 failed attempts
    if secret.failed_attempts >= 3:
        secret.has_suspicious_activity = True
        secret.suspicious_reason = f"Multiple failed access attempts detected ({secret.failed_attempts} attempts within a short period)."
        await log_secret_event(
            db,
            secret_id=secret_id,
            event_type="suspicious_activity",
            status="warning",
            detail=f"Suspicious activity alert: {secret.failed_attempts} failed attempts detected",
            client_env=client_env,
        )

    await db.commit()
    return True


async def destroy_secret(
    db: AsyncSession, 
    secret_id: str,
    client_env: str | None = None
) -> SecretStatus | bool:
    """Permanently marks a secret as destroyed."""
    now = datetime.now(timezone.utc)
    result = await db.execute(select(Secret).where(Secret.id == secret_id))
    secret = result.scalar_one_or_none()

    if secret is None:
        return SecretStatus.NOT_FOUND

    if secret.destroyed:
        return SecretStatus.DESTROYED

    if now >= _ensure_utc(secret.expires_at):
        return SecretStatus.EXPIRED

    secret.destroyed = True
    secret.viewed_at = now
    await log_secret_event(
        db,
        secret_id=secret_id,
        event_type="burned",
        status="info",
        detail="Secret permanently destroyed by recipient or manual deletion",
        client_env=client_env,
    )
    await db.commit()
    return True


async def revoke_secret_by_creator_token(
    db: AsyncSession, 
    secret_id: str, 
    creator_token: str,
    client_env: str | None = None
) -> SecretStatus | bool:
    """Revokes a secret using the creator's secret token."""
    result = await db.execute(select(Secret).where(Secret.id == secret_id))
    secret = result.scalar_one_or_none()

    if secret is None:
        return SecretStatus.NOT_FOUND

    if secret.creator_token != creator_token:
        return False  # Unauthorized

    if secret.destroyed:
        return SecretStatus.DESTROYED

    secret.destroyed = True
    await log_secret_event(
        db,
        secret_id=secret_id,
        event_type="revoked",
        status="warning",
        detail="Secret revoked by owner via creator token",
        client_env=client_env,
    )
    await db.commit()
    return True


async def toggle_lock_secret(
    db: AsyncSession,
    secret_id: str,
    creator_token: str,
    lock: bool,
    client_env: str | None = None
) -> SecretStatus | bool:
    """Locks or unlocks a secret using the creator token."""
    result = await db.execute(select(Secret).where(Secret.id == secret_id))
    secret = result.scalar_one_or_none()

    if secret is None:
        return SecretStatus.NOT_FOUND

    if secret.creator_token != creator_token:
        return False  # Unauthorized

    if secret.destroyed:
        return SecretStatus.DESTROYED

    secret.is_locked = lock
    event_type = "locked" if lock else "unlocked"
    detail = "Secret locked by owner (access temporarily blocked)" if lock else "Secret unlocked by owner (access restored)"
    
    await log_secret_event(
        db,
        secret_id=secret_id,
        event_type=event_type,
        status="warning" if lock else "info",
        detail=detail,
        client_env=client_env,
    )
    await db.commit()
    return True


async def update_secret_settings(
    db: AsyncSession,
    secret_id: str,
    creator_token: str,
    max_views: int | None = None,
    expires_in_seconds: int | None = None,
    one_time: bool | None = None,
    client_env: str | None = None
) -> SecretStatus | bool:
    """Updates allowable views or expiration for an active secret."""
    now = datetime.now(timezone.utc)
    result = await db.execute(select(Secret).where(Secret.id == secret_id))
    secret = result.scalar_one_or_none()

    if secret is None:
        return SecretStatus.NOT_FOUND

    if secret.creator_token != creator_token:
        return False  # Unauthorized

    if secret.destroyed:
        return SecretStatus.DESTROYED

    if now >= _ensure_utc(secret.expires_at):
        return SecretStatus.EXPIRED

    changes = []
    if one_time is not None:
        secret.one_time = one_time
        if one_time:
            secret.max_views = 1
            changes.append("enabled burn-after-reading")
        else:
            changes.append("disabled burn-after-reading")

    if max_views is not None and not secret.one_time:
        secret.max_views = max_views
        changes.append(f"updated max views to {max_views}")

    if expires_in_seconds is not None:
        secret.expires_at = now + timedelta(seconds=expires_in_seconds)
        changes.append(f"updated expiration (+{expires_in_seconds}s)")

    if changes:
        await log_secret_event(
            db,
            secret_id=secret_id,
            event_type="settings_updated",
            status="info",
            detail=f"Security settings updated by owner: {', '.join(changes)}",
            client_env=client_env,
        )

    await db.commit()
    return True


async def emergency_revoke_all(
    db: AsyncSession,
    creator_tokens: list[str],
    client_env: str | None = None
) -> int:
    """Emergency lockdown: Revokes all active secrets belonging to the provided creator tokens."""
    if not creator_tokens:
        return 0

    result = await db.execute(
        select(Secret).where(
            Secret.creator_token.in_(creator_tokens),
            Secret.destroyed == False,  # noqa: E712
        )
    )
    active_secrets = result.scalars().all()
    count = 0

    for secret in active_secrets:
        secret.destroyed = True
        await log_secret_event(
            db,
            secret_id=secret.id,
            event_type="revoked",
            status="warning",
            detail="Emergency lockdown: Secret revoked during bulk revocation",
            client_env=client_env,
        )
        count += 1

    await db.commit()
    return count


def _build_activity_response(secret: Secret, now: datetime) -> SecretActivityResponse:
    is_expired = now >= _ensure_utc(secret.expires_at)
    has_anomaly, anomaly_reason = detect_anomaly(secret)
    status = compute_secret_status(secret, now)

    return SecretActivityResponse(
        id=secret.id,
        secret_type=secret.secret_type,
        created_at=secret.created_at,
        expires_at=secret.expires_at,
        one_time=secret.one_time,
        max_views=secret.max_views,
        view_count=secret.view_count,
        access_attempt_count=secret.access_attempt_count,
        successful_view_count=secret.successful_view_count,
        failed_attempts=secret.failed_attempts,
        destroyed=secret.destroyed,
        is_locked=secret.is_locked,
        is_expired=is_expired,
        status=status,
        has_anomaly=has_anomaly,
        anomaly_reason=anomaly_reason,
        has_suspicious_activity=secret.has_suspicious_activity,
        suspicious_reason=secret.suspicious_reason,
        last_accessed_at=secret.last_accessed_at,
        file_name=secret.file_name,
        file_size=secret.file_size,
    )


async def get_my_secrets(
    db: AsyncSession, 
    creator_tokens: list[str]
) -> list[SecretActivityResponse]:
    """Returns activity responses for all secrets matching the given creator tokens."""
    if not creator_tokens:
        return []

    result = await db.execute(
        select(Secret).where(Secret.creator_token.in_(creator_tokens)).order_by(Secret.created_at.desc())
    )
    secrets_list = result.scalars().all()

    now = datetime.now(timezone.utc)
    return [_build_activity_response(secret, now) for secret in secrets_list]


async def get_my_secrets_overview(
    db: AsyncSession,
    creator_tokens: list[str]
) -> DashboardOverviewResponse:
    """Returns comprehensive dashboard overview including statistics, secret cards, and recent events."""
    if not creator_tokens:
        return DashboardOverviewResponse(
            active_secrets=0,
            total_views=0,
            failed_attempts=0,
            suspicious_events=0,
            secrets=[],
            recent_events=[],
        )

    result = await db.execute(
        select(Secret).where(Secret.creator_token.in_(creator_tokens)).order_by(Secret.created_at.desc())
    )
    secrets_list = result.scalars().all()
    secret_ids = [s.id for s in secrets_list]

    now = datetime.now(timezone.utc)
    activities = [_build_activity_response(s, now) for s in secrets_list]

    # Calculate overview cards
    active_count = sum(1 for a in activities if a.status == SecretStatusEnum.ACTIVE)
    total_views = sum(s.successful_view_count or s.view_count for s in secrets_list)
    failed_attempts = sum(s.failed_attempts for s in secrets_list)
    suspicious_count = sum(1 for s in secrets_list if s.has_suspicious_activity)

    # Fetch recent events for these secrets
    recent_events: list[SecretEventResponse] = []
    if secret_ids:
        events_result = await db.execute(
            select(SecretEvent)
            .where(SecretEvent.secret_id.in_(secret_ids))
            .order_by(SecretEvent.created_at.desc())
            .limit(50)
        )
        events_list = events_result.scalars().all()
        recent_events = [
            SecretEventResponse(
                id=e.id,
                secret_id=e.secret_id,
                event_type=e.event_type,
                status=e.status,
                detail=e.detail,
                client_env=e.client_env,
                created_at=e.created_at,
            )
            for e in events_list
        ]

    return DashboardOverviewResponse(
        active_secrets=active_count,
        total_views=total_views,
        failed_attempts=failed_attempts,
        suspicious_events=suspicious_count,
        secrets=activities,
        recent_events=recent_events,
    )


async def get_secret_events(
    db: AsyncSession,
    secret_id: str,
    creator_token: str
) -> list[SecretEventResponse] | SecretStatus | bool:
    """Returns the security audit timeline for a specific secret."""
    result = await db.execute(select(Secret).where(Secret.id == secret_id))
    secret = result.scalar_one_or_none()

    if secret is None:
        return SecretStatus.NOT_FOUND

    if secret.creator_token != creator_token:
        return False  # Unauthorized

    events_result = await db.execute(
        select(SecretEvent)
        .where(SecretEvent.secret_id == secret_id)
        .order_by(SecretEvent.created_at.desc())
    )
    events = events_result.scalars().all()
    return [
        SecretEventResponse(
            id=e.id,
            secret_id=e.secret_id,
            event_type=e.event_type,
            status=e.status,
            detail=e.detail,
            client_env=e.client_env,
            created_at=e.created_at,
        )
        for e in events
    ]


async def cleanup_expired_secrets(db: AsyncSession) -> int:
    """Delete all expired or destroyed secrets and orphaned events. Returns count of deleted rows."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        delete(Secret).where(
            (Secret.expires_at < now) | (Secret.destroyed == True)  # noqa: E712
        )
    )
    await db.commit()
    return result.rowcount or 0

