from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, field_validator


class SecretType(str, Enum):
    TEXT = "text"
    CODE = "code"
    MARKDOWN = "markdown"
    API_KEY = "api_key"
    PASSWORD = "password"
    ENV = "env"
    JSON = "json"
    FILE = "file"


class SecretStatusEnum(str, Enum):
    ACTIVE = "active"
    LOCKED = "locked"
    REVOKED = "revoked"
    EXPIRED = "expired"
    BURNED = "burned"
    SUSPICIOUS = "suspicious"


# Allows up to ~15MB encrypted files + JSON metadata after base64 overhead
MAX_CIPHERTEXT_LENGTH = 20_000_000
MIN_EXPIRATION = 60              # 1 minute (for fast test/demo)
MAX_EXPIRATION = 604_800         # 7 days (max in UI)


class SecretCreate(BaseModel):
    ciphertext: str = Field(..., min_length=1)
    iv: str = Field(..., min_length=1)
    secret_type: SecretType
    expires_in_seconds: int = Field(..., ge=MIN_EXPIRATION, le=MAX_EXPIRATION)
    one_time: bool = False
    max_views: int = Field(default=1, ge=1, le=100)
    password_protected: bool = False
    password_salt: str | None = None
    password_verifier: str | None = None
    file_name: str | None = None
    file_size: int | None = None
    file_type: str | None = None
    device_binding_hash: str | None = None

    @field_validator("ciphertext")
    @classmethod
    def check_size(cls, v: str) -> str:
        if len(v) > MAX_CIPHERTEXT_LENGTH:
            raise ValueError(f"Ciphertext too large (max {MAX_CIPHERTEXT_LENGTH} chars)")
        return v

    def model_post_init(self, __context) -> None:
        if self.one_time:
            self.max_views = 1
        if self.password_protected and (not self.password_salt or not self.password_verifier):
            raise ValueError("password_salt and password_verifier required when password_protected is true")


class SecretCreateResponse(BaseModel):
    id: str
    expires_at: datetime
    creator_token: str


class SecretResponse(BaseModel):
    ciphertext: str
    iv: str
    secret_type: SecretType
    expires_at: datetime
    one_time: bool
    max_views: int
    view_count: int
    access_attempt_count: int = 0
    successful_view_count: int = 0
    failed_attempts: int = 0
    is_locked: bool = False
    password_protected: bool
    password_salt: str | None = None
    password_verifier: str | None = None
    file_name: str | None = None
    file_size: int | None = None
    file_type: str | None = None
    status: SecretStatusEnum = SecretStatusEnum.ACTIVE
    has_anomaly: bool = False
    has_suspicious_activity: bool = False
    suspicious_reason: str | None = None


class SecretEventResponse(BaseModel):
    id: int
    secret_id: str
    event_type: str
    status: str
    detail: str | None = None
    client_env: str | None = None
    created_at: datetime


class SecretActivityResponse(BaseModel):
    id: str
    secret_type: SecretType
    created_at: datetime
    expires_at: datetime
    one_time: bool
    max_views: int
    view_count: int
    access_attempt_count: int = 0
    successful_view_count: int = 0
    failed_attempts: int = 0
    destroyed: bool
    is_locked: bool = False
    is_expired: bool
    status: SecretStatusEnum
    has_anomaly: bool
    anomaly_reason: str | None = None
    has_suspicious_activity: bool = False
    suspicious_reason: str | None = None
    last_accessed_at: datetime | None = None
    file_name: str | None = None
    file_size: int | None = None


class SecretRevokeRequest(BaseModel):
    creator_token: str


class SecretLockRequest(BaseModel):
    creator_token: str
    lock: bool = True


class SecretSettingsUpdateRequest(BaseModel):
    creator_token: str
    max_views: int | None = Field(default=None, ge=1, le=100)
    expires_in_seconds: int | None = Field(default=None, ge=MIN_EXPIRATION, le=MAX_EXPIRATION)
    one_time: bool | None = None


class SecretMineRequest(BaseModel):
    creator_tokens: list[str]


class EmergencyRevokeRequest(BaseModel):
    creator_tokens: list[str]


class FailedAttemptRequest(BaseModel):
    client_env: str | None = None
    reason: str | None = None


class DashboardOverviewResponse(BaseModel):
    active_secrets: int
    total_views: int
    failed_attempts: int
    suspicious_events: int
    secrets: list[SecretActivityResponse]
    recent_events: list[SecretEventResponse]


class ErrorResponse(BaseModel):
    detail: str

