from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class Secret(Base):
    """Stores encrypted secrets. Never contains plaintext or encryption keys."""

    __tablename__ = "secrets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    iv: Mapped[str] = mapped_column(Text, nullable=False)
    secret_type: Mapped[str] = mapped_column(String(20), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    one_time: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    max_views: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    view_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    destroyed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    password_protected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    password_salt: Mapped[str | None] = mapped_column(Text, nullable=True)
    password_verifier: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Encrypted file metadata (if secret_type == 'file')
    file_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    
    # Creator token for secret management/revocation without accounts
    creator_token: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    
    # Analytics and access counters
    access_attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    successful_view_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    has_suspicious_activity: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    suspicious_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_binding_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_client_env: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_accessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    viewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    events: Mapped[list["SecretEvent"]] = relationship("SecretEvent", back_populates="secret", cascade="all, delete-orphan", order_by="SecretEvent.created_at.desc()")

    __table_args__ = (
        Index("ix_secrets_expires_at", "expires_at"),
    )

    def __repr__(self) -> str:
        return f"<Secret id={self.id!r} type={self.secret_type!r} views={self.view_count}/{self.max_views}>"


class SecretEvent(Base):
    """Stores security audit timeline events for encrypted secrets. Zero plaintext logged."""

    __tablename__ = "secret_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    secret_id: Mapped[str] = mapped_column(String(64), ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(30), nullable=False)  # created, access_attempt, view_success, failed_attempt, suspicious_activity, locked, unlocked, revoked, burned, expired
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="info")  # success, failure, warning, info
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    client_env: Mapped[str | None] = mapped_column(String(100), nullable=True)  # e.g., "Chrome / Desktop"
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    secret: Mapped["Secret"] = relationship("Secret", back_populates="events")

    __table_args__ = (
        Index("ix_secret_events_secret_created", "secret_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<SecretEvent secret_id={self.secret_id!r} event={self.event_type!r} at={self.created_at!r}>"

