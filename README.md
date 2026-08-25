# VaultDrop

> **Zero-Knowledge Temporary Secret & Code Sharing Platform**
> *"Share sensitive information. Let it disappear."*

[![Live Demo](https://img.shields.io/badge/Live%20App-vaultdrop--frontend.vercel.app-22c55e?style=for-the-badge&logo=vercel)](https://vaultdrop-frontend.vercel.app/)
[![Backend Status](https://img.shields.io/badge/Backend%20API-Active%20(Render)-38bdf8?style=for-the-badge&logo=fastapi)](https://vaultdrop-backend.onrender.com/api/health)
[![Tests](https://img.shields.io/badge/Tests-37%20Passing-emerald?style=for-the-badge&logo=pytest)](backend/tests)
[![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-blueviolet?style=for-the-badge)](https://vaultdrop-frontend.vercel.app/privacy)

---

## Quick Links for Judges

- **Live Frontend Application:** [https://vaultdrop-frontend.vercel.app/](https://vaultdrop-frontend.vercel.app/)
- **Live Backend API (Render):** [https://vaultdrop-backend.onrender.com](https://vaultdrop-backend.onrender.com)
- **Zero-Knowledge Threat Model:** [https://vaultdrop-frontend.vercel.app/privacy](https://vaultdrop-frontend.vercel.app/privacy)
- **Owner Control Center:** [https://vaultdrop-frontend.vercel.app/dashboard](https://vaultdrop-frontend.vercel.app/dashboard)

---

## The Problem & Executive Summary

Developers, security teams, and organizations routinely share API keys, `.env` configs, credentials, passwords, and source code files over Slack, Teams, Email, or WhatsApp. This leaves permanent, unencrypted traces across chat logs, backups, search indexes, and notifications.

**VaultDrop solves this with true zero-knowledge encryption:**
- **Plaintext never reaches the server.** Encryption occurs in the sender's browser using AES-256-GCM.
- **The encryption key is isolated.** The key lives exclusively in the URL `#fragment`, which browsers never transmit over HTTP.
- **Self-destruction is atomic.** Once consumed or expired, ciphertext is permanently purged.

---

## Key Innovations & Highlights

### 1. 100% Client-Side Deterministic Risk Analysis
Unlike solutions that compromise privacy by sending plaintext to third-party AI APIs, VaultDrop runs a **deterministic client-side regex engine** directly in the browser. It instantly detects AWS keys, private keys, database strings, GitHub tokens, and Stripe secrets, providing an interactive risk badge (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and a **1-click "Apply Recommended Security Settings"** button.

### 2. Markdown & Syntax-Highlighted Code Sharing
Share `.md`, `.py`, `.ts`, `.js`, `.json`, `.yaml`, `.env`, `.sh`, `.cpp`, and general files up to **15MB**. Decrypted files render directly in the browser with syntax highlighting and instant download/copy controls.

### 3. Secret Owner Control Center (`/dashboard`)
Creators manage secret lifecycles from their browser without creating an account:
- **Live Real-Time Sync:** Background auto-polling (every 5s) displays active secrets, view counts, and failed attempts.
- **Temporary Lock / Unlock:** Suspend access instantly (returns `423 Locked`) and restore on demand.
- **Dynamic Policy Updates:** Modify allowed view limits or extend expiration times.
- **Emergency Lockdown:** 1-click **"Revoke All Active Secrets"** with confirmation dialog.

### 4. Suspicious Access Detection & Audit Timeline
Tracks access attempts, failed password submissions, and hits to burned secrets without collecting user IP addresses or identifying data. Suspicious patterns trigger immediate warning banners on the creator dashboard.

### 5. Zero-Knowledge Password Protection
Derives a Key Encryption Key (KEK) using **PBKDF2-HMAC-SHA256 with 600,000 iterations** and a random 32-byte salt, wrapping the AES data key client-side before link generation.

---

## Architecture & Zero-Knowledge Flow

```
                              BROWSER (Sender)
               [ Plaintext Secret ] + [ Web Crypto API ]
                                   │
            ┌──────────────────────┴──────────────────────┐
            ▼                                             ▼
[ Ciphertext + IV + Metadata ]                  [ 256-bit AES Key ]
            │                                             │
  POST /api/secrets                                       │
 (HTTP Request Body)                                      │
            │                                             │
            ▼                                             │
  ┌──────────────────┐                                    │
  │  FastAPI Backend │                                    │
  └────────┬─────────┘                                    │
           │                                              │
     INSERT Ciphertext (SELECT FOR UPDATE)                │
           │                                              │
           ▼                                              │
  ┌──────────────────┐                                    │
  │    PostgreSQL    │                                    │
  │ (Ciphertext only)│                                    │
  └────────┬─────────┘                                    │
                                                          │
                   Shareable Secret Link:                 │
        https://vaultdrop.app/s/<secret_id> # <AES_Key> ◄─┘
                                            ▲
                                            │ (Fragment NEVER sent to server)
                                            ▼
                              BROWSER (Recipient)
                 GET /api/secrets/<secret_id> -> Ciphertext
               [ Web Crypto API ] + [ AES Key from Fragment ]
                                   │
                                   ▼
                          [ Decrypted Plaintext ]
```

---

## Cryptographic Guarantees

| Security Layer | Implementation | Purpose |
|---|---|---|
| **Cipher** | AES-256-GCM | Authenticated Encryption with Associated Data (AEAD) |
| **Key Generation** | `crypto.getRandomValues()` | 256-bit cryptographically secure random key |
| **Nonce / IV** | 96-bit unique IV per secret | Prevents replay and ciphertext collision |
| **Key Isolation** | URL Fragment (`#<key>`) | Browser standard: fragment is never transmitted over HTTP |
| **Password KDF** | PBKDF2 (600,000 iterations) | SHA-256 derivation with 32-byte salt |
| **Concurrency Lock** | PostgreSQL `SELECT FOR UPDATE` | Atomic row locking prevents double-consumption race conditions |
| **Risk Detection** | Client-side rule engine | Zero plaintext leakage to cloud/AI servers |

---

## Tech Stack

- **Frontend:** React 19, TypeScript, Vite, React Router, Web Crypto API, `react-syntax-highlighter`, `react-markdown`, `qrcode.react`, Vanilla CSS
- **Backend:** Python 3.10+, FastAPI, Pydantic v2, SQLAlchemy 2.0 (Async), asyncpg, Alembic
- **Database:** PostgreSQL 16 (SQLite in-memory for testing)
- **Deployment:** Frontend on Vercel, Backend on Render, Database on PostgreSQL

---

## Automated Testing & Verification

```bash
# Run backend test suite (37 unit & concurrency tests)
cd backend && pytest tests/ -v
```

```
tests/test_concurrency.py::test_one_time_secret_concurrency PASSED
tests/test_health.py::test_health_returns_200 PASSED
tests/test_secrets.py::test_create_secret_success PASSED
tests/test_secrets.py::test_create_secret_one_time PASSED
tests/test_secrets.py::test_create_secret_password_protected PASSED
tests/test_consume_secret_double_consumption PASSED
tests/test_access_attempt_and_view_counting PASSED
tests/test_failed_attempt_and_suspicious_activity_detection PASSED
tests/test_lock_and_unlock_secret PASSED
tests/test_emergency_revoke_all PASSED
...
============================= 37 passed in 1.74s ==============================
```

```bash
# Run frontend build & typecheck
cd frontend && npm run build
# Output: ✓ built in 427ms with 0 errors
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

