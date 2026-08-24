# VaultDrop

> Share sensitive information. Let it disappear.

VaultDrop is a zero-knowledge platform for securely sharing temporary secrets, credentials, configurations, and files. Content is encrypted directly in the sender's browser using AES-256-GCM prior to transmission, while self-destructing links, atomic access controls, and client-side security intelligence provide controlled, ephemeral sharing.

---

## Quick Links

- Live Application: [https://vaultdrop-frontend.vercel.app](https://vaultdrop-frontend.vercel.app)
- Backend API: [https://vaultdrop-backend.onrender.com](https://vaultdrop-backend.onrender.com)
- GitHub Repository: [https://github.com/ammy194/clonefest](https://github.com/ammy194/clonefest)
- Owner Dashboard: [https://vaultdrop-frontend.vercel.app/dashboard](https://vaultdrop-frontend.vercel.app/dashboard)
- Privacy and Threat Model: [https://vaultdrop-frontend.vercel.app/privacy](https://vaultdrop-frontend.vercel.app/privacy)

---

## 1. Overview

### The Problem
Engineering teams, system administrators, and security professionals routinely exchange sensitive data such as API tokens, private keys, database credentials, environment files, and system passwords. Standard collaboration channels (Slack, Microsoft Teams, email, ticketing systems, and messaging apps) store unencrypted copies across cloud servers, local caches, search indexes, and backup snapshots indefinitely. This creates an unmonitored attack surface long after the initial communication has concluded.

### What VaultDrop Provides
VaultDrop provides an ephemeral transfer mechanism engineered with zero-knowledge cryptography. Data is encrypted on the sender's client device before transmission. The server receives only opaque ciphertext and minimal operational metadata. Once a secret meets its expiration time or view limit, the database record is atomically destroyed.

### Target Audience
VaultDrop is designed for software engineers, DevOps practitioners, security analysts, and IT administrators who require a disposable, verifiable transfer pipeline for confidential data. It was built as an independent, modern implementation inspired by the core concept of zero-knowledge temporary sharing.

---

## 2. Key Features

| Feature | Description |
|---|---|
| Client-Side Encryption | AES-256-GCM authenticated encryption executed locally in the browser via the Web Crypto API before transmission. |
| Secret Risk Analysis | Local pattern-matching engine detects credential types and calculates a risk score with actionable recommendations. |
| Self-Destructing Secrets | Configurable time-to-live (5 minutes to 7 days) and view limits (1 to 100 views) with automatic permanent deletion. |
| Encrypted File Sharing | In-browser binary encryption supporting source code, configurations, and documents up to 15MB with syntax highlighting. |
| Access Analytics | Non-identifying operational metrics tracking view counts, failed decryption attempts, and audit events without storing IP addresses. |
| Suspicious Activity Detection | Heuristic detection engine flags abnormal access frequencies, repeated incorrect passwords, and attempts on burned links. |
| Owner Control Center | Token-based management dashboard allowing creators to inspect activity, toggle locks, update limits, and trigger emergency revocations. |
| Mobile QR Transfer | Direct QR code generation for transferring encrypted secret URLs across mobile devices without third-party tools. |

---

## 3. Architecture

```
                                SENDER BROWSER
                    [ Plaintext Secret or File Content ]
                                     |
                                     v
                    [ Client-Side Security Analysis ]
                                     |
                                     v
                    [ AES-256-GCM Web Crypto API ]
                                     |
              +----------------------+----------------------+
              |                                             |
              v                                             v
 [ Ciphertext + IV + Metadata ]                      [ 256-bit AES Key ]
              |                                             |
      POST /api/secrets                                     |
     (HTTP Request Body)                                    |
              |                                             |
              v                                             |
    +------------------+                                    |
    |  FastAPI Backend |                                    |
    +---------+--------+                                    |
              |                                             |
     INSERT (Ciphertext)                                    |
              |                                             |
              v                                             |
    +------------------+                                    |
    |    PostgreSQL    |                                    |
    | (Ciphertext only)|                                    |
    +---------+--------+                                    |
                                                            |
                     Shareable Secret Link:                 |
          https://vaultdrop.app/s/<secret_id> # <AES_Key> <--+
                                              |
                        (URL Fragment NEVER sent to server)
                                              |
                                              v
                                      RECIPIENT BROWSER
                         GET /api/secrets/<secret_id> -> Ciphertext
                        [ Web Crypto API ] + [ AES Key from Fragment ]
                                              |
                                              v
                                    [ Decrypted Plaintext ]
```

### Encryption and Transmission Flow
1. The sender inputs plaintext data or uploads a file into the web interface.
2. The browser generates a cryptographically secure 256-bit AES key and a 96-bit initialization vector (IV) using `window.crypto`.
3. The content is encrypted using AES-256-GCM.
4. The ciphertext, IV, secret type, view limits, and expiration settings are dispatched via `POST /api/secrets`.
5. The backend stores the ciphertext and metadata in PostgreSQL, returning a unique secret identifier and an owner authorization token.
6. The frontend constructs a shareable URL containing the secret ID in the path and the base64url-encoded decryption key in the URL fragment (`#<key>`).

### Recipient and Decryption Flow
1. The recipient opens the shareable URL in their browser.
2. The browser extracts the secret ID from the path and queries `GET /api/secrets/<secret_id>`.
3. The backend returns the ciphertext, IV, and status metadata.
4. The client extracts the encryption key from `window.location.hash` and decrypts the payload locally.
5. If the secret is protected by a password, the client requests the user password, derives the key-encryption-key via PBKDF2, unwraps the master key, and decrypts the payload.
6. The client calls `POST /api/secrets/<secret_id>/consume` to register a successful view and trigger destruction if limits are met.

### Key Isolation and Server Metadata
The backend never receives the plaintext secret or the client-side encryption key.

Per RFC 3986, URI fragments (everything following the `#` character) are strictly client-side constructs and are never included in HTTP request headers or transmission bodies. The server processes only ciphertext and operational metadata required for lifecycle enforcement, including expiration timestamps, view counts, and client environment identifiers.

---

## 4. Security Model

| Mechanism | Implementation | Purpose |
|---|---|---|
| Symmetric Cipher | AES-256-GCM | Authenticated Encryption with Associated Data (AEAD) ensuring confidentiality and integrity. |
| Nonce Generation | Unique 96-bit IV per secret | Generated via `crypto.getRandomValues()` to eliminate IV reuse risks. |
| Key Isolation | URL Fragment (`#<key>`) | Keeps master decryption keys out of server logs, proxies, and network requests. |
| Key Derivation | PBKDF2-HMAC-SHA256 | Derives a wrapping key from user passwords using 600,000 iterations and a 32-byte salt. |
| Concurrency Control | PostgreSQL `SELECT FOR UPDATE` | Prevents race conditions during simultaneous reads of one-time secrets. |
| Rate Limiting | In-Memory Sliding Window | Prevents brute-force retrieval and denial-of-service abuse. |
| Automated Purging | Async Background Task | Periodically deletes expired and burned records from persistent storage. |
| Security Headers | Strict HTTP Headers | Enforces `HSTS`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`. |

---

## 5. Security Intelligence

VaultDrop includes a client-side security analysis engine that inspects secret content directly in the browser before encryption occurs.

```
[ User Inputs Secret ]
         |
         v
[ Client-Side Rule Engine ]
         |
         v
[ Risk Evaluation: CRITICAL / HIGH / MEDIUM / LOW ]
         |
         v
[ Recommended Policy: TTL, Max Views, Passcode ]
         |
         v
[ User Confirms / Applies Settings ]
         |
         v
[ Client-Side AES-256-GCM Encryption ]
         |
         v
[ Dispatch Ciphertext to Server ]
```

### Operational Principles
- Deterministic Local Execution: Analysis runs entirely within the browser JavaScript runtime. No text, tokens, or heuristics are transmitted to external AI endpoints or cloud APIs.
- Pattern Signatures: Detects AWS access keys, GitHub personal access tokens, private keys (RSA, OpenSSH, PGP), Stripe secret keys, database connection strings, JWTs, and sensitive environment variables.
- Automated Policy Suggestions: When high-risk credentials are identified, the system provides a 1-click option to enforce single-view consumption, short expiration windows (e.g., 10 minutes), and mandatory passphrase wrapping.

---

## 6. Owner Control Center

Creators manage their active secrets via the `/dashboard` route. Authorization relies on client-generated creator tokens stored in browser `localStorage`, eliminating the need for traditional user accounts or persistent identity records.

### Dashboard Sections
- Overview: Displays aggregated operational metrics including total active secrets, total views, failed access attempts, and flagged suspicious events.
- Secrets: Lists individual secrets with associated payload type, view counters, remaining lifespan, real-time status indicators (Active, Locked, Expired, Burned), and management controls.
- Security Activity: An immutable security audit timeline logging access attempts, successful decryptions, failed attempts, and administrative modifications with associated client environment indicators.
- Emergency Controls: Provides immediate risk-mitigation actions, including temporary secret locking (returns HTTP 423 to recipients), policy updates, individual destruction, and a global "Revoke All Active Secrets" command.

The Owner Control Center processes metadata and creator tokens exclusively; it cannot view or reconstruct secret plaintext.

---

## 7. Threat Model and Limitations

### Protected Scenarios
- Server-Side Compromise: An attacker gaining access to backend databases or application memory retrieves only AES-256-GCM ciphertext without corresponding keys.
- Network Eavesdropping: Decryption keys are confined to URL fragments and are never transmitted over the wire.
- Concurrency Exploits: Atomic row-level database locking ensures one-time secrets cannot be read simultaneously by competing requests.
- Stale Data Persistence: Burn-after-reading policies and background sweep tasks permanently remove consumed and expired records.

### Limitations and Out-of-Scope Risks
- Compromised Endpoints: Keyloggers, compromised browser extensions, or malware on the sender or recipient devices can capture secrets before encryption or after decryption.
- Recipient Malfeasance: Once decrypted, a legitimate recipient can copy, photograph, screenshot, or redistribute the revealed content.
- URL Leakage: If a sender transmits the full URL (including the fragment) over an insecure medium or to an unintended party, the bearer of that URL can decrypt the secret.
- Physical Shoulder Surfing: Visual observation of the decrypted screen on the recipient device.

For complete architectural details, visit the [Privacy and Threat Model Specification](https://vaultdrop-frontend.vercel.app/privacy).

---

## 8. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend Framework | React 19, TypeScript | Reactive user interface and type-safe state management |
| Build Tool | Vite 8 | Development server and production bundling |
| Client Cryptography | Web Crypto API | Standard browser implementation of AES-256-GCM and PBKDF2 |
| Syntax & Markdown | React Syntax Highlighter, React Markdown | In-browser preview for code snippets and formatted text |
| QR Generation | qrcode.react | Client-side QR generation for mobile transfer |
| Styling | Vanilla CSS | Custom design system with zero external UI framework dependencies |
| Backend Framework | Python 3.10+, FastAPI | High-performance asynchronous REST API |
| Schema Validation | Pydantic v2 | Request/response data serialization and validation |
| ORM & Database Driver | SQLAlchemy 2.0 (Async), asyncpg | Asynchronous database access and migration management |
| Database Migrations | Alembic | Schema versioning and relational database migrations |
| Primary Database | PostgreSQL 16 | Relational persistence with row-level locking support |
| Test Database | aiosqlite | Lightweight async SQLite driver for local test execution |
| Hosting & Deployment | Vercel (Frontend), Render (Backend) | Global edge hosting and cloud application infrastructure |

---

## 9. Local Development

### Prerequisites
- Node.js 18+ and npm
- Python 3.10+
- PostgreSQL (optional, SQLite supported for local testing)
- Docker & Docker Compose (optional)

### 1. Clone Repository
```bash
git clone https://github.com/ammy194/clonefest.git
cd clonefest/VaultDrop
```

### 2. Backend Setup
```bash
cd backend

# Create and activate Python virtual environment
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp ../.env.example .env

# Run database migrations (or allow auto-creation on startup)
alembic upgrade head

# Start FastAPI development server
uvicorn app.main:app --reload --port 8000
```
The backend API is accessible at `http://localhost:8000`. Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

### 3. Frontend Setup
```bash
cd ../frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
The frontend application is accessible at `http://localhost:5173`.

### 4. Running with Docker Compose
To run the full stack (PostgreSQL, FastAPI backend, and Nginx frontend) in isolated containers:
```bash
docker compose up --build
```
- Frontend: `http://localhost`
- Backend API: `http://localhost:8000`
- PostgreSQL: `localhost:5432`

---

## 10. Environment Variables

Configure environment variables in `backend/.env` using `backend/.env.example` as a template:

| Variable | Type | Default / Example | Description |
|---|---|---|---|
| DATABASE_URL | String | `postgresql+asyncpg://postgres:postgres@localhost:5432/vaultdrop` | Asynchronous database connection string |
| CORS_ORIGINS | String | `http://localhost:5173,http://localhost` | Comma-separated list of allowed frontend origins |
| ENVIRONMENT | String | `development` | Runtime environment mode (`development` or `production`) |
| RATE_LIMIT_CREATE | Integer | `10` | Maximum secret creation requests allowed per minute per IP |
| RATE_LIMIT_RETRIEVE | Integer | `30` | Maximum secret retrieval requests allowed per minute per IP |
| VITE_API_BASE_URL | String | `http://localhost:8000` | Backend API base URL for frontend build configuration |

Do not commit production credentials, database passwords, or secrets to version control.

---

## 11. API Overview

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service health check and readiness status |
| POST | `/api/secrets` | Store new encrypted ciphertext and return secret ID with creator token |
| GET | `/api/secrets/{secret_id}` | Retrieve encrypted ciphertext and metadata (increments attempt counter) |
| POST | `/api/secrets/{secret_id}/consume` | Atomically increment view count and destroy payload if limit is reached |
| POST | `/api/secrets/{secret_id}/failed-attempt` | Report failed password or decryption event for anomaly monitoring |
| DELETE | `/api/secrets/{secret_id}` | Unauthenticated immediate destruction of secret |
| POST | `/api/secrets/mine` | List active and historical secrets matching provided creator tokens |
| POST | `/api/secrets/mine/overview` | Fetch aggregated dashboard metrics for provided creator tokens |
| POST | `/api/secrets/{secret_id}/events` | Fetch immutable audit timeline events (requires creator token) |
| POST | `/api/secrets/{secret_id}/lock` | Toggle temporary access lock (requires creator token) |
| PATCH | `/api/secrets/{secret_id}` | Update TTL or view limit parameters (requires creator token) |
| POST | `/api/secrets/{secret_id}/revoke` | Permanently burn a specific secret (requires creator token) |
| POST | `/api/secrets/emergency-revoke-all` | Batch-burn all active secrets owned by creator tokens |

API responses never return encryption keys or decrypted plaintext.

---

## 12. Project Structure

```
VaultDrop/
|-- backend/
|   |-- alembic/                 # Database schema migrations
|   |   `-- versions/            # Migration scripts (001_initial, 002_security)
|   |-- app/
|   |   |-- api/                 # REST routing and endpoint handlers
|   |   |   `-- routes.py        # FastAPI route definitions
|   |   |-- core/                # Core configuration and rate limiters
|   |   |   |-- config.py        # Pydantic application settings
|   |   |   `-- rate_limit.py    # Request rate limiting logic
|   |   |-- db/                  # Database session and base definitions
|   |   |   |-- base.py          # SQLAlchemy declarative base
|   |   |   `-- session.py       # Async engine and session factory
|   |   |-- models/              # SQLAlchemy database models
|   |   |   `-- secret.py        # Secret and SecretEvent table definitions
|   |   |-- schemas/             # Pydantic request/response validation schemas
|   |   |   `-- secret.py        # API schemas and validation models
|   |   |-- services/            # Business logic and lifecycle management
|   |   |   `-- secret_service.py # Secret CRUD, atomic consume, audit logs
|   |   `-- main.py              # FastAPI application entrypoint & lifespan
|   |-- tests/                   # Automated backend test suite
|   |   |-- conftest.py          # Pytest async fixtures and test client
|   |   |-- test_concurrency.py  # Race condition and atomic consumption tests
|   |   |-- test_health.py       # Health check test coverage
|   |   `-- test_secrets.py      # Secret lifecycle and security policy tests
|   |-- Dockerfile               # Backend container configuration
|   |-- requirements.txt         # Python package dependencies
|   `-- pyproject.toml           # Pytest configuration
|-- frontend/
|   |-- src/
|   |   |-- components/          # Reusable UI components (Layout, Toast, Score)
|   |   |-- crypto/              # Web Crypto API wrapper (AES-256-GCM, PBKDF2)
|   |   |-- pages/               # Application view routes
|   |   |   |-- CreatePage.tsx   # Secret creation and risk analysis
|   |   |   |-- CreatedPage.tsx  # Share link and QR presentation
|   |   |   |-- DashboardPage.tsx# Owner Control Center and audit timeline
|   |   |   |-- HomePage.tsx     # Landing presentation
|   |   |   |-- PrivacyPage.tsx  # Detailed threat model documentation
|   |   |   `-- ViewPage.tsx     # Recipient decryption and file preview
|   |   |-- services/            # Frontend API client
|   |   |-- types/               # TypeScript interfaces and type definitions
|   |   |-- utils/               # Detection rule definitions
|   |   |-- App.tsx              # Router and application layout
|   |   `-- index.css            # Custom CSS styling tokens
|   |-- Dockerfile               # Production multi-stage Nginx build
|   |-- package.json             # Node dependencies and scripts
|   |-- tsconfig.json            # TypeScript configuration
|   `-- vite.config.ts           # Vite build configuration
|-- docs/
|   `-- screenshots/             # Interface and architectural screenshots
|-- docker-compose.yml           # Multi-container orchestration specification
|-- render.yaml                  # Cloud backend deployment configuration
|-- .env.example                 # Environment configuration template
`-- README.md                    # Project documentation
```

---

## 13. Testing

### Automated Backend Tests
The backend test suite contains 39 automated unit and concurrency tests implemented with `pytest` and `pytest-asyncio`, using in-memory SQLite for isolated test execution.

```bash
cd backend
pytest -v
```

Test coverage includes:
- Concurrency and Race Conditions: Verifies that multiple parallel requests to a one-time secret result in exactly one successful consumption and 410 responses for all subsequent callers.
- Secret Lifecycle: Validates creation, retrieval, view decrementing, expiration enforcement, and permanent deletion.
- Password Protection: Validates password verifier checks, PBKDF2 salt handling, and invalid-attempt tracking.
- Access Analytics and Anomaly Detection: Asserts that failed access attempts and burned-link requests trigger warning events without incrementing successful view counts.
- Emergency Revocation: Tests creator-token-authenticated single and batch secret terminations.
- Rate Limiting: Confirms creation and retrieval limit enforcement.

### Frontend Validation
```bash
cd frontend

# Run TypeScript typecheck
npx tsc -b

# Run production build
npm run build
```

---

## 14. Screenshots

The following interface captures illustrate the primary user workflows and security controls:

### 1. Secret Creation Interface
![Secret Creation Interface](docs/screenshots/01_secret_creation.png)
*Client-side secret creation form with payload type selectors, view limits, and expiration options.*

### 2. Security Risk Analysis
![Security Risk Analysis](docs/screenshots/02_security_risk_analysis.png)
*Deterministic pattern analyzer identifying credential types and calculating a risk score locally.*

### 3. Security Configuration & Policy Enforcement
![Security Configuration](docs/screenshots/03_security_configuration.png)
*Configuring passphrase wrapping, view counts, and time-to-live restrictions.*

### 4. Encrypted File Sharing & Syntax Highlighting
![Encrypted File Sharing](docs/screenshots/04_encrypted_file_sharing.png)
*Decrypted code and markdown rendered directly in the browser with syntax formatting.*

### 5. Mobile QR Transfer
![Mobile QR Transfer](docs/screenshots/05_mobile_qr_transfer.png)
*Client-side QR generation for secure mobile link handoff.*

### 6. Owner Control Center
![Owner Control Center](docs/screenshots/06_owner_control_center.png)
*Active secret overview, view counts, and management controls authorized via creator tokens.*

### 7. Security Activity Audit Timeline
![Security Activity](docs/screenshots/07_security_activity.png)
*Immutable event timeline detailing access attempts, decryptions, and administrative changes.*

### 8. Suspicious Activity Detection
![Suspicious Activity](docs/screenshots/08_suspicious_activity.png)
*Heuristic alert banner triggered by repeated failed passcodes or access to burned links.*

### 9. Privacy & Threat Model
![Privacy and Threat Model](docs/screenshots/09_privacy_threat_model.png)
*Comprehensive in-app security specification outlining protection boundaries.*

---

## 15. Industry Use Cases

VaultDrop serves as an ephemeral transport layer for scenarios where long-term persistence in collaboration tools introduces security risk:

- DevOps & Cloud Infrastructure: Transmitting temporary AWS session tokens, SSH access keys, or Kubernetes configurations without leaving credentials in persistent chat histories.
- Incident Response: Distributing emergency database credentials, triage tokens, or mitigation scripts during active security events.
- IT Administration & Support: Delivering temporary one-time passwords, VPN configurations, and administrative access links to remote employees.
- Contractor & Vendor Onboarding: Providing scoped credentials and API keys with guaranteed expiration and single-read destruction.
- Ephemeral Code and Config Sharing: Exchanging sensitive `.env` snippets or proprietary configuration files with syntax highlighting and instant burning.

VaultDrop is intended as a temporary sharing tool and does not replace persistent enterprise secrets managers such as HashiCorp Vault or AWS Secrets Manager.

---

## 16. Deployment

### Production Architecture
- Frontend: Hosted on Vercel Edge Network with automated continuous integration from repository pushes.
  - Production URL: [https://vaultdrop-frontend.vercel.app](https://vaultdrop-frontend.vercel.app)
- Backend: Deployed on Render running Python 3.10 with Uvicorn and FastAPI.
  - Production API: [https://vaultdrop-backend.onrender.com](https://vaultdrop-backend.onrender.com)
- Database: Managed PostgreSQL 16 on Render with SSL enforcement.

---

## 17. License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
