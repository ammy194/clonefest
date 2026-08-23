export default function PrivacyPage() {
  return (
    <div className="fade-in">
      <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
        <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🛡️</div>
        <h1 style={{ fontSize: '2.5rem', fontWeight: 800, marginBottom: '1rem' }}>
          Zero-Knowledge Privacy & Threat Model
        </h1>
        <p style={{ fontSize: '1.1rem', color: 'var(--text-secondary)', maxWidth: '680px', margin: '0 auto', lineHeight: 1.6 }}>
          VaultDrop is engineered around a mathematically verifiable zero-knowledge architecture.
          Plaintext and cryptographic keys never leave your browser unencrypted.
        </p>
      </div>

      {/* Grid: What VaultDrop Can Know vs What It Cannot */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '2rem', marginBottom: '3rem' }}>
        <div className="card card-accent" style={{ border: '1px solid var(--accent)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <span style={{ fontSize: '1.5rem' }}>👁️</span>
            <h3 style={{ fontSize: '1.25rem', color: 'var(--accent)', margin: 0 }}>
              What VaultDrop Can Know
            </h3>
          </div>
          <ul style={{ color: 'var(--text-secondary)', paddingLeft: '1.25rem', lineHeight: 1.8, fontSize: '0.9rem' }}>
            <li><strong>Encrypted Ciphertext:</strong> The AES-256-GCM ciphertext payload.</li>
            <li><strong>Initialization Vector (IV):</strong> The random 96-bit nonce required for AES-GCM.</li>
            <li><strong>Lifecycle Metadata:</strong> Expiration timestamp, maximum views, and view count.</li>
            <li><strong>Security Event Metrics:</strong> Access attempt timestamps, failed decryption counts, and locked states.</li>
            <li><strong>Password Verifier & Salt:</strong> PBKDF2 salt and derived verification hash (if password protection is enabled).</li>
            <li><strong>Basic File Headers:</strong> Original filename, size, and MIME type for downloads.</li>
            <li><strong>Rate-Limiting Counters:</strong> Ephemeral IP request rates to mitigate abuse.</li>
          </ul>
        </div>

        <div className="card card-accent" style={{ border: '1px solid var(--success)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <span style={{ fontSize: '1.5rem' }}>🔒</span>
            <h3 style={{ fontSize: '1.25rem', color: 'var(--success)', margin: 0 }}>
              What VaultDrop CANNOT Know
            </h3>
          </div>
          <ul style={{ color: 'var(--text-secondary)', paddingLeft: '1.25rem', lineHeight: 1.8, fontSize: '0.9rem' }}>
            <li><strong>Secret Plaintext:</strong> Content is encrypted in the browser before transmission.</li>
            <li><strong>Encryption Keys:</strong> Keys reside strictly in the URL fragment (<code style={{ color: 'var(--accent)' }}>#key</code>), which browsers never transmit over HTTP.</li>
            <li><strong>Uploaded File Contents:</strong> Code, Markdown, documents, and binaries are encrypted before upload.</li>
            <li><strong>Master Passwords:</strong> Passwords derive local keys via 600,000-round PBKDF2-SHA256 and never touch the server.</li>
            <li><strong>User Identities:</strong> No mandatory accounts, tracking cookies, or persistent identity profiles.</li>
          </ul>
        </div>
      </div>

      {/* Threat Model: What VaultDrop Does NOT Protect Against */}
      <div className="card" style={{ border: '1px solid rgba(245, 158, 11, 0.4)', background: 'rgba(245, 158, 11, 0.03)', marginBottom: '3rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
          <span style={{ fontSize: '1.75rem' }}>⚠️</span>
          <h2 style={{ fontSize: '1.35rem', color: '#fbbf24', margin: 0 }}>
            What VaultDrop Does NOT Protect Against
          </h2>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.25rem' }}>
          We believe in honest, transparent security engineering. No web-based tool can protect against compromised execution environments:
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
          <div style={{ background: 'var(--bg-input)', padding: '1rem', borderRadius: 'var(--radius-sm)' }}>
            <strong style={{ color: '#fbbf24' }}>⚠️ Compromised Recipient Device</strong>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.35rem', fontSize: '0.85rem' }}>
              If malware, a keylogger, or spyware is running on the recipient's computer, decrypted content can be stolen at the OS level.
            </p>
          </div>

          <div style={{ background: 'var(--bg-input)', padding: '1rem', borderRadius: 'var(--radius-sm)' }}>
            <strong style={{ color: '#fbbf24' }}>⚠️ Screenshots & Screen Recording</strong>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.35rem', fontSize: '0.85rem' }}>
              Once a secret is displayed on screen, the recipient can capture images, record videos, or transcribe the plaintext.
            </p>
          </div>

          <div style={{ background: 'var(--bg-input)', padding: '1rem', borderRadius: 'var(--radius-sm)' }}>
            <strong style={{ color: '#fbbf24' }}>⚠️ Malicious Browser Extensions</strong>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.35rem', fontSize: '0.85rem' }}>
              Third-party extensions with DOM access permissions can intercept plaintext after browser decryption.
            </p>
          </div>

          <div style={{ background: 'var(--bg-input)', padding: '1rem', borderRadius: 'var(--radius-sm)' }}>
            <strong style={{ color: '#fbbf24' }}>⚠️ Leaked Sharing URLs</strong>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.35rem', fontSize: '0.85rem' }}>
              If a link with the URL fragment is forwarded or intercepted in transit without password protection, anyone with the link can decrypt it.
            </p>
          </div>
        </div>
      </div>

      {/* Cryptographic Architecture */}
      <div className="card" style={{ marginBottom: '3rem' }}>
        <h2 style={{ fontSize: '1.5rem', marginBottom: '1.25rem' }}>The Cryptographic Architecture</h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ background: 'var(--bg-input)', padding: '1.25rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <strong style={{ color: 'var(--accent)', fontSize: '1rem' }}>1. Local AES-256-GCM Encryption</strong>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', fontSize: '0.9rem' }}>
              When creating a secret, your browser invokes the native <code style={{ color: 'var(--accent)' }}>Web Crypto API</code> to generate a cryptographically strong 256-bit AES key and a 96-bit initialization vector (IV). Plaintext is encrypted locally before sending ciphertext to the backend.
            </p>
          </div>

          <div style={{ background: 'var(--bg-input)', padding: '1.25rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <strong style={{ color: 'var(--accent)', fontSize: '1rem' }}>2. Client-Side Key Isolation (URL Fragments)</strong>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', fontSize: '0.9rem' }}>
              The 256-bit encryption key is encoded into the URL fragment (after the <code style={{ color: 'var(--accent)' }}>#</code> delimiter). RFC 3986 specifies that fragments are processed exclusively by the browser and are never transmitted over HTTP requests or logged in server access logs.
            </p>
          </div>

          <div style={{ background: 'var(--bg-input)', padding: '1.25rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <strong style={{ color: 'var(--accent)', fontSize: '1rem' }}>3. PBKDF2-SHA256 Key Derivation for Password Protection</strong>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', fontSize: '0.9rem' }}>
              When password protection is enabled, a Key Encryption Key (KEK) is derived from the user password using PBKDF2-HMAC-SHA256 with <strong>600,000 iterations</strong> and a random 32-byte salt. The AES data key is wrapped with AES-GCM-KW.
            </p>
          </div>

          <div style={{ background: 'var(--bg-input)', padding: '1.25rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <strong style={{ color: 'var(--accent)', fontSize: '1rem' }}>4. Atomic Burn-After-Reading & Lifecycle Enforcement</strong>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem', fontSize: '0.9rem' }}>
              The database server executes atomic row locking (<code style={{ color: 'var(--accent)' }}>SELECT FOR UPDATE</code>) to ensure single-use secrets are consumed exactly once. When burned or expired, ciphertext is permanently expunged.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

