import { Link } from 'react-router-dom';

export default function HomePage() {
  return (
    <div className="fade-in">
      <section className="hero">
        {/* Animated grid background */}
        <div className="hero-grid-bg" aria-hidden="true">
          <div className="grid-line grid-line-1" />
          <div className="grid-line grid-line-2" />
          <div className="grid-line grid-line-3" />
          <div className="grid-dot grid-dot-1" />
          <div className="grid-dot grid-dot-2" />
          <div className="grid-dot grid-dot-3" />
          <div className="grid-dot grid-dot-4" />
          <div className="grid-dot grid-dot-5" />
        </div>

        <h1 className="hero-title">
          Share sensitive information.
          <br />
          <span className="hero-gradient-text">Let it disappear.</span>
        </h1>
        <p className="hero-subtitle">
          VaultDrop provides zero-knowledge encrypted, self-destructing links for passwords,
          API keys, code files, and sensitive payloads. The server never receives plaintext or encryption keys.
        </p>
        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
          <Link to="/create" className="btn btn-primary btn-lg btn-glow">
            🔒 Create Secure Secret
          </Link>
          <Link to="/dashboard" className="btn btn-secondary btn-lg">
            🛡️ Owner Control Center
          </Link>
        </div>

        <div className="security-badges" style={{ marginTop: '2rem' }}>
          <span className="security-badge">🔐 AES-256-GCM</span>
          <span className="security-badge">🧠 Client-Side Risk Analysis</span>
          <span className="security-badge">💻 Code & Markdown Sharing</span>
          <span className="security-badge">⏱ Auto-Expiration</span>
          <span className="security-badge">💥 Single-View Burn</span>
          <span className="security-badge">🚨 Suspicious Access Detection</span>
        </div>
      </section>

      {/* How It Works Section */}
      <section className="how-it-works">
        <h2 className="section-title">How It Works</h2>
        <p className="section-subtitle">Three simple steps to share secrets securely</p>

        <div className="steps-container">
          <div className="step-card">
            <div className="step-number">1</div>
            <div className="step-icon">✍️</div>
            <h3 className="step-title">Analyze & Encrypt Locally</h3>
            <p className="step-desc">
              Type or drag files. Our client-side risk engine scores sensitivity and encrypts with AES-256-GCM locally. Plaintext never leaves your device.
            </p>
          </div>

          <div className="step-connector" aria-hidden="true">
            <div className="connector-line" />
            <div className="connector-arrow">→</div>
          </div>

          <div className="step-card">
            <div className="step-number">2</div>
            <div className="step-icon">🔗</div>
            <h3 className="step-title">Share the Protected Link</h3>
            <p className="step-desc">
              The decryption key lives solely in the URL fragment (#key), which browsers never send to servers over HTTP.
            </p>
          </div>

          <div className="step-connector" aria-hidden="true">
            <div className="connector-line" />
            <div className="connector-arrow">→</div>
          </div>

          <div className="step-card">
            <div className="step-number">3</div>
            <div className="step-icon">💥</div>
            <h3 className="step-title">Decrypted & Destroyed</h3>
            <p className="step-desc">
              The recipient decrypts in their browser. Single-use secrets self-destruct immediately with atomic server-side deletion.
            </p>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="features-section">
        <h2 className="section-title">Engineered for Security & Control</h2>
        <p className="section-subtitle">Zero-knowledge protection paired with comprehensive owner lifecycle management</p>

        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon">🔒</div>
            <h3 className="feature-title">End-to-End Zero-Knowledge</h3>
            <p className="feature-desc">
              Client-side AES-256-GCM encryption with keys isolated in URL fragments. Neither VaultDrop nor any intermediary can access plaintext.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🧠</div>
            <h3 className="feature-title">Intelligent Risk Analysis</h3>
            <p className="feature-desc">
              Deterministic 100% in-browser risk engine detects credentials, private keys, database strings, and cloud tokens with 1-click recommended hardening.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">💻</div>
            <h3 className="feature-title">Code & Markdown Files</h3>
            <p className="feature-desc">
              Encrypt source code files (.py, .ts, .js, .env, .json, .sh, etc.) and Markdown docs up to 15MB with syntax highlighting and instant download.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🚨</div>
            <h3 className="feature-title">Suspicious Access Detection</h3>
            <p className="feature-desc">
              Anomalous access attempts, repeated password failures, or hits on burned secrets trigger instant alert banners on your owner dashboard.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">📊</div>
            <h3 className="feature-title">Owner Control Center</h3>
            <p className="feature-desc">
              Real-time live dashboard tracking active secrets, total decryptions, failed attempts, audit timelines, and temporary lock/unlock toggles.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">⚡</div>
            <h3 className="feature-title">Emergency Lockdown</h3>
            <p className="feature-desc">
              Instantly terminate access and permanently revoke all active secrets created from your browser with a single emergency lockdown command.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

