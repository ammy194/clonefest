import { useState, useMemo, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { encryptSecret, encryptBytes, wrapKeyWithPassword } from '../crypto';
import { createSecret } from '../services/api';
import type { SecretType } from '../types';
import { SECRET_TYPE_LABELS, EXPIRATION_OPTIONS } from '../types';
import { detectSecrets } from '../utils/secretDetection';
import SecurityScore from '../components/SecurityScore';

function getPasswordStrength(pw: string): { label: string; level: number; color: string } {
  if (!pw) return { label: '', level: 0, color: 'transparent' };

  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  if (score <= 2) return { label: 'Weak', level: 1, color: 'var(--danger)' };
  if (score <= 4) return { label: 'Fair', level: 2, color: 'var(--warning)' };
  if (score <= 5) return { label: 'Strong', level: 3, color: 'var(--accent)' };
  return { label: 'Very Strong', level: 4, color: 'var(--success)' };
}

export default function CreatePage() {
  const navigate = useNavigate();

  const [secretType, setSecretType] = useState<SecretType>('text');
  const [secretContent, setSecretContent] = useState('');
  const [expiresIn, setExpiresIn] = useState(3600);
  const [oneTime, setOneTime] = useState(false);
  const [passwordProtected, setPasswordProtected] = useState(false);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const [apiService, setApiService] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [username, setUsername] = useState('');
  const [passwordValue, setPasswordValue] = useState('');
  
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const passwordStrength = useMemo(() => getPasswordStrength(password), [password]);

  const rawContent = secretType === 'api_key'
    ? `${apiService} ${apiKey}`
    : secretType === 'password'
    ? `${username} ${passwordValue}`
    : secretContent;

  const detectionResult = useMemo(() => detectSecrets(rawContent), [rawContent]);

  function applyRecommendations() {
    if (detectionResult.detected && detectionResult.recommendedSettings) {
      setOneTime(detectionResult.recommendedSettings.oneTime);
      setExpiresIn(detectionResult.recommendedSettings.expiresInSeconds);
      setPasswordProtected(detectionResult.recommendedSettings.passwordProtected);
    }
  }

  function buildPlaintext(): string {
    switch (secretType) {
      case 'api_key':
        return JSON.stringify({ service: apiService, api_key: apiKey });
      case 'password':
        return JSON.stringify({ username, password: passwordValue });
      case 'json':
        try {
          const parsed = JSON.parse(secretContent);
          return JSON.stringify(parsed, null, 2);
        } catch {
          throw new Error('Invalid JSON format.');
        }
      default:
        return secretContent;
    }
  }

  const currentPayloadSize = secretType === 'file' 
    ? (selectedFile?.size || 0)
    : new TextEncoder().encode(
        secretType === 'api_key' || secretType === 'password'
          ? rawContent
          : secretContent
      ).length;

  const maxPayloadSize = secretType === 'file' ? 15_000_000 : 100_000;
  const payloadPercent = Math.min((currentPayloadSize / maxPayloadSize) * 100, 100);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');

    if (secretType === 'file') {
      if (!selectedFile) {
        setError('Please select a file to encrypt.');
        return;
      }
    } else {
      if (!rawContent.trim()) {
        setError('Secret content cannot be empty.');
        return;
      }
    }

    if (passwordProtected) {
      if (!password) {
        setError('Please enter a password.');
        return;
      }
      if (password !== confirmPassword) {
        setError('Passwords do not match.');
        return;
      }
      if (passwordStrength.level < 2) {
        setError('Password is too weak. Use at least 8 characters with mixed case, numbers, or symbols.');
        return;
      }
    }

    let plaintext = '';
    if (secretType !== 'file') {
      try {
        plaintext = buildPlaintext();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Invalid input.');
        return;
      }

      if (new TextEncoder().encode(plaintext).length > 100_000) {
        setError('Secret text is too large (max 100KB).');
        return;
      }
    } else {
      if (selectedFile!.size > 15_000_000) {
        setError('File is too large (max 15MB).');
        return;
      }
    }

    setLoading(true);

    try {
      let encrypted;
      
      if (secretType === 'file') {
        const arrayBuffer = await selectedFile!.arrayBuffer();
        encrypted = await encryptBytes(new Uint8Array(arrayBuffer));
      } else {
        encrypted = await encryptSecret(plaintext);
      }

      let keyForFragment = encrypted.key;
      let passwordSalt: string | null = null;
      let passwordVerifier: string | null = null;

      if (passwordProtected) {
        const wrapped = await wrapKeyWithPassword(encrypted.key, password);
        keyForFragment = `${wrapped.wrappedKey}.${wrapped.wrapIv}`;
        passwordSalt = wrapped.salt;
        passwordVerifier = wrapped.passwordVerifier;
      }

      const response = await createSecret({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        secret_type: secretType,
        expires_in_seconds: expiresIn,
        one_time: oneTime,
        password_protected: passwordProtected,
        password_salt: passwordSalt,
        password_verifier: passwordVerifier,
        file_name: secretType === 'file' ? selectedFile!.name : null,
        file_size: secretType === 'file' ? selectedFile!.size : null,
        file_type: secretType === 'file' ? (selectedFile!.type || 'application/octet-stream') : null,
      });

      const fragmentData = passwordProtected
        ? `${keyForFragment}.${passwordSalt}`
        : keyForFragment;

      sessionStorage.setItem(`vd_key_${response.id}`, fragmentData);
      sessionStorage.setItem(`vd_exp_${response.id}`, response.expires_at);
      
      // Save creator token for management dashboard
      const existingTokens = JSON.parse(localStorage.getItem('vd_creator_tokens') || '{}');
      existingTokens[response.id] = response.creator_token;
      localStorage.setItem('vd_creator_tokens', JSON.stringify(existingTokens));
      
      navigate(`/created/${response.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create secret.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fade-in">
      <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '1.5rem' }}>
        🔒 Create Secure Secret
      </h1>

      <form onSubmit={handleSubmit} className="card">
        {/* Secret Type Selector */}
        <div className="form-group">
          <label className="form-label">Secret Type</label>
          <div className="pill-group" role="radiogroup" aria-label="Secret type">
            {(Object.keys(SECRET_TYPE_LABELS) as SecretType[]).map((type) => (
              <button
                key={type}
                type="button"
                role="radio"
                aria-checked={secretType === type}
                className={`pill ${secretType === type ? 'active' : ''}`}
                onClick={() => {
                  setSecretType(type);
                  setError('');
                }}
              >
                {SECRET_TYPE_LABELS[type]}
              </button>
            ))}
          </div>
        </div>

        {/* Dynamic Fields */}
        {secretType === 'api_key' && (
          <>
            <div className="form-group">
              <label htmlFor="api-service" className="form-label">Service (optional)</label>
              <input
                id="api-service"
                type="text"
                className="form-input"
                placeholder="e.g. OpenAI, Stripe, AWS"
                value={apiService}
                onChange={(e) => setApiService(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label htmlFor="api-key" className="form-label">API Key</label>
              <input
                id="api-key"
                type="text"
                className="form-input"
                placeholder="sk-..."
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                style={{ fontFamily: 'var(--font-mono)' }}
              />
            </div>
          </>
        )}

        {secretType === 'password' && (
          <>
            <div className="form-group">
              <label htmlFor="pw-username" className="form-label">Username / Email (optional)</label>
              <input
                id="pw-username"
                type="text"
                className="form-input"
                placeholder="user@example.com"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label htmlFor="pw-value" className="form-label">Password</label>
              <input
                id="pw-value"
                type="text"
                className="form-input"
                placeholder="Password to share"
                value={passwordValue}
                onChange={(e) => setPasswordValue(e.target.value)}
                style={{ fontFamily: 'var(--font-mono)' }}
              />
            </div>
          </>
        )}

        {(secretType === 'text' || secretType === 'env' || secretType === 'json' || secretType === 'code' || secretType === 'markdown') && (
          <div className="form-group">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <label htmlFor="secret-content" className="form-label" style={{ marginBottom: 0 }}>
                {secretType === 'env' ? '.env Variables' : secretType === 'json' ? 'JSON Content' : secretType === 'code' ? 'Code Snippet' : secretType === 'markdown' ? 'Markdown Content' : 'Secret Content'}
              </label>
              <span style={{
                fontSize: '0.75rem',
                color: currentPayloadSize > 80_000 ? 'var(--danger)' : currentPayloadSize > 50_000 ? 'var(--warning)' : 'var(--text-muted)',
                fontWeight: currentPayloadSize > 80_000 ? 600 : 400,
              }}>
                {(currentPayloadSize / 1024).toFixed(1)} KB / 100 KB
              </span>
            </div>
            <textarea
              id="secret-content"
              className="form-textarea"
              placeholder={
                secretType === 'env'
                  ? 'DATABASE_URL=postgresql://...\nAPI_KEY=...\nSECRET_KEY=...'
                  : secretType === 'json'
                  ? '{\n  "token": "secret_value"\n}'
                  : secretType === 'code'
                  ? 'function authenticate() {\n  const secret = "...";\n}'
                  : secretType === 'markdown'
                  ? '# Confidential Notes\n\n- Sensitive details here...'
                  : 'Enter secret text here...'
              }
              value={secretContent}
              onChange={(e) => setSecretContent(e.target.value)}
            />
            {/* Payload Size Progress Bar */}
            <div className="progress-bar-track">
              <div
                className="progress-bar-fill"
                style={{
                  width: `${payloadPercent}%`,
                  background: payloadPercent > 80 ? 'var(--danger)' : payloadPercent > 50 ? 'var(--warning)' : 'var(--accent)',
                }}
              />
            </div>
          </div>
        )}

        {secretType === 'file' && (
          <div className="form-group fade-in">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <label className="form-label" style={{ marginBottom: 0 }}>
                File to Encrypt (Code, Markdown, Text, Configs, or Binaries)
              </label>
              <span style={{
                fontSize: '0.75rem',
                color: currentPayloadSize > 12_000_000 ? 'var(--danger)' : currentPayloadSize > 10_000_000 ? 'var(--warning)' : 'var(--text-muted)',
                fontWeight: currentPayloadSize > 12_000_000 ? 600 : 400,
              }}>
                {(currentPayloadSize / 1024 / 1024).toFixed(2)} MB / 15 MB
              </span>
            </div>
            
            <div className="file-drop-area" style={{
              border: '2px dashed var(--border)',
              borderRadius: 'var(--radius-md)',
              padding: '2rem',
              textAlign: 'center',
              background: 'var(--bg-input)',
              cursor: 'pointer',
              position: 'relative'
            }}>
              <input 
                type="file" 
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                style={{
                  position: 'absolute',
                  inset: 0,
                  opacity: 0,
                  cursor: 'pointer'
                }}
              />
              <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>📁</div>
              {selectedFile ? (
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--accent)', marginBottom: '0.25rem' }}>
                    {selectedFile.name}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {(selectedFile.size / 1024).toFixed(1)} KB ({selectedFile.type || 'plain file'})
                  </div>
                </div>
              ) : (
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
                    Click or drag file here (.md, .py, .ts, .js, .env, .json, .yaml, or any file)
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Max 15MB. Encrypted locally with AES-256-GCM before upload.
                  </div>
                </div>
              )}
            </div>

            <div className="progress-bar-track" style={{ marginTop: '0.5rem' }}>
              <div
                className="progress-bar-fill"
                style={{
                  width: `${payloadPercent}%`,
                  background: payloadPercent > 80 ? 'var(--danger)' : payloadPercent > 50 ? 'var(--warning)' : 'var(--accent)',
                }}
              />
            </div>
          </div>
        )}

        {/* Intelligent Risk Analysis Warning Banner */}
        {detectionResult.detected && (
          <div className={`risk-card risk-card-${detectionResult.riskLevel?.toLowerCase() || 'medium'} fade-in`}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontSize: '1.25rem' }}>⚠️</span>
                <strong style={{ fontSize: '1rem', color: 'var(--text-primary)' }}>{detectionResult.title}</strong>
              </div>
              <span className={`risk-badge risk-badge-${detectionResult.riskLevel?.toLowerCase() || 'medium'}`}>
                Risk Level: {detectionResult.riskLevel}
              </span>
            </div>

            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.75rem', lineHeight: 1.5 }}>
              {detectionResult.explanation}
            </p>

            <div style={{ background: 'var(--bg-input)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-sm)', marginBottom: '0.75rem' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
                Recommended Security Settings:
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                {detectionResult.recommendations.map((rec, i) => (
                  <li key={i} style={{ marginBottom: '0.15rem' }}>{rec}</li>
                ))}
              </ul>
            </div>

            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={applyRecommendations}
              style={{ width: '100%', fontSize: '0.85rem' }}
            >
              ✨ Apply Recommended Security Settings (Burn + 5min + Password)
            </button>
          </div>
        )}

        {/* Expiration */}
        <div className="form-group">
          <label className="form-label">Expiration</label>
          <div className="pill-group" role="radiogroup" aria-label="Expiration time">
            {EXPIRATION_OPTIONS.map((opt) => (
              <button
                key={opt.seconds}
                type="button"
                role="radio"
                aria-checked={expiresIn === opt.seconds}
                className={`pill ${expiresIn === opt.seconds ? 'active' : ''}`}
                onClick={() => setExpiresIn(opt.seconds)}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* One-time toggle */}
        <div className="toggle-group">
          <label className="toggle">
            <input
              type="checkbox"
              checked={oneTime}
              onChange={(e) => setOneTime(e.target.checked)}
            />
            <span className="toggle-slider" />
          </label>
          <div>
            <span className="toggle-label">Destroy after first view (Burn after reading)</span>
            <div className="toggle-desc">Link permanently self-destructs after being viewed once</div>
          </div>
        </div>

        {/* Password toggle */}
        <div className="toggle-group">
          <label className="toggle">
            <input
              type="checkbox"
              checked={passwordProtected}
              onChange={(e) => {
                setPasswordProtected(e.target.checked);
                if (!e.target.checked) {
                  setPassword('');
                  setConfirmPassword('');
                }
              }}
            />
            <span className="toggle-slider" />
          </label>
          <div>
            <span className="toggle-label">Password protect</span>
            <div className="toggle-desc">Recipient must provide a password to unlock</div>
          </div>
        </div>

        {passwordProtected && (
          <div className="fade-in" style={{ marginTop: '0.5rem' }}>
            <div className="form-group">
              <label htmlFor="protect-pw" className="form-label">Password</label>
              <input
                id="protect-pw"
                type="password"
                className="form-input"
                placeholder="Set password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
              />
              {/* Password Strength Meter */}
              {password && (
                <div className="strength-meter">
                  <div className="strength-bar-track">
                    {[1, 2, 3, 4].map((level) => (
                      <div
                        key={level}
                        className="strength-bar-segment"
                        style={{
                          background: level <= passwordStrength.level ? passwordStrength.color : 'var(--bg-hover)',
                        }}
                      />
                    ))}
                  </div>
                  <span className="strength-label" style={{ color: passwordStrength.color }}>
                    {passwordStrength.label}
                  </span>
                </div>
              )}
            </div>
            <div className="form-group">
              <label htmlFor="protect-pw-confirm" className="form-label">Confirm Password</label>
              <input
                id="protect-pw-confirm"
                type="password"
                className="form-input"
                placeholder="Confirm password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
              />
              {confirmPassword && password !== confirmPassword && (
                <div className="form-error">Passwords do not match</div>
              )}
            </div>
          </div>
        )}

        {/* Security Score */}
        <SecurityScore 
          passwordProtected={passwordProtected} 
          expiresInSeconds={expiresIn} 
          oneTime={oneTime} 
        />

        {error && (
          <div className="banner banner-danger" style={{ marginBottom: '1rem', marginTop: '1rem' }}>
            <span className="banner-icon">⚠️</span>
            <span>{error}</span>
          </div>
        )}

        <button
          type="submit"
          className="btn btn-primary btn-lg btn-glow"
          disabled={loading}
          style={{ width: '100%', marginTop: '1.5rem' }}
        >
          {loading ? (
            <>
              <span className="spinner" /> Encrypting Locally...
            </>
          ) : (
            '🔐 Create Secure Link'
          )}
        </button>
      </form>
    </div>
  );
}

