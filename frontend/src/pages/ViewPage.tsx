import { useEffect, useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { decryptSecret, decryptBytes, unwrapKeyWithPassword } from '../crypto';
import { getSecret, consumeSecret, destroySecret, recordFailedAttempt, ApiError } from '../services/api';
import { useToast } from '../components/Toast';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import ReactMarkdown from 'react-markdown';
import type { SecretResponse } from '../types';
import { SECRET_TYPE_LABELS } from '../types';

type ViewState =
  | 'loading'
  | 'password-required'
  | 'decrypted'
  | 'expired'
  | 'destroyed'
  | 'locked'
  | 'not-found'
  | 'error'
  | 'missing-key';

function useCountdown(targetDate: string | null) {
  const [remaining, setRemaining] = useState('');

  useEffect(() => {
    if (!targetDate) return;

    function update() {
      const diff = new Date(targetDate!).getTime() - Date.now();
      if (diff <= 0) {
        setRemaining('Expired');
        return;
      }
      const d = Math.floor(diff / 86400000);
      const h = Math.floor((diff % 86400000) / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      const s = Math.floor((diff % 60000) / 1000);

      if (d > 0) setRemaining(`${d}d ${h}h ${m}m ${s}s`);
      else if (h > 0) setRemaining(`${h}h ${m}m ${s}s`);
      else setRemaining(`${m}m ${s}s`);
    }

    update();
    const timer = setInterval(update, 1000);
    return () => clearInterval(timer);
  }, [targetDate]);

  return remaining;
}

function getFileLanguage(fileName: string | null | undefined): string | null {
  if (!fileName) return null;
  const ext = fileName.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'js':
    case 'jsx':
    case 'mjs':
    case 'cjs':
      return 'javascript';
    case 'ts':
    case 'tsx':
      return 'typescript';
    case 'py':
      return 'python';
    case 'json':
      return 'json';
    case 'html':
    case 'htm':
      return 'html';
    case 'css':
      return 'css';
    case 'yaml':
    case 'yml':
      return 'yaml';
    case 'sh':
    case 'bash':
    case 'zsh':
      return 'bash';
    case 'env':
      return 'properties';
    case 'cpp':
    case 'cc':
    case 'cxx':
      return 'cpp';
    case 'c':
    case 'h':
      return 'c';
    case 'java':
      return 'java';
    case 'sql':
      return 'sql';
    case 'md':
    case 'markdown':
      return 'markdown';
    default:
      return null;
  }
}

export default function ViewPage() {
  const { id } = useParams<{ id: string }>();
  const { showToast } = useToast();

  const [state, setState] = useState<ViewState>('loading');
  const [secretData, setSecretData] = useState<SecretResponse | null>(null);
  const [plaintext, setPlaintext] = useState('');
  const [fileBytes, setFileBytes] = useState<Uint8Array | null>(null);
  const [fileText, setFileText] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [destroying, setDestroying] = useState(false);
  const [unlocking, setUnlocking] = useState(false);

  const countdown = useCountdown(secretData?.expires_at ?? null);
  const fileLanguage = useMemo(() => getFileLanguage(secretData?.file_name), [secretData?.file_name]);

  useEffect(() => {
    if (!id) return;

    const fragment = window.location.hash.slice(1);
    if (!fragment) {
      setState('missing-key');
      return;
    }

    fetchAndDecrypt(id, fragment);
  }, [id]);

  async function fetchAndDecrypt(secretId: string, fragment: string) {
    try {
      let data: SecretResponse;

      try {
        data = await getSecret(secretId);
      } catch (err) {
        if (err instanceof ApiError) {
          if (err.status === 404) {
            setState('not-found');
            return;
          }
          if (err.status === 423) {
            setState('locked');
            return;
          }
          if (err.status === 410) {
            if (err.message.toLowerCase().includes('expired')) {
              setState('expired');
            } else {
              setState('destroyed');
            }
            return;
          }
        }
        throw err;
      }

      setSecretData(data);

      if (data.is_locked) {
        setState('locked');
        return;
      }

      // If password-protected, prompt for password before consumption
      if (data.password_protected) {
        setState('password-required');
        return;
      }

      // Non-password one-time secrets: consume immediately
      if (data.one_time) {
        try {
          data = await consumeSecret(secretId);
          setSecretData(data);
        } catch (err) {
          if (err instanceof ApiError && err.status === 410) {
            setState('destroyed');
            return;
          }
          if (err instanceof ApiError && err.status === 423) {
            setState('locked');
            return;
          }
          throw err;
        }
      }

      if (data.secret_type === 'file') {
        const result = await decryptBytes(data.ciphertext, data.iv, fragment);
        setFileBytes(result.plaintextBytes);
        try {
          const text = new TextDecoder('utf-8', { fatal: true }).decode(result.plaintextBytes);
          setFileText(text);
        } catch {
          setFileText(null);
        }
      } else {
        const result = await decryptSecret(data.ciphertext, data.iv, fragment);
        setPlaintext(formatPlaintext(result.plaintext, data.secret_type));
      }
      setState('decrypted');
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Decryption failed.');
      setState('error');
    }
  }

  async function handlePasswordSubmit(e: React.FormEvent) {
    e.preventDefault();
    setPasswordError('');

    if (!secretData || !id) return;

    const fragment = window.location.hash.slice(1);
    setUnlocking(true);

    try {
      const parts = fragment.split('.');
      if (parts.length < 3) {
        setPasswordError('Invalid key payload format.');
        setUnlocking(false);
        return;
      }

      const [wrappedKey, wrapIv, salt] = parts;
      const dataKey = await unwrapKeyWithPassword(wrappedKey, wrapIv, salt, password);

      // Consume after successful password verification
      let dataToDecrypt = secretData;
      if (secretData.one_time) {
        try {
          dataToDecrypt = await consumeSecret(id);
          setSecretData(dataToDecrypt);
        } catch (err) {
          if (err instanceof ApiError && err.status === 410) {
            setState('destroyed');
            return;
          }
          if (err instanceof ApiError && err.status === 423) {
            setState('locked');
            return;
          }
          throw err;
        }
      }

      if (dataToDecrypt.secret_type === 'file') {
        const result = await decryptBytes(dataToDecrypt.ciphertext, dataToDecrypt.iv, dataKey);
        setFileBytes(result.plaintextBytes);
        try {
          const text = new TextDecoder('utf-8', { fatal: true }).decode(result.plaintextBytes);
          setFileText(text);
        } catch {
          setFileText(null);
        }
      } else {
        const result = await decryptSecret(dataToDecrypt.ciphertext, dataToDecrypt.iv, dataKey);
        setPlaintext(formatPlaintext(result.plaintext, dataToDecrypt.secret_type));
      }
      setState('decrypted');
    } catch {
      setPasswordError('Incorrect password or corrupted link.');
      // Report failed attempt to backend for anomaly & security monitoring
      recordFailedAttempt(id, 'Incorrect password attempt').catch(() => {});
    } finally {
      setUnlocking(false);
    }
  }

  async function handleDestroy() {
    if (!id) return;
    setDestroying(true);
    try {
      await destroySecret(id);
      showToast('Secret permanently destroyed', 'success');
      setState('destroyed');
    } catch {
      setState('destroyed');
    }
  }

  async function copySecret() {
    const textToCopy = plaintext || fileText || '';
    try {
      await navigator.clipboard.writeText(textToCopy);
      showToast('Secret copied to clipboard!', 'success');
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = textToCopy;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showToast('Secret copied to clipboard!', 'success');
    }
  }

  async function downloadFile() {
    if (!fileBytes || !secretData) return;
    const blob = new Blob([fileBytes as unknown as BlobPart], { type: secretData.file_type || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = secretData.file_name || 'vaultdrop-file';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Download started', 'success');
  }

  function formatPlaintext(text: string, type: string): string {
    if (type === 'json') {
      try {
        return JSON.stringify(JSON.parse(text), null, 2);
      } catch {
        return text;
      }
    }
    if (type === 'api_key' || type === 'password') {
      try {
        const parsed = JSON.parse(text);
        return Object.entries(parsed)
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n');
      } catch {
        return text;
      }
    }
    return text;
  }

  if (state === 'loading') {
    return (
      <div className="loading-center">
        <div className="spinner" />
      </div>
    );
  }

  if (state === 'missing-key') {
    return (
      <div className="status-page fade-in">
        <div className="status-icon">🔑</div>
        <h2 className="status-title">Missing Decryption Key</h2>
        <p className="status-subtitle">
          The link does not contain the required key in the URL fragment.
        </p>
        <Link to="/create" className="btn btn-primary">Create New Secret</Link>
      </div>
    );
  }

  if (state === 'not-found') {
    return (
      <div className="status-page fade-in">
        <div className="status-icon">🔍</div>
        <h2 className="status-title">Secret Not Found</h2>
        <p className="status-subtitle">
          This secret does not exist or has already been removed.
        </p>
        <Link to="/create" className="btn btn-primary">Create New Secret</Link>
      </div>
    );
  }

  if (state === 'locked') {
    return (
      <div className="status-page fade-in">
        <div className="status-icon">🔒</div>
        <h2 className="status-title">Secret Locked</h2>
        <p className="status-subtitle">
          This secret is currently locked by the owner. Access is temporarily suspended.
        </p>
        <Link to="/create" className="btn btn-primary">Create New Secret</Link>
      </div>
    );
  }

  if (state === 'expired') {
    return (
      <div className="status-page fade-in">
        <div className="status-icon">⏰</div>
        <h2 className="status-title">Secret Expired</h2>
        <p className="status-subtitle">
          The lifetime for this secret has elapsed. It can no longer be accessed.
        </p>
        <Link to="/create" className="btn btn-primary">Create New Secret</Link>
      </div>
    );
  }

  if (state === 'destroyed') {
    return (
      <div className="status-page fade-in">
        <div className="status-icon">💥</div>
        <h2 className="status-title">Secret Destroyed</h2>
        <p className="status-subtitle">
          This secret has already been viewed or permanently deleted.
        </p>
        <Link to="/create" className="btn btn-primary">Create New Secret</Link>
      </div>
    );
  }

  if (state === 'error') {
    return (
      <div className="status-page fade-in">
        <div className="status-icon">❌</div>
        <h2 className="status-title">Decryption Failed</h2>
        <p className="status-subtitle">{errorMessage}</p>
        <Link to="/create" className="btn btn-primary">Create New Secret</Link>
      </div>
    );
  }

  if (state === 'password-required') {
    return (
      <div className="fade-in" style={{ maxWidth: '480px', margin: '2rem auto' }}>
        <div className="card card-accent">
          <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
            <div style={{ fontSize: '2.5rem', marginBottom: '0.75rem' }}>🔒</div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Password Required</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.5rem' }}>
              Enter the password provided by the sender to decrypt this secret locally.
            </p>
          </div>

          <form onSubmit={handlePasswordSubmit}>
            <div className="form-group">
              <label htmlFor="view-password" className="form-label">Password</label>
              <input
                id="view-password"
                type="password"
                className="form-input"
                placeholder="Enter password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoFocus
                autoComplete="off"
              />
            </div>

            {passwordError && (
              <div className="banner banner-danger" style={{ marginBottom: '1rem' }}>
                <span className="banner-icon">⚠️</span>
                <span>{passwordError}</span>
              </div>
            )}

            <button
              type="submit"
              className="btn btn-primary btn-glow"
              style={{ width: '100%' }}
              disabled={unlocking}
            >
              {unlocking ? (
                <>
                  <span className="spinner" /> Decrypting...
                </>
              ) : (
                '🔓 Unlock & Decrypt'
              )}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="fade-in">
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>
            🔓 Decrypted Secret
          </h2>
          <span className="security-badge">
            {SECRET_TYPE_LABELS[secretData?.secret_type || 'text']}
          </span>
        </div>

        {/* Countdown Timer */}
        {countdown && !secretData?.one_time && countdown !== 'Expired' && (
          <div className="countdown-banner" style={{ marginBottom: '1rem' }}>
            <span className="countdown-icon">⏱</span>
            <div>
              <span className="countdown-label">Expires in</span>
              <span className="countdown-value">{countdown}</span>
            </div>
          </div>
        )}

        {secretData?.one_time && (
          <div className="banner banner-warning" style={{ marginBottom: '1rem' }}>
            <span className="banner-icon">⚠️</span>
            <span>This is a one-time secret. It has been consumed and permanently destroyed.</span>
          </div>
        )}

        {secretData?.secret_type === 'file' ? (
          <div style={{ marginTop: '1.5rem' }}>
            <div className="card card-accent" style={{ textAlign: 'center', padding: '2rem', marginBottom: '1.5rem' }}>
              <div style={{ fontSize: '2.5rem', marginBottom: '0.75rem' }}>📁</div>
              <h3 style={{ marginBottom: '0.25rem' }}>{secretData.file_name}</h3>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '1.25rem', fontSize: '0.9rem' }}>
                {(secretData.file_size || 0) > 0 ? ((secretData.file_size || 0) / 1024 / 1024).toFixed(2) + ' MB' : 'Decrypted file'} • {secretData.file_type || 'binary'}
              </p>
              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn btn-primary btn-lg btn-glow"
                  onClick={downloadFile}
                >
                  ⬇️ Download Original File
                </button>
                {fileText && (
                  <button
                    type="button"
                    className="btn btn-secondary btn-lg"
                    onClick={copySecret}
                  >
                    📋 Copy File Content
                  </button>
                )}
              </div>
            </div>

            {/* In-browser preview for code and markdown files */}
            {fileText && fileLanguage === 'markdown' ? (
              <div className="secret-display" style={{ padding: '2rem', marginTop: '1rem' }}>
                <ReactMarkdown>{fileText}</ReactMarkdown>
              </div>
            ) : fileText && fileLanguage ? (
              <div style={{ borderRadius: 'var(--radius-sm)', overflow: 'hidden', border: '1px solid var(--border)', marginTop: '1rem' }}>
                <div style={{ background: 'var(--bg-hover)', padding: '0.5rem 1rem', fontSize: '0.8rem', color: 'var(--text-muted)', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between' }}>
                  <span>Code Preview ({fileLanguage})</span>
                  <span>{secretData.file_name}</span>
                </div>
                <SyntaxHighlighter 
                  language={fileLanguage}
                  style={vscDarkPlus}
                  customStyle={{ margin: 0, padding: '1rem', background: 'var(--bg-input)', fontSize: '0.85rem' }}
                  showLineNumbers={true}
                >
                  {fileText}
                </SyntaxHighlighter>
              </div>
            ) : fileText ? (
              <div className="secret-display" style={{ marginTop: '1rem' }}>{fileText}</div>
            ) : null}
          </div>
        ) : secretData?.secret_type === 'json' || secretData?.secret_type === 'env' || secretData?.secret_type === 'code' ? (
          <div style={{ marginTop: '1.5rem', borderRadius: 'var(--radius-sm)', overflow: 'hidden', border: '1px solid var(--border)' }}>
            <SyntaxHighlighter 
              language={secretData.secret_type === 'json' ? 'json' : secretData.secret_type === 'env' ? 'properties' : 'javascript'}
              style={vscDarkPlus}
              customStyle={{ margin: 0, padding: '1rem', background: 'var(--bg-input)', fontSize: '0.9rem' }}
              showLineNumbers={true}
            >
              {plaintext}
            </SyntaxHighlighter>
          </div>
        ) : secretData?.secret_type === 'markdown' ? (
          <div className="secret-display" style={{ padding: '2rem' }}>
            <ReactMarkdown>{plaintext}</ReactMarkdown>
          </div>
        ) : (
          <div className="secret-display">{plaintext}</div>
        )}

        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.25rem', flexWrap: 'wrap' }}>
          {secretData?.secret_type !== 'file' && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={copySecret}
            >
              📋 Copy Secret
            </button>
          )}

          {!secretData?.one_time && (
            <button
              type="button"
              className="btn btn-danger"
              onClick={handleDestroy}
              disabled={destroying}
            >
              {destroying ? 'Destroying...' : '🗑️ Destroy Now'}
            </button>
          )}

          <Link to="/create" className="btn btn-ghost">
            ➕ Create New
          </Link>
        </div>
      </div>
    </div>
  );
}

