import { useEffect, useState, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { QRCodeSVG } from 'qrcode.react';
import { useToast } from '../components/Toast';

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

export default function CreatedPage() {
  const { id } = useParams<{ id: string }>();
  const [shareUrl, setShareUrl] = useState('');
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const [keyUnavailable, setKeyUnavailable] = useState(false);
  const qrRef = useRef<HTMLDivElement>(null);
  const { showToast } = useToast();
  const countdown = useCountdown(expiresAt);

  useEffect(() => {
    if (!id) return;

    // The encryption key never touches the server — it only ever lives in this
    // browser's sessionStorage (set at creation time in CreatePage). We read it
    // here WITHOUT deleting it, so that navigating back to this page later (e.g.
    // via Dashboard -> Manage -> View URL/QR) can still reconstruct the original
    // share link for the lifetime of this browser session.
    const keyData = sessionStorage.getItem(`vd_key_${id}`);
    const exp = sessionStorage.getItem(`vd_exp_${id}`);

    if (exp) {
      setExpiresAt(exp);
      sessionStorage.removeItem(`vd_exp_${id}`);
    }

    if (!keyData) {
      // Zero-knowledge architecture: the key was never sent to or stored by the
      // backend, so if it's no longer in this browser's session storage (e.g. a
      // different browser/session, or the tab was closed and reopened), there is
      // no way to recover it. Surface that clearly instead of generating a share
      // link/QR code that's missing the decryption key fragment.
      setKeyUnavailable(true);
      setShareUrl(`${window.location.origin}/s/${id}`);
      return;
    }

    const url = `${window.location.origin}/s/${id}#${keyData}`;
    setShareUrl(url);
  }, [id]);

  async function copyToClipboard() {
    try {
      await navigator.clipboard.writeText(shareUrl);
      showToast('Link copied to clipboard!', 'success');
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = shareUrl;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showToast('Link copied to clipboard!', 'success');
    }
  }

  function downloadQR() {
    if (!qrRef.current) return;
    const svg = qrRef.current.querySelector('svg');
    if (!svg) return;

    const svgData = new XMLSerializer().serializeToString(svg);
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const img = new Image();

    img.onload = () => {
      canvas.width = 400;
      canvas.height = 400;
      if (ctx) {
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 20, 20, 360, 360);
        const pngFile = canvas.toDataURL('image/png');
        const downloadLink = document.createElement('a');
        downloadLink.download = `vaultdrop-qr-${id?.slice(0, 8)}.png`;
        downloadLink.href = pngFile;
        downloadLink.click();
      }
    };
    img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
  }

  if (!shareUrl) {
    return (
      <div className="status-page fade-in">
        <div className="status-icon">⏳</div>
        <h2 className="status-title">Loading...</h2>
      </div>
    );
  }

  return (
    <div className="fade-in">
      <div className="card card-accent">
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{ fontSize: '3rem', marginBottom: '0.75rem' }}>✅</div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.5rem' }}>
            Your secure secret is ready
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
            Share this link with the recipient. The key is in the link and never sent to the server.
          </p>
        </div>

        {/* Countdown Timer */}
        {countdown && (
          <div className="countdown-banner">
            <span className="countdown-icon">⏱</span>
            <div>
              <span className="countdown-label">Expires in</span>
              <span className="countdown-value">{countdown}</span>
            </div>
          </div>
        )}

        {keyUnavailable ? (
          <div className="banner banner-danger" style={{ marginBottom: '1rem' }}>
            <span className="banner-icon">⚠️</span>
            <div>
              <strong>Decryption key not available in this session.</strong> VaultDrop never
              sends or stores the key on the server, so it can only be recovered from the
              browser session that created this secret. Use the original share link or QR
              code you saved when this secret was first created.
            </div>
          </div>
        ) : (
          <>
            {/* Share Link Box */}
            <div className="form-group">
              <label className="form-label">Secret Share Link</label>
              <div className="copy-area">
                <span className="copy-area-text">{shareUrl}</span>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={copyToClipboard}
                  aria-label="Copy link to clipboard"
                >
                  📋 Copy
                </button>
              </div>
            </div>

            {/* QR Code Section */}
            <div style={{ textAlign: 'center', margin: '1.5rem 0' }}>
              <label className="form-label" style={{ textAlign: 'center', marginBottom: '0.75rem' }}>
                Mobile QR Transfer
              </label>
              <div ref={qrRef} className="qr-container">
                <QRCodeSVG
                  value={shareUrl}
                  size={180}
                  bgColor="#ffffff"
                  fgColor="#0a0e17"
                  level="M"
                />
              </div>
              <div style={{ marginTop: '0.75rem' }}>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={downloadQR}
                >
                  📥 Download QR Image
                </button>
              </div>
            </div>
          </>
        )}

        {/* Warning Banner */}
        {!keyUnavailable && (
          <div className="banner banner-warning" style={{ marginTop: '1rem' }}>
            <span className="banner-icon">⚠️</span>
            <div>
              <strong>Security Notice:</strong> Anyone with this link can decrypt the secret.
              VaultDrop does not store this link or key.
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.5rem', flexWrap: 'wrap' }}>
          <Link to="/create" className="btn btn-secondary" style={{ flex: 1 }}>
            ➕ Create Another
          </Link>
          <Link to="/" className="btn btn-ghost" style={{ flex: 1 }}>
            🏠 Home
          </Link>
        </div>
      </div>
    </div>
  );
}
