import { useEffect, useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  getMySecretsOverview,
  getSecretEvents,
  revokeSecret,
  lockSecret,
  updateSecretSettings,
  emergencyRevokeAll,
} from '../services/api';
import { useToast } from '../components/Toast';
import type {
  SecretActivityResponse,
  SecretEvent,
  DashboardOverviewResponse,
  SecretStatus,
} from '../types';
import { SECRET_TYPE_LABELS, EXPIRATION_OPTIONS } from '../types';

export default function DashboardPage() {
  const { showToast } = useToast();
  const [overview, setOverview] = useState<DashboardOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Modals state
  const [selectedSecret, setSelectedSecret] = useState<SecretActivityResponse | null>(null);
  const [secretEvents, setSecretEvents] = useState<SecretEvent[]>([]);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [showEmergencyModal, setShowEmergencyModal] = useState(false);
  const [emergencyLoading, setEmergencyLoading] = useState(false);

  // Edit settings form inside modal
  const [editMaxViews, setEditMaxViews] = useState(1);
  const [editExpiresIn, setEditExpiresIn] = useState(3600);
  const [editOneTime, setEditOneTime] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);

  const pollingRef = useRef<number | null>(null);

  useEffect(() => {
    fetchDashboard(true);

    // Poll every 5 seconds for real-time live updates
    pollingRef.current = window.setInterval(() => {
      fetchDashboard(false);
    }, 5000);

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, []);

  async function fetchDashboard(isInitial = false) {
    try {
      const storedTokens = JSON.parse(localStorage.getItem('vd_creator_tokens') || '{}');
      const tokens = Object.values(storedTokens) as string[];

      if (tokens.length === 0) {
        setOverview({
          active_secrets: 0,
          total_views: 0,
          failed_attempts: 0,
          suspicious_events: 0,
          secrets: [],
          recent_events: [],
        });
        if (isInitial) setLoading(false);
        return;
      }

      const data = await getMySecretsOverview(tokens);
      setOverview(data);
      if (isInitial) setLoading(false);
    } catch {
      if (isInitial) setError('Failed to load secrets dashboard.');
      if (isInitial) setLoading(false);
    }
  }

  function getStoredToken(secretId: string): string | null {
    const storedTokens = JSON.parse(localStorage.getItem('vd_creator_tokens') || '{}');
    return storedTokens[secretId] || null;
  }

  async function handleOpenManage(secret: SecretActivityResponse) {
    setSelectedSecret(secret);
    setEditMaxViews(secret.max_views);
    setEditOneTime(secret.one_time);
    setSecretEvents([]);
    setLoadingEvents(true);

    const token = getStoredToken(secret.id);
    if (token) {
      try {
        const events = await getSecretEvents(secret.id, token);
        setSecretEvents(events);
      } catch {
        // Silently handle event fetch error
      } finally {
        setLoadingEvents(false);
      }
    } else {
      setLoadingEvents(false);
    }
  }

  async function handleRevoke(id: string) {
    if (!window.confirm('Are you sure you want to revoke this secret permanently?')) {
      return;
    }

    try {
      const token = getStoredToken(id);
      if (!token) throw new Error('Creator token missing');

      await revokeSecret(id, token);
      showToast('Secret revoked successfully', 'success');
      if (selectedSecret?.id === id) {
        setSelectedSecret(null);
      }
      fetchDashboard(false);
    } catch {
      showToast('Failed to revoke secret', 'error');
    }
  }

  async function handleToggleLock(secret: SecretActivityResponse) {
    try {
      const token = getStoredToken(secret.id);
      if (!token) throw new Error('Creator token missing');

      const nextLockState = !secret.is_locked;
      await lockSecret(secret.id, token, nextLockState);
      showToast(nextLockState ? 'Secret locked (access suspended)' : 'Secret unlocked (access restored)', 'success');
      
      if (selectedSecret?.id === secret.id) {
        setSelectedSecret({ ...secret, is_locked: nextLockState });
      }
      fetchDashboard(false);
    } catch {
      showToast('Failed to update secret lock state', 'error');
    }
  }

  async function handleSaveSettings(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedSecret) return;

    setSavingSettings(true);
    try {
      const token = getStoredToken(selectedSecret.id);
      if (!token) throw new Error('Creator token missing');

      await updateSecretSettings(selectedSecret.id, token, {
        max_views: editMaxViews,
        expires_in_seconds: editExpiresIn,
        one_time: editOneTime,
      });

      showToast('Security settings updated successfully', 'success');
      fetchDashboard(false);
      handleOpenManage({
        ...selectedSecret,
        max_views: editOneTime ? 1 : editMaxViews,
        one_time: editOneTime,
      });
    } catch {
      showToast('Failed to update settings', 'error');
    } finally {
      setSavingSettings(false);
    }
  }

  async function handleEmergencyRevokeAll() {
    setEmergencyLoading(true);
    try {
      const storedTokens = JSON.parse(localStorage.getItem('vd_creator_tokens') || '{}');
      const tokens = Object.values(storedTokens) as string[];

      const result = await emergencyRevokeAll(tokens);
      showToast(`Emergency Lockdown complete: ${result.revoked_count} active secrets revoked`, 'success');
      setShowEmergencyModal(false);
      fetchDashboard(false);
    } catch {
      showToast('Failed to execute emergency revocation', 'error');
    } finally {
      setEmergencyLoading(false);
    }
  }

  function renderStatusBadge(status: SecretStatus, hasSuspicious: boolean) {
    if (hasSuspicious && status === 'active') {
      return <span className="status-pill status-pill-suspicious">⚠️ Suspicious</span>;
    }
    switch (status) {
      case 'active':
        return <span className="status-pill status-pill-active">✓ Active</span>;
      case 'locked':
        return <span className="status-pill status-pill-locked">🔒 Locked</span>;
      case 'burned':
        return <span className="status-pill status-pill-burned">💥 Burned</span>;
      case 'revoked':
        return <span className="status-pill status-pill-revoked">🚫 Revoked</span>;
      case 'expired':
        return <span className="status-pill status-pill-expired">⏱ Expired</span>;
      case 'suspicious':
        return <span className="status-pill status-pill-suspicious">⚠️ Suspicious</span>;
      default:
        return <span className="status-pill status-pill-active">{status}</span>;
    }
  }

  if (loading) {
    return (
      <div className="loading-center">
        <div className="spinner" />
      </div>
    );
  }

  const secrets = overview?.secrets || [];
  const suspiciousSecrets = secrets.filter((s) => s.has_suspicious_activity && s.status !== 'revoked' && s.status !== 'burned' && s.status !== 'expired');

  return (
    <div className="fade-in">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800 }}>
            🛡️ Secret Owner Control Center
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            Zero-knowledge encrypted secret lifecycle, access events, and security management.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => fetchDashboard(false)}
            title="Refresh dashboard"
          >
            🔄 Live Sync
          </button>
          <Link to="/create" className="btn btn-primary btn-sm">
            + Create Secret
          </Link>
        </div>
      </div>

      {error && (
        <div className="banner banner-danger" style={{ marginBottom: '1.5rem' }}>
          <span className="banner-icon">⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {/* Suspicious Activity Warning Banner */}
      {suspiciousSecrets.length > 0 && (
        <div className="risk-card risk-card-critical fade-in" style={{ marginBottom: '2rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontSize: '1.5rem' }}>⚠️</span>
              <div>
                <strong style={{ fontSize: '1rem', color: '#f87171' }}>Suspicious Activity Detected</strong>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  Multiple failed access attempts or repeated hits detected on {suspiciousSecrets.length} active secret(s).
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                type="button"
                className="btn btn-danger btn-sm"
                onClick={() => handleOpenManage(suspiciousSecrets[0])}
              >
                Review Threat ({suspiciousSecrets[0].id.slice(0, 8)}...)
              </button>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 1: OVERVIEW METRIC CARDS */}
      <div className="stats-grid">
        <div className="stat-card stat-card-active">
          <span className="stat-label">Active Secrets</span>
          <span className="stat-value" style={{ color: '#34d399' }}>
            {overview?.active_secrets ?? 0}
          </span>
        </div>

        <div className="stat-card stat-card-views">
          <span className="stat-label">Total Views</span>
          <span className="stat-value" style={{ color: 'var(--accent)' }}>
            {overview?.total_views ?? 0}
          </span>
        </div>

        <div className="stat-card stat-card-failed">
          <span className="stat-label">Failed Attempts</span>
          <span className="stat-value" style={{ color: '#fbbf24' }}>
            {overview?.failed_attempts ?? 0}
          </span>
        </div>

        <div className="stat-card stat-card-suspicious">
          <span className="stat-label">Suspicious Events</span>
          <span className="stat-value" style={{ color: '#f87171' }}>
            {overview?.suspicious_events ?? 0}
          </span>
        </div>
      </div>

      {/* SECTION 2: SECRETS TABLE */}
      <div className="card" style={{ padding: 0, overflow: 'hidden', marginBottom: '2.5rem' }}>
        <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Your Secrets</h2>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            {secrets.length} total created on this browser
          </span>
        </div>

        {secrets.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '4rem 2rem' }}>
            <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📭</div>
            <h3>No secrets active</h3>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem', fontSize: '0.9rem' }}>
              Secrets you create from this browser will appear here with live metrics and control actions.
            </p>
            <Link to="/create" className="btn btn-primary">Create your first secret</Link>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
              <thead>
                <tr style={{ background: 'var(--bg-hover)', borderBottom: '1px solid var(--border)' }}>
                  <th style={{ padding: '1rem', fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Secret / Type</th>
                  <th style={{ padding: '1rem', fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Views</th>
                  <th style={{ padding: '1rem', fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Expiry</th>
                  <th style={{ padding: '1rem', fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Status</th>
                  <th style={{ padding: '1rem', fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {secrets.map((secret) => {
                  const isAlive = secret.status === 'active' || secret.status === 'locked' || secret.status === 'suspicious';
                  return (
                    <tr key={secret.id} style={{ borderBottom: '1px solid var(--border)', transition: 'background var(--transition-fast)' }}>
                      <td style={{ padding: '1rem' }}>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                          {secret.file_name ? secret.file_name : `${secret.id.slice(0, 12)}...`}
                        </div>
                        <div style={{ marginTop: '0.2rem' }}>
                          <span className="security-badge" style={{ fontSize: '0.7rem', padding: '0.15rem 0.4rem' }}>
                            {SECRET_TYPE_LABELS[secret.secret_type] || secret.secret_type}
                          </span>
                        </div>
                      </td>

                      <td style={{ padding: '1rem', fontSize: '0.85rem' }}>
                        <div style={{ fontWeight: 600 }}>
                          {secret.successful_view_count ?? secret.view_count} / {secret.max_views}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {secret.access_attempt_count} attempts • {secret.failed_attempts} failed
                        </div>
                      </td>

                      <td style={{ padding: '1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        {secret.is_expired ? (
                          <span style={{ color: 'var(--text-muted)' }}>Expired</span>
                        ) : (
                          new Date(secret.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })
                        )}
                      </td>

                      <td style={{ padding: '1rem' }}>
                        {renderStatusBadge(secret.status, secret.has_suspicious_activity)}
                      </td>

                      <td style={{ padding: '1rem' }}>
                        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                          <button
                            type="button"
                            onClick={() => handleOpenManage(secret)}
                            className="btn btn-secondary btn-sm"
                            style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}
                          >
                            Manage
                          </button>

                          {isAlive && (
                            <button
                              type="button"
                              onClick={() => handleToggleLock(secret)}
                              className="btn btn-ghost btn-sm"
                              style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                              title={secret.is_locked ? 'Unlock secret' : 'Lock secret'}
                            >
                              {secret.is_locked ? '🔓 Unlock' : '🔒 Lock'}
                            </button>
                          )}

                          {isAlive && (
                            <button
                              type="button"
                              onClick={() => handleRevoke(secret.id)}
                              className="btn btn-danger btn-sm"
                              style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                              title="Revoke secret"
                            >
                              Revoke
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* SECTION 3: SECURITY ACTIVITY TIMELINE */}
      <div className="card" style={{ marginBottom: '2.5rem' }}>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.5rem' }}>
          🛡️ Security Activity Timeline
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
          Real-time privacy-preserving audit events for all secrets created from this browser.
        </p>

        {(!overview?.recent_events || overview.recent_events.length === 0) ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
            No recent activity logged yet.
          </div>
        ) : (
          <div className="timeline-container">
            {overview.recent_events.map((evt) => {
              const dotClass =
                evt.status === 'success'
                  ? 'timeline-dot-success'
                  : evt.status === 'warning'
                  ? 'timeline-dot-warning'
                  : evt.status === 'failure'
                  ? 'timeline-dot-danger'
                  : 'timeline-dot-info';

              const icon =
                evt.event_type === 'created'
                  ? '🔐'
                  : evt.event_type === 'view_success'
                  ? '🔓'
                  : evt.event_type === 'failed_attempt'
                  ? '❌'
                  : evt.event_type === 'suspicious_activity'
                  ? '⚠️'
                  : evt.event_type === 'locked'
                  ? '🔒'
                  : evt.event_type === 'unlocked'
                  ? '🔓'
                  : evt.event_type === 'revoked'
                  ? '🚫'
                  : evt.event_type === 'burned'
                  ? '💥'
                  : '👁️';

              return (
                <div key={evt.id} className="timeline-item">
                  <div className={`timeline-dot ${dotClass}`}>{icon}</div>
                  <div className="timeline-content">
                    <div className="timeline-header">
                      <span className="timeline-type">
                        {evt.event_type.replace('_', ' ')} • <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>{evt.secret_id.slice(0, 8)}...</span>
                      </span>
                      <span className="timeline-time">
                        {new Date(evt.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                    </div>
                    {evt.detail && <div className="timeline-detail">{evt.detail}</div>}
                    {evt.client_env && (
                      <span className="timeline-env">🌐 {evt.client_env}</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* SECTION 4: EMERGENCY CONTROLS */}
      <div className="card" style={{ border: '1px solid rgba(239, 68, 68, 0.4)', background: 'rgba(239, 68, 68, 0.04)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f87171', marginBottom: '0.25rem' }}>
              🚨 Emergency Controls
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              Instantly terminate access to all active links created from this browser session.
            </p>
          </div>
          <button
            type="button"
            className="btn btn-danger"
            onClick={() => setShowEmergencyModal(true)}
            disabled={overview?.active_secrets === 0}
          >
            ⚠️ Revoke All Active Secrets
          </button>
        </div>
      </div>

      {/* MANAGE SECRET MODAL */}
      {selectedSecret && (
        <div className="modal-backdrop fade-in" onClick={() => setSelectedSecret(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>
                ⚙️ Manage Secret: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{selectedSecret.id.slice(0, 12)}...</span>
              </h2>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setSelectedSecret(null)}
              >
                ✕
              </button>
            </div>

            {/* Secret Analytics Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem', marginBottom: '1.5rem' }}>
              <div style={{ background: 'var(--bg-input)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Views</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>{selectedSecret.successful_view_count ?? selectedSecret.view_count} / {selectedSecret.max_views}</div>
              </div>
              <div style={{ background: 'var(--bg-input)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Attempts</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>{selectedSecret.access_attempt_count}</div>
              </div>
              <div style={{ background: 'var(--bg-input)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Failed</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: selectedSecret.failed_attempts > 0 ? '#fbbf24' : 'inherit' }}>
                  {selectedSecret.failed_attempts}
                </div>
              </div>
              <div style={{ background: 'var(--bg-input)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Status</div>
                <div style={{ marginTop: '0.2rem' }}>{renderStatusBadge(selectedSecret.status, selectedSecret.has_suspicious_activity)}</div>
              </div>
            </div>

            {/* Suspicious Note if any */}
            {selectedSecret.has_suspicious_activity && (
              <div className="banner banner-warning" style={{ marginBottom: '1.25rem' }}>
                <span className="banner-icon">⚠️</span>
                <div>
                  <strong>Suspicious Activity Flagged:</strong> {selectedSecret.suspicious_reason || 'High volume of access attempts detected.'}
                </div>
              </div>
            )}

            {/* Action Buttons */}
            <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                className={`btn ${selectedSecret.is_locked ? 'btn-primary' : 'btn-secondary'} btn-sm`}
                onClick={() => handleToggleLock(selectedSecret)}
              >
                {selectedSecret.is_locked ? '🔓 Unlock Secret' : '🔒 Lock Secret'}
              </button>

              <button
                type="button"
                className="btn btn-danger btn-sm"
                onClick={() => handleRevoke(selectedSecret.id)}
              >
                🗑️ Revoke Permanently
              </button>

              <Link
                to={`/created/${selectedSecret.id}`}
                className="btn btn-ghost btn-sm"
              >
                🔗 View QR & Link
              </Link>
            </div>

            {/* Update Settings Form */}
            {(selectedSecret.status === 'active' || selectedSecret.status === 'locked' || selectedSecret.status === 'suspicious') && (
              <form onSubmit={handleSaveSettings} style={{ background: 'var(--bg-input)', padding: '1.25rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', marginBottom: '1.5rem' }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '1rem' }}>
                  Update Security Settings
                </h4>

                <div className="form-group">
                  <label className="form-label" style={{ fontSize: '0.8rem' }}>Allowed Views (1 - 100)</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    className="form-input"
                    value={editMaxViews}
                    onChange={(e) => setEditMaxViews(parseInt(e.target.value, 10) || 1)}
                    disabled={editOneTime}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" style={{ fontSize: '0.8rem' }}>Extend / Reset Expiration</label>
                  <select
                    className="form-input"
                    value={editExpiresIn}
                    onChange={(e) => setEditExpiresIn(parseInt(e.target.value, 10))}
                  >
                    {EXPIRATION_OPTIONS.map((opt) => (
                      <option key={opt.seconds} value={opt.seconds}>
                        {opt.label} from now
                      </option>
                    ))}
                  </select>
                </div>

                <div className="toggle-group" style={{ marginBottom: '1rem' }}>
                  <label className="toggle">
                    <input
                      type="checkbox"
                      checked={editOneTime}
                      onChange={(e) => setEditOneTime(e.target.checked)}
                    />
                    <span className="toggle-slider" />
                  </label>
                  <div>
                    <span className="toggle-label" style={{ fontSize: '0.85rem' }}>Burn after reading (Single-use)</span>
                  </div>
                </div>

                <button
                  type="submit"
                  className="btn btn-primary btn-sm"
                  disabled={savingSettings}
                  style={{ width: '100%' }}
                >
                  {savingSettings ? 'Saving...' : '💾 Save Security Settings'}
                </button>
              </form>
            )}

            {/* Secret-Specific Timeline */}
            <h4 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.75rem' }}>
              Audit Events for this Secret
            </h4>
            {loadingEvents ? (
              <div style={{ textAlign: 'center', padding: '1rem' }}><span className="spinner" /></div>
            ) : secretEvents.length === 0 ? (
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No audit events found.</div>
            ) : (
              <div className="timeline-container" style={{ paddingLeft: '1.5rem' }}>
                {secretEvents.map((evt) => (
                  <div key={evt.id} className="timeline-item" style={{ paddingBottom: '1rem' }}>
                    <div className="timeline-dot" style={{ left: '-1.5rem', width: '1.25rem', height: '1.25rem', fontSize: '0.65rem' }}>
                      {evt.event_type === 'created' ? '🔐' : evt.event_type === 'view_success' ? '🔓' : evt.event_type === 'failed_attempt' ? '❌' : '👁️'}
                    </div>
                    <div className="timeline-content" style={{ padding: '0.5rem 0.75rem' }}>
                      <div className="timeline-header">
                        <span className="timeline-type" style={{ fontSize: '0.8rem' }}>{evt.event_type.replace('_', ' ')}</span>
                        <span className="timeline-time" style={{ fontSize: '0.7rem' }}>
                          {new Date(evt.created_at).toLocaleString()}
                        </span>
                      </div>
                      {evt.detail && <div className="timeline-detail" style={{ fontSize: '0.75rem' }}>{evt.detail}</div>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* EMERGENCY REVOKE CONFIRMATION MODAL */}
      {showEmergencyModal && (
        <div className="modal-backdrop fade-in" onClick={() => setShowEmergencyModal(false)}>
          <div className="modal-content" style={{ maxWidth: '480px', border: '1px solid rgba(239, 68, 68, 0.6)' }} onClick={(e) => e.stopPropagation()}>
            <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
              <div style={{ fontSize: '3rem', marginBottom: '0.75rem' }}>⚠️</div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#f87171' }}>
                Emergency Lockdown
              </h2>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.5rem' }}>
                This will immediately revoke all active secrets created from this browser. All recipients will immediately receive a 410 Gone error.
              </p>
            </div>

            <div className="banner banner-danger" style={{ marginBottom: '1.5rem', fontSize: '0.85rem' }}>
              <span>This action is immediate and cannot be undone.</span>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button
                type="button"
                className="btn btn-ghost"
                style={{ flex: 1 }}
                onClick={() => setShowEmergencyModal(false)}
                disabled={emergencyLoading}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger"
                style={{ flex: 1 }}
                onClick={handleEmergencyRevokeAll}
                disabled={emergencyLoading}
              >
                {emergencyLoading ? 'Revoking All...' : '⚠️ Revoke All'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

