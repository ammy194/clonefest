import { Link, Outlet } from 'react-router-dom';

export default function Layout() {
  return (
    <div className="app-container">
      <header className="app-header">
        <div className="header-inner">
          <Link to="/" className="logo" aria-label="VaultDrop Home">
            <span className="logo-icon">🔐</span>
            <span>Vault<span className="logo-accent">Drop</span></span>
          </Link>
          <nav className="header-nav">
            <Link to="/" className="nav-link">Home</Link>
            <Link to="/dashboard" className="nav-link">Dashboard</Link>
            <Link to="/privacy" className="nav-link">Privacy</Link>
            <Link to="/create" className="btn btn-primary btn-sm">
              + Create Secret
            </Link>
          </nav>
        </div>
      </header>

      <main className="app-main fade-in">
        <Outlet />
      </main>

      <footer className="app-footer">
        <div className="footer-inner">
          <p className="footer-brand">
            <span className="footer-logo">🔐</span> VaultDrop
          </p>
          <p className="footer-tagline">
            Secure temporary information sharing — encrypted in your browser before transfer.
          </p>
          <div className="footer-badges">
            <span className="footer-badge">AES-256-GCM</span>
            <span className="footer-badge">Zero-Knowledge</span>
            <span className="footer-badge">Open Source</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
