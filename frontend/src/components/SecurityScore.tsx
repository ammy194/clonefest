interface Props {
  passwordProtected: boolean;
  expiresInSeconds: number;
  oneTime: boolean;
}

export default function SecurityScore({ passwordProtected, expiresInSeconds, oneTime }: Props) {
  let score = 50; // Base score for AES-GCM encryption
  let label = 'Fair';
  let color = 'var(--warning)';

  const reasons = [];

  if (passwordProtected) {
    score += 25;
    reasons.push('Password protection enabled');
  } else {
    reasons.push('Enable password for better protection');
  }

  if (oneTime) {
    score += 15;
    reasons.push('Burn-after-reading active');
  } else {
    reasons.push('Use burn-after-reading to prevent replay');
  }

  if (expiresInSeconds <= 3600) {
    score += 10;
    reasons.push('Short expiration time');
  } else if (expiresInSeconds <= 86400) {
    score += 5;
  }

  if (score >= 90) {
    label = 'Excellent';
    color = 'var(--success)';
  } else if (score >= 70) {
    label = 'Good';
    color = 'var(--accent)';
  } else if (score < 60) {
    label = 'Fair';
    color = 'var(--warning)';
  }

  return (
    <div className="card" style={{ padding: '1rem', marginTop: '1.5rem', border: `1px solid ${color}` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
        <h4 style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-primary)' }}>Security Score</h4>
        <span style={{ fontWeight: 700, color, fontSize: '1.1rem' }}>{score}/100 - {label}</span>
      </div>
      <ul style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', paddingLeft: '1.25rem', margin: 0 }}>
        {reasons.map((r, i) => (
          <li key={i}>{r}</li>
        ))}
      </ul>
    </div>
  );
}
