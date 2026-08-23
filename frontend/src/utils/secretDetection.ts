export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface DetectionResult {
  detected: boolean;
  riskLevel?: RiskLevel;
  type: string;
  title: string;
  message: string;
  recommendations: string[];
  recommendedSettings: {
    oneTime: boolean;
    expiresInSeconds: number;
    passwordProtected: boolean;
  };
  explanation: string;
}

interface PatternRule {
  type: string;
  riskLevel: RiskLevel;
  regex: RegExp;
  explanation: string;
}

const RULES: PatternRule[] = [
  // ==========================================
  // CRITICAL: Private Keys & Production DBs
  // ==========================================
  {
    type: 'RSA / SSH Private Key',
    riskLevel: 'CRITICAL',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/i,
    explanation: 'Private keys grant full cryptographic authorization to servers, infrastructure, or identity credentials. Compromise could allow complete impersonation or unauthorized server access.',
  },
  {
    type: 'Production Database Connection String',
    riskLevel: 'CRITICAL',
    regex: /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|mssql|oracle):\/\/[^\s:@]+:[^\s:@]+@[^\s/]+/i,
    explanation: 'Direct database connection strings containing credentials can grant unauthorized access to sensitive persistent customer data and internal records.',
  },
  {
    type: 'Slack User / Bot Token',
    riskLevel: 'CRITICAL',
    regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/i,
    explanation: 'Slack tokens can allow reading organization chat channels, private direct messages, and executing workspace bot actions.',
  },
  {
    type: 'AWS Secret Access Key',
    riskLevel: 'CRITICAL',
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)[\s:=]+['"]?[0-9a-zA-Z/+=]{40}['"]?/i,
    explanation: 'AWS secret access keys provide root or high-privilege access to cloud resources, infrastructure, and storage buckets.',
  },

  // ==========================================
  // HIGH: Cloud, Code & Payment API Credentials
  // ==========================================
  {
    type: 'AWS Access Key ID',
    riskLevel: 'HIGH',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
    explanation: 'AWS Access Key IDs identify active IAM accounts or temporary session roles within Amazon Web Services cloud infrastructure.',
  },
  {
    type: 'GitHub Personal Access Token',
    riskLevel: 'HIGH',
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}/,
    explanation: 'GitHub personal access tokens grant access to source code repositories, automated CI/CD workflows, and organization assets.',
  },
  {
    type: 'Stripe Live Secret Key',
    riskLevel: 'HIGH',
    regex: /(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}/,
    explanation: 'Live Stripe secret keys allow initiating transactions, viewing customer payment details, and managing billing operations.',
  },
  {
    type: 'OpenAI / Anthropic API Key',
    riskLevel: 'HIGH',
    regex: /sk-proj-[a-zA-Z0-9_-]{48,}|sk-ant-api[0-9a-zA-Z_-]{40,}|sk-[a-zA-Z0-9]{48}/,
    explanation: 'AI API keys provide direct access to paid model inference and linked billing accounts without additional authentication.',
  },
  {
    type: 'Google Cloud / Maps API Key',
    riskLevel: 'HIGH',
    regex: /AIzaSy[0-9a-zA-Z_-]{33}/,
    explanation: 'Google API keys authenticate requests to Google Cloud, Maps, Firebase, and associated billable services.',
  },

  // ==========================================
  // MEDIUM: Auth Tokens, Configs & Endpoints
  // ==========================================
  {
    type: 'JSON Web Token (JWT)',
    riskLevel: 'MEDIUM',
    regex: /ey[a-zA-Z0-9_=]+(?:\.ey[a-zA-Z0-9_=]+){2}/,
    explanation: 'JWT tokens carry authenticated user session identity and authorization claims across microservices.',
  },
  {
    type: 'Sensitive Environment Variable',
    riskLevel: 'MEDIUM',
    regex: /(?:SECRET_KEY|API_SECRET|ENCRYPTION_KEY|CLIENT_SECRET|AUTH_SECRET|MASTER_KEY)[\s:=]+['"][^\s'"]{8,}['"]/i,
    explanation: 'High-entropy application secret variables are used for cryptographic signing, session hashing, or webhook validation.',
  },
  {
    type: 'Database Connection Endpoint',
    riskLevel: 'MEDIUM',
    regex: /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[^\s/]+/i,
    explanation: 'Database host URLs expose internal database infrastructure endpoints and network topology.',
  },
  {
    type: 'Bearer Authentication Token',
    riskLevel: 'MEDIUM',
    regex: /Bearer\s+[a-zA-Z0-9_\-.]{24,}/i,
    explanation: 'Bearer tokens authenticate API requests and may represent active user sessions or service-to-service credentials.',
  },

  // ==========================================
  // LOW: Generic High-Entropy & Secret Patterns
  // ==========================================
  {
    type: 'Generic API Key Pattern',
    riskLevel: 'LOW',
    regex: /(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)[\s:=]+['"][a-zA-Z0-9_.-]{16,}['"]/i,
    explanation: 'This value matches common credential labeling formats, though confidence is lower than a recognized vendor signature.',
  },
];

export function detectSecrets(text: string): DetectionResult {
  if (!text || typeof text !== 'string') {
    return {
      detected: false,
      type: '',
      title: '',
      message: '',
      recommendations: [],
      recommendedSettings: { oneTime: false, expiresInSeconds: 3600, passwordProtected: false },
      explanation: '',
    };
  }

  for (const rule of RULES) {
    if (rule.regex.test(text)) {
      const recommendations = [
        '✓ Burn after reading (one-time view)',
        '✓ 5-minute expiration window',
        '✓ Client-side password protection',
      ];

      return {
        detected: true,
        riskLevel: rule.riskLevel,
        type: rule.type,
        title: `⚠️ Potential ${rule.type} Detected`,
        message: `Potential ${rule.type} detected.`,
        recommendations,
        recommendedSettings: {
          oneTime: true,
          expiresInSeconds: 300, // 5 minutes
          passwordProtected: true,
        },
        explanation: rule.explanation,
      };
    }
  }

  return {
    detected: false,
    type: '',
    title: '',
    message: '',
    recommendations: [],
    recommendedSettings: { oneTime: false, expiresInSeconds: 3600, passwordProtected: false },
    explanation: '',
  };
}

