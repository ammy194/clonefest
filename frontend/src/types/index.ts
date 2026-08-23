export type SecretType = 'text' | 'api_key' | 'password' | 'env' | 'json' | 'code' | 'markdown' | 'file';

export type SecretStatus = 'active' | 'locked' | 'revoked' | 'expired' | 'burned' | 'suspicious';

export const SECRET_TYPE_LABELS: Record<SecretType, string> = {
  text: 'Text',
  api_key: 'API Key',
  password: 'Password',
  env: '.env',
  json: 'JSON',
  code: 'Code snippet',
  markdown: 'Markdown',
  file: 'File',
};

export interface ExpirationOption {
  label: string;
  seconds: number;
}

export const EXPIRATION_OPTIONS: ExpirationOption[] = [
  { label: '5 minutes', seconds: 300 },
  { label: '1 hour', seconds: 3600 },
  { label: '6 hours', seconds: 21600 },
  { label: '24 hours', seconds: 86400 },
  { label: '7 days', seconds: 604800 },
];

export interface CreateSecretRequest {
  ciphertext: string;
  iv: string;
  secret_type: SecretType;
  expires_in_seconds: number;
  one_time: boolean;
  max_views?: number;
  password_protected: boolean;
  password_salt?: string | null;
  password_verifier?: string | null;
  file_name?: string | null;
  file_size?: number | null;
  file_type?: string | null;
  device_binding_hash?: string | null;
}

export interface CreateSecretResponse {
  id: string;
  expires_at: string;
  creator_token: string;
}

export interface SecretResponse {
  ciphertext: string;
  iv: string;
  secret_type: SecretType;
  expires_at: string;
  one_time: boolean;
  max_views: number;
  view_count: number;
  access_attempt_count: number;
  successful_view_count: number;
  failed_attempts: number;
  is_locked: boolean;
  password_protected: boolean;
  password_salt: string | null;
  password_verifier: string | null;
  file_name: string | null;
  file_size: number | null;
  file_type: string | null;
  status: SecretStatus;
  has_anomaly: boolean;
  has_suspicious_activity: boolean;
  suspicious_reason: string | null;
}

export interface SecretEvent {
  id: number;
  secret_id: string;
  event_type: string;
  status: string;
  detail: string | null;
  client_env: string | null;
  created_at: string;
}

export interface SecretActivityResponse {
  id: string;
  secret_type: SecretType;
  created_at: string;
  expires_at: string;
  one_time: boolean;
  max_views: number;
  view_count: number;
  access_attempt_count: number;
  successful_view_count: number;
  failed_attempts: number;
  destroyed: boolean;
  is_locked: boolean;
  is_expired: boolean;
  status: SecretStatus;
  has_anomaly: boolean;
  anomaly_reason: string | null;
  has_suspicious_activity: boolean;
  suspicious_reason: string | null;
  last_accessed_at: string | null;
  file_name: string | null;
  file_size: number | null;
}

export interface DashboardOverviewResponse {
  active_secrets: number;
  total_views: number;
  failed_attempts: number;
  suspicious_events: number;
  secrets: SecretActivityResponse[];
  recent_events: SecretEvent[];
}

export interface ApiError {
  detail: string;
}

