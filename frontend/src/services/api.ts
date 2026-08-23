import type {
  CreateSecretRequest,
  CreateSecretResponse,
  SecretResponse,
  SecretActivityResponse,
  SecretEvent,
  DashboardOverviewResponse,
} from '../types';

const API_BASE =
  import.meta.env.VITE_API_BASE_URL || 
  (import.meta.env.PROD ? 'https://vaultdrop-backend.onrender.com' : 'http://localhost:8000');

export class ApiError extends Error {
  public status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}`;

    try {
      const errorData = await response.json();

      if (errorData.detail) {
        detail = errorData.detail;
      }
    } catch {
      // Non-JSON error response
    }

    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

export async function checkHealth(): Promise<{ status: string }> {
  return apiFetch<{ status: string }>('/api/health');
}

export async function createSecret(
  data: CreateSecretRequest,
): Promise<CreateSecretResponse> {
  return apiFetch<CreateSecretResponse>('/api/secrets', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function getSecret(
  id: string,
): Promise<SecretResponse> {
  return apiFetch<SecretResponse>(`/api/secrets/${id}`);
}

export async function consumeSecret(
  id: string,
): Promise<SecretResponse> {
  return apiFetch<SecretResponse>(`/api/secrets/${id}/consume`, {
    method: 'POST',
  });
}

export async function recordFailedAttempt(
  id: string,
  reason?: string,
): Promise<{ recorded: boolean }> {
  return apiFetch<{ recorded: boolean }>(`/api/secrets/${id}/failed-attempt`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

export async function destroySecret(
  id: string,
): Promise<void> {
  return apiFetch<void>(`/api/secrets/${id}`, {
    method: 'DELETE',
  });
}

export async function getMySecrets(
  creatorTokens: string[],
): Promise<SecretActivityResponse[]> {
  return apiFetch<SecretActivityResponse[]>('/api/secrets/mine', {
    method: 'POST',
    body: JSON.stringify({ creator_tokens: creatorTokens }),
  });
}

export async function getMySecretsOverview(
  creatorTokens: string[],
): Promise<DashboardOverviewResponse> {
  return apiFetch<DashboardOverviewResponse>('/api/secrets/mine/overview', {
    method: 'POST',
    body: JSON.stringify({ creator_tokens: creatorTokens }),
  });
}

export async function getSecretEvents(
  id: string,
  creatorToken: string,
): Promise<SecretEvent[]> {
  return apiFetch<SecretEvent[]>(`/api/secrets/${id}/events`, {
    method: 'POST',
    body: JSON.stringify({ creator_token: creatorToken }),
  });
}

export async function revokeSecret(
  id: string,
  creatorToken: string,
): Promise<void> {
  return apiFetch<void>(`/api/secrets/${id}/revoke`, {
    method: 'POST',
    body: JSON.stringify({ creator_token: creatorToken }),
  });
}

export async function lockSecret(
  id: string,
  creatorToken: string,
  lock: boolean = true,
): Promise<{ status: string }> {
  return apiFetch<{ status: string }>(`/api/secrets/${id}/lock`, {
    method: 'POST',
    body: JSON.stringify({ creator_token: creatorToken, lock }),
  });
}

export async function updateSecretSettings(
  id: string,
  creatorToken: string,
  settings: {
    max_views?: number;
    expires_in_seconds?: number;
    one_time?: boolean;
  },
): Promise<{ status: string }> {
  return apiFetch<{ status: string }>(`/api/secrets/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({
      creator_token: creatorToken,
      ...settings,
    }),
  });
}

export async function emergencyRevokeAll(
  creatorTokens: string[],
): Promise<{ revoked_count: number }> {
  return apiFetch<{ revoked_count: number }>('/api/secrets/emergency-revoke-all', {
    method: 'POST',
    body: JSON.stringify({ creator_tokens: creatorTokens }),
  });
}