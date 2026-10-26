import { resolve } from '$app/paths';

const API_BASE = '/api';
const REQUEST_TIMEOUT_MS = 10_000;

/** Error raised for any non-2xx API response or network failure. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = 'ApiError';
  }
}

/** Human-readable message for an unknown thrown value. */
export function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError || error instanceof Error) return error.message || fallback;
  return fallback;
}

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

async function send(method: Method, path: string, body: unknown, token: string | null): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;

  try {
    return await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    });
  } catch (cause) {
    const timedOut = cause instanceof DOMException && cause.name === 'TimeoutError';
    throw new ApiError(0, timedOut ? 'The server took too long to respond' : 'Network error', {
      cause
    });
  }
}

async function parse<T>(response: Response): Promise<T> {
  const text = await response.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = undefined;
    }
  }
  if (!response.ok) {
    const message =
      typeof data === 'object' && data !== null && 'message' in data && typeof data.message === 'string'
        ? data.message
        : `Request failed (${response.status})`;
    throw new ApiError(response.status, message);
  }
  return data as T;
}

interface TokenPair {
  token: string;
  refresh_token: string;
}

// Single-flight refresh: concurrent 401s share one refresh request.
let refreshPromise: Promise<string> | null = null;

function refreshAccessToken(refreshToken: string): Promise<string> {
  refreshPromise ??= send('POST', '/auth/refresh', { refresh_token: refreshToken }, null)
    .then((res) => parse<TokenPair>(res))
    .then((pair) => {
      localStorage.setItem('token', pair.token);
      localStorage.setItem('refresh_token', pair.refresh_token);
      return pair.token;
    })
    .finally(() => {
      refreshPromise = null;
    });
  return refreshPromise;
}

function redirectToLogin(): void {
  localStorage.removeItem('token');
  localStorage.removeItem('refresh_token');
  window.location.href = resolve('/login');
}

async function request<T>(method: Method, path: string, body?: unknown): Promise<T> {
  const response = await send(method, path, body, localStorage.getItem('token'));
  if (response.status !== 401 || path.startsWith('/auth/')) return parse<T>(response);

  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) {
    redirectToLogin();
    return parse<T>(response);
  }
  let newToken: string;
  try {
    newToken = await refreshAccessToken(refreshToken);
  } catch {
    redirectToLogin();
    return parse<T>(response);
  }
  return parse<T>(await send(method, path, body, newToken));
}

export interface PublicUser {
  id: string;
  email: string;
  created_at: string;
}

export interface AuthResponse extends TokenPair {
  user: PublicUser;
}

export interface MessageResponse {
  message: string;
}

export interface UserProfile extends PublicUser {
  email_verified: boolean;
  has_password: boolean;
  oauth_providers: string[];
  daily_usage: { count: number; quota: number; date: string };
}

export interface SandboxResult {
  plaintext_result: number;
  result_b64: string;
}

export interface JobResponse {
  id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  result_b64: string | null;
  error_message: string | null;
}

export const auth = {
  register: (email: string, password: string) =>
    request<MessageResponse>('POST', '/auth/register', { email, password }),
  login: (email: string, password: string) =>
    request<AuthResponse>('POST', '/auth/login', { email, password }),
  resendVerification: (email: string) =>
    request<MessageResponse>('POST', '/auth/resend-verification', { email }),
  logout: (refreshToken: string) =>
    request<MessageResponse>('POST', '/auth/logout', { refresh_token: refreshToken }),
  forgotPassword: (email: string) =>
    request<MessageResponse>('POST', '/auth/forgot-password', { email }),
  resetPassword: (token: string, newPassword: string) =>
    request<MessageResponse>('POST', '/auth/reset-password', { token, new_password: newPassword })
};

export const user = {
  me: () => request<UserProfile>('GET', '/user/me'),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<MessageResponse>('PUT', '/user/password', {
      current_password: currentPassword,
      new_password: newPassword
    }),
  deleteAccount: (password: string) =>
    request<MessageResponse>('DELETE', '/user/account', { password })
};

export const compute = {
  submitJob: (inputDataB64: string, operation: string) =>
    request<JobResponse>('POST', '/compute/jobs', { input_data_b64: inputDataB64, operation }),
  getJobStatus: (jobId: string) =>
    request<JobResponse>('GET', `/compute/jobs/${encodeURIComponent(jobId)}`),
  sandboxCompute: (value1: number, value2: number, operation: string) =>
    request<SandboxResult>('POST', '/compute/sandbox', { value1, value2, operation }),
  listJobs: () => request<JobResponse[]>('GET', '/compute/jobs')
};
