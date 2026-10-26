import { resolve } from '$app/paths';

const API_BASE = '/api';
const REQUEST_TIMEOUT_MS = 10_000;
/** Compressed server keys are ~60 MB; give slow uplinks time to send them. */
const KEY_UPLOAD_TIMEOUT_MS = 10 * 60_000;

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

type Body = { json: unknown } | { binary: Uint8Array<ArrayBuffer> };

interface RequestOptions {
  body?: Body;
  timeoutMs?: number;
}

async function send(
  method: Method,
  path: string,
  options: RequestOptions,
  token: string | null
): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  let payload: BodyInit | undefined;
  if (options.body && 'json' in options.body) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(options.body.json);
  } else if (options.body) {
    headers['Content-Type'] = 'application/octet-stream';
    payload = options.body.binary;
  }
  if (token) headers.Authorization = `Bearer ${token}`;

  try {
    return await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: payload,
      signal: AbortSignal.timeout(options.timeoutMs ?? REQUEST_TIMEOUT_MS)
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
  refreshPromise ??= send('POST', '/auth/refresh', { body: { json: { refresh_token: refreshToken } } }, null)
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

async function request<T>(method: Method, path: string, options: RequestOptions = {}): Promise<T> {
  const response = await send(method, path, options, localStorage.getItem('token'));
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
  return parse<T>(await send(method, path, options, newToken));
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

export type Operation = 'add' | 'subtract' | 'multiply' | 'min' | 'max';

export interface HeParams {
  scheme: string;
  library: string;
  tfhe_version: string;
  config: string;
  integer_type: string;
  plaintext_modulus: number;
  operations: Operation[];
  max_ciphertext_bytes: number;
  max_server_key_bytes: number;
  max_keys_per_user: number;
}

export interface ServerKeyInfo {
  id: string;
  sha256: string;
  size_bytes: number;
  created_at: string;
}

export type JobStatus = 'pending' | 'processing' | 'completed' | 'failed';

export interface JobResponse {
  id: string;
  status: JobStatus;
  result_b64: string | null;
  error_message: string | null;
}

const json = (value: unknown): RequestOptions => ({ body: { json: value } });

export const auth = {
  register: (email: string, password: string) =>
    request<MessageResponse>('POST', '/auth/register', json({ email, password })),
  login: (email: string, password: string) =>
    request<AuthResponse>('POST', '/auth/login', json({ email, password })),
  resendVerification: (email: string) =>
    request<MessageResponse>('POST', '/auth/resend-verification', json({ email })),
  logout: (refreshToken: string) =>
    request<MessageResponse>('POST', '/auth/logout', json({ refresh_token: refreshToken })),
  forgotPassword: (email: string) =>
    request<MessageResponse>('POST', '/auth/forgot-password', json({ email })),
  resetPassword: (token: string, newPassword: string) =>
    request<MessageResponse>('POST', '/auth/reset-password', json({ token, new_password: newPassword }))
};

export const user = {
  me: () => request<UserProfile>('GET', '/user/me'),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<MessageResponse>(
      'PUT',
      '/user/password',
      json({ current_password: currentPassword, new_password: newPassword })
    ),
  deleteAccount: (password: string) =>
    request<MessageResponse>('DELETE', '/user/account', json({ password }))
};

export const he = {
  params: () => request<HeParams>('GET', '/he/params')
};

export const keys = {
  /** Registers a `safe_serialize`d TFHE CompressedServerKey (never the client key). */
  upload: (compressedServerKey: Uint8Array<ArrayBuffer>) =>
    request<ServerKeyInfo>('POST', '/keys', {
      body: { binary: compressedServerKey },
      timeoutMs: KEY_UPLOAD_TIMEOUT_MS
    }),
  list: () => request<ServerKeyInfo[]>('GET', '/keys'),
  remove: (keyId: string) => request<void>('DELETE', `/keys/${encodeURIComponent(keyId)}`)
};

export const compute = {
  /** `inputs` are base64 `safe_serialize`d FheUint16 ciphertexts. */
  submitJob: (keyId: string, operation: Operation, inputs: [string, string]) =>
    request<JobResponse>('POST', '/compute/jobs', json({ key_id: keyId, operation, inputs })),
  getJobStatus: (jobId: string) =>
    request<JobResponse>('GET', `/compute/jobs/${encodeURIComponent(jobId)}`),
  listJobs: () => request<JobResponse[]>('GET', '/compute/jobs')
};
