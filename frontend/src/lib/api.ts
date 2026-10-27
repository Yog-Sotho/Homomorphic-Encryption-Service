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
  headers?: Record<string, string>;
  timeoutMs?: number;
}

async function send(
  method: Method,
  path: string,
  options: RequestOptions,
  token: string | null
): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json', ...options.headers };
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

/** Sends with the stored access token, refreshing it once on a 401. */
async function authorized(method: Method, path: string, options: RequestOptions): Promise<Response> {
  const response = await send(method, path, options, localStorage.getItem('token'));
  if (response.status !== 401 || path.startsWith('/auth/')) return response;

  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) {
    redirectToLogin();
    return response;
  }
  let newToken: string;
  try {
    newToken = await refreshAccessToken(refreshToken);
  } catch {
    redirectToLogin();
    return response;
  }
  return send(method, path, options, newToken);
}

async function request<T>(method: Method, path: string, options: RequestOptions = {}): Promise<T> {
  return parse<T>(await authorized(method, path, options));
}

/** Like `request`, for endpoints that answer with raw bytes. */
async function requestBytes(path: string): Promise<Uint8Array<ArrayBuffer>> {
  const response = await authorized('GET', path, {});
  if (!response.ok) return parse<never>(response);
  return new Uint8Array(await response.arrayBuffer());
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

/** A job's metadata; the encrypted result is fetched separately. */
export interface JobSummary {
  id: string;
  status: JobStatus;
  operation: Operation;
  key_id: string | null;
  attempts: number;
  error_message: string | null;
  input_bytes: number | null;
  result_bytes: number | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface JobPage {
  data: JobSummary[];
  /** Pass to `listJobs` for the next (older) page; `null` on the last page. */
  next_cursor: string | null;
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

const jobPath = (jobId: string) => `/compute/jobs/${encodeURIComponent(jobId)}`;

export const compute = {
  /**
   * Queues a job. `inputs` are base64 `safe_serialize`d FheUint16 ciphertexts.
   * A network failure is retried once with the same `Idempotency-Key`, so the
   * job is never queued (or charged) twice.
   */
  submitJob: async (keyId: string, operation: Operation, inputs: [string, string]) => {
    const options: RequestOptions = {
      ...json({ key_id: keyId, operation, inputs }),
      headers: { 'Idempotency-Key': crypto.randomUUID() }
    };
    try {
      return await request<JobSummary>('POST', '/compute/jobs', options);
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 0) throw e;
      return request<JobSummary>('POST', '/compute/jobs', options);
    }
  },
  getJobStatus: (jobId: string) => request<JobSummary>('GET', jobPath(jobId)),
  /** The encrypted result of a completed job (a `safe_serialize`d FheUint16). */
  getJobResult: (jobId: string) => requestBytes(`${jobPath(jobId)}/result`),
  listJobs: (cursor?: string, limit?: number) => {
    const query = new URLSearchParams();
    if (cursor) query.set('cursor', cursor);
    if (limit) query.set('limit', String(limit));
    const qs = query.toString();
    return request<JobPage>('GET', qs ? `/compute/jobs?${qs}` : '/compute/jobs');
  },
  deleteJob: (jobId: string) => request<void>('DELETE', jobPath(jobId))
};
