import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import { ApiError, auth, compute, errorMessage, session, user } from './api.js';
import { userStore } from './stores.js';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function memoryStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (k) => data.get(k) ?? null,
    key: (i) => [...data.keys()][i] ?? null,
    removeItem: (k) => void data.delete(k),
    setItem: (k, v) => void data.set(k, String(v))
  };
}

describe('api client', () => {
  const fetchMock = vi.fn<typeof fetch>();
  const location = { href: '' };

  beforeEach(() => {
    fetchMock.mockReset();
    location.href = '';
    vi.stubGlobal('fetch', fetchMock);
    vi.stubGlobal('localStorage', memoryStorage());
    vi.stubGlobal('window', { location });
    session.clear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const SESSION = {
    token: 'access-1',
    expires_in: 900,
    user: { id: 'u1', email: 'a@b.co', created_at: '2026-10-27T00:00:00' }
  };

  it('keeps the access token in memory only and sends it as a bearer token', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, SESSION))
      .mockResolvedValueOnce(jsonResponse(200, { message: 'ok' }));

    await auth.login('a@b.co', 'pw');
    expect(get(userStore)).toEqual(SESSION.user);
    await expect(auth.forgotPassword('a@b.co')).resolves.toEqual({ message: 'ok' });

    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe('/api/auth/forgot-password');
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe(JSON.stringify({ email: 'a@b.co' }));
    expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer access-1');
    expect(localStorage.length).toBe(0);
  });

  it('maps error responses to ApiError with the server message', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(400, { message: 'Invalid email address.' }));

    const error = await auth.register('bad', 'x').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(400);
    expect(errorMessage(error, 'fallback')).toBe('Invalid email address.');
  });

  it('falls back to a generic message for non-JSON error bodies', async () => {
    fetchMock.mockResolvedValueOnce(new Response('upstream exploded', { status: 502 }));

    await expect(user.me()).rejects.toMatchObject({ status: 502, message: 'Request failed (502)' });
  });

  it('reports network failures as status 0', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('fetch failed'));

    await expect(user.me()).rejects.toMatchObject({ status: 0, message: 'Network error' });
  });

  it('refreshes once from the cookie for concurrent 401s and retries with the new token', async () => {
    fetchMock.mockImplementation(async (url, init) => {
      const authHeader = (init?.headers as Record<string, string>).Authorization;
      if (url === '/api/auth/refresh') {
        // The refresh token travels only as the HttpOnly cookie.
        expect(init?.body).toBeUndefined();
        expect(authHeader).toBeUndefined();
        return jsonResponse(200, { ...SESSION, token: 'access-2' });
      }
      return authHeader === 'Bearer access-2'
        ? jsonResponse(200, { id: 'u1' })
        : jsonResponse(401, { message: 'Invalid or missing token' });
    });

    const results = await Promise.all([user.me(), user.me()]);

    expect(results).toEqual([{ id: 'u1' }, { id: 'u1' }]);
    const refreshCalls = fetchMock.mock.calls.filter(([url]) => url === '/api/auth/refresh');
    expect(refreshCalls).toHaveLength(1);
  });

  it('redirects to login when the session cannot be refreshed', async () => {
    fetchMock.mockImplementation(async (url) =>
      url === '/api/auth/refresh'
        ? jsonResponse(401, { message: 'Session expired' })
        : jsonResponse(401, { message: 'Invalid or missing token' })
    );

    await expect(user.me()).rejects.toMatchObject({ status: 401 });
    expect(location.href).toBe('/heaas/login');
    expect(get(userStore)).toBeNull();
  });

  it('restores a session after a reload, or reports there is none', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SESSION));
    await expect(session.restore()).resolves.toBe(true);
    // Already signed in: no second request.
    await expect(session.restore()).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    session.clear();
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { message: 'Not signed in' }));
    await expect(session.restore()).resolves.toBe(false);
  });

  it('signs out on the server and forgets the session even if that fails', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SESSION));
    await auth.login('a@b.co', 'pw');
    fetchMock.mockRejectedValueOnce(new TypeError('offline'));
    await expect(session.end()).rejects.toBeInstanceOf(ApiError);
    expect(get(userStore)).toBeNull();
    expect(fetchMock.mock.calls[1][0]).toBe('/api/auth/logout');
  });

  it('does not try to refresh on auth endpoints', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { message: 'Invalid credentials' }));

    await expect(auth.login('a@b.co', 'wrong')).rejects.toMatchObject({
      status: 401,
      message: 'Invalid credentials'
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('retries a submission once after a network error with the same idempotency key', async () => {
    fetchMock
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockResolvedValueOnce(jsonResponse(202, { id: 'job-1', status: 'pending' }));

    await expect(compute.submitJob('key-1', 'add', ['YQ==', 'Yg=='])).resolves.toMatchObject({
      id: 'job-1'
    });

    const keys = fetchMock.mock.calls.map(
      ([, init]) => (init?.headers as Record<string, string>)['Idempotency-Key']
    );
    expect(keys).toHaveLength(2);
    expect(keys[0]).toMatch(/^[0-9a-f-]{36}$/);
    expect(keys[1]).toBe(keys[0]);
  });

  it('does not retry submissions the server refused', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(503, { message: 'The job queue is full' }));

    await expect(compute.submitJob('key-1', 'add', ['YQ==', 'Yg=='])).rejects.toMatchObject({
      status: 503,
      message: 'The job queue is full'
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('returns job results as bytes and reports errors from the result endpoint', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(new Uint8Array([1, 2, 3]), { status: 200 }))
      .mockResolvedValueOnce(jsonResponse(409, { message: 'Job is pending' }));

    await expect(compute.getJobResult('job/1')).resolves.toEqual(new Uint8Array([1, 2, 3]));
    expect(fetchMock.mock.calls[0][0]).toBe('/api/compute/jobs/job%2F1/result');
    await expect(compute.getJobResult('job-2')).rejects.toMatchObject({
      status: 409,
      message: 'Job is pending'
    });
  });

  it('pages through jobs with a cursor', async () => {
    fetchMock.mockImplementation(async () => jsonResponse(200, { data: [], next_cursor: null }));

    await compute.listJobs();
    await compute.listJobs('abc', 50);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/api/compute/jobs',
      '/api/compute/jobs?cursor=abc&limit=50'
    ]);
  });
});
