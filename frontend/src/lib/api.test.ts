import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, auth, errorMessage, user } from './api.js';

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
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends JSON with the bearer token and returns the parsed body', async () => {
    localStorage.setItem('token', 'access-1');
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { message: 'ok' }));

    await expect(auth.forgotPassword('a@b.co')).resolves.toEqual({ message: 'ok' });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/auth/forgot-password');
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe(JSON.stringify({ email: 'a@b.co' }));
    expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer access-1');
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

  it('refreshes once for concurrent 401s and retries with the new token', async () => {
    localStorage.setItem('token', 'expired');
    localStorage.setItem('refresh_token', 'refresh-1');
    fetchMock.mockImplementation(async (url, init) => {
      const authHeader = (init?.headers as Record<string, string>).Authorization;
      if (url === '/api/auth/refresh') {
        return jsonResponse(200, { token: 'access-2', refresh_token: 'refresh-2' });
      }
      return authHeader === 'Bearer access-2'
        ? jsonResponse(200, { id: 'u1' })
        : jsonResponse(401, { message: 'Invalid or missing token' });
    });

    const results = await Promise.all([user.me(), user.me()]);

    expect(results).toEqual([{ id: 'u1' }, { id: 'u1' }]);
    const refreshCalls = fetchMock.mock.calls.filter(([url]) => url === '/api/auth/refresh');
    expect(refreshCalls).toHaveLength(1);
    expect(localStorage.getItem('token')).toBe('access-2');
    expect(localStorage.getItem('refresh_token')).toBe('refresh-2');
  });

  it('clears the session and redirects to login when refresh fails', async () => {
    localStorage.setItem('token', 'expired');
    localStorage.setItem('refresh_token', 'revoked');
    fetchMock.mockImplementation(async (url) =>
      url === '/api/auth/refresh'
        ? jsonResponse(401, { message: 'Invalid refresh token' })
        : jsonResponse(401, { message: 'Invalid or missing token' })
    );

    await expect(user.me()).rejects.toMatchObject({ status: 401 });
    expect(localStorage.getItem('token')).toBeNull();
    expect(localStorage.getItem('refresh_token')).toBeNull();
    expect(location.href).toBe('/heaas/login');
  });

  it('does not try to refresh on auth endpoints', async () => {
    localStorage.setItem('refresh_token', 'refresh-1');
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { message: 'Invalid credentials' }));

    await expect(auth.login('a@b.co', 'wrong')).rejects.toMatchObject({
      status: 401,
      message: 'Invalid credentials'
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
