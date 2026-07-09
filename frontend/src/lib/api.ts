import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' }
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let refreshPromise: Promise<string> | null = null;

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        if (!refreshPromise) {
          refreshPromise = axios.post('/api/auth/refresh', { refresh_token: refreshToken })
            .then(res => {
              localStorage.setItem('token', res.data.token);
              localStorage.setItem('refresh_token', res.data.refresh_token);
              return res.data.token as string;
            })
            .finally(() => { refreshPromise = null; });
        }
        try {
          const newToken = await refreshPromise;
          original.headers.Authorization = `Bearer ${newToken}`;
          return api(original);
        } catch {
          localStorage.removeItem('token');
          localStorage.removeItem('refresh_token');
          window.location.href = '/heaas/login';
          return Promise.reject(error);
        }
      } else {
        localStorage.removeItem('token');
        window.location.href = '/heaas/login';
      }
    }
    return Promise.reject(error);
  }
);

export const auth = {
  register: (email: string, password: string) => api.post('/auth/register', { email, password }),
  login: (email: string, password: string) => api.post('/auth/login', { email, password }),
  resendVerification: (email: string) => api.post('/auth/resend-verification', { email }),
  logout: (refreshToken: string) => api.post('/auth/logout', { refresh_token: refreshToken }),
  forgotPassword: (email: string) => api.post('/auth/forgot-password', { email }),
  resetPassword: (token: string, newPassword: string) => api.post('/auth/reset-password', { token, new_password: newPassword }),
};

export const user = {
  me: () => api.get('/user/me'),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.put('/user/password', { current_password: currentPassword, new_password: newPassword }),
  deleteAccount: (password: string) =>
    api.delete('/user/account', { data: { password } }),
};

export const compute = {
  submitJob: (inputDataB64: string, operation: string) => api.post('/compute/jobs', { input_data_b64: inputDataB64, operation }),
  getJobStatus: (jobId: string) => api.get(`/compute/jobs/${jobId}`),
  sandboxCompute: (value1: number, value2: number, operation: string) =>
    api.post('/compute/sandbox', { value1, value2, operation }),
  listJobs: () =>
    api.get('/compute/jobs'),
};
