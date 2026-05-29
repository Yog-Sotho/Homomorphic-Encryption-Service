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

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const auth = {
  register: (email: string, password: string) => api.post('/auth/register', { email, password }),
  login: (email: string, password: string) => api.post('/auth/login', { email, password })
};

export const compute = {
  submitJob: (inputDataB64: string, operation: string) => api.post('/compute/jobs', { input_data_b64: inputDataB64, operation }),
  getJobStatus: (jobId: string) => api.get(`/compute/jobs/${jobId}`),
  sandboxCompute: (value1: number, value2: number, operation: string) =>
    api.post('/compute/sandbox', { value1, value2, operation }),
  listJobs: () =>
    api.get('/compute/jobs'),
};
