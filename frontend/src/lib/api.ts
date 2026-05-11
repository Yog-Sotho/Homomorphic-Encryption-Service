import axios from 'axios';

const API_BASE = 'http://localhost:8080/api';

const api = axios.create({
  baseURL: API_BASE,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const auth = {
  register: (email: string, password: string) => 
    api.post('/auth/register', { email, password }),
  login: (email: string, password: string) => 
    api.post('/auth/login', { email, password }),
};

export const compute = {
  submitJob: (inputDataB64: string, operation: string) => 
    api.post('/compute/jobs', { input_data_b64: inputDataB64, operation }),
  getJobStatus: (jobId: string) => 
    api.get(`/compute/jobs/${jobId}`),
};