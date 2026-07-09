import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// BACKEND_URL is set to http://backend:8080 when running inside Docker Compose.
// When running natively (npm run dev on the host) it falls back to localhost:8080.
export default defineConfig({
  plugins: [sveltekit()],
  server: {
    port: 3000,
    strictPort: true,
    proxy: {
      '/api': {
        target: process.env.BACKEND_URL ?? 'http://localhost:8080',
        changeOrigin: true,
        secure: false
      }
    }
  },
  build: {
    target: 'es2022'
  }
});
