import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// NOTE: The proxy configuration below is for local development only.
// In production, requests are routed through nginx (or another reverse proxy)
// which forwards /api/* to the backend container. Do not rely on this Vite
// proxy outside of `npm run dev`.
export default defineConfig({
  plugins: [sveltekit()],
  server: {
    port: 3000,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        secure: false
      }
    }
  },
  build: {
    target: 'es2022'
  }
});
