import { sveltekit } from '@sveltejs/kit/vite';
import adapter from '@sveltejs/adapter-node';
import { defineConfig } from 'vite';

// BACKEND_URL is set to http://backend:8080 when running inside Docker Compose.
// When running natively (pnpm dev on the host) it falls back to localhost:8080.
const backendUrl = process.env.BACKEND_URL ?? 'http://localhost:8080';

export default defineConfig({
  plugins: [
    sveltekit({
      adapter: adapter(),
      // nginx serves the app under /heaas/ and the backend redirects there.
      paths: { base: '/heaas' },
      // SvelteKit bootstraps with an inline script; hash mode emits a matching
      // CSP header instead of the static <meta> tag that used to block it.
      csp: {
        mode: 'hash',
        directives: {
          'default-src': ['self'],
          'script-src': ['self'],
          'style-src': ['self', 'unsafe-inline'],
          'img-src': ['self', 'data:'],
          'font-src': ['self'],
          'connect-src': ['self'],
          'object-src': ['none'],
          'base-uri': ['self'],
          'form-action': ['self'],
          'frame-ancestors': ['none']
        }
      }
    })
  ],
  server: {
    port: 3000,
    strictPort: true,
    proxy: {
      '/api': { target: backendUrl, changeOrigin: true, secure: false }
    }
  },
  preview: {
    port: 4173,
    strictPort: true,
    proxy: {
      '/api': { target: backendUrl, changeOrigin: true, secure: false }
    }
  },
  build: {
    target: 'es2022'
  }
});
