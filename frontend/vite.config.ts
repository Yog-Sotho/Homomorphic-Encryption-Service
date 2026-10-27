/// <reference types="vitest/config" />
import { sveltekit } from '@sveltejs/kit/vite';
import adapter from '@sveltejs/adapter-node';
import { defineConfig, type Connect, type Plugin } from 'vite';
import { ISOLATION_HEADERS } from './isolation-headers.js';

// BACKEND_URL is set to http://backend:8080 when running inside Docker Compose.
// When running natively (pnpm dev on the host) it falls back to localhost:8080.
const backendUrl = process.env.BACKEND_URL ?? 'http://localhost:8080';

const setIsolationHeaders: Connect.NextHandleFunction = (_req, res, next) => {
  for (const [name, value] of Object.entries(ISOLATION_HEADERS)) res.setHeader(name, value);
  next();
};

/**
 * Cross-origin isolation in dev and preview (see isolation-headers.js). Vite's
 * `server.headers`/`preview.headers` miss pages and assets SvelteKit serves itself,
 * so the headers are set by the first middleware instead; production uses server.js.
 */
const crossOriginIsolation: Plugin = {
  name: 'heaas:cross-origin-isolation',
  configureServer(server) {
    server.middlewares.use(setIsolationHeaders);
  },
  configurePreviewServer(server) {
    server.middlewares.use(setIsolationHeaders);
  }
};

export default defineConfig({
  plugins: [
    crossOriginIsolation,
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
          // WebAssembly compilation needs 'wasm-unsafe-eval' (not 'unsafe-eval').
          'script-src': ['self', 'wasm-unsafe-eval'],
          'worker-src': ['self'],
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
      '/api': { target: backendUrl, changeOrigin: true, secure: false, xfwd: true }
    }
  },
  preview: {
    port: 4173,
    strictPort: true,
    proxy: {
      '/api': { target: backendUrl, changeOrigin: true, secure: false, xfwd: true }
    }
  },
  build: {
    target: 'es2022'
  },
  // The TFHE worker spawns rayon sub-workers with `new Worker(new URL(...))`,
  // which needs ES-module workers; pre-bundling would break its relative imports.
  worker: { format: 'es' },
  optimizeDeps: { exclude: ['tfhe'] },
  test: {
    // Playwright specs live in e2e/ and run under `pnpm test:e2e`.
    include: ['src/**/*.test.ts']
  }
});
