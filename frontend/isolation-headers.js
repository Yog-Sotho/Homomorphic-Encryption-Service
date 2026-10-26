// TFHE's WASM build uses shared memory (SharedArrayBuffer), which browsers only
// allow on cross-origin isolated pages. Every response (pages, assets and worker
// scripts) must carry these headers: vite.config.ts sets them in dev/preview and
// server.js in production.
export const ISOLATION_HEADERS = Object.freeze({
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp'
});
