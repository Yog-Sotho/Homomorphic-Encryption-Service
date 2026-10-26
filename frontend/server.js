// Production entry point: adapter-node's handler behind cross-origin isolation headers.
// TFHE's WASM build needs SharedArrayBuffer, which browsers only expose when every
// response (pages, assets and worker scripts) is sent with COOP + COEP.
import http from 'node:http';
import { handler } from './build/handler.js';

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? '0.0.0.0';

const server = http.createServer((req, res) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  handler(req, res);
});

server.listen(port, host, () => {
  console.log(`HEaaS frontend listening on http://${host}:${port}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
