// Production entry point: adapter-node's handler behind cross-origin isolation
// headers. Static assets bypass SvelteKit's hooks, so they are set here for every
// response (see isolation-headers.js).
import http from 'node:http';
import { handler } from './build/handler.js';
import { ISOLATION_HEADERS } from './isolation-headers.js';

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? '0.0.0.0';

const server = http.createServer((req, res) => {
  for (const [name, value] of Object.entries(ISOLATION_HEADERS)) res.setHeader(name, value);
  handler(req, res);
});

server.listen(port, host, () => {
  console.log(`HE Engine frontend listening on http://${host}:${port}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
