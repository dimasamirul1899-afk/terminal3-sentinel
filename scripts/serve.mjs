// Tiny static server for local demo verification (stdlib only).
// Usage: node scripts/serve.mjs [port]  (default 8123)
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const port = Number(process.argv[2] ?? 8123);
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.md': 'text/markdown' };

const server = createServer(async (req, res) => {
  try {
    const path = req.url === '/' ? '/docs/index.html' : decodeURIComponent(req.url.split('?')[0]);
    const data = await readFile(join(root, path));
    res.writeHead(200, { 'content-type': TYPES[extname(path)] ?? 'application/octet-stream' });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end('not found');
  }
});
server.listen(port, () => console.log(`Sentinel demo at http://127.0.0.1:${port}/docs/index.html`));
