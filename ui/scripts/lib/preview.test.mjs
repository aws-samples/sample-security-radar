import { describe, it, expect } from 'vitest';
import { createServer } from 'net';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { assertPortFree } from './preview.mjs';

const here = dirname(fileURLToPath(import.meta.url));

describe('assertPortFree', () => {
  it('rejects when the port is taken (fail fast instead of auditing a stray server)', async () => {
    const s = createServer(); await new Promise(r => s.listen(0, '127.0.0.1', r));
    const { port } = s.address();
    await expect(assertPortFree(port)).rejects.toThrow(/already in use/);
    await new Promise(r => s.close(r));
  });
  it('resolves when the port is free', async () => {
    const s = createServer(); await new Promise(r => s.listen(0, '127.0.0.1', r));
    const { port } = s.address(); await new Promise(r => s.close(r));
    await expect(assertPortFree(port)).resolves.toBeUndefined();
  });
});

describe('startVite cleanup', () => {
  it('a throw after the server is up leaves no listener behind', async () => {
    const port = 4190 + Math.floor(Math.random() * 9);
    const r = spawnSync(process.execPath, [resolve(here, 'preview-crash.fixture.mjs'), String(port)],
      { cwd: resolve(here, '../..'), encoding: 'utf8', timeout: 60_000 });
    const pgid = Number(r.stdout.match(/UP (\d+)/)?.[1]);
    try {
      expect(pgid).toBeGreaterThan(0);          // the server really started (else the test proves nothing)
      expect(r.status).toBe(1);                 // the throw surfaced as a failure, not swallowed
      await new Promise(res => setTimeout(res, 500));
      await expect(assertPortFree(port)).resolves.toBeUndefined();
    } finally {
      try { process.kill(-pgid, 'SIGKILL'); } catch { /* already gone: the expected case */ }
    }
  }, 70_000);
});
