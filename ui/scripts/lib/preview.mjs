// Shared vite preview/dev lifecycle for a11y.mjs and screenshot*.mjs (NEXT-STEPS B3).
// Why: a parent that dies on a throw / Ctrl-C used to orphan `npx → vite`, which then held the port; the next
// a11y run reused that stale server (built from old dist/) and passed against the wrong bundle — a false green.
import { spawn } from 'child_process';
import { createServer } from 'net';

/** Resolve if nothing listens on host:port, else reject with a fix hint. Fail fast — never reuse a stray server. */
export function assertPortFree(port, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', err => reject(new Error(
      err.code === 'EADDRINUSE'
        ? `port ${host}:${port} is already in use — a stray preview? find it: lsof -iTCP:${port} -sTCP:LISTEN -n -P`
        : `cannot probe port ${port}: ${err.message}`)));
    s.once('listening', () => s.close(() => resolve()));
    s.listen(port, host);
  });
}

/** Start `vite <args>` in its own process group; returns { child, stop }. stop() is idempotent and sync. */
export async function startVite(args, { cwd, port, readyTimeoutMs = 30_000 }) {
  await assertPortFree(port);
  // detached ⇒ new process group, so stop() can kill npx AND its vite grandchild with one signal.
  const child = spawn('npx', ['vite', ...args, '--host', '127.0.0.1', '--port', String(port), '--strictPort'],
    { cwd, stdio: ['ignore', 'pipe', 'pipe'], detached: true, env: { ...process.env, NO_COLOR: '1' } });
  let stopped = false;
  const stop = () => {
    if (stopped || child.exitCode !== null) return;
    stopped = true;
    try { process.kill(-child.pid, 'SIGTERM'); } catch (e) { if (e.code !== 'ESRCH') throw e; }
  };
  process.once('exit', stop);                                     // sync path: also covers process.exit()
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.once(sig, () => { stop(); process.exit(128 + ({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15 })[sig]); });
  }
  process.once('uncaughtException', err => { stop(); console.error(err); process.exit(1); });
  process.once('unhandledRejection', err => { stop(); console.error(err); process.exit(1); });

  await new Promise((resolve, reject) => {
    const t = setTimeout(() => { stop(); reject(new Error(`vite ${args[0] ?? 'dev'} not ready in ${readyTimeoutMs} ms`)); }, readyTimeoutMs);
    // Strip ANSI too: picocolors turns colour ON when `CI` is set (GitLab), splitting "127.0.0.1:" from the bold port.
    const onData = d => { if (String(d).replace(/\x1b\[[0-9;]*m/g, '').includes(`127.0.0.1:${port}`)) { clearTimeout(t); resolve(); } };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.once('error', e => { clearTimeout(t); reject(e); });
    child.once('exit', code => { clearTimeout(t); reject(new Error(`vite exited early with code ${code}`)); });
  });
  return { child, stop };
}
