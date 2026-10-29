import { useEffect, useState } from 'react';
import { PATCH_LIMITS, safeDataPath } from '@/utils/diff';

export type PatchState =
  | { state: 'idle' }
  | { state: 'rejected' }
  | { state: 'loading' }
  | { state: 'ok'; text: string; truncated: boolean; bytes: number }
  | { state: 'error'; message: string };

/**
 * Lazily fetch a captured patch (`./data/<path>`) as text once `enabled`. The path is external data:
 * it is validated with safeDataPath BEFORE any fetch (rejected ⇒ no request at all).
 */
export function usePatch(path: string, enabled: boolean): PatchState {
  const [st, setSt] = useState<PatchState>({ state: 'idle' });

  useEffect(() => {
    if (!enabled) return;
    if (!safeDataPath(path)) { setSt({ state: 'rejected' }); return; }
    let cancelled = false;
    setSt({ state: 'loading' });
    fetch(`./data/${path}`)
      .then(async r => {
        if (!r.ok) throw new Error(`补丁不可用（HTTP ${r.status}）`);
        // SPA fallback returns index.html with 200 for a missing file — that is not a diff.
        if ((r.headers.get('content-type') ?? '').includes('text/html')) throw new Error('补丁不可用（服务器返回了 HTML 页面，而非 diff）');
        const text = await r.text();
        const bytes = new TextEncoder().encode(text).length;
        if (bytes > PATCH_LIMITS.maxBytes) {
          return { text: text.split('\n').slice(0, PATCH_LIMITS.truncatedLines).join('\n'), truncated: true, bytes };
        }
        return { text, truncated: false, bytes };
      })
      .then(v => { if (!cancelled) setSt({ state: 'ok', ...v }); })
      .catch((e: unknown) => { if (!cancelled) setSt({ state: 'error', message: e instanceof Error ? e.message : String(e) }); });
    return () => { cancelled = true; };
  }, [path, enabled]);

  return st;
}
