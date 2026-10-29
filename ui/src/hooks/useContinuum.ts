import { useState, useEffect, useRef } from 'react';
import { classifyContinuumResponse } from '@/utils/continuum';
import type { Capability, ContinuumRecent, ContinuumResource, ContinuumTarget, Ledger } from '@/types/site-data';

const REFRESH_INTERVAL_MS = 60_000;

export interface ContinuumDoc {
  /** null when the publisher omitted generated_at (rendered as 发布时间未知, never crashes). */
  generatedAt: string | null;
  resources: ContinuumResource[];
  targets: ContinuumTarget[];
  coverage: Capability[];
  recent: ContinuumRecent[];
  /** null = key missing (older publisher) — rendered as NoData, never as zeros. */
  ledger: Ledger | null;
}

export interface ContinuumState {
  /**
   * loading = first fetch in flight; unpublished = /data/continuum.json does not exist (404 / SPA fallback html);
   * error = transport/parse failure (doc keeps the last good copy); ok = doc is current.
   * "unpublished" and "error" must read differently from "0%" (BRIEF §3).
   */
  state: 'loading' | 'unpublished' | 'error' | 'ok';
  doc: ContinuumDoc | null;
  error: string | null;
  staleSecs: number | null;
}

export function useContinuum(): ContinuumState {
  const [st, setSt] = useState<ContinuumState>({ state: 'loading', doc: null, error: null, staleSecs: null });
  const lastFetchedRef = useRef<Date | null>(null);

  useEffect(() => {
    let cancelled = false;
    function doFetch() {
      fetch('./data/continuum.json')
        .then(async r => {
          // Missing file vs outage: rule lives in classifyContinuumResponse (a 5xx HTML error page is an error).
          const c = classifyContinuumResponse(r.status, r.headers.get('content-type') ?? '');
          if (c.kind === 'unpublished') return { unpublished: true as const, status: r.status };
          if (c.kind === 'error') throw new Error(`HTTP ${c.status}`);
          return { data: await r.json() };
        })
        .then(res => {
          if (cancelled) return;
          if ('unpublished' in res) {
            // keep an older good doc if we had one: the file vanishing mid-session is an error, not "never published"
            setSt(s => s.doc ? { ...s, state: 'error', error: `continuum.json 不再存在（HTTP ${res.status}）` } : { state: 'unpublished', doc: null, error: null, staleSecs: null });
            return;
          }
          const d = res.data;
          if (d?.kind !== 'continuum') throw new Error(`Unexpected data kind: ${String(d?.kind)}`);
          lastFetchedRef.current = new Date();
          setSt({
            state: 'ok',
            doc: {
              generatedAt: typeof d.generated_at === 'string' ? d.generated_at : null,
              resources: d.resources ?? [],
              targets: d.targets ?? [],
              coverage: d.coverage ?? [],
              recent: d.recent ?? [],
              ledger: d.ledger ?? null,
            },
            error: null,
            staleSecs: 0,
          });
        })
        .catch((err: unknown) => {
          if (!cancelled) setSt(s => ({ ...s, state: 'error', error: String(err) }));
        });
    }
    doFetch();
    const interval = setInterval(doFetch, REFRESH_INTERVAL_MS);
    const tick = setInterval(() => {
      if (!lastFetchedRef.current) return;
      const secs = Math.floor((Date.now() - lastFetchedRef.current.getTime()) / 1000);
      setSt(s => (s.staleSecs === secs ? s : { ...s, staleSecs: secs }));
    }, 1000);
    return () => { cancelled = true; clearInterval(interval); clearInterval(tick); };
  }, []);

  return st;
}
