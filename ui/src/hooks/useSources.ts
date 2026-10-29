import { useState, useEffect, useRef } from 'react';
import type { SourceHealth } from '@/types/site-data';

const REFRESH_INTERVAL_MS = 60_000;

export interface SourcesState {
  sources: SourceHealth[];
  generatedAt: string | null;
  loading: boolean;
  error: string | null;
  lastFetched: string | null;
  staleSecs: number | null;
}

export function useSources(): SourcesState {
  const [state, setState] = useState<SourcesState>({
    sources: [], generatedAt: null, loading: true, error: null,
    lastFetched: null, staleSecs: null,
  });

  const lastFetchedRef = useRef<Date | null>(null);

  function doFetch() {
    fetch('./data/sources.json')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => {
        if (data.kind !== 'sources') throw new Error('Unexpected data kind');
        const now = new Date();
        lastFetchedRef.current = now;
        setState(s => ({
          ...s,
          sources: data.sources,
          generatedAt: data.generated_at,
          loading: false,
          error: null,
          lastFetched: now.toISOString(),
          staleSecs: 0,
        }));
      })
      .catch((err: unknown) => {
        setState(s => ({ ...s, loading: false, error: String(err) }));
      });
  }

  useEffect(() => {
    doFetch();
    const interval = setInterval(doFetch, REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const tick = setInterval(() => {
      if (!lastFetchedRef.current) return;
      const secs = Math.floor((Date.now() - lastFetchedRef.current.getTime()) / 1000);
      setState(s => ({ ...s, staleSecs: secs }));
    }, 1000);
    return () => clearInterval(tick);
  }, []);

  return state;
}
