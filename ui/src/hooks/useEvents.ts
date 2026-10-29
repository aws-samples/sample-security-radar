import { useState, useEffect, useRef } from 'react';
import type { Digest, EventSummary, Funnel, NowItem } from '@/types/site-data';

const REFRESH_INTERVAL_MS = 60_000;

export interface EventsState {
  events: EventSummary[];
  /** M2 keys. null = the publisher did not emit the key (older backend) — never coerced to []/0 (BRIEF §3). */
  now: NowItem[] | null;
  headline: string | null;
  funnel: Funnel | null;
  /** C7 daily digest; null = not published yet (older backend, or before the first 08:00 HKT run). */
  digest: Digest | null;
  generatedAt: string | null;
  loading: boolean;
  error: string | null;
  /** ISO timestamp of last successful fetch, or null */
  lastFetched: string | null;
  /** Seconds since last successful fetch (updated every second) */
  staleSecs: number | null;
}

// Event detail lives in ./useEventDetail.ts (response tri-state, analysis, progress, pipeline steps).

export function useEvents(): EventsState {
  const [state, setState] = useState<EventsState>({
    events: [], now: null, headline: null, funnel: null, digest: null, generatedAt: null, loading: true, error: null,
    lastFetched: null, staleSecs: null,
  });

  const lastFetchedRef = useRef<Date | null>(null);

  function doFetch() {
    fetch('./data/events.json')
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => {
        if (data.kind !== 'events') throw new Error('Unexpected data kind');
        const now = new Date();
        lastFetchedRef.current = now;
        setState(s => ({
          ...s,
          events: data.events,
          now: Array.isArray(data.now) ? data.now : null,
          headline: typeof data.headline === 'string' ? data.headline : null,
          funnel: data.funnel ?? null,
          digest: data.digest ?? null,
          generatedAt: data.generated_at,
          loading: false,
          error: null,
          lastFetched: now.toISOString(),
          staleSecs: 0,
        }));
      })
      .catch((err: unknown) => {
        // Fetch failed — keep old data, mark stale, surface error
        setState(s => ({ ...s, loading: false, error: String(err) }));
      });
  }

  useEffect(() => {
    doFetch();
    const interval = setInterval(doFetch, REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, []);

  // Update staleSecs every second so consumers can show countdown/warning
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
