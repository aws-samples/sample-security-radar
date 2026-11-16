/** Data freshness for the wall. Two independent failure modes, reported separately (never silently):
 *  - publish_stale: the backend stopped publishing (generated_at too old) — fetches still "succeed"
 *  - fetch_failing: the browser cannot reach data/*.json
 * Measured 2026-11-15 over 24 h (142 published cycles): the gap between publishes is p50 9.9 min, p90 11.2, p99 24.8
 * (the schedule fires every 5 min; a cycle still running skips the next). 20 min = about twice the p90: a stale
 * notice means something stopped, not a slow cycle. It was 25 min, set for the old 10-minute schedule — five missed
 * triggers before the page said anything (audit 03 1.7). The server-side alarm (NoPublishedCycle) fires at 30. */
export const PUBLISH_STALE_SECS = 20 * 60;
export const FETCH_STALE_SECS = 120;

export type Freshness =
  | { kind: 'unknown' }
  | { kind: 'fresh'; dataAgeSecs: number }
  | { kind: 'publish_stale'; dataAgeSecs: number }
  | { kind: 'fetch_failing'; sinceFetchSecs: number };

export function freshness(generatedAt: string | null, sinceFetchSecs: number | null, nowMs: number): Freshness {
  if (sinceFetchSecs !== null && sinceFetchSecs > FETCH_STALE_SECS) return { kind: 'fetch_failing', sinceFetchSecs };
  if (!generatedAt) return { kind: 'unknown' };
  const age = Math.max(0, Math.floor((nowMs - new Date(generatedAt).getTime()) / 1000));
  return age > PUBLISH_STALE_SECS ? { kind: 'publish_stale', dataAgeSecs: age } : { kind: 'fresh', dataAgeSecs: age };
}
