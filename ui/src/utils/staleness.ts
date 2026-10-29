/** Data freshness for the wall. Two independent failure modes, reported separately (never silently):
 *  - publish_stale: the backend stopped publishing (generated_at too old) — fetches still "succeed"
 *  - fetch_failing: the browser cannot reach data/*.json
 * Pipeline cadence is 10 min, so >25 min without a new generated_at means ≥2 missed cycles. */
export const PUBLISH_STALE_SECS = 25 * 60;
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
