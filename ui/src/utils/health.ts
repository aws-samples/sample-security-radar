import type { SourceHealth } from '@/types/site-data';

export type HealthSummary =
  | { kind: 'loading' }
  | { kind: 'no_data' }
  | { kind: 'attention'; count: number }
  | { kind: 'healthy' };

/** Never claim "healthy" without data: loading and empty are distinct states (degradation must be visible). */
export function healthSummary(sources: SourceHealth[], loading: boolean): HealthSummary {
  if (loading) return { kind: 'loading' };
  const enabled = sources.filter(s => s.enabled);
  if (enabled.length === 0) return { kind: 'no_data' };
  const bad = enabled.filter(s => s.status !== 'ok');
  return bad.length ? { kind: 'attention', count: bad.length } : { kind: 'healthy' };
}

export type ErrorView =
  | { kind: 'none' }
  | { kind: 'current'; text: string }
  | { kind: 'recovered'; text: string; at: string };

/** A source's last error is CURRENT only when no success came after it. Live 2026-11-11: 49 of 215 sources showed a
 *  red error on #/sources, 48 of them had fetched fine since (the oldest error was from 10-25) — a recovered error read
 *  as a live failure. The one place this is decided; the page only renders it. */
export function errorView(src: Pick<SourceHealth, 'last_error' | 'last_error_at' | 'last_success'>): ErrorView {
  if (!src.last_error) return { kind: 'none' };
  const err = Date.parse(src.last_error_at ?? '');
  const ok = Date.parse(src.last_success ?? '');
  if (!Number.isNaN(err) && !Number.isNaN(ok) && ok > err) {
    return { kind: 'recovered', text: src.last_error, at: src.last_error_at as string };
  }
  return { kind: 'current', text: src.last_error };   // no timestamps to compare ⇒ never assumed recovered
}
