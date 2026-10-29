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
