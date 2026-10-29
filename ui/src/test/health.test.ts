import { describe, expect, it } from 'vitest';
import { healthSummary } from '@/utils/health';
import type { SourceHealth } from '@/types/site-data';

const src = (status: SourceHealth['status'], enabled = true): SourceHealth => ({
  source_id: status, name: status, tier: 'T1', domain: 'vuln', cadence_min: 10, enabled, status,
  last_success: null, last_error: null, last_error_at: null, items_24h: 0,
});

describe('healthSummary', () => {
  it('is loading, not healthy, before data arrives', () => {
    expect(healthSummary([], true)).toEqual({ kind: 'loading' });
  });
  it('is no_data when nothing is enabled', () => {
    expect(healthSummary([src('disabled', false)], false)).toEqual({ kind: 'no_data' });
  });
  it('counts never_run / degraded / failing as needing attention', () => {
    expect(healthSummary([src('ok'), src('never_run'), src('failing')], false)).toEqual({ kind: 'attention', count: 2 });
  });
  it('ignores disabled sources', () => {
    expect(healthSummary([src('ok'), src('disabled', false)], false)).toEqual({ kind: 'healthy' });
  });
});
