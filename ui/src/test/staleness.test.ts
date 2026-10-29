import { describe, expect, it } from 'vitest';
import { freshness } from '@/utils/staleness';

const now = Date.parse('2026-10-23T06:00:00Z');

describe('freshness', () => {
  it('flags a dead pipeline even when fetches keep succeeding', () => {
    expect(freshness('2026-10-23T05:00:00Z', 5, now)).toEqual({ kind: 'publish_stale', dataAgeSecs: 3600 });
  });
  it('flags failing fetches first', () => {
    expect(freshness('2026-10-23T05:59:00Z', 300, now)).toEqual({ kind: 'fetch_failing', sinceFetchSecs: 300 });
  });
  it('is fresh within two cycles', () => {
    expect(freshness('2026-10-23T05:50:00Z', 3, now)).toEqual({ kind: 'fresh', dataAgeSecs: 600 });
  });
  it('is unknown before the first load', () => {
    expect(freshness(null, null, now)).toEqual({ kind: 'unknown' });
  });
});
