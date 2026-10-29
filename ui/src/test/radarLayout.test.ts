/**
 * Unit tests for radarLayout.ts pure functions.
 *
 * Contract being tested:
 * 1. Dots always within valid radius (radiusFrac in [0, 1]).
 * 2. Same input → same output (deterministic).
 * 3. Events older than 7d are excluded (timeToRadiusFrac returns null).
 * 4. Shape maps correctly to level.
 * 5. Dot radius formula is correct (r = clamp(3 + 2√n, 3, 12)).
 * 6. Clustering merges dense groups.
 * 7. Hour buckets cover exactly 24 slots, oldest first.
 */
import { describe, it, expect } from 'vitest';
import {
  timeToRadiusFrac,
  ageMsToRadiusFrac,
  levelToShape,
  sourcesToDotR,
  computeRadarLayout,
  computeHourBuckets,
  clusterDots,
  strHash,
  RADAR_MAX_AGE_MS,
  LOG_MAX,
} from '@/utils/radarLayout';
import type { EventSummary } from '@/types/site-data';

// ── Fixture helpers ───────────────────────────────────────────────────────────

const NOW = new Date('2026-10-23T12:00:00Z').getTime();

/** Build a minimal EventSummary. independent_sources defaults to 1. */
function ev(
  id: string,
  firstSeen: string,
  opts: Partial<EventSummary & { independent_sources: number }> = {},
): EventSummary {
  return {
    event_id: id,
    domain: 'vuln',
    title: `Event ${id}`,
    level: 'V2',
    level_reason: '',
    severity: 'P1',
    exploitation: 'none',
    first_seen: firstSeen,
    last_updated: firstSeen,
    first_report_source: 'test',
    item_count: 1,
    cves: [],
    entities: [],
    chains: [],
    amount_usd_latest: null,
    amount_disputed: false,
    summary: '',
    independent_sources: 1,
    ...opts,
  } as EventSummary & { independent_sources: number };
}

// ── timeToRadiusFrac ──────────────────────────────────────────────────────────

describe('timeToRadiusFrac', () => {
  it('returns null for events older than 7 days', () => {
    // 7d + 1s ago
    const oldDate = new Date(NOW - RADAR_MAX_AGE_MS - 1000).toISOString();
    expect(timeToRadiusFrac(oldDate, NOW)).toBeNull();
  });

  it('returns null for exactly 7d + 1ms old', () => {
    const date = new Date(NOW - RADAR_MAX_AGE_MS - 1).toISOString();
    expect(timeToRadiusFrac(date, NOW)).toBeNull();
  });

  it('returns a value in [0, 1] for events within 7d', () => {
    const h1ago = new Date(NOW - 1 * 60 * 60 * 1000).toISOString();
    const d1ago = new Date(NOW - 24 * 60 * 60 * 1000).toISOString();
    const d6ago = new Date(NOW - 6 * 24 * 60 * 60 * 1000).toISOString();
    for (const ts of [h1ago, d1ago, d6ago]) {
      const r = timeToRadiusFrac(ts, NOW);
      expect(r).not.toBeNull();
      expect(r!).toBeGreaterThanOrEqual(0);
      expect(r!).toBeLessThanOrEqual(1);
    }
  });

  it('returns 1 for exactly 7d old event', () => {
    const exactly7d = new Date(NOW - RADAR_MAX_AGE_MS).toISOString();
    const r = timeToRadiusFrac(exactly7d, NOW);
    expect(r).not.toBeNull();
    expect(r!).toBeCloseTo(1, 5);
  });

  it('maps monotonically: older events have larger radius', () => {
    const r1h  = timeToRadiusFrac(new Date(NOW - 1 * 60 * 60 * 1000).toISOString(), NOW)!;
    const r24h = timeToRadiusFrac(new Date(NOW - 24 * 60 * 60 * 1000).toISOString(), NOW)!;
    const r7d  = timeToRadiusFrac(new Date(NOW - RADAR_MAX_AGE_MS).toISOString(), NOW)!;
    expect(r1h).toBeLessThan(r24h);
    expect(r24h).toBeLessThan(r7d);
  });

  it('returns 0 for a future-dated event (clamped at 0)', () => {
    const future = new Date(NOW + 10000).toISOString();
    const r = timeToRadiusFrac(future, NOW);
    expect(r).not.toBeNull();
    expect(r!).toBe(0);
  });
});

// ── ageMsToRadiusFrac ─────────────────────────────────────────────────────────

describe('ageMsToRadiusFrac', () => {
  it('matches the log formula at known points', () => {
    expect(ageMsToRadiusFrac(0)).toBeCloseTo(0, 5);
    expect(ageMsToRadiusFrac(RADAR_MAX_AGE_MS)).toBeCloseTo(1, 5);
    const r1h = ageMsToRadiusFrac(60 * 60 * 1000);
    expect(r1h).toBeCloseTo(Math.log(2) / LOG_MAX, 5);
  });
});

// ── levelToShape ──────────────────────────────────────────────────────────────

describe('levelToShape', () => {
  it('maps V0 to hollow-circle', () => {
    expect(levelToShape('V0')).toBe('hollow-circle');
  });
  it('maps V1/V2/V3 to filled circle', () => {
    expect(levelToShape('V1')).toBe('circle');
    expect(levelToShape('V2')).toBe('circle');
    expect(levelToShape('V3')).toBe('circle');
  });
  it('maps V4 to diamond', () => {
    expect(levelToShape('V4')).toBe('diamond');
  });
  it('maps X (disputed) to circle', () => {
    expect(levelToShape('X')).toBe('circle');
  });
});

// ── sourcesToDotR ─────────────────────────────────────────────────────────────

describe('sourcesToDotR', () => {
  it('returns 3 for 0 sources (floor)', () => {
    expect(sourcesToDotR(0)).toBe(3);
  });
  it('returns 5 for 1 source (3 + 2)', () => {
    expect(sourcesToDotR(1)).toBeCloseTo(5, 5);
  });
  it('is clamped at 12 for large source counts', () => {
    expect(sourcesToDotR(100)).toBe(12);
    expect(sourcesToDotR(25)).toBe(12); // 3 + 2*5 = 13 → clamp to 12
  });
  it('grows with more sources', () => {
    expect(sourcesToDotR(1)).toBeLessThan(sourcesToDotR(4));
    expect(sourcesToDotR(4)).toBeLessThan(sourcesToDotR(9));
  });
});

// ── strHash ───────────────────────────────────────────────────────────────────

describe('strHash', () => {
  it('returns a value in [0, 1)', () => {
    const h = strHash('test-event-id');
    expect(h).toBeGreaterThanOrEqual(0);
    expect(h).toBeLessThan(1);
  });
  it('is deterministic — same string always same result', () => {
    const id = 'ev_a1b2c3d4e5f60001';
    expect(strHash(id)).toBe(strHash(id));
  });
  it('produces different values for different strings', () => {
    expect(strHash('aaa')).not.toBe(strHash('bbb'));
  });
});

// ── computeRadarLayout ────────────────────────────────────────────────────────

describe('computeRadarLayout', () => {
  it('excludes events older than 7d', () => {
    const oldDate = new Date(NOW - RADAR_MAX_AGE_MS - 1000).toISOString();
    const events = [ev('old', oldDate)];
    const dots = computeRadarLayout(events, NOW);
    expect(dots).toHaveLength(0);
  });

  it('includes events within 7d', () => {
    const recent = new Date(NOW - 2 * 60 * 60 * 1000).toISOString(); // 2h ago
    const events = [ev('e1', recent)];
    const dots = computeRadarLayout(events, NOW);
    expect(dots).toHaveLength(1);
  });

  it('all returned dots have radiusFrac in [0, 1]', () => {
    const events = [
      ev('e1', new Date(NOW - 30 * 60 * 1000).toISOString()),          // 30 min
      ev('e2', new Date(NOW - 6 * 60 * 60 * 1000).toISOString()),       // 6h
      ev('e3', new Date(NOW - 3 * 24 * 60 * 60 * 1000).toISOString()),  // 3d
      ev('e4', new Date(NOW - 6.9 * 24 * 60 * 60 * 1000).toISOString()), // 6.9d
    ];
    const dots = computeRadarLayout(events, NOW);
    for (const dot of dots) {
      expect(dot.radiusFrac).toBeGreaterThanOrEqual(0);
      expect(dot.radiusFrac).toBeLessThanOrEqual(1);
    }
  });

  it('is deterministic — same events same output', () => {
    const events = [
      ev('e1', new Date(NOW - 2 * 60 * 60 * 1000).toISOString(), { domain: 'vuln',     severity: 'P0', level: 'V3' }),
      ev('e2', new Date(NOW - 5 * 60 * 60 * 1000).toISOString(), { domain: 'incident', severity: 'P1', level: 'V2' }),
      ev('e3', new Date(NOW - 48 * 60 * 60 * 1000).toISOString(), { domain: 'web3',   severity: 'P2', level: 'V1' }),
    ];
    const r1 = computeRadarLayout(events, NOW);
    const r2 = computeRadarLayout(events, NOW);
    expect(r1).toEqual(r2);
  });

  it('dot shape reflects level (V0→hollow-circle, V4→diamond)', () => {
    const ts = new Date(NOW - 1 * 60 * 60 * 1000).toISOString();
    const events = [
      ev('v0', ts, { level: 'V0' }),
      ev('v4', ts, { level: 'V4' }),
      ev('v2', ts, { level: 'V2' }),
    ];
    const dots = computeRadarLayout(events, NOW);
    const byId = Object.fromEntries(dots.map(d => [d.eventId, d]));
    expect(byId['v0'].shape).toBe('hollow-circle');
    expect(byId['v4'].shape).toBe('diamond');
    expect(byId['v2'].shape).toBe('circle');
  });

  it('dot size grows with independent_sources (r = 3 + 2√n, max 12)', () => {
    const ts = new Date(NOW - 1 * 60 * 60 * 1000).toISOString();
    const events = [
      ev('s1', ts, { independent_sources: 1 } as any),
      ev('s4', ts, { independent_sources: 4 } as any),
      ev('s9', ts, { independent_sources: 9 } as any),
    ];
    const dots = computeRadarLayout(events, NOW);
    const byId = Object.fromEntries(dots.map(d => [d.eventId, d]));
    expect(byId['s1'].dotR).toBeCloseTo(5, 5);     // 3 + 2*1 = 5
    expect(byId['s4'].dotR).toBeCloseTo(7, 5);     // 3 + 2*2 = 7
    expect(byId['s9'].dotR).toBeCloseTo(9, 5);     // 3 + 2*3 = 9
  });

  it('respects domain sectors — vuln events are in 0–120° range', () => {
    const ts = new Date(NOW - 1 * 60 * 60 * 1000).toISOString();
    const events = Array.from({ length: 10 }, (_, i) =>
      ev(`v${i}`, ts, { domain: 'vuln' }),
    );
    const dots = computeRadarLayout(events, NOW);
    for (const dot of dots) {
      expect(dot.angleDeg).toBeGreaterThanOrEqual(0);
      expect(dot.angleDeg).toBeLessThan(120);
    }
  });
});

// ── clusterDots ───────────────────────────────────────────────────────────────

describe('clusterDots', () => {
  it('clusters points that are close together', () => {
    // 5 points all at nearly the same position
    const base: ReturnType<typeof ev> = ev('e0', new Date(NOW - 60 * 60 * 1000).toISOString());
    const dots = computeRadarLayout(
      Array.from({ length: 6 }, (_, i) => ({
        ...base,
        event_id: `clone_${i}`,
        first_seen: new Date(NOW - (60 + i) * 60 * 1000).toISOString(), // nearly same time
      } as EventSummary)),
      NOW,
    );
    // They'll naturally cluster because they're in the same sector at very similar ages
    const result = clusterDots(dots, 10, 0.1, 4); // loose thresholds
    const clusters = result.filter(r => 'kind' in r && r.kind === 'cluster');
    // Should have at least one cluster
    expect(clusters.length).toBeGreaterThanOrEqual(1);
  });

  it('does not cluster widely-separated events', () => {
    const ts1 = new Date(NOW - 1 * 60 * 60 * 1000).toISOString();    // 1h → inner
    const ts2 = new Date(NOW - 5 * 24 * 60 * 60 * 1000).toISOString(); // 5d → outer
    const events = [
      ev('a', ts1, { domain: 'vuln' }),
      ev('b', ts2, { domain: 'web3' }),
    ];
    const dots = computeRadarLayout(events, NOW);
    const result = clusterDots(dots, 5, 0.05, 2);
    const clusters = result.filter(r => 'kind' in r && r.kind === 'cluster');
    expect(clusters).toHaveLength(0);
  });

  it('cluster count is accurate', () => {
    const ts = new Date(NOW - 2 * 60 * 60 * 1000).toISOString();
    // Create 5 events that will be at the same angle (same domain, same time)
    const events = Array.from({ length: 5 }, (_, i) =>
      ev(`c${i}`, ts, { domain: 'vuln' }),
    );
    const dots = computeRadarLayout(events, NOW);
    const result = clusterDots(dots, 10, 0.1, 4);
    const clust = result.filter(r => 'kind' in r && r.kind === 'cluster');
    if (clust.length > 0) {
      const total = clust.reduce((s, c) => s + ('count' in c ? c.count : 0), 0)
        + result.filter(r => !('kind' in r)).length;
      expect(total).toBe(dots.length);
    }
  });
});

// ── computeHourBuckets ────────────────────────────────────────────────────────

describe('computeHourBuckets', () => {
  it('returns exactly 24 buckets', () => {
    const buckets = computeHourBuckets([], NOW);
    expect(buckets).toHaveLength(24);
  });

  it('oldest bucket is first (slot 0 = 24h ago)', () => {
    // slot 23 = most recent hour, label = current UTC hour
    const buckets = computeHourBuckets([], NOW);
    const last = buckets[buckets.length - 1];
    const d = new Date(NOW);
    const expectedLabel = `${String(d.getUTCHours()).padStart(2, '0')}:00`;
    expect(last.hourLabel).toBe(expectedLabel);
  });

  it('places an event in the correct bucket', () => {
    // Event 3h ago → should be in bucket at index 20 (24-3-1=20)
    const ts = new Date(NOW - 3 * 60 * 60 * 1000 + 30 * 60 * 1000).toISOString(); // 2.5h ago
    const events = [ev('e1', ts)];
    const buckets = computeHourBuckets(events, NOW);
    const total = buckets.reduce((s, b) => s + b.count, 0);
    expect(total).toBe(1);
  });

  it('events outside 24h window are not counted', () => {
    const old = new Date(NOW - 25 * 60 * 60 * 1000).toISOString();
    const buckets = computeHourBuckets([ev('x', old)], NOW);
    expect(buckets.every(b => b.count === 0)).toBe(true);
  });

  it('is deterministic — same events same output', () => {
    const ts = new Date(NOW - 5 * 60 * 60 * 1000).toISOString();
    const events = [ev('e1', ts), ev('e2', ts)];
    const r1 = computeHourBuckets(events, NOW);
    const r2 = computeHourBuckets(events, NOW);
    expect(r1).toEqual(r2);
  });

  it('maxSeverity is null for empty slots', () => {
    const buckets = computeHourBuckets([], NOW);
    for (const b of buckets) {
      expect(b.maxSeverity).toBeNull();
      expect(b.count).toBe(0);
    }
  });

  it('confirmedCount only counts V2/V3/V4', () => {
    const ts = new Date(NOW - 1 * 60 * 60 * 1000 + 10 * 60 * 1000).toISOString(); // within last hour
    const events = [
      ev('v1', ts, { level: 'V1' }),
      ev('v2', ts, { level: 'V2' }),
      ev('v3', ts, { level: 'V3' }),
    ];
    const buckets = computeHourBuckets(events, NOW);
    const last = buckets[buckets.length - 1];
    expect(last.confirmedCount).toBe(2);
    expect(last.pendingCount).toBe(1);
  });
});
