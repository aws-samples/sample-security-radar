/** Guards that the B7 mutation audit (2026-10-24) found unobserved — each test pins one guard. */
import { describe, it, expect } from 'vitest';
import { freshness } from '@/utils/staleness';
import { computeRadarLayout, DOMAIN_SECTORS } from '@/utils/radarLayout';
import { chainOrbitLayout } from '@/utils/radar3dLayout';
import type { EventSummary } from '@/types/site-data';

// Hex ids like the real ones: FNV-1a over sequential suffixes (`ev_m_1`, `ev_m_2`…) only spans ~[0.13, 0.90),
// so a boundary guard would never be exercised (verified 2026-10-24).
const hexId = (i: number) => 'ev_' + ((Math.imul(i + 1, 2654435761) >>> 0).toString(16) + (Math.imul(i + 7, 40503) >>> 0).toString(16)).padStart(16, '0').slice(0, 16);
const NOW = Date.parse('2026-10-23T12:00:00Z');
const ev = (id: string, o: Partial<EventSummary> = {}): EventSummary => ({
  event_id: id, domain: 'vuln', title: id, level: 'V2', level_reason: '', severity: 'P1',
  exploitation: 'none', first_seen: '2026-10-23T11:00:00Z', last_updated: '2026-10-23T11:00:00Z',
  first_report_source: 't', independent_sources: 1, item_count: 1, cves: [], entities: [], chains: [],
  amount_usd_latest: null, amount_disputed: false, summary: null, ...o,
} as EventSummary);

describe('freshness clock skew', () => {
  it('a generated_at slightly in the future (client clock behind) reads fresh with age 0, never negative', () => {
    expect(freshness('2026-10-23T12:05:00Z', 1, NOW)).toEqual({ kind: 'fresh', dataAgeSecs: 0 });
  });
});

describe('computeRadarLayout guards', () => {
  it('a brand-new event never leaves the [0.01, 0.97] band, whatever its jitter', () => {
    const dots = computeRadarLayout(Array.from({ length: 60 }, (_, i) => ev(`ev_new_${i}`, { first_seen: '2026-10-23T12:00:00Z' })), NOW, 2000);
    expect(dots.length).toBe(60);
    for (const d of dots) { expect(d.radiusFrac).toBeGreaterThanOrEqual(0.01); expect(d.radiusFrac).toBeLessThanOrEqual(0.97); }
  });
  it('P0 is sampled first when over budget', () => {
    const many = [...Array.from({ length: 10 }, (_, i) => ev(`ev_p2_${i}`, { severity: 'P2' })), ev('ev_p0', { severity: 'P0' })];
    const dots = computeRadarLayout(many, NOW, 4);
    expect(dots.map(d => d.eventId)).toContain('ev_p0');
  });
  it('dots keep an 8% margin inside their sector (no dot sits on a sector boundary)', () => {
    const dots = computeRadarLayout(Array.from({ length: 200 }, (_, i) => ev(hexId(i))), NOW, 2000);
    const s = DOMAIN_SECTORS.vuln, m = s.span * 0.08;
    for (const d of dots) { expect(d.angleDeg).toBeGreaterThanOrEqual(s.start + m); expect(d.angleDeg).toBeLessThanOrEqual(s.start + s.span - m); }
  });
});

describe('chainOrbitLayout', () => {
  it('only counts web3 events', () => {
    const nodes = chainOrbitLayout([ev('a', { domain: 'web3', chains: ['bsc'] }), ev('b', { domain: 'vuln', chains: ['eth'] })]);
    expect(nodes.map(n => n.chain)).toEqual(['bsc']);
  });
});
