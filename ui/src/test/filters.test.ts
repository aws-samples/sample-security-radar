import { describe, it, expect } from 'vitest';
import { applyFilters, sortEvents, DEFAULT_FILTERS } from '@/utils/filters';
import type { EventSummary } from '@/types/site-data';

function makeEvent(overrides: Partial<EventSummary>): EventSummary {
  return {
    event_id: 'ev_' + Math.random().toString(16).slice(2, 18).padEnd(16, '0'),
    domain: 'vuln',
    title: 'Test Event',
    level: 'V1',
    level_reason: 'test',
    severity: 'P1',
    exploitation: 'none',
    first_seen: '2026-10-23T00:00:00Z',
    last_updated: '2026-10-23T01:00:00Z',
    first_report_source: 'test-source',
    independent_sources: 1,
    item_count: 1,
    cves: [],
    entities: [],
    chains: [],
    amount_usd_latest: null,
    amount_disputed: false,
    summary: null,
    ...overrides,
  };
}

describe('applyFilters', () => {
  const events: EventSummary[] = [
    makeEvent({ domain: 'vuln',     level: 'V3', severity: 'P0', exploitation: 'confirmed', title: 'Ivanti RCE',  cves: ['CVE-2026-0971'] }),
    makeEvent({ domain: 'web3',     level: 'V2', severity: 'P1', exploitation: 'confirmed', title: 'Bitget Hack', entities: ['Bitget'] }),
    makeEvent({ domain: 'incident', level: 'V0', severity: 'P2', exploitation: 'none',      title: 'Data Breach', entities: ['Okta'] }),
  ];

  it('returns all events for default (no) filters', () => {
    expect(applyFilters(events, DEFAULT_FILTERS)).toHaveLength(3);
  });

  it('filters by domain: vuln', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, domain: 'vuln' });
    expect(res).toHaveLength(1);
    expect(res[0].domain).toBe('vuln');
  });

  it('filters by domain: web3', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, domain: 'web3' });
    expect(res).toHaveLength(1);
    expect(res[0].domain).toBe('web3');
  });

  it('filters by level: V3', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, level: 'V3' });
    expect(res).toHaveLength(1);
    expect(res[0].level).toBe('V3');
  });

  it('filters by severity: P0', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, severity: 'P0' });
    expect(res).toHaveLength(1);
    expect(res[0].severity).toBe('P0');
  });

  it('filters by exploitation: confirmed', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, exploitation: 'confirmed' });
    expect(res).toHaveLength(2);
    expect(res.every(e => e.exploitation === 'confirmed')).toBe(true);
  });

  it('text search matches title', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, search: 'bitget' });
    expect(res).toHaveLength(1);
    expect(res[0].title).toContain('Bitget');
  });

  it('text search matches CVE', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, search: 'CVE-2026-0971' });
    expect(res).toHaveLength(1);
  });

  it('text search matches entity', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, search: 'okta' });
    expect(res).toHaveLength(1);
    expect(res[0].entities).toContain('Okta');
  });

  it('text search is case-insensitive', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, search: 'IVANTI' });
    expect(res).toHaveLength(1);
  });

  it('text search with no match returns empty', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, search: 'xyz-nonexistent' });
    expect(res).toHaveLength(0);
  });

  it('combined domain + severity filter', () => {
    const res = applyFilters(events, { ...DEFAULT_FILTERS, domain: 'vuln', severity: 'P0' });
    expect(res).toHaveLength(1);
    expect(res[0].domain).toBe('vuln');
    expect(res[0].severity).toBe('P0');
  });
});

describe('sortEvents', () => {
  it('puts P0 events first', () => {
    const events: EventSummary[] = [
      makeEvent({ severity: 'P2', last_updated: '2026-10-23T02:00:00Z' }),
      makeEvent({ severity: 'P0', last_updated: '2026-10-22T00:00:00Z' }),
      makeEvent({ severity: 'P1', last_updated: '2026-10-23T01:00:00Z' }),
    ];
    const sorted = sortEvents(events);
    expect(sorted[0].severity).toBe('P0');
    expect(sorted[1].severity).toBe('P1');
    expect(sorted[2].severity).toBe('P2');
  });

  it('within same severity, newer last_updated comes first', () => {
    const events: EventSummary[] = [
      makeEvent({ severity: 'P1', last_updated: '2026-10-22T00:00:00Z' }),
      makeEvent({ severity: 'P1', last_updated: '2026-10-23T12:00:00Z' }),
    ];
    const sorted = sortEvents(events);
    expect(new Date(sorted[0].last_updated) > new Date(sorted[1].last_updated)).toBe(true);
  });

  it('does not mutate original array', () => {
    const events: EventSummary[] = [
      makeEvent({ severity: 'P2' }),
      makeEvent({ severity: 'P0' }),
    ];
    const orig = [...events];
    sortEvents(events);
    expect(events[0].severity).toBe(orig[0].severity);
  });
});

describe('applyFilters stage (home funnel drill-down)', () => {
  const NOW = Date.parse('2026-10-23T17:33:37Z');
  const events: EventSummary[] = [
    makeEvent({ title: 'fresh V1', level: 'V1', last_updated: '2026-10-23T10:00:00Z' }),
    makeEvent({ title: 'old V3', level: 'V3', last_updated: '2026-10-20T10:00:00Z' }),
    makeEvent({ title: 'edge V2', level: 'V2', last_updated: '2026-10-22T17:33:37Z' }), // exactly 24 h
    // 1 s past the edge: without it any widening of the window (25 h, 72 h…) stays green (B7 mutation UM26 was alive)
    makeEvent({ title: 'past edge V1', level: 'V1', last_updated: '2026-10-22T17:33:36Z' }),
    makeEvent({ title: 'old X', level: 'X', last_updated: '2026-10-01T00:00:00Z' }),
  ];
  it('touched_24h keeps last_updated within 24 h (inclusive edge)', () => {
    expect(applyFilters(events, { ...DEFAULT_FILTERS, stage: 'touched_24h' }, NOW).map(e => e.title)).toEqual(['fresh V1', 'edge V2']);
  });
  it('corroborated keeps V2/V3/V4 only (X and V1 excluded)', () => {
    expect(applyFilters(events, { ...DEFAULT_FILTERS, stage: 'corroborated' }, NOW).map(e => e.title)).toEqual(['old V3', 'edge V2']);
  });
  it('stage=all is a no-op', () => {
    expect(applyFilters(events, DEFAULT_FILTERS, NOW)).toHaveLength(5);
  });
});
