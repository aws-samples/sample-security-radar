import { describe, expect, it } from 'vitest';
import { hitLink, searchRows } from '@/utils/search';
import type { SearchRow } from '@/types/site-data';

const r = (id: string, t: string, f: string, c: string[] = [], e: string[] = []): SearchRow =>
  ({ id, t, d: 'vuln', s: 'P2', l: 'V1', f, u: f, c, e, a: null });
const ROWS = [r('ev_1', 'Fortinet FortiWeb zero-day', '2026-08-01', ['CVE-2026-1'], ['fortinet']),
              r('ev_2', 'Binance hot wallet theft', '2026-11-01', [], ['binance']),
              r('ev_3', 'Fortinet FortiOS SSL VPN', '2026-10-01', ['CVE-2026-3'], ['fortinet'])];

describe('static search', () => {
  it('needs every term and returns newest first', () => {
    expect(searchRows(ROWS, 'fortinet').map(x => x.id)).toEqual(['ev_3', 'ev_1']);
    expect(searchRows(ROWS, 'fortinet vpn').map(x => x.id)).toEqual(['ev_3']);
  });
  it('matches CVE ids and entities, and nothing for an empty query', () => {
    expect(searchRows(ROWS, 'cve-2026-1').map(x => x.id)).toEqual(['ev_1']);
    expect(searchRows(ROWS, 'BINANCE').map(x => x.id)).toEqual(['ev_2']);
    expect(searchRows(ROWS, '  ')).toEqual([]);
  });
});

describe('R3.5 search: one row per event, relevance first, filters', async () => {
  const { dedupe, searchHits } = await import('@/utils/search');
  const x = (id: string, t: string, f: string, extra: Partial<SearchRow> = {}): SearchRow =>
    ({ id, t, d: 'vuln', s: 'P2', l: 'V1', f, u: f, c: [], e: [], a: null, ...extra });

  it('keeps the newest copy of an event that sits in two month shards', () => {
    const rows = dedupe([x('ev_1', 'old title', '2026-09-01'), x('ev_1', 'new title', '2026-09-01', { u: '2026-11-01' })]);
    expect(rows.map(r => r.t)).toEqual(['new title']);
  });

  it('an exact CVE or a title word outranks a mere substring; severity breaks ties before recency', () => {
    const rows = [x('ev_a', 'Ivanti EPMM flaw', '2026-11-10', { c: ['CVE-2026-100'] }),
                  x('ev_b', 'Roundup mentions ivantis', '2026-11-12'),
                  x('ev_c', 'Ivanti VPN zero-day', '2026-10-01', { s: 'P0' })];
    expect(searchHits(rows, 'cve-2026-100').hits.map(r => r.id)).toEqual(['ev_a']);
    expect(searchHits(rows, 'ivanti').hits.map(r => r.id)).toEqual(['ev_c', 'ev_a', 'ev_b']);
  });

  it('filters by domain, lowest severity and month, and counts the matches before the limit', () => {
    const rows = [x('ev_1', 'hack a', '2026-11-01', { d: 'web3', s: 'P1' }), x('ev_2', 'hack b', '2026-10-01', { s: 'P2' }),
                  x('ev_3', 'hack c', '2026-11-02', { d: 'web3', s: 'P2' })];
    expect(searchHits(rows, 'hack', { domain: 'web3' }).hits.map(r => r.id)).toEqual(['ev_1', 'ev_3']);   // P1 before P2
    expect(searchHits(rows, 'hack', { severity: 'P1' }).hits.map(r => r.id)).toEqual(['ev_1']);
    expect(searchHits(rows, 'hack', { month: '2026-10' }).hits.map(r => r.id)).toEqual(['ev_2']);
    const many = Array.from({ length: 250 }, (_, k) => x(`ev_${k}`, 'hack', '2026-11-01'));
    expect(searchHits(many, 'hack')).toMatchObject({ total: 250 });
    expect(searchHits(many, 'hack').hits).toHaveLength(200);
  });
});

describe('R3.5 where a hit leads', () => {
  const row = (x: Partial<SearchRow>): SearchRow => ({ id: 'ev_1', t: 't', d: 'vuln', s: 'P1', l: 'V1', f: '2026-11-01', u: '2026-11-01', c: [], e: [], a: null, ...x });
  it('its page when it has one, else its source, else nowhere — never a javascript: link', () => {
    expect(hitLink(row({ p: true, r: 'https://x.example/a' }))).toEqual({ kind: 'page', to: '/events/ev_1' });
    expect(hitLink(row({ r: 'https://x.example/a' }))).toEqual({ kind: 'source', href: 'https://x.example/a' });
    expect(hitLink(row({}))).toEqual({ kind: 'none' });
    expect(hitLink(row({ r: 'javascript:alert(1)' }))).toEqual({ kind: 'none' });
  });
});
