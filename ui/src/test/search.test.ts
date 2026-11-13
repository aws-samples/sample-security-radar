import { describe, expect, it } from 'vitest';
import { searchRows } from '@/utils/search';
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
