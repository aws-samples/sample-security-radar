import { describe, expect, it } from 'vitest';
import { filterNotices } from '@/utils/announcements';
import type { Notice } from '@/types/site-data';

const NOW = new Date('2026-11-10T12:00:00Z');
const n = (title: string, kind: Notice['kind'], at: string, exchange = 'OKX'): Notice =>
  ({ source_id: `ex_${exchange}`, exchange, title, url: `https://x/${title}`, kind, published_at: at, seen_at: at });

const ROWS = [
  n('Will list FOO', 'listing', '2026-11-10T11:00:00Z'),
  n('Suspension of TRX deposits', 'suspension', '2026-11-10T09:00:00Z', 'Bybit'),
  n('Security Incident | Recovery Update', 'security', '2026-11-09T09:00:00Z', 'Binance'),
  n('Old hack notice', 'security', '2026-11-01T09:00:00Z', 'Zaif'),
];

describe('announcement board', () => {
  it('pins security and suspension notices of the last 72 h above newer listings', () => {
    const out = filterNotices(ROWS, { kinds: [], exchange: null, query: '' }, NOW).map(r => r.title);
    expect(out.slice(0, 2)).toEqual(['Suspension of TRX deposits', 'Security Incident | Recovery Update']);
    expect(out.indexOf('Old hack notice')).toBeGreaterThan(out.indexOf('Will list FOO'));   // older than 72 h: not pinned
  });
  it('filters by kind, exchange and text', () => {
    expect(filterNotices(ROWS, { kinds: ['security'], exchange: null, query: '' }, NOW)).toHaveLength(2);
    expect(filterNotices(ROWS, { kinds: [], exchange: 'Bybit', query: '' }, NOW).map(r => r.exchange)).toEqual(['Bybit']);
    expect(filterNotices(ROWS, { kinds: [], exchange: null, query: 'recovery' }, NOW)).toHaveLength(1);
  });
});
