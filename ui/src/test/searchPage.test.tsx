/**
 * #/search loading and rendering (research/action/06 B1, B3, B4): a shard that failed is said, not shown as fewer
 * hits; the index's kind is checked; nothing is reported after unmount; a hit without a detail page is not a link.
 */
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import type { SearchRow } from '@/types/site-data';
import { fetchShard, loadSearch, type SearchMonth, type SearchSink } from '@/utils/search';
import { SearchView } from '@/pages/SearchPage';

const row = (id: string, p?: true): SearchRow => ({ id, t: `Event ${id}`, d: 'vuln', s: 'P2', l: 'V1', f: '2026-10-01',
                                                  u: '2026-10-01', c: [], e: [], a: null, ...(p ? { p } : {}) });
const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const status = (code: number) => Promise.resolve({ ok: false, status: code, json: () => Promise.reject(new Error('no body')) });
const notJson = () => Promise.resolve({ ok: true, status: 200, json: () => Promise.reject(new SyntaxError('Unexpected token <')) });

function sink() {
  const got = { months: [] as SearchMonth[], cap: undefined as number | null | undefined, rows: [] as SearchRow[], loaded: 0,
                failed: [] as string[], error: null as string | null };
  const s: SearchSink = {
    index: (m, cap) => { got.months = m; got.cap = cap; },
    shards: (rows, n, failed) => { got.rows.push(...rows); got.loaded += n; got.failed.push(...failed); },
    error: e => { got.error = e; },
  };
  return { got, s };
}

const INDEX = { kind: 'search-index', generated_at: 't', total: 3, months: [{ month: '2026-10', events: 2 }, { month: '2026-09', events: 1 }] };

describe('search loading', () => {
  it('a month that failed to load is reported as failed, not as an empty month', async () => {
    const { got, s } = sink();
    const get = (u: string) => u.endsWith('index.json') ? ok(INDEX)
      : u.endsWith('2026-10.json') ? ok({ kind: 'search-shard', month: '2026-10', events: [row('ev_1'), row('ev_2')] })
      : status(503);
    await loadSearch(get, () => true, s);
    expect(got.rows.map(r => r.id)).toEqual(['ev_1', 'ev_2']);
    expect(got.loaded).toBe(2);
    expect(got.failed).toEqual(['2026-09']);
    expect(got.error).toBeNull();
  });

  it('the publish cap comes from the index (Limits.PUBLISH_MAX_EVENTS), absent when the index predates it', async () => {
    for (const [idx, want] of [[{ ...INDEX, detail_cap: 750 }, 750], [INDEX, null], [{ ...INDEX, detail_cap: '500' }, null]] as const) {
      const { got, s } = sink();
      await loadSearch(u => u.endsWith('index.json') ? ok(idx) : ok({ kind: 'search-shard', events: [] }), () => true, s);
      expect(got.cap).toBe(want);
    }
  });

  it('a shard that is not a search shard (SPA fallback, network error) counts as failed', async () => {
    expect(await fetchShard(() => notJson(), '2026-10')).toBeNull();
    expect(await fetchShard(() => ok({ kind: 'events', events: [] }), '2026-10')).toBeNull();
    expect(await fetchShard(() => Promise.reject(new TypeError('Failed to fetch')), '2026-10')).toBeNull();
    expect(await fetchShard(() => ok({ kind: 'search-shard', events: [] }), '2026-10')).toEqual([]);
  });

  it('an index that is not a search index is an error, not zero months', async () => {
    for (const get of [() => ok({ kind: 'ops', months: [] }), () => notJson(), () => ok({ kind: 'search-index' })]) {
      const { got, s } = sink();
      await loadSearch(get, () => true, s);
      expect(got.error).toMatch(/unexpected data kind/);
      expect(got.months).toEqual([]);
    }
  });

  it('nothing is reported after the page unmounted — not even an error', async () => {
    const { got, s } = sink();
    let live = true;
    await loadSearch(() => { live = false; return status(500); }, () => live, s);
    expect(got.error).toBeNull();
  });
});

describe('search rendering', () => {
  const view = (rows: SearchRow[], failed: string[] = [], detailCap: number | null = 500) => renderToStaticMarkup(
    <MemoryRouter><SearchView months={[{ month: '2026-10', events: rows.length }, { month: '2026-09', events: 4 }]} rows={rows}
                              loaded={2} failed={failed} detailCap={detailCap} q="event" setQ={() => {}} /></MemoryRouter>);

  it('the unlinked hit names the cap the index states, never a number of its own', () => {
    expect(view([row('ev_nopage')], [], 750)).toContain('未进入发布的前 750 条');
    const old = view([row('ev_nopage')], [], null);
    expect(old).toContain('无详情页');
    expect(old).not.toMatch(/前 \d+ 条/);
  });

  it('only a hit with a published detail page links to it', () => {
    const html = view([row('ev_page', true), row('ev_nopage')]);
    expect(html).toContain('href="/events/ev_page"');
    expect(html).not.toContain('/events/ev_nopage');
    expect(html).toContain('Event ev_nopage');
    expect(html).toContain('无详情页');
  });

  it('failed months are shown with their count', () => {
    expect(view([row('ev_1', true)], ['2026-09'])).toContain('1 个月载入失败');
    expect(view([row('ev_1', true)])).not.toContain('载入失败');
  });
});

describe('document language', () => {
  it('the page is declared Chinese (screen readers pick the voice from lang)', () => {
    const html = readFileSync(resolve(__dirname, '../../index.html'), 'utf-8');
    expect(html).toMatch(/<html lang="zh-CN">/);
  });
});
