/** R7.2 — #/subscribe lists every published feed with both of its addresses, and only real feed paths become links. */
import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import type { FeedEntry } from '@/types/site-data';
import { feedRows, filterText } from '@/utils/subscribe';

const feed = (name: string, filters: Record<string, unknown> = {}, over: Partial<FeedEntry> = {}): FeedEntry =>
  ({ name, title: name.toUpperCase(), filters, items: 3, json: `feeds/${name}.json`, atom: `feeds/${name}.atom`, ...over } as FeedEntry);

describe('feed rows', () => {
  it('gives each feed its site address and its token address, for both formats', () => {
    const [r] = feedRows([feed('p0', { severity: ['P0'] })], 'https://radar.example/');
    expect(r.atom).toEqual({ site: 'https://radar.example/data/feeds/p0.atom', api: 'https://radar.example/api/data/feeds/p0.atom' });
    expect(r.json).toEqual({ site: 'https://radar.example/data/feeds/p0.json', api: 'https://radar.example/api/data/feeds/p0.json' });
    expect(feedRows([feed('all')], 'https://radar.example')[0].atom.site).toBe('https://radar.example/data/feeds/all.atom');
  });

  it('drops a row whose path is not a feed document', () => {
    const rows = feedRows([feed('ok'), feed('bad', {}, { atom: 'https://evil.example/x.atom' }),
                           feed('up', {}, { json: 'feeds/../ops.json' }), feed('js', {}, { atom: 'javascript:alert(1)' })],
                          'https://radar.example/');
    expect(rows.map(r => r.name)).toEqual(['ok']);
  });

  it('says the filter in words, and says when there is none', () => {
    expect(filterText({})).toBe('不筛选');
    expect(filterText({ severity: ['P0'], domain: ['web3'] })).toBe('级别：P0 · 域：web3');
    expect(filterText({ has_waf_pack: true })).toBe('已有 WAF 规则包');
    expect(filterText({ exchanges: ['a', 'b', 'c', 'd', 'e'] })).toBe('交易所：5 个');
  });
});

const state = { feeds: [feed('p0', { severity: ['P0'] }), feed('all')], generatedAt: '2026-11-14T00:00:00Z', loading: false, error: null as string | null };
vi.mock('@/hooks/useFeeds', () => ({ useFeeds: () => state }));

describe('#/subscribe', () => {
  it('lists the feeds and the three ways to connect', async () => {
    const { SubscribePage } = await import('@/pages/SubscribePage');
    const html = renderToStaticMarkup(<SubscribePage />);
    expect(html.match(/class="sub-row"/g)).toHaveLength(2);
    expect(html).toContain('data/feeds/p0.atom');
    expect(html).toContain('api/data/feeds/p0.atom');
    // a link inside a sentence is underlined, not told apart by colour alone (axe link-in-text-block, CI 2026-11-14)
    expect(html).toMatch(/<a href="\.\/llms\.txt" style="text-decoration:underline"/);
    for (const word of ['Feed', 'Webhook', 'Agent', 'X-Radar-Signature', 'radar-token.py', 'llms.txt', 'radar.agentkit.subscriptions add', '--subscribe']) expect(html).toContain(word);
  });

  it('a failed feed list is an alert, not an empty table', async () => {
    const { SubscribePage } = await import('@/pages/SubscribePage');
    state.error = 'Error: HTTP 500'; state.feeds = [];
    const html = renderToStaticMarkup(<SubscribePage />);
    expect(html).toContain('role="alert"');
    expect(html).not.toContain('还没有发布任何 feed');
  });
});
