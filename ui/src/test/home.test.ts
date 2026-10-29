import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import type { EventSummary, SourceHealth } from '@/types/site-data';
import {
  groupByLifecycle, resolveNow, funnelView, applyFunnelAction, eventTimeLabel, signalCells,
  web3Loss24h, sourceRatio, parseHomeQuery, toHomeQuery, corroborationView } from '@/utils/home';
import { DEFAULT_FILTERS } from '@/utils/filters';
import { impactView } from '@/utils/response';

function ev(o: Partial<EventSummary>): EventSummary {
  return {
    event_id: 'ev_0000000000000000', domain: 'vuln', title: 't', level: 'V1', level_reason: '', severity: 'P1',
    exploitation: 'none', first_seen: '2026-10-23T00:00:00Z', last_updated: '2026-10-23T01:00:00Z',
    first_report_source: 's', independent_sources: 1, item_count: 1, cves: [], entities: [], chains: [],
    amount_usd_latest: null, amount_disputed: false, summary: null, ...o,
  };
}

const NOW = Date.parse('2026-10-23T17:33:37Z');

// The live sample (2026-10-23) the UI is reviewed against — acceptance criteria from spec 01 §3.2.
const mock = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/events.json'), 'utf8'));

describe('home on the live mock sample (spec 01 §3.2 acceptance)', () => {
  it('NOW keeps backend order and joins every id', () => {
    const cards = resolveNow(mock.now, mock.events)!;
    expect(cards.map(c => c.item.event_id)).toEqual(['ev_3fa1b7cea621a766', 'ev_bb65db3b8694e5f4', 'ev_ae62e1affab415ac']);
    expect(cards.every(c => c.event !== null)).toBe(true);
  });
  it('PHP2Shell chip reads 命中 1/2; Arista (not_eligible) renders no chip in lists', () => {
    const cards = resolveNow(mock.now, mock.events)!;
    expect(impactView(cards[1].event!.impact, 'list')!.label).toBe('命中 1/2');
    expect(impactView(cards[0].event!.impact, 'list')).toBeNull();
  });
  it('lifecycle tabs = 升级中 6 / 活跃 7 / 冷却 1 / 定稿 2 / 休眠 0, no unknown bucket', () => {
    const g = groupByLifecycle(mock.events);
    expect(g.map(x => [x.key, x.events.length])).toEqual([
      ['escalating', 6], ['active', 7], ['cooling', 1], ['finalized', 2], ['dormant', 0],
    ]);
  });
  it('funnel 34,404 → 250 → 21 → 3 → 2', () => {
    expect(funnelView(mock.funnel)!.segments.map(s => s.value)).toEqual([34404, 250, 21, 3, 2]);
  });
});

describe('groupByLifecycle', () => {
  it('missing lifecycle goes to a visible "unknown" group, never dropped', () => {
    const g = groupByLifecycle([ev({ event_id: 'a', lifecycle: 'active' }), ev({ event_id: 'b' })]);
    expect(g.at(-1)).toMatchObject({ key: 'unknown', label: '未分组' });
    expect(g.at(-1)!.events.map(e => e.event_id)).toEqual(['b']);
    expect(g.reduce((n, x) => n + x.events.length, 0)).toBe(2);
  });
  it('order is escalating → active → cooling → finalized → dormant; only dormant folded', () => {
    const g = groupByLifecycle([]);
    expect(g.map(x => x.key)).toEqual(['escalating', 'active', 'cooling', 'finalized', 'dormant']);
    expect(g.filter(x => x.folded).map(x => x.key)).toEqual(['dormant']);
  });
  it('sorts inside a group: P0 before P1 regardless of input order', () => {
    const g = groupByLifecycle([
      ev({ event_id: 'p1', severity: 'P1', lifecycle: 'active', last_updated: '2026-10-23T17:00:00Z' }),
      ev({ event_id: 'p0', severity: 'P0', lifecycle: 'active', last_updated: '2026-10-20T00:00:00Z' }),
    ]);
    expect(g[1].events.map(e => e.event_id)).toEqual(['p0', 'p1']);
  });
});

describe('resolveNow', () => {
  it('absent key ⇒ null (NOW 未生成); [] ⇒ [] (nothing must be handled) — distinct states', () => {
    expect(resolveNow(undefined, [])).toBeNull();
    expect(resolveNow(null, [])).toBeNull();
    expect(resolveNow([], [])).toEqual([]);
  });
  it('id missing from events[] is kept with event=null, not silently dropped', () => {
    const r = resolveNow([{ event_id: 'ev_gone', score: 1, reasons: ['x'] }], [ev({ event_id: 'ev_other' })])!;
    expect(r).toHaveLength(1);
    expect(r[0].event).toBeNull();
  });
});

describe('funnelView', () => {
  it('absent funnel ⇒ null (NoData), not zeros', () => {
    expect(funnelView(undefined)).toBeNull();
    expect(funnelView(null)).toBeNull();
  });
  it('fetched = 0 ⇒ blind (collection down), zeros give frac 0 and no NaN', () => {
    const v = funnelView({ window_hours: 24, fetched: 0, new_or_updated_items: 0, events_touched: 0, corroborated: 0, p0: 0 })!;
    expect(v.blind).toBe(true);
    expect(v.segments.every(s => s.frac === 0)).toBe(true);
  });
  it('log-scale widths: max = 1, monotone, small stages still visible', () => {
    const v = funnelView({ window_hours: 24, fetched: 34404, new_or_updated_items: 250, events_touched: 21, corroborated: 3, p0: 2 })!;
    const f = v.segments.map(s => s.frac);
    expect(f[0]).toBe(1);
    for (let i = 1; i < f.length; i++) expect(f[i]).toBeLessThanOrEqual(f[i - 1]);
    expect(f[4]).toBeGreaterThan(0.08); // linear would be 0.00006
    expect(v.blind).toBe(false);
  });
  it('only 事件 / 证实 / P0 are clickable and map to the right filters', () => {
    const v = funnelView({ window_hours: 24, fetched: 1, new_or_updated_items: 1, events_touched: 1, corroborated: 1, p0: 1 })!;
    expect(v.segments.map(s => s.action)).toEqual([null, null, 'touched_24h', 'corroborated', 'p0']);
    expect(applyFunnelAction(DEFAULT_FILTERS, 'touched_24h').stage).toBe('touched_24h');
    expect(applyFunnelAction(DEFAULT_FILTERS, 'corroborated').stage).toBe('corroborated');
    expect(applyFunnelAction(DEFAULT_FILTERS, 'p0')).toMatchObject({ severity: 'P0', stage: 'all' });
    expect(applyFunnelAction(DEFAULT_FILTERS, null)).toBe(DEFAULT_FILTERS);
  });
});

describe('eventTimeLabel', () => {
  it('backfilled 2021 hack updated 15 min ago says both dates', () => {
    const r = eventTimeLabel({ first_seen: '2021-05-26T00:00:00Z', last_updated: '2026-10-23T17:18:00Z' }, NOW);
    expect(r).toEqual({ text: '首见 2021-05 · 更新 15 分钟前', longRunning: true });
  });
  it('fresh event: update age only', () => {
    expect(eventTimeLabel({ first_seen: '2026-10-23T07:50:00Z', last_updated: '2026-10-23T15:33:37Z' }, NOW))
      .toEqual({ text: '更新 2 小时前', longRunning: false });
  });
  it('gap of exactly 30 d is not long-running (strict >)', () => {
    expect(eventTimeLabel({ first_seen: '2026-09-23T17:00:00Z', last_updated: '2026-10-23T17:00:00Z' }, NOW).longRunning).toBe(false);
  });
});

describe('signalCells', () => {
  it('V0 = 1 … V4 = 5; X = 0 + disputed', () => {
    expect(['V0', 'V1', 'V2', 'V3', 'V4'].map(l => signalCells(l as 'V0').filled)).toEqual([1, 2, 3, 4, 5]);
    expect(signalCells('X')).toEqual({ filled: 0, disputed: true });
    expect(signalCells('V4').disputed).toBe(false);
  });
});

describe('web3Loss24h', () => {
  it('sums web3 first_seen within 24 h; excludes backfills, other domains and null amounts', () => {
    const r = web3Loss24h([
      ev({ domain: 'web3', first_seen: '2026-10-23T00:00:00Z', amount_usd_latest: 385000 }),
      ev({ domain: 'web3', first_seen: '2026-10-23T07:37:00Z', amount_usd_latest: 2600000 }),
      ev({ domain: 'web3', first_seen: '2021-05-26T00:00:00Z', last_updated: '2026-10-23T17:18:00Z', amount_usd_latest: 550000 }),
      ev({ domain: 'vuln', first_seen: '2026-10-23T07:00:00Z', amount_usd_latest: 999 }),
      ev({ domain: 'web3', first_seen: '2026-10-23T07:00:00Z', amount_usd_latest: null }),
    ], NOW);
    expect(r).toEqual({ usd: 2985000, count: 2 });
  });
  it('mock sample: $2.99M from 2 events', () => {
    expect(web3Loss24h(mock.events, NOW)).toEqual({ usd: 2985000, count: 2 });
  });
});

describe('sourceRatio', () => {
  const s = (enabled: boolean, status: SourceHealth['status']) => ({ enabled, status }) as SourceHealth;
  it('loading / no enabled sources ⇒ null (unknown, not "0/0 正常")', () => {
    expect(sourceRatio([], true)).toBeNull();
    expect(sourceRatio([s(false, 'disabled')], false)).toBeNull();
  });
  it('denominator = enabled only', () => {
    expect(sourceRatio([s(true, 'ok'), s(true, 'failing'), s(false, 'disabled')], false)).toEqual({ ok: 1, enabled: 2 });
  });
});

describe('URL state round-trip', () => {
  it('defaults serialise to an empty query', () => {
    expect(toHomeQuery(DEFAULT_FILTERS, 'all').toString()).toBe('');
  });
  it('round-trips every field', () => {
    const f = { domain: 'web3', level: 'V3', severity: 'P0', exploitation: 'reported', stage: 'corroborated', search: 'php 8' } as const;
    const back = parseHomeQuery(toHomeQuery(f, 'escalating'));
    expect(back).toEqual({ filters: f, tab: 'escalating' });
  });
  it('rejects values outside the allowlist (query string is external input)', () => {
    const r = parseHomeQuery(new URLSearchParams('domain=../../x&sev=P9&tab=<script>&stage=1&level=v3'));
    expect(r).toEqual({ filters: DEFAULT_FILTERS, tab: 'all' });
  });
  it('caps search length', () => {
    expect(parseHomeQuery(new URLSearchParams('q=' + 'a'.repeat(500))).filters.search).toHaveLength(200);
  });
});

describe('impactView warns on dirty affected/0 (list chip guard)', () => {
  it('logs and shows 命中 ?', () => {
    const w = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(impactView({ status: 'affected', affected: 1, checked: 0 })!.label).toBe('命中 ?');
    expect(w).toHaveBeenCalled();
    w.mockRestore();
  });
});

describe('C5′ corroboration (P0/P1 at level ≥ V2)', () => {
  it('counts only P0/P1, and V2/V3/V4 as corroborated', () => {
    const ev = (severity: string, level: string) => ({ severity, level });
    const v = corroborationView([ev('P0', 'V3'), ev('P1', 'V2'), ev('P1', 'V1'), ev('P1', 'V4'), ev('P2', 'V1'), ev('P2', 'V0')]);
    expect(v).toEqual({ high: 4, corroborated: 3, single: 1, pct: 75 });
  });
  it('no high-severity events ⇒ no percentage (never a fake 0 % or 100 %)', () => {
    expect(corroborationView([{ severity: 'P2', level: 'V1' }]).pct).toBeNull();
  });
});
