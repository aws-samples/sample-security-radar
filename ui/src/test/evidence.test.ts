/**
 * Evidence grouping / citation numbering / progress order (utils/evidence.ts), on the live PHP2Shell sample.
 * Liveness (by hand): sort progressRows by time ⇒ "fixed order" red; compute corroborationMs from
 * second_source ⇒ "T1 = 0" red.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import type { ItemRef, ProgressStage } from '@/types/site-data';
import { groupEvidence, citationNumbers, progressRows, corroborationMs } from '@/utils/evidence';
import { durationZh, agoZh, utcShort } from '@/utils/timeZh';

const detail = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/events/ev_bb65db3b8694e5f4.json'), 'utf-8'));
const ITEMS: ItemRef[] = detail.items;
const PROGRESS: ProgressStage[] = detail.progress;

describe('groupEvidence', () => {
  const groups = groupEvidence(ITEMS);
  it('one group per independent source, echoes folded, nothing lost', () => {
    expect(groups).toHaveLength(8);
    expect(groups.reduce((n, g) => n + 1 + g.echoes.length, 0)).toBe(ITEMS.length);
    expect(groups.reduce((n, g) => n + g.echoes.length, 0)).toBe(ITEMS.length - 8);
  });
  it('first group is the T1 first report; each lead is the earliest of its group', () => {
    expect(groups[0].lead.source_id).toBe('fortinet_psirt');
    for (const g of groups) for (const e of g.echoes) expect(Date.parse(e.published_at)).toBeGreaterThanOrEqual(Date.parse(g.lead.published_at));
    for (let i = 1; i < groups.length; i++) expect(Date.parse(groups[i].lead.published_at)).toBeGreaterThanOrEqual(Date.parse(groups[i - 1].lead.published_at));
  });
  it('citation numbers: leads 1..G (no gaps while echoes are folded), echoes G+1..N', () => {
    const m = citationNumbers(groups);
    expect(m.size).toBe(ITEMS.length);
    expect(groups.map(g => m.get(g.lead.item_id))).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(m.get(groups.find(g => g.echoes.length)!.echoes[0].item_id)).toBe(9);
    expect([...m.values()].sort((a, b) => a - b)).toEqual(ITEMS.map((_, i) => i + 1));
  });
  it('every analysis citation resolves to an evidence item (else the [n] link would be dead)', () => {
    const m = citationNumbers(groups);
    const a = detail.analysis;
    const cites: string[] = ['bluf', 'what', 'impact', 'exploitation', 'actions', 'unknowns'].flatMap(k => a[k].flatMap((s: { cite: string[] }) => s.cite));
    expect(cites.length).toBeGreaterThan(0);
    expect(cites.filter(c => !m.has(c))).toEqual([]);
  });
});

describe('progress', () => {
  it('fixed 7-stage order regardless of timestamps; missing ⇒ null', () => {
    const rows = progressRows(PROGRESS);
    expect(rows.map(r => r.stage)).toEqual(['first_report', 'second_source', 'corroborated', 'confirmed', 'exploited', 'analyzed', 'finalized']);
    expect(rows[6].at).toBeNull();
    expect(progressRows([]).every(r => r.at === null)).toBe(true);
  });
  it('time-to-corroborate = corroborated − first_report (T1 ⇒ 0), null when unknown', () => {
    expect(corroborationMs(PROGRESS)).toBe(0);
    expect(corroborationMs(undefined)).toBeNull();
    expect(corroborationMs([{ stage: 'first_report', at: '2026-10-21T07:00:00Z' }, { stage: 'corroborated', at: null }])).toBeNull();
    expect(corroborationMs([{ stage: 'first_report', at: '2026-10-21T07:00:00Z' }, { stage: 'corroborated', at: '2026-10-21T09:00:00Z' }])).toBe(7_200_000);
  });
});

describe('timeZh', () => {
  it('durations', () => {
    expect(durationZh(0)).toBe('0 分钟');
    expect(durationZh(125 * 60_000)).toBe('2 小时 5 分');
    expect(durationZh((2 * 24 + 9) * 3_600_000)).toBe('2 天 9 小时');
    expect(durationZh(-1)).toBeNull();
    expect(durationZh(null)).toBeNull();
  });
  it('ago clamps the future to 刚刚 and formats UTC', () => {
    const now = Date.parse('2026-10-23T17:33:37Z');
    expect(agoZh('2026-10-24T00:00:00Z', now)).toBe('刚刚');
    expect(agoZh('2026-10-21T07:00:00Z', now)).toBe('2 天 10 小时前');
    expect(utcShort('2026-10-21T07:00:00Z')).toBe('10-21 07:00');
    expect(utcShort(null)).toBe('—');
  });
});
