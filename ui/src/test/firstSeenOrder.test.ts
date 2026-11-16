/** R3.4 — 「按首见排序」: the reader is owed (invariants over random lists, not one example):
 *  1. the same events as the filtered list, none dropped or doubled;
 *  2. newest first seen first, throughout;
 *  3. everything above the 「上次来访」 line arrived after the previous visit, nothing below it did. */
import { describe, expect, it } from 'vitest';
import { byFirstSeen, visitLineRows } from '@/utils/lastVisit';

function rng(seed: number) { return () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31); }

describe('first-seen order with the last-visit line', () => {
  it('holds the three invariants over 300 random lists', () => {
    for (let s = 1; s <= 300; s++) {
      const r = rng(s);
      const evs = Array.from({ length: Math.floor(r() * 40) }, (_, i) => ({
        id: i, first_seen: r() < 0.05 ? null : new Date(Date.UTC(2026, 10, 1 + Math.floor(r() * 14), Math.floor(r() * 24))).toISOString(),
      }));
      const boundary = r() < 0.1 ? null : new Date(Date.UTC(2026, 10, 1 + Math.floor(r() * 14))).toISOString();
      const { fresh, older } = byFirstSeen(evs, boundary);
      const all = [...fresh, ...older];
      expect(all.map(e => e.id).sort((a, b) => a - b)).toEqual(evs.map(e => e.id));                     // 1
      for (let k = 1; k < all.length; k++) expect((all[k - 1].first_seen ?? '') >= (all[k].first_seen ?? '')).toBe(true);  // 2
      expect(fresh.every(e => boundary && e.first_seen && e.first_seen > boundary)).toBe(true);           // 3
      expect(older.every(e => !(boundary && e.first_seen && e.first_seen > boundary))).toBe(true);
    }
  });
  it('a first visit has no line: nothing is fresh', () => {
    expect(byFirstSeen([{ first_seen: '2026-11-15T00:00:00Z' }], null).fresh).toEqual([]);
  });
});

describe('the previous-visit line', () => {
  const B = '2026-11-14T08:30:00.000Z';
  const order = byFirstSeen([{ id: 1, first_seen: '2026-11-15T01:00:00Z' }, { id: 2, first_seen: '2026-11-13T01:00:00Z' }], B);
  it('sits between the fresh and the older events, with the visit time', () => {
    expect(visitLineRows(order, B)).toEqual([{ ev: order.fresh[0] }, { line: '上次来访 · 11-14 08:30 UTC' }, { ev: order.older[0] }]);
  });
  it('is not drawn when it separates nothing', () => {
    const onlyOld = byFirstSeen([{ first_seen: '2026-11-13T01:00:00Z' }], B);
    const onlyNew = byFirstSeen([{ first_seen: '2026-11-15T01:00:00Z' }], B);
    expect(visitLineRows(onlyOld, B).some(r => 'line' in r)).toBe(false);
    expect(visitLineRows(onlyNew, B).some(r => 'line' in r)).toBe(false);
  });
});
