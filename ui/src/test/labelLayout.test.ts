/**
 * B2 criterion (spec 01 §6.4): NOW leader labels never overlap, never leave the viewport, never cover an anchor.
 * Live check: make utils/labelLayout.rectsOverlap return false ⇒ the coincident-anchor and random suites go red.
 */
import { describe, it, expect } from 'vitest';
import { layoutLeaderLabels, LAYOUT } from '@/utils/labelLayout';
import type { LabelAnchor, LabelPlacement } from '@/utils/labelLayout';

const BOX = { w: 236, h: 46 };

// Independent overlap check (does not reuse the implementation under test).
function overlaps(a: LabelPlacement, b: LabelPlacement): boolean {
  return !(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y);
}

function assertValid(ps: LabelPlacement[], anchors: LabelAnchor[], vp: { w: number; h: number }) {
  for (const p of ps) {
    expect(p.x).toBeGreaterThanOrEqual(0);
    expect(p.y).toBeGreaterThanOrEqual(0);
    expect(p.x + p.w).toBeLessThanOrEqual(vp.w);
    expect(p.y + p.h).toBeLessThanOrEqual(vp.h);
    if (p.mode === 'float') {
      for (const a of anchors.filter(x => x.visible)) {
        const nx = Math.max(p.x, Math.min(a.x, p.x + p.w));
        const ny = Math.max(p.y, Math.min(a.y, p.y + p.h));
        expect(Math.hypot(nx - a.x, ny - a.y)).toBeGreaterThanOrEqual(LAYOUT.anchorClear);
      }
    }
  }
  for (let i = 0; i < ps.length; i++) {
    for (let j = i + 1; j < ps.length; j++) expect(overlaps(ps[i], ps[j]), `${ps[i].id} × ${ps[j].id}`).toBe(false);
  }
}

// Deterministic PRNG (mulberry32) so a failure is reproducible.
function rng(seed: number) {
  return () => {
    seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe('layoutLeaderLabels', () => {
  it('three coincident anchors (the 2026-10-23 screenshot case) get three disjoint floating labels', () => {
    const vp = { w: 1200, h: 800 };
    const anchors = ['a', 'b', 'c'].map(id => ({ id, x: 600, y: 400, visible: true }));
    const ps = layoutLeaderLabels(anchors, BOX, vp);
    expect(ps.map(p => p.id)).toEqual(['a', 'b', 'c']);
    expect(ps.every(p => p.mode === 'float')).toBe(true);
    assertValid(ps, anchors, vp);
  });

  it('rank 1 gets first pick: up-right at the shortest leader when the space is free', () => {
    const ps = layoutLeaderLabels([{ id: 'a', x: 300, y: 300, visible: true }], BOX, { w: 1000, h: 800 });
    expect(ps[0]).toMatchObject({ mode: 'float', x: 300 + 28 * 0.7, y: 300 - 28 * 0.7 - BOX.h });
    // leader ends on the box edge nearest to the anchor (its bottom-left corner here)
    expect(ps[0].lx).toBeCloseTo(ps[0].x);
    expect(ps[0].ly).toBeCloseTo(ps[0].y + BOX.h);
  });

  it('anchors in a corner flip to the side that fits', () => {
    const vp = { w: 900, h: 600 };
    const anchors = [{ id: 'tr', x: 895, y: 4, visible: true }];
    const [p] = layoutLeaderLabels(anchors, BOX, vp);
    expect(p.mode).toBe('float');
    expect(p.x + p.w).toBeLessThanOrEqual(p.ax); // went left
    expect(p.y).toBeGreaterThanOrEqual(p.ay);    // went down
    assertValid([p], anchors, vp);
  });

  it('an off-radar NOW event (>7 d) goes to the rail without a leader', () => {
    const vp = { w: 900, h: 600 };
    const [p] = layoutLeaderLabels([{ id: 'old', x: NaN, y: NaN, visible: false }], BOX, vp);
    expect(p.mode).toBe('offscreen');
    expect(p.x).toBe(vp.w - LAYOUT.pad - BOX.w);
    expect(p.y).toBe(LAYOUT.pad);
  });

  it('1000 random anchor sets (incl. coincident, edge-hugging, off-radar): disjoint, in viewport, nothing dropped', () => {
    const rand = rng(20261024);
    for (let n = 0; n < 1000; n++) {
      const vp = { w: Math.round(500 + rand() * 1100), h: Math.round(320 + rand() * 700) };
      const k = 1 + Math.floor(rand() * 3);
      const anchors: LabelAnchor[] = [];
      for (let i = 0; i < k; i++) {
        const mode = rand();
        if (mode < 0.15 && i > 0) anchors.push({ ...anchors[0], id: `n${i}` });                 // coincident
        else if (mode < 0.3) anchors.push({ id: `n${i}`, x: rand() < 0.5 ? 1 : vp.w - 1, y: rand() * vp.h, visible: true }); // edge
        else if (mode < 0.38) anchors.push({ id: `n${i}`, x: 0, y: 0, visible: false });          // off radar
        else anchors.push({ id: `n${i}`, x: rand() * vp.w, y: rand() * vp.h, visible: true });
      }
      const ps = layoutLeaderLabels(anchors, BOX, vp);
      expect(ps.length, `case ${n}`).toBe(k);
      assertValid(ps, anchors, vp);
    }
  });

  it('a viewport too small for a second box omits it instead of overlapping', () => {
    const vp = { w: 250, h: 60 };
    const anchors = ['a', 'b'].map(id => ({ id, x: 0, y: 0, visible: false }));
    const ps = layoutLeaderLabels(anchors, BOX, vp);
    expect(ps).toHaveLength(1);
    assertValid(ps, anchors, vp);
  });
});
