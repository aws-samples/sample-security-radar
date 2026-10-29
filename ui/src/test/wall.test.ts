/**
 * Wall (#/wall) view logic — NOW labels and the L2 drawer URL (spec 01 §6.2 / §6.4 / §6.5).
 * Live checks: rank from i (not i+1) / sort by severity / drop the SAFE_ID fullmatch ⇒ red.
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { nowLabels, drawerEventId, drawerHref } from '@/utils/wall';
import { computeRadarLayout, scopePointPx, SCOPE } from '@/utils/radarLayout';
import { impactView } from '@/utils/response';

const mock = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/events.json'), 'utf8'));
const CLOCK = Date.parse(mock.generated_at) + 5 * 60_000;

describe('nowLabels on the live mock sample', () => {
  it('labels exactly the NOW events in backend order (not "the 3 newest P0")', () => {
    const ls = nowLabels(mock.now, mock.events);
    expect(ls.map(l => [l.rank, l.id])).toEqual([
      [1, 'ev_3fa1b7cea621a766'], [2, 'ev_bb65db3b8694e5f4'], [3, 'ev_ae62e1affab415ac'],
    ]);
    // #3 is a P1 — a severity-based picker would have dropped it
    expect(ls[2].severity).toBe('P1');
  });

  it('PHP2Shell label carries the 命中 1/2 chip; Arista (not_eligible) carries none', () => {
    const ls = nowLabels(mock.now, mock.events);
    expect(impactView(ls[1].impact)?.label).toBe('命中 1/2');
    expect(impactView(ls[0].impact)).toBeNull();
  });

  it('all three NOW events are on the 7-day radar at the gate clock (so all three get a leader, none on the rail)', () => {
    const ids = new Set(computeRadarLayout(mock.events, CLOCK, 2000).map(d => d.eventId));
    for (const l of nowLabels(mock.now, mock.events)) expect(ids.has(l.id), l.id).toBe(true);
  });

  it('missing now key ⇒ no labels; an id absent from the list is skipped, ranks keep backend positions', () => {
    expect(nowLabels(null, mock.events)).toEqual([]);
    const ls = nowLabels([{ event_id: 'ev_gone', score: 1, reasons: [] }, ...mock.now.slice(0, 1)], mock.events);
    expect(ls.map(l => l.rank)).toEqual([2]);
  });
});

describe('drawer URL', () => {
  it('round-trips a real id', () => {
    const href = drawerHref('ev_bb65db3b8694e5f4');
    expect(href).toBe('/wall?event=ev_bb65db3b8694e5f4');
    expect(drawerEventId(new URLSearchParams(href.split('?')[1]))).toBe('ev_bb65db3b8694e5f4');
  });

  it('refuses path-like or multi-line values (they are spliced into ./data/events/<id>.json)', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    for (const bad of ['../sources', 'a/b', 'ev_1\n', 'ev_1.json', 'x'.repeat(65), 'ev 1']) {
      expect(drawerEventId(new URLSearchParams({ event: bad })), JSON.stringify(bad)).toBeNull();
    }
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
    expect(drawerEventId(new URLSearchParams(''))).toBeNull();
    expect(drawerEventId(new URLSearchParams('event='))).toBeNull();
  });
});

describe('scopePointPx (2D label anchors use RadarScope geometry)', () => {
  it('north on the outer ring and the centre at native size', () => {
    const top = scopePointPx(0, 1, SCOPE.viewBox);
    expect(top.x).toBeCloseTo(SCOPE.cx);
    expect(top.y).toBeCloseTo(SCOPE.cy - SCOPE.rMax);
    const c = scopePointPx(123, 0, 1040);
    expect(c).toEqual({ x: SCOPE.cx * 2, y: SCOPE.cy * 2 });
  });

  it('east is +x at 90°', () => {
    const e = scopePointPx(90, 1, SCOPE.viewBox);
    expect(e.x).toBeCloseTo(SCOPE.cx + SCOPE.rMax);
    expect(e.y).toBeCloseTo(SCOPE.cy);
  });
});
