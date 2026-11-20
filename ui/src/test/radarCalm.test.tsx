/**
 * R9.4 calm (Neo's colleague 2026-11-19: 「3D…现在有点太混乱了」; Neo: 「能不能更好…看得更加直观」): only what matters stands
 * out. The camera holds still; only P0 stands tall (P1 a stub, P2 on the floor); decoration (stars, the sweep's
 * curtain, orbits, tether, compass bearings, the orbiting status text) is gone; the NOW marks are rank badges.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { renderToStaticMarkup } from 'react-dom/server';
import { displayHeight } from '@/utils/radar3dLayout';
import { TIER_SETTINGS } from '@/components/wall3d/engine/quality';
import { LABEL_BOX, LeaderLabels } from '@/components/radar/LeaderLabels';
import { STAGE_PALETTE } from '@/components/wall3d/engine/createEngine';
import { RadarScope } from '@/components/radar/RadarScope';

const ENGINE = readFileSync(resolve(__dirname, '../components/wall3d/engine/createEngine.ts'), 'utf8');
const SCENE = readFileSync(resolve(__dirname, '../components/wall3d/WallScene3D.tsx'), 'utf8');

describe('3D holds still and keeps one hierarchy', () => {
  it('the camera never orbits, at any quality tier', () => {
    for (const [t, s] of Object.entries(TIER_SETTINGS)) expect(s.cameraOrbit, `tier ${t}`).toBe(false);
  });
  it('only P0 stands tall', () => {
    for (const h of [0.2, 1, 3]) {
      expect(displayHeight('P0', h)).toBeGreaterThanOrEqual(1.2);
      expect(displayHeight('P1', h)).toBeLessThanOrEqual(0.32);
      expect(displayHeight('P2', h)).toBeLessThan(0.05);
    }
  });
  it('no decoration behind the data', () => {
    expect(ENGINE).not.toMatch(/scene\.add\(stars\)/);
    expect(ENGINE).not.toMatch(/scene\.add\(curtain\)/);
    expect(ENGINE).not.toMatch(/core\.add\(orbitA, orbitB\)/);
    expect(STAGE_PALETTE.dark.stars).toBe(false);
  });
  it('a ring in place carries no label (only off / failing / unread ones are named)', () => {
    expect(SCENE).toMatch(/if \(!pos\?\.visible \|\| c\.state === 'on'\) return null;/);
  });
});

describe('the NOW marks are rank badges, the titles are in the NOW column', () => {
  it('a badge is small and carries the title as its hover text', () => {
    expect(LABEL_BOX.w).toBeLessThanOrEqual(90);
    expect(LABEL_BOX.h).toBeLessThanOrEqual(26);
    const items = [{ id: 'ev_1', rank: 1, severity: 'P0', title: 'Java4Shell: Remote Code Execution in OpenJDK', impact: { status: 'affected', affected: 1, checked: 2 } }];
    const html = renderToStaticMarkup(<LeaderLabels items={items as never} anchors={{ ev_1: { x: 300, y: 200, visible: true } }}
      width={800} height={500} onSelect={() => {}} />);
    expect(html).toMatch(/title="Java4Shell: Remote Code Execution in OpenJDK"/);
    expect(html).not.toMatch(/class="ll-title"/);
    expect(html).toMatch(/class="ll-hit"/);              // a hit on your code is still marked on the badge
  });
});

describe('2D says only what the reader needs', () => {
  it('no compass bearings, no orbiting status text', () => {
    const html = renderToStaticMarkup(<RadarScope points={[]} onSelect={() => {}} />);
    expect(html).not.toMatch(/SECURITY RADAR · LIVE/);
    expect(html).not.toMatch(/>0[369]0</);
    expect(html).not.toMatch(/>(120|150|210|240|270|300|330)</);
  });
});

describe('2D: the NOW badges sit outside the scope (Neo 2026-11-19: 「把整个雷达中心挡住了，你要不挪到雷达圆圈的外面去」)', () => {
  it('every badge clears the circle and keeps clear of the others', async () => {
    const { layoutLeaderLabels } = await import('@/utils/labelLayout');
    const o = { cx: 400, cy: 300, r: 200 };
    const anchors = [{ id: 'a', x: 430, y: 260, visible: true }, { id: 'b', x: 380, y: 330, visible: true },
      { id: 'c', x: 520, y: 290, visible: true }];
    const out = layoutLeaderLabels(anchors, LABEL_BOX, { w: 800, h: 600, outside: o });
    expect(out.length).toBe(3);
    for (const p of out) {
      // the rectangle's nearest point to the centre is beyond the rim
      const nx = Math.max(p.x, Math.min(o.cx, p.x + p.w)), ny = Math.max(p.y, Math.min(o.cy, p.y + p.h));
      expect(Math.hypot(nx - o.cx, ny - o.cy), p.id).toBeGreaterThan(o.r);
      // …and beside its own dot's direction (on the ray centre → dot), not parked on the stage's edge rail
      expect(p.mode, p.id).toBe('float');
      const a = anchors.find(x => x.id === p.id)!;
      const da = Math.atan2(a.y - o.cy, a.x - o.cx), dl = Math.atan2(p.y + p.h / 2 - o.cy, p.x + p.w / 2 - o.cx);
      expect(Math.abs(Math.atan2(Math.sin(da - dl), Math.cos(da - dl))), p.id).toBeLessThan(0.7);
    }
    const SCOPE_WL = readFileSync(resolve(__dirname, '../components/radar/ScopeWithLabels.tsx'), 'utf8');
    expect(SCOPE_WL).toMatch(/focusId=\{focusId\} outside=\{circle\} \/>/);
  });
});

describe('3D: the reader turns the scene about its axis (Neo 2026-11-19: 「围绕中轴线…像地球一样搓一下」)', () => {
  it('a horizontal drag turns full circles, a vertical drag tilts within limits, the axis stays vertical', async () => {
    const { dragView, orbitPosition, ELEV_MIN, ELEV_MAX, CAM_ELEV, CAM_DIST } = await import('@/components/wall3d/engine/project');
    let v = { az: 0, elev: CAM_ELEV };
    v = dragView(v, -450, 0);                       // 450 px right-to-left ⇒ 180°
    expect(v.az).toBeCloseTo(180, 5);
    expect(dragView(v, 0, -10_000).elev).toBe(ELEV_MAX);
    expect(dragView(v, 0, 10_000).elev).toBe(ELEV_MIN);
    const p = orbitPosition(v.az, 0.5);
    expect(Math.hypot(p.x, p.y, p.z)).toBeCloseTo(CAM_DIST, 5);   // it orbits the centre, never moves the axis
    expect(orbitPosition(0, 99).y).toBeCloseTo(CAM_DIST * Math.cos(ELEV_MAX), 5);   // clamped even when asked
  });
  it('a drag is never a pick; a double-click resets; touch keeps vertical page scroll', () => {
    expect(ENGINE).toMatch(/if \(swallowClick\) \{ swallowClick = false; return; \}/);
    expect(ENGINE).toMatch(/function handleDoubleClick\(\) \{ view = \{ az: 0, elev: CAM_ELEV \}; applyView\(\); \}/);
    expect(ENGINE).toMatch(/canvas\.style\.touchAction = 'pan-y';/);
    expect(SCENE).toMatch(/拖动旋转 · 双击复位/);
  });
});
