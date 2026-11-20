/**
 * Neo 2026-11-19: 「当前给到的这个标签，会和我点击这些圆圈上展示的标签有覆盖效果，会让我看不到我点击的这个圆圈所体现的
 * 标签，因为你会把当前呈现的三个标签置顶」. The focused dot's tip is drawn above the NOW labels, beside its dot and inside
 * the stage; while a dot is focused (hovered, or open in the drawer) the other NOW labels dim and let the pointer through.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { renderToStaticMarkup } from 'react-dom/server';
import { TIP, tipPlacement, ageWord } from '@/utils/dotTip';
import { LeaderLabels } from '@/components/radar/LeaderLabels';

const CSS = readFileSync(resolve(__dirname, '../styles/wall.css'), 'utf8');
const SCOPE = readFileSync(resolve(__dirname, '../components/radar/ScopeWithLabels.tsx'), 'utf8');
const SCENE = readFileSync(resolve(__dirname, '../components/wall3d/WallScene3D.tsx'), 'utf8');
const ENGINE = readFileSync(resolve(__dirname, '../components/wall3d/engine/createEngine.ts'), 'utf8');

describe('the tip of a focused dot', () => {
  it('sits beside its dot, flips to the left near the right edge, never leaves the stage', () => {
    const box = { w: 600, h: 400 };
    expect(tipPlacement(100, 200, box)).toEqual({ left: 100 + TIP.gap, top: 200 - TIP.h / 2, side: 'right' });
    const near = tipPlacement(560, 390, box);
    expect(near.side).toBe('left');
    expect(near.left + TIP.w).toBeLessThanOrEqual(560);
    expect(near.top + TIP.h).toBeLessThanOrEqual(box.h);
    expect(tipPlacement(5, 2, box).top).toBeGreaterThanOrEqual(TIP.pad);
  });

  it('is drawn above the NOW labels (z-index over the label layer)', () => {
    const z = (sel: string, css: string) => Number(css.split(`${sel} {`)[1]?.match(/z-index: (\d+)/)?.[1]);
    expect(z('.dot-tip', CSS)).toBeGreaterThan(z('.ll-layer', CSS));
  });

  it('says its age in words', () => {
    const now = Date.parse('2026-11-19T12:00:00Z');
    expect(ageWord('2026-11-19T11:30:00Z', now)).toBe('30 分钟前');
    expect(ageWord('2026-11-19T07:00:00Z', now)).toBe('5 小时前');
    expect(ageWord('2026-11-16T12:00:00Z', now)).toBe('3 天前');
  });
});

describe('NOW labels step back while a dot is focused', () => {
  const items = [1, 2, 3].map(r => ({ id: `ev_${r}`, rank: r, severity: 'P0', title: `Event ${r}`, impact: null }));
  const anchors = Object.fromEntries(items.map((it, i) => [it.id, { x: 100 + i * 120, y: 200, visible: true }]));
  it('the others dim, the focused one is marked', () => {
    const html = renderToStaticMarkup(<LeaderLabels items={items as never} anchors={anchors} width={800} height={500}
      onSelect={() => {}} focusId="ev_2" />);
    expect(html).toMatch(/class="ll-layer has-focus"/);
    expect((html.match(/ll-label[^"]* is-focus/g) ?? []).length).toBe(1);
    expect(CSS).toMatch(/\.ll-layer\.has-focus \.ll-label:not\(\.is-focus\), \.ll-layer\.has-focus \.ll-line:not\(\.is-focus\) \{\s*opacity: \.18; pointer-events: none;/);
    const none = renderToStaticMarkup(<LeaderLabels items={items as never} anchors={anchors} width={800} height={500} onSelect={() => {}} />);
    expect(none).not.toMatch(/has-focus/);
  });

  it('2D and 3D both focus the hovered dot (or the one open in the drawer) and draw its tip', () => {
    expect(SCOPE).toMatch(/const focusId = hovered\?\.eventId \?\? selectedId;/);
    expect(SCOPE).toMatch(/<DotTip dot=\{hovered\}/);
    expect(SCENE).toMatch(/focusId=\{hover\?\.dot\.eventId \?\? selectedEventId \?\? null\}/);
    expect(SCENE).toMatch(/<DotTip dot=\{hover\.dot\}/);
    expect(ENGINE).not.toMatch(/canvas\.title =/);         // the browser's title tooltip it replaces
  });
});
