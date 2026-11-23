/**
 * R9.1 / R9.2 (Neo 2026-11-19): the sidebar collapses to an icon rail and remembers it; the wall lives in the shell
 * (no back button); under 800 px the sidebar is a top bar with a menu.
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { initialNavMode, isWallPath, RAIL_BELOW_PX } from '@/utils/navMode';
import { Layout } from '@/components/Layout';

const APP = readFileSync(resolve(__dirname, '../App.tsx'), 'utf8');
const WALL = readFileSync(resolve(__dirname, '../pages/WallPage.tsx'), 'utf8');
const CSS = readFileSync(resolve(__dirname, '../styles/layout.css'), 'utf8');

describe('nav mode', () => {
  it('a stored choice wins; with none: a rail below 1100 px (iPad), expanded above', () => {
    expect(initialNavMode(1440, 'rail')).toBe('rail');
    expect(initialNavMode(800, 'full')).toBe('full');
    expect(initialNavMode(RAIL_BELOW_PX - 1, null)).toBe('rail');
    expect(initialNavMode(RAIL_BELOW_PX, null)).toBe('full');
    expect(initialNavMode(1440, 'garbage')).toBe('full');       // a hand-edited value falls back to the default
    expect([isWallPath('/wall'), isWallPath('/wall/x'), isWallPath('/wallet'), isWallPath('/')]).toEqual([true, true, false, false]);
  });
});

describe('shell', () => {
  it('renders the rail class, a labelled collapse control and a title on every link in rail mode', () => {
    const store = new Map([['sr-nav', 'rail']]);
    vi.stubGlobal('localStorage', { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => store.set(k, v) });
    vi.stubGlobal('window', { innerWidth: 1440, matchMedia: () => ({ matches: false }) });
    const html = renderToStaticMarkup(<MemoryRouter><Layout /></MemoryRouter>);
    expect(html).toMatch(/class="app-shell is-rail"/);
    expect(html).toMatch(/data-testid="nav-collapse"[^>]*aria-label="展开侧栏"|aria-label="展开侧栏"[^>]*data-testid="nav-collapse"/);
    const links = html.match(/<a\b[^>]*app-nav-link[^>]*>/g) ?? [];
    expect(links.length).toBe(12);
    expect(links.every(a => / title="[^"]+"/.test(a))).toBe(true);     // the rail has no labels: a hover title each
    vi.unstubAllGlobals();
  });

  it('the wall is a route inside the shell and has no back button', () => {
    const shell = APP.split('<Route path="/" element={<Layout />}>')[1];
    expect(shell).toMatch(/<Route path="wall" element={<WallPage \/>} \/>/);
    expect(APP.split('<Route path="/" element={<Layout />}>')[0]).not.toMatch(/path="\/wall"/);
    expect(WALL).not.toMatch(/← 返回/);
    expect(WALL).not.toMatch(/position: 'fixed',\s*inset: 0/);
  });

  it('under 800 px the sidebar is a top bar whose menu opens as a full-screen sheet', () => {
    const phone = CSS.split('@media (max-width: 799px)')[1];
    expect(phone).toMatch(/\.app-shell \{ flex-direction: column; \}/);
    expect(phone).toMatch(/\.app-nav-links, \.app-nav-foot \{ display: none; \}/);
    expect(phone).toMatch(/\.app-nav\.is-open \{ position: fixed; inset: 0;/);
    expect(phone).toMatch(/\.app-nav-link \{ min-height: 44px;/);            // a finger-sized target
  });
});

describe('R9.2 page bodies', () => {
  const css = CSS;
  it('the wall re-flows by the main area: 2 rows under 1280 px, 1 column under 760 px, its status bar wraps', () => {
    expect(css).toMatch(/\.app-main \{ container-type: inline-size; container-name: main; \}/);
    const two = css.split('@container main (max-width: 1279px)')[1].split('@container')[0];
    expect(two).toMatch(/\.wall-center \{ grid-column: 1 \/ -1; order: -1;/);
    const one = css.split('@container main (max-width: 759px)')[1].split('@container')[0];
    expect(one).toMatch(/\.wall-grid \{ grid-template-columns: minmax\(0, 1fr\) !important;/);
    expect(one).toMatch(/\.wall-bar \{ height: auto !important; flex-wrap: wrap;/);
    expect(one).toMatch(/\.wall-kpis \{ display: grid !important; grid-template-columns: 1fr 1fr;/);
    for (const cls of ['wall-root', 'wall-grid', 'wall-left', 'wall-center', 'wall-right', 'wall-foot', 'wall-bar', 'wall-kpis'])
      expect(WALL, cls).toContain(`className="${cls}"`);
  });

  it('wide content scrolls in its own box, grids never demand more than the screen', () => {
    expect(css).toMatch(/\.app-main table \{ display: block; max-width: 100%; overflow-x: auto;/);
    const ct = readFileSync(resolve(__dirname, '../styles/continuum.css'), 'utf8');
    expect(ct).not.toMatch(/minmax\((420|480)px, 1fr\)/);
    const detail = readFileSync(resolve(__dirname, '../styles/detail.css'), 'utf8');
    expect(detail).toMatch(/\.crumbs li:last-child \{ display: block; flex: 1 1 0; overflow: hidden; text-overflow: ellipsis;/);
  });
});

describe('the wall opens with the sidebar collapsed (Neo 2026-11-19)', () => {
  it('entering the wall forces the rail; leaving restores the stored choice; expanding on the wall is not stored', () => {
    const LAYOUT = readFileSync(resolve(__dirname, '../components/Layout.tsx'), 'utf8');
    expect(LAYOUT).toMatch(/useEffect\(\(\) => \{ setMode\(onWall \? 'rail' : initialNavMode\(\)\); \}, \[onWall\]\);/);
    expect(LAYOUT).toMatch(/if \(!onWall\) storeNavMode\(next\);/);
  });
});

describe('the sidebar speaks English (Neo 2026-11-19: 「左边栏里面的内容应该全都是英文…大屏就叫 dashboard」)', () => {
  it('every label is English; Vulns is written out; 大屏 is Dashboard', () => {
    const LAYOUT = readFileSync(resolve(__dirname, '../components/Layout.tsx'), 'utf8');
    const labels = [...LAYOUT.matchAll(/label: '([^']+)'/g)].map(m => m[1]);
    expect(labels.length).toBe(12);
    expect(labels.filter(l => /[^\x20-\x7e]/.test(l))).toEqual([]);
    expect(labels).toContain('Dashboard');
    expect(labels).toContain('Vulnerabilities');
    expect(labels).not.toContain('Vulns');
  });
});

describe('the subscribe page says what a token address is (Neo 2026-11-19: 「令牌地址是无效的，是吗？」)', () => {
  it('names who each address is for, that a browser gets 401 by design, and offers a copy and a curl line', () => {
    const SUB = readFileSync(resolve(__dirname, '../pages/SubscribePage.tsx'), 'utf8');
    expect(SUB).toMatch(/在浏览器里直接打开会返回 401<\/b>，这是设计如此，不是故障/);
    expect(SUB).toMatch(/<CopyButton value=\{r\.atom\.api\} label="复制" \/>/);
    expect(SUB).not.toMatch(/Basic Auth/);              // a wrong claim on the public entrance
    expect(SUB).not.toMatch(/云端阅读器不能带凭证，订不了/);
  });
});
