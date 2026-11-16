import { describe, it, expect } from 'vitest';
import { evaluate, evaluateCss, evaluateEntry, LIMIT_KB, BLOCKING_CSS_LIMIT_KB, ENTRY_LIMIT_KB, LAZY_PAGES } from './chunk-budget.mjs';

const KB = 1024;
const lazy = (kb) => [{ name: 'three-abc.js', text: '', gzBytes: kb * KB }];
const main = (text = 'react') => ({ name: 'index-abc.js', text, gzBytes: 50 * KB });

describe('chunk-budget evaluate', () => {
  it('the 3D budget is 150 KB gzip and is never loosened', () => { expect(LIMIT_KB).toBe(150); });
  it('passes at 149 KB of lazy 3D chunks', () => { expect(evaluate([main(), ...lazy(149)]).ok).toBe(true); });
  it('fails at 151 KB of lazy 3D chunks', () => { expect(evaluate([main(), ...lazy(151)]).ok).toBe(false); });
  it('fails when three.js leaks into the main bundle', () => {
    expect(evaluate([main('new WebGLRenderer('), ...lazy(10)]).ok).toBe(false);
  });
  it('fails when no lazy 3D chunk exists (3D silently dropped is not a pass)', () => {
    expect(evaluate([main()]).ok).toBe(false);
  });
});

describe('render-blocking CSS (R3.6)', () => {
  const html = '<link rel="stylesheet" crossorigin href="/assets/index-a.css">';
  const css = (kb, text = '.x{}') => [{ name: 'index-a.css', text, gzBytes: kb * KB },
                                      { name: 'fonts-b.css', text: '@font-face{}', gzBytes: 70 * KB }];
  it('the budget is 20 KB gzip', () => { expect(BLOCKING_CSS_LIMIT_KB).toBe(20); });
  it('passes the measured build (12.7 KB, fonts in a lazy sheet)', () => { expect(evaluateCss(html, css(12.7)).ok).toBe(true); });
  it('fails over the budget', () => { expect(evaluateCss(html, css(21)).ok).toBe(false); });
  it('fails when @font-face is back in the blocking sheet', () => { expect(evaluateCss(html, css(5, '@font-face{}')).ok).toBe(false); });
  it('fails when index.html links no stylesheet (an empty check is not a pass)', () => { expect(evaluateCss('', css(5)).ok).toBe(false); });
});

describe('entry chunk (R3.6 route splitting)', () => {
  const build = (entryKb, pages = LAZY_PAGES) => [{ name: 'index-x.js', text: '', gzBytes: entryKb * KB },
    ...pages.map(p => ({ name: `${p}-x.js`, text: '', gzBytes: KB }))];
  it('passes the measured build (103.7 KB, ten page chunks)', () => { expect(evaluateEntry(build(103.7)).ok).toBe(true); });
  it('fails over the budget (the unsplit build was 138.1 KB)', () => { expect(evaluateEntry(build(138.1)).ok).toBe(false); });
  it('fails when a page is imported eagerly again', () => {
    const r = evaluateEntry(build(100, LAZY_PAGES.filter(p => p !== 'OpsPage')));
    expect(r.ok).toBe(false); expect(r.errors.join()).toContain('OpsPage');
  });
  it('fails without an entry chunk (an empty check is not a pass)', () => { expect(evaluateEntry(build(0).slice(1)).ok).toBe(false); });
  it('keeps the budget near the measurement', () => { expect(ENTRY_LIMIT_KB).toBeLessThanOrEqual(130); });
});
