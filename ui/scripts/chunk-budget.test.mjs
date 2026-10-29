import { describe, it, expect } from 'vitest';
import { evaluate, LIMIT_KB } from './chunk-budget.mjs';

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
