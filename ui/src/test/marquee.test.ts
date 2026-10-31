/** Wall marquee (live feed + ticker): it must keep moving and wrap by exactly one copy, never snap back to 0. */
import { describe, it, expect } from 'vitest';
import { marqueeOffset } from '@/hooks/useMarquee';

describe('marqueeOffset', () => {
  it('advances by speed·dt in sub-pixel steps (no stall at < 1 px per frame)', () => {
    let acc = 0;
    for (let i = 0; i < 60; i++) acc = marqueeOffset(acc, 1000 / 60, 22, 1000);
    expect(acc).toBeCloseTo(22, 5);
  });
  it('wraps by one period, keeping the remainder (seamless, not a jump to the top)', () => {
    expect(marqueeOffset(995, 100, 220, 1000)).toBeCloseTo(17, 5);
  });
  it('a long frame (background tab) moves at most 100 ms worth', () => {
    expect(marqueeOffset(0, 5000, 22, 1000)).toBeCloseTo(2.2, 5);
  });
  it('no period ⇒ stays at 0', () => {
    expect(marqueeOffset(40, 16, 22, 0)).toBe(0);
  });
});
