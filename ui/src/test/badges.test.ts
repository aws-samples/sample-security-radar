import { describe, it, expect } from 'vitest';
import { LEVEL_META } from '@/components/LevelBadge';
import { SEV_META } from '@/components/SeverityBadge';
import type { Level, Severity } from '@/types/site-data';

const ALL_LEVELS: Level[] = ['V0', 'V1', 'V2', 'V3', 'V4', 'X'];
const ALL_SEVERITIES: Severity[] = ['P0', 'P1', 'P2'];

describe('LevelBadge LEVEL_META', () => {
  it('has an entry for every level', () => {
    for (const level of ALL_LEVELS) {
      expect(LEVEL_META).toHaveProperty(level);
    }
  });

  it('every level has label, color, shape, title', () => {
    for (const level of ALL_LEVELS) {
      const m = LEVEL_META[level];
      expect(m.label).toBeTruthy();
      expect(m.color).toMatch(/^var\(--/);
      expect(m.shape).toBeTruthy();
      expect(m.title).toBeTruthy();
    }
  });

  it('V0 is the lowest-certainty level (gray)', () => {
    expect(LEVEL_META.V0.color).toBe('var(--level-v0)');
  });

  it('X has distinct color from V0-V4', () => {
    const v0to4Colors = ALL_LEVELS
      .filter(l => l !== 'X')
      .map(l => LEVEL_META[l].color);
    expect(v0to4Colors).not.toContain(LEVEL_META.X.color);
  });

  it('label matches level key', () => {
    for (const level of ALL_LEVELS) {
      expect(LEVEL_META[level].label).toBe(level);
    }
  });
});

describe('SeverityBadge SEV_META', () => {
  it('has an entry for every severity', () => {
    for (const sev of ALL_SEVERITIES) {
      expect(SEV_META).toHaveProperty(sev);
    }
  });

  it('every severity has label, color, title', () => {
    for (const sev of ALL_SEVERITIES) {
      const m = SEV_META[sev];
      expect(m.label).toBeTruthy();
      expect(m.color).toMatch(/^var\(--/);
      expect(m.title).toBeTruthy();
    }
  });

  it('P0 uses a distinct color from P1 and P2', () => {
    expect(SEV_META.P0.color).not.toBe(SEV_META.P1.color);
    expect(SEV_META.P0.color).not.toBe(SEV_META.P2.color);
  });

  it('label matches severity key', () => {
    for (const sev of ALL_SEVERITIES) {
      expect(SEV_META[sev].label).toBe(sev);
    }
  });
});
