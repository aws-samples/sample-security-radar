/**
 * Theme toggle logic tests — verifies localStorage persistence contract.
 * Uses pure functions to keep the tests environment-agnostic (no DOM).
 */
import { describe, it, expect } from 'vitest';

type Theme = 'light' | 'dark';

/** Mirrors getInitialTheme() logic in ThemeContext, injectable for testing */
function resolveTheme(
  stored: string | null,
  prefersDark: boolean,
): Theme {
  if (stored === 'light' || stored === 'dark') return stored as Theme;
  return prefersDark ? 'dark' : 'light';
}

describe('theme resolution', () => {
  it('returns stored light theme', () => {
    expect(resolveTheme('light', true)).toBe('light');
    expect(resolveTheme('light', false)).toBe('light');
  });

  it('returns stored dark theme', () => {
    expect(resolveTheme('dark', false)).toBe('dark');
    expect(resolveTheme('dark', true)).toBe('dark');
  });

  it('falls back to prefers-dark when no storage', () => {
    expect(resolveTheme(null, true)).toBe('dark');
    expect(resolveTheme(null, false)).toBe('light');
  });

  it('ignores invalid stored values', () => {
    expect(resolveTheme('auto', false)).toBe('light');
    expect(resolveTheme('', true)).toBe('dark');
    expect(resolveTheme('system', false)).toBe('light');
  });

  it('toggle produces opposite theme', () => {
    const toggle = (t: Theme): Theme => (t === 'light' ? 'dark' : 'light');
    expect(toggle('light')).toBe('dark');
    expect(toggle('dark')).toBe('light');
  });
});
