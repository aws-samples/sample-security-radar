/** Event page tabs: the incident is the default; the environment tab is reachable by ?tab=env and the older ?section=env. */
import { describe, it, expect } from 'vitest';
import { detailTab, nextTab } from '@/utils/detailTabs';

describe('detailTab', () => {
  it('opens the incident by default and for ?section=evidence', () => {
    expect(detailTab(new URLSearchParams(''))).toBe('track');
    expect(detailTab(new URLSearchParams('section=evidence'))).toBe('track');
  });
  it('opens the environment tab for ?tab=env and for the older ?section=env deep link', () => {
    expect(detailTab(new URLSearchParams('tab=env'))).toBe('env');
    expect(detailTab(new URLSearchParams('section=env'))).toBe('env');
  });
  it('arrow keys wrap, other keys do nothing', () => {
    expect(nextTab('track', 'ArrowRight')).toBe('env');
    expect(nextTab('env', 'ArrowRight')).toBe('track');
    expect(nextTab('track', 'ArrowLeft')).toBe('env');
    expect(nextTab('env', 'Home')).toBe('track');
    expect(nextTab('track', 'Enter')).toBeNull();
  });
});
