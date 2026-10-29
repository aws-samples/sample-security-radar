import { describe, expect, it } from 'vitest';
import { safeHref } from '@/utils/safeHref';

describe('safeHref', () => {
  it('keeps http(s) links', () => {
    expect(safeHref('https://www.cisa.gov/kev?x=1')).toBe('https://www.cisa.gov/kev?x=1');
    expect(safeHref('http://example.com/a')).toBe('http://example.com/a');
  });
  it('drops script, data and other schemes, and anything relative or malformed', () => {
    for (const bad of ['javascript:alert(1)', ' JavaScript:alert(1)', 'data:text/html,<b>x</b>', 'vbscript:x', 'file:///etc/passwd',
      '//evil.example', '/relative', 'not a url', '', null, undefined]) {
      expect(safeHref(bad as string)).toBeUndefined();
    }
  });
});
