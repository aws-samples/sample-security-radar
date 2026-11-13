import { describe, expect, it } from 'vitest';
import { errorView } from '@/utils/health';

// Live 2026-11-11: 49 of 215 sources showed a red error on #/sources; 48 had fetched fine since.
describe('errorView — a recovered error is not a live failure', () => {
  it('an error followed by a success is recovered', () => {
    const v = errorView({ last_error: 'network_error: timed out', last_error_at: '2026-11-11T14:00:00Z', last_success: '2026-11-11T14:15:00Z' });
    expect(v).toEqual({ kind: 'recovered', text: 'network_error: timed out', at: '2026-11-11T14:00:00Z' });
  });
  it('an error after the last success is current', () => {
    expect(errorView({ last_error: 'http_error: 429', last_error_at: '2026-11-11T14:20:00Z', last_success: '2026-11-11T14:15:00Z' }).kind).toBe('current');
  });
  it('never assumes recovery without both timestamps', () => {
    expect(errorView({ last_error: 'x', last_error_at: null, last_success: '2026-11-11T14:15:00Z' }).kind).toBe('current');
    expect(errorView({ last_error: 'x', last_error_at: '2026-11-11T14:00:00Z', last_success: null }).kind).toBe('current');
  });
  it('no error is none', () => {
    expect(errorView({ last_error: null, last_error_at: null, last_success: null }).kind).toBe('none');
  });
});
