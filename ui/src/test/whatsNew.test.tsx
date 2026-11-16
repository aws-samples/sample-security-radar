/** R3.4 — 「有什么新的」 (since the previous visit) and 「我该做什么」 (actions at the verdict). */
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { readFileSync } from 'fs';
import { isNewSince, rollVisit, SESSION_GAP_MS } from '@/utils/lastVisit';
import { EventCard } from '@/components/EventCard';
import { VerdictPanel } from '@/components/detail/VerdictPanel';
import { resolveImpact } from '@/utils/response';

const mem = () => { const m = new Map<string, string>(); return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) }; };
const T = Date.parse('2026-11-15T04:00:00Z');

describe('the previous visit', () => {
  it('is nothing on a first visit, the last session after a gap, and survives a reload within the session', () => {
    const s = mem();
    expect(rollVisit(s, T)).toBeNull();
    expect(rollVisit(s, T + 5 * 60_000)).toBeNull();                       // a reload: same session
    const later = T + 5 * 60_000 + SESSION_GAP_MS + 1;
    expect(rollVisit(s, later)).toBe(new Date(T + 5 * 60_000).toISOString());
    expect(rollVisit(s, later + 60_000)).toBe(new Date(T + 5 * 60_000).toISOString());   // reload keeps the boundary
  });
  it('marks only what was first seen after it, and nothing on a first visit', () => {
    expect(isNewSince('2026-11-15T05:00:00Z', '2026-11-15T04:00:00Z')).toBe(true);
    expect(isNewSince('2026-11-15T03:00:00Z', '2026-11-15T04:00:00Z')).toBe(false);
    expect(isNewSince('2026-11-15T05:00:00Z', null)).toBe(false);
  });
});

const EV = JSON.parse(readFileSync('mock-data/data/events.json', 'utf8')).events[0];

describe('cards and the verdict', () => {
  it('a new event carries the 「新」 badge', () => {
    const html = (isNew: boolean) => renderToStaticMarkup(<MemoryRouter><EventCard event={EV} isNew={isNew} /></MemoryRouter>);
    expect(html(true)).toContain('data-testid="new-badge"');
    expect(html(false)).not.toContain('new-badge');
  });
  it('the verdict lists up to 3 grounded actions and offers the rule pack', () => {
    const acts = [1, 2, 3, 4].map(n => ({ text: `动作 ${n}`, cite: [], grounded: true }));
    const props = { event: EV, progress: undefined, response: null, impact: resolveImpact(undefined, null, undefined),
                    cite: () => undefined, onCite: () => {}, onEnv: () => {} };
    const html = renderToStaticMarkup(<VerdictPanel {...props} hasRulePack
      analysis={{ status: 'ok', bluf: [], what: [], impact: [], exploitation: [], actions: [...acts, { text: '无据', cite: [], grounded: false }], unknowns: [] } as never} />);
    expect(html).toContain('动作 1') ; expect(html).toContain('动作 3');
    expect(html).not.toContain('动作 4'); expect(html).not.toContain('无据');
    expect(html).toContain('data-testid="verdict-rulepack"');
    expect(renderToStaticMarkup(<VerdictPanel {...props} analysis={null} />)).not.toContain('verdict-actions');
  });
});
