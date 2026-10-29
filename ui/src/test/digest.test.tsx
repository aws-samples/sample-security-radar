import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { DigestCard } from '@/components/home/DigestCard';
import type { Digest, EventSummary } from '@/types/site-data';

const doc = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/events.json'), 'utf-8'));
const html = (d: Digest | null, ev: EventSummary[] = doc.events) =>
  renderToStaticMarkup(<MemoryRouter><DigestCard digest={d} events={ev} /></MemoryRouter>);

describe('C7 DigestCard', () => {
  it('not published ⇒ nothing (never an empty card)', () => {
    expect(html(null)).toBe('');
  });
  it('counts come from the header; cited events link to their pages; an ungrounded sentence shows why', () => {
    const out = html(doc.digest);
    expect(out).toContain(`${doc.digest.header.events} 个事件`);
    expect(out).toContain(`href="/events/${doc.digest.event_ids[0]}"`);
    expect(out).toContain('未通过校验：数字未核实');
    expect(out).toContain('部分句子未通过校验');
  });
  it('a cite to an event no longer on the board is flagged, not linked', () => {
    const d: Digest = { ...doc.digest, summary: [{ text: 'x', cite: ['ev_gone'], grounded: true, issues: [] }] };
    expect(html(d)).toContain('[引用不在榜]');
  });
  it('a quiet day says so instead of rendering empty sections', () => {
    const d: Digest = { ...doc.digest, status: 'ok', header: { events: 0, p0: 0, p1: 0, new: 0, escalated: 0, web3: 0 },
      summary: [], highlights: [], watch: [] };
    expect(html(d)).toContain('没有 P0/P1 动态');
  });
});
