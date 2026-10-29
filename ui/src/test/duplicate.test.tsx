import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { DuplicateNote } from '@/components/detail/DuplicateNote';

const html = (dups: Parameters<typeof DuplicateNote>[0]['dups']) =>
  renderToStaticMarkup(<MemoryRouter><DuplicateNote dups={dups} /></MemoryRouter>);

describe('C4 DuplicateNote', () => {
  it('no duplicates ⇒ nothing', () => { expect(html([])).toBe(''); });
  it('links each duplicate, carries the reason, and says it was not merged', () => {
    const out = html([{ event_id: 'ev_a', title: 'A', why: 'same victim' }, { event_id: 'ev_b', title: 'B', why: 'same day' }]);
    expect(out).toContain('href="/events/ev_a"');
    expect(out).toContain('title="same victim"');
    expect(out).toContain('未合并');
    expect(out).toContain('、');
  });
});
