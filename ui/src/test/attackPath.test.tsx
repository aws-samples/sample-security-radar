/**
 * R9.5 (requirement 2026-11-18): the event page shows how a vulnerability is attacked — entry → condition → trigger →
 * impact — and puts every defence under the step it stops, tagged immediate block / temporary / long-term fix.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { renderToStaticMarkup } from 'react-dom/server';
import { AttackPathPanel, HORIZON, STEPS } from '@/components/detail/AttackPathPanel';
import { AttackFlow } from '@/components/detail/AttackFlow';
import type { AttackPath, EventSummary } from '@/types/site-data';

const mock = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/events/ev_bb65db3b8694e5f4.json'), 'utf8'));
const PATH: AttackPath = mock.attack_path;
const PAGE = readFileSync(resolve(__dirname, '../pages/EventDetailPage.tsx'), 'utf8');
const ids = new Map<string, number>((mock.items as { item_id: string }[]).map((it, i) => [it.item_id, i + 1]));
const render = (p: AttackPath) => renderToStaticMarkup(<AttackPathPanel path={p} cite={id => ids.get(id)} onCite={() => {}} />);

describe('attack path panel', () => {
  it('four steps in order, each with its sentences and citation buttons', () => {
    const html = render(PATH);
    expect(STEPS.map(s => s.title)).toEqual(['入口', '前提', '触发', '后果']);
    const pos = STEPS.map(s => html.indexOf(`</span>${s.title}<span class="ap-hint">`));
    expect(pos.every(p => p > 0)).toBe(true);
    expect([...pos].sort((a, b) => a - b)).toEqual(pos);
    expect((html.match(/class="cite"/g) ?? []).length).toBeGreaterThanOrEqual(8);
  });

  it('every defence sits in the lane of its own step, tagged by horizon and source', () => {
    const html = render(PATH);
    const lanes = html.split('class="ap-lane"').slice(1);
    const lane = (k: string) => lanes[STEPS.findIndex(s => s.key === k)].split('class="ap-col"')[0];
    expect(lane('entry')).toContain('立即拦截');
    expect(lane('entry')).toContain('立即拦截 · 雷达');
    expect(lane('trigger')).toContain(HORIZON.temporary.word);
    expect(lane('trigger')).toContain(HORIZON.fix.word);
    expect(lane('impact')).not.toContain('ap-def');
    expect(lane('condition')).not.toContain('ap-def');
  });

  it('a step the evidence does not explain says so instead of staying blank', () => {
    const html = render({ ...PATH, steps: { ...PATH.steps, condition: [] } });
    expect(html).toMatch(/ap-step is-empty/);
    expect(html).toContain('证据没有说明');
  });

  it('the event page shows it for an event that has one, numbered in sequence', () => {
    expect(PAGE).toMatch(/\.\.\.\(d\.attackPath \? \['path'\] : \[\]\)/);
    expect(PAGE).toMatch(/\{d\.attackPath && \(/);
    expect(PAGE).toMatch(/<AttackPathPanel path=\{d\.attackPath\}/);
  });
});

describe('attack path accessibility', () => {
  it('names a defence lane only on an element whose role allows a name (CI axe 2026-11-19: aria-prohibited-attr on a bare div)', () => {
    const html = render(PATH);
    const bare = [...html.matchAll(/<(div|span)\b([^>]*)>/g)].filter(([, , a]) => /aria-label=/.test(a) && !/role="/.test(a));
    expect(bare.map(m => m[0])).toEqual([]);
    expect(html).toContain('role="group" aria-label="在「前提」这一步拦"');
  });
});

describe('attack flow', () => {
  it('renders nothing when there are no phases and the page passes only empty panels', () => {
    const ev = { ...mock.event, domain: 'vuln', attribution: null } as EventSummary;
    const html = renderToStaticMarkup(<AttackFlow event={ev} items={[]} chain={[]} onCite={() => {}}>{null}{null}</AttackFlow>);
    expect(html).toBe('');
  });
});
