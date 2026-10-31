/**
 * Wall center stage (2026-10-30 redesign): which events draw a link into the core, how the shield ring reads the
 * mitigate station, and the severity silhouette. A line or a lit shield arc is a claim on the big screen — these
 * pin that it is only drawn when the data says so.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { CORE, arcPoints, displayHeight, linkKind, threatLinks } from '@/utils/radar3dLayout';
import type { Dot3D } from '@/utils/radar3dLayout';
import { shieldChannels } from '@/utils/mitigate';
import type { MitigateDoc } from '@/types/mitigate';
import type { EventSummary } from '@/types/site-data';

const doc: MitigateDoc = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/mitigate.json'), 'utf-8'));

const ev = (id: string, severity: EventSummary['severity'], impact: EventSummary['impact']) =>
  ({ event_id: id, severity, impact } as EventSummary);
const dot = (id: string, severity: string): Dot3D => ({
  eventId: id, x: 1, z: -2, y: 0, height: 1, drawHeight: displayHeight(severity, 1), colorHDR: [1, 1, 1],
  shape: 1, severity, level: 'V2', domain: 'vuln', title: id, firstSeen: '2026-10-30T00:00:00Z', sourcesCount: 2,
});

describe('linkKind', () => {
  it('affected with a hit ⇒ affected; queued / running ⇒ checking', () => {
    expect(linkKind({ status: 'affected', affected: 1, checked: 2 })).toBe('affected');
    expect(linkKind({ status: 'running', affected: 0, checked: 0 })).toBe('checking');
    expect(linkKind({ status: 'queued', affected: 0, checked: 0 })).toBe('checking');
  });
  it('no confirmed hit ⇒ no line', () => {
    for (const status of ['not_affected', 'failed', 'not_eligible'] as const) {
      expect(linkKind({ status, affected: 0, checked: 1 })).toBeNull();
    }
    expect(linkKind({ status: 'affected', affected: 0, checked: 1 })).toBeNull();
    expect(linkKind(null)).toBeNull();
    expect(linkKind(undefined)).toBeNull();
  });
});

describe('threatLinks', () => {
  const hit = { status: 'affected' as const, affected: 1, checked: 1 };
  const run = { status: 'running' as const, affected: 0, checked: 0 };
  it('affected before checking, then P0 first; starts on the drawn pillar top', () => {
    const events = [ev('a', 'P1', run), ev('b', 'P1', hit), ev('c', 'P0', run), ev('d', 'P0', hit)];
    const links = threatLinks(events, events.map(e => dot(e.event_id, e.severity)));
    expect(links.map(l => l.eventId)).toEqual(['d', 'b', 'c', 'a']);
    expect(links[0].from.y).toBe(displayHeight('P0', 1));
  });
  it('events without a dot on screen draw nothing; the cap holds', () => {
    expect(threatLinks([ev('x', 'P0', hit)], [])).toEqual([]);
    const many = Array.from({ length: 30 }, (_, i) => ev(`e${i}`, 'P1', hit));
    expect(threatLinks(many, many.map(e => dot(e.event_id, 'P1')), 16)).toHaveLength(16);
  });
});

describe('arcPoints', () => {
  it('starts at the pillar, ends in the core, rises above both', () => {
    const from = { x: 3, y: 1, z: -2 };
    const pts = arcPoints(from);
    expect(pts[0]).toEqual(from);
    expect(pts.at(-1)!.x).toBeCloseTo(CORE.x);
    expect(pts.at(-1)!.y).toBeCloseTo(CORE.y);
    expect(Math.max(...pts.map(p => p.y))).toBeGreaterThan(Math.max(from.y, CORE.y));
  });
});

describe('displayHeight', () => {
  it('P0 always towers over every P1; P2 is a ground blip', () => {
    for (const h of [0.25, 1, 2]) {
      expect(displayHeight('P0', 0.25)).toBeGreaterThan(displayHeight('P1', h));
      expect(displayHeight('P2', h)).toBeLessThan(0.1);
    }
  });
});

describe('shieldChannels', () => {
  it('mock station ⇒ WAF / DNS / Inspector on, with counts', () => {
    const ch = shieldChannels(doc);
    expect(ch.map(c => [c.key, c.state])).toEqual([['WAF', 'on'], ['DNS', 'on'], ['INSPECTOR', 'on']]);
    expect(ch[0].detail).toBe('1 规则组');
  });
  it('not read ⇒ unknown on every arc (never "protected", never "off")', () => {
    expect(shieldChannels(null).every(c => c.state === 'unknown')).toBe(true);
  });
  it('a channel error wins over its data', () => {
    const ch = shieldChannels({ ...doc, errors: [{ channel: 'dns', what: 'x', error: 'boom' }] });
    expect(ch.find(c => c.key === 'DNS')!.state).toBe('error');
    expect(ch.find(c => c.key === 'WAF')!.state).toBe('on');
  });
  it('WAF reads the newest write per ACL — a group removed later is off', () => {
    const later = { ...doc, applied: [...doc.applied, { at: '2026-10-24T00:00:00Z', web_acl: 'security-radar-waf-demo', rules: [] }] };
    expect(shieldChannels(later)[0].state).toBe('off');
  });
});

describe('threatLinks default', () => {
  it('is uncapped, so the HUD count of hits is exact', () => {
    const hit = { status: 'affected' as const, affected: 1, checked: 1 };
    const many = Array.from({ length: 30 }, (_, i) => ev(`e${i}`, 'P1', hit));
    expect(threatLinks(many, many.map(e => dot(e.event_id, 'P1')))).toHaveLength(30);
  });
});
