/** The P0 wall (#/p0, Neo 2026-11-22): many product tiles in groups, click one for all its P0s. */
import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { EXPLOIT, P0WallView } from '@/pages/P0WallPage';
import { eventsOf, monogram, teamLine, visibleGroups, wallMarks, type P0Doc, type P0Event } from '@/utils/p0wall';

const schema = JSON.parse(readFileSync(resolve(__dirname, '../../../schemas/site-data.schema.json'), 'utf-8'));
const doc: P0Doc = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/p0.json'), 'utf-8'));
const view = (url = '/p0') => renderToStaticMarkup(<MemoryRouter initialEntries={[url]}><P0WallView doc={doc} /></MemoryRouter>);
const ev = (over: Partial<P0Event>): P0Event => ({ ...doc.events[0], ...over });

describe('the tile mark', () => {
  it.each([
    ['Apache HTTP Server', 'AH'], ['Nginx', 'Ng'], ['MySQL / MariaDB', 'My'], ['路由器 / NAS', '路由'], ['.NET', 'NE'],
    ['远程运维 (ScreenConnect 等)', '远程'], ['SAP', 'SA'], ['7-Zip / WinRAR', '7Z'], ['Go', 'Go'],
    ['Python 框架 (Django 等)', 'Dj'], ['Ruby on Rails', 'RR'],
  ])('%s → %s', (label, mark) => expect(monogram(label)).toBe(mark));
  it('no two tiles of the published wall share a mark', () => {
    const labels = doc.groups.flatMap(g => g.tiles.map(t => t.label));
    expect(new Set(wallMarks(labels).values()).size).toBe(labels.length);
  });
  it('every tile of the published wall has a 1–2 character mark', () => {
    for (const g of doc.groups) for (const t of g.tiles) expect([...monogram(t.label)].length).toBeGreaterThanOrEqual(1);
  });
});

describe('filters', () => {
  it('the full wall shows the empty tiles too; fired-only keeps the tiles with a P0', () => {
    const all = visibleGroups(doc.groups, { firedOnly: false, cloudOnly: false });
    const fired = visibleGroups(doc.groups, { firedOnly: true, cloudOnly: false });
    const n = (gs: typeof all) => gs.reduce((k, g) => k + g.tiles.length, 0);
    expect(n(all)).toBeGreaterThan(n(fired));
    expect(fired.every(g => g.tiles.every(t => t.count > 0))).toBe(true);
    expect(fired.reduce((k, g) => k + g.count, 0)).toBe(doc.total);         // no P0 is lost by the filter
  });
  it('cloud-only keeps the cloud groups', () => {
    expect(visibleGroups(doc.groups, { firedOnly: false, cloudOnly: true }).every(g => g.cloud)).toBe(true);
  });
  it('a tile lists exactly its own events', () => {
    const t = doc.groups.flatMap(g => g.tiles).find(x => x.count > 1)!;
    expect(eventsOf(doc.events, t.product)).toHaveLength(t.count);
  });
});

describe('the team channel line', () => {
  it('a non-cloud product never reads as waiting for the team channel', () => {
    expect(teamLine(ev({ cloud: false, team_send: null })).tone).toBe('none');
    expect(teamLine(ev({ cloud: true, team_send: null })).tone).toBe('wait');
    expect(teamLine(ev({ cloud: true, team_send: true, team_send_reason: 'r' }))).toMatchObject({ tone: 'sent', reason: 'r' });
    expect(teamLine(ev({ cloud: true, team_send: false })).tone).toBe('held');
  });
  it('every exploitation state has its word', () => {
    expect(Object.keys(EXPLOIT).sort()).toEqual([...schema.$defs.Exploitation.enum].sort());
  });
});

describe('the page', () => {
  it('draws every group and tile, empty tiles disabled, nothing open', () => {
    const html = view();
    for (const g of doc.groups) expect(html).toContain(`id="p0-g-${g.id}"`);
    const tiles = html.match(/class="p0-tile(?: [^"]*)?"/g) ?? [];
    expect(tiles).toHaveLength(doc.groups.reduce((k, g) => k + g.tiles.length, 0));
    expect((html.match(/class="p0-tile is-empty"[^>]*disabled=""/g) ?? []).length)
      .toBe(doc.groups.reduce((k, g) => k + g.tiles.filter(t => t.count === 0).length, 0));
    expect(html).not.toContain('class="p0-list"');
  });
  it('?tile= opens that tile: its P0s link to their event pages', () => {
    const t = doc.groups.flatMap(g => g.tiles).find(x => x.count > 1)!;
    const html = view(`/p0?tile=${t.product}`);
    expect(html).toContain(`id="p0-list-${t.product}"`);
    expect(html).toMatch(new RegExp(`aria-pressed="true"[^>]*aria-controls="p0-list-${t.product}"`));
    for (const e of eventsOf(doc.events, t.product)) expect(html).toContain(`href="/events/${e.event_id}"`);
    expect((html.match(/class="p0-row"/g) ?? []).length).toBe(t.count);
  });
  it('a demoted event says so, never reads as P0', () => {
    const d: P0Doc = { ...doc, events: doc.events.map((e, i) => (i === 0 ? { ...e, severity: 'P1' } : e)) };
    const html = renderToStaticMarkup(<MemoryRouter initialEntries={[`/p0?tile=${d.events[0].product}`]}><P0WallView doc={d} /></MemoryRouter>);
    expect(html).toContain('已降为 P1');
  });
});
