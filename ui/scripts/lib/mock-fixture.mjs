// Single source for "what moment / which event the dev-preview gates look at" (a11y.mjs, screenshot*.mjs).
// Derived from mock-data so a refreshed live sample can never again leave the gates pointing at a dead id (2026-10-24:
// ev_a1b2c3d4e5f60001 vanished ⇒ detail audit red) or at a clock 7 h before generated_at (future events, frozen freshness).
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const DATA = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'mock-data', 'data');
const read = f => JSON.parse(readFileSync(resolve(DATA, f), 'utf8'));
const fail = msg => { console.error(`mock-fixture: ${msg}`); process.exit(1); };

const events = read('events.json');
/** One pipeline tick (5 min) after publish: fresh, and every event is in the past. */
export const CLOCK = new Date(Date.parse(events.generated_at) + 5 * 60_000);
if (Number.isNaN(CLOCK.getTime())) fail(`events.json generated_at unparsable: ${events.generated_at}`);
const future = events.events.filter(e => Date.parse(e.first_seen) > CLOCK.getTime() || Date.parse(e.last_updated) > CLOCK.getTime());
if (future.length) fail(`${future.length} event(s) after CLOCK ${CLOCK.toISOString()}: ${future.map(e => e.event_id).join(' ')}`);

const hasResponse = id => { try { return 'response' in read(`events/${id}.json`); } catch { return false; } };
const responseOf = id => { try { return read(`events/${id}.json`).response; } catch { return undefined; } };

/** The detail page under audit: the first P0 that carries a Continuum `response` block (contract 2026-10-23). */
export const DETAIL_ID = (() => {
  const ids = events.events.filter(e => e.severity === 'P0').map(e => e.event_id).sort();
  const hit = ids.find(id => Boolean(responseOf(id)));
  return hit ?? fail(`no P0 event with a response block in mock-data/data/events/ (checked ${ids.length})`);
})();

/** A second detail page whose response is explicitly null (the "未触发环境检查" state must be audited too). */
export const DETAIL_NO_ENV_ID = (() => {
  const ids = events.events.map(e => e.event_id).sort();
  const hit = ids.find(id => hasResponse(id) && responseOf(id) === null);
  return hit ?? fail('no event with response: null in mock-data/data/events/');
})();
