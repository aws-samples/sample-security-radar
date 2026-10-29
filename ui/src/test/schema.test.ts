/**
 * Validates all mock data files against the site-data schema.
 * This is the contract test: if mock data is invalid, the UI would crash on real data too.
 */
import { describe, it, expect } from 'vitest';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import { readFileSync, readdirSync } from 'fs';
import { join, resolve } from 'path';

const schemaPath = resolve(__dirname, '../../../schemas/site-data.schema.json');
const schema = JSON.parse(readFileSync(schemaPath, 'utf-8'));

const ajv = new Ajv2020({ strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);

function loadJson(filePath: string): unknown {
  return JSON.parse(readFileSync(filePath, 'utf-8'));
}

const dataDir = resolve(__dirname, '../../mock-data/data');

describe('Mock data schema validation', () => {
  it('events.json validates against schema', () => {
    const data = loadJson(join(dataDir, 'events.json'));
    const valid = validate(data);
    if (!valid) {
      console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
    }
    expect(valid).toBe(true);
  });

  it('sources.json validates against schema', () => {
    const data = loadJson(join(dataDir, 'sources.json'));
    const valid = validate(data);
    if (!valid) {
      console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
    }
    expect(valid).toBe(true);
  });

  it('continuum.json validates against schema', () => {
    const data = loadJson(join(dataDir, 'continuum.json'));
    const valid = validate(data);
    if (!valid) {
      console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
    }
    expect(valid).toBe(true);
    expect((data as { kind: string }).kind).toBe('continuum');
  });

  it('mitigate.json validates against schema', () => {
    const data = loadJson(join(dataDir, 'mitigate.json'));
    const valid = validate(data);
    if (!valid) {
      console.error('Validation errors:', JSON.stringify(validate.errors, null, 2));
    }
    expect(valid).toBe(true);
    expect((data as { kind: string }).kind).toBe('mitigate');
  });

  it('at least one event detail carries a mitigation block (M3 panel under test / a11y)', () => {
    const files = readdirSync(join(dataDir, 'events')).filter(f => f.endsWith('.json'));
    const hit = files.filter(f => (loadJson(join(dataDir, 'events', f)) as { mitigation?: unknown }).mitigation);
    expect(hit.length).toBeGreaterThan(0);
  });

  // Test each event detail file
  const eventDir = join(dataDir, 'events');
  let eventFiles: string[] = [];
  try {
    eventFiles = readdirSync(eventDir).filter(f => f.endsWith('.json'));
  } catch {
    // directory may not exist yet in CI
  }

  for (const file of eventFiles) {
    it(`events/${file} validates against schema`, () => {
      const data = loadJson(join(eventDir, file));
      const valid = validate(data);
      if (!valid) {
        console.error(`${file} errors:`, JSON.stringify(validate.errors, null, 2));
      }
      expect(valid).toBe(true);
    });
  }

  it('events.json has at least 12 events', () => {
    const data = loadJson(join(dataDir, 'events.json')) as { events: unknown[] };
    expect(data.events.length).toBeGreaterThanOrEqual(12);
  });

  it('events.json covers all three domains', () => {
    const data = loadJson(join(dataDir, 'events.json')) as { events: Array<{ domain: string }> };
    const domains = new Set(data.events.map(e => e.domain));
    expect(domains.has('vuln')).toBe(true);
    expect(domains.has('incident')).toBe(true);
    expect(domains.has('web3')).toBe(true);
  });

  it('events.json has events with amount_disputed=true', () => {
    const data = loadJson(join(dataDir, 'events.json')) as { events: Array<{ amount_disputed: boolean }> };
    expect(data.events.some(e => e.amount_disputed === true)).toBe(true);
  });

  it('events.json has events with summary=null', () => {
    const data = loadJson(join(dataDir, 'events.json')) as { events: Array<{ summary: unknown }> };
    expect(data.events.some(e => e.summary === null)).toBe(true);
  });

  it('events.json covers V0-V4 and X levels', () => {
    const data = loadJson(join(dataDir, 'events.json')) as { events: Array<{ level: string }> };
    const levels = new Set(data.events.map(e => e.level));
    for (const l of ['V0', 'V1', 'V2', 'V3', 'V4', 'X']) {
      expect(levels.has(l), `Expected level ${l} to be present`).toBe(true);
    }
  });

  it('events.json covers P0, P1, P2 severities', () => {
    const data = loadJson(join(dataDir, 'events.json')) as { events: Array<{ severity: string }> };
    const severities = new Set(data.events.map(e => e.severity));
    for (const s of ['P0', 'P1', 'P2']) {
      expect(severities.has(s), `Expected severity ${s} to be present`).toBe(true);
    }
  });

  it('sources.json has at least 10 sources', () => {
    const data = loadJson(join(dataDir, 'sources.json')) as { sources: unknown[] };
    expect(data.sources.length).toBeGreaterThanOrEqual(10);
  });

  it('sources.json covers ok/degraded/failing/never_run statuses', () => {
    const data = loadJson(join(dataDir, 'sources.json')) as { sources: Array<{ status: string }> };
    const statuses = new Set(data.sources.map(s => s.status));
    for (const st of ['ok', 'degraded', 'failing', 'never_run']) {
      expect(statuses.has(st), `Expected status ${st} to be present`).toBe(true);
    }
  });
});
