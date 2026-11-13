/**
 * P2 「WAF 规则包」 block: note first, every schema state worded, unchecked WCU never reads as 0, a PoC outage never
 * reads as "no template", rejected candidates listed, every rendering copyable and downloadable.
 * Fixture = the backend's own pack (tests/test_rulepack_station.py regenerates and checks it).
 */
import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { RulePackPanel } from '@/components/detail/RulePackPanel';
import { CAPACITY_STATE, CONFIDENCE, OFFLINE_STATE, POC_STATE, capacityText, quoteView } from '@/utils/rulePack';
import type { RulePack } from '@/types/site-data';

const schema = JSON.parse(readFileSync(resolve(__dirname, '../../../schemas/site-data.schema.json'), 'utf-8'));
const defs = schema.$defs;
const pack: RulePack = JSON.parse(readFileSync(resolve(__dirname, 'fixtures/rule-pack.json'), 'utf-8'));
const html = (p: RulePack | null | undefined) => renderToStaticMarkup(<RulePackPanel rulePack={p} />);

function sameKeys(map: object, schemaEnum: unknown[]) {
  expect(Object.keys(map).sort()).toEqual(schemaEnum.map(String).sort());
}

describe('rule pack label maps cover every schema enum', () => {
  it('capacity state', () => sameKeys(CAPACITY_STATE, defs.RulePackCapacity.properties.state.enum));
  it('poc state', () => sameKeys(POC_STATE, defs.RulePackPoc.properties.state.enum));
  it('confidence', () => sameKeys(CONFIDENCE, defs.RulePackRule.properties.confidence.enum));
  it('offline check', () => sameKeys(OFFLINE_STATE, defs.RulePackCheck.properties.state.enum));
});

describe('RulePackPanel', () => {
  it('renders nothing without a pack', () => {
    expect(html(null)).toBe('');
    expect(html(undefined)).toBe('');
  });

  it('opens with 缓解 ≠ 修复 before any rule', () => {
    const h = html(pack);
    expect(h).toContain('WAF 规则包');
    expect(h.indexOf(pack.note)).toBeGreaterThan(-1);
    expect(h.indexOf(pack.note)).toBeLessThan(h.indexOf(pack.custom[0].rule_id));
    expect(pack.note).toContain('缓解 ≠ 修复');
  });

  it('shows every custom and template rule with its generated description and quote link', () => {
    const h = html(pack);
    for (const r of [...pack.custom, ...pack.templates]) {
      expect(h).toContain(`data-rule="${r.rule_id}"`);
      expect(h).toContain(r.what!.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));
    }
    const q = pack.custom[0].source_quotes[0];
    expect(h).toContain(quoteView(q).href!);
  });

  it('a quote link is the backend href only — a feed url / path is never turned into a link here', () => {
    const ev = { token: 'X-A: bb', url: 'javascript:alert(1)', sentence: 'X-A: bb', item_id: 'i', span: [0, 7] as [number, number] };
    expect(quoteView(ev).href).toBeUndefined();
    expect(quoteView({ ...ev, href: null }).href).toBeUndefined();
    const tpl = pack.custom[0].source_quotes[0];
    expect(quoteView({ ...tpl, href: undefined }).href).toBeUndefined();
    expect(quoteView(tpl).href).toBe(tpl.href);
  });

  it('an unchecked capacity is worded as unchecked, never 0 WCU', () => {
    const p: RulePack = { ...pack, capacity: { state: 'unchecked', wcu: null, detail: 'CheckCapacity 调用失败' } };
    const h = html(p);
    expect(h).toContain('data-state="unchecked"');
    expect(h).toContain('WCU 未检查');
    const line = h.match(/data-testid="rp-capacity"[^>]*>(.*?)<\/p>/)![1];
    expect(line).not.toMatch(/\b0 WCU/);
    expect(line).toContain('CheckCapacity 调用失败');
    expect(capacityText(pack.capacity)).toBe('41 WCU');
    expect(capacityText({ state: 'over_budget', wcu: 600, max_wcu: 500, detail: '' })).toBe('600 WCU（上限 500）');
  });

  it('a PoC outage reads 「暂不可用」, not 「暂无模板」', () => {
    const h = html(pack);
    const row = pack.poc.find(x => x.state === 'unavailable')!;
    expect(row).toBeTruthy();
    expect(h).toContain('PoC 来源暂不可用');
    expect(POC_STATE.unavailable.label).not.toBe(POC_STATE.no_template.label);
  });

  it('lists the rejected candidates with their reason', () => {
    const h = html(pack);
    expect(pack.rejected.length).toBeGreaterThan(0);
    for (const x of pack.rejected) expect(h).toContain(`data-reason="${x.reason}"`);
  });

  it('offers copy and download for the shown rendering and a switch for every format', () => {
    const h = html(pack);
    for (const r of pack.renderings!) expect(h).toContain(`>${r.label}</button>`);
    expect(h).toContain(`aria-label="复制${pack.renderings![0].label}"`);
    expect(h).toContain(`下载 ${pack.renderings![0].filename}`);
    expect(h).toContain(`data-rendering="${pack.renderings![0].id}"`);
  });
});
