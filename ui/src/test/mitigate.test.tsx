/**
 * M3 mitigate station UI: the note is always shown, every schema state has a 中文 label, cwe tier is advisory,
 * null ⇒ no block, and an unjudged Inspector baseline never reads as "无漏洞".
 */
import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { MitigationPanel } from '@/components/detail/MitigationPanel';
import { MitigateView } from '@/pages/MitigatePage';
import { ADVISORY_NOTE, BASELINE_STATE, DNS_STATE, PLAN_STATE, SEVERITY, TIER, purlName } from '@/utils/mitigate';
import type { Mitigation, MitigationPlan, MitigateDoc } from '@/types/mitigate';

const schema = JSON.parse(readFileSync(resolve(__dirname, '../../../schemas/site-data.schema.json'), 'utf-8'));
const defs = schema.$defs;
const mitigateRoot = (schema.oneOf as Array<{ properties: { kind?: { const?: string }; inspector?: { items: { properties: { state: { enum: string[] } } } } } }>)
  .find(o => o.properties.kind?.const === 'mitigate')!;

const sample: Mitigation = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/events/ev_bb65db3b8694e5f4.json'), 'utf-8')).mitigation;
const doc: MitigateDoc = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/mitigate.json'), 'utf-8'));

const panel = (m: Mitigation | null | undefined) => renderToStaticMarkup(<MemoryRouter><MitigationPanel mitigation={m} /></MemoryRouter>);
const view = (d: MitigateDoc) => renderToStaticMarkup(<MemoryRouter><MitigateView doc={d} /></MemoryRouter>);
const plan = (over: Partial<MitigationPlan>): MitigationPlan => ({ ...sample.plans[0], ...over });

/** Every value of a schema enum must be a key of the label map (and the map must not carry stale keys). */
function sameKeys(map: object, schemaEnum: unknown[]) {
  const want = schemaEnum.filter(v => v !== null).map(String).sort();
  expect(Object.keys(map).sort()).toEqual(want);
}

describe('M3 label maps cover every schema enum', () => {
  it('WAF plan state', () => sameKeys(PLAN_STATE, defs.MitigationPlan.properties.state.enum));
  it('WAF tier', () => sameKeys(TIER, defs.MitigationPlan.properties.tier.enum));
  it('DNS state', () => sameKeys(DNS_STATE, defs.Mitigation.properties.dns.oneOf[1].properties.state.enum));
  it('Inspector severity', () => sameKeys(SEVERITY, defs.InspectorFinding.properties.severity.enum));
  it('Inspector baseline state', () => sameKeys(BASELINE_STATE, mitigateRoot.properties.inspector!.items.properties.state.enum));
  it('labels are non-empty Chinese, distinct per state', () => {
    const labels = Object.values(PLAN_STATE).map(w => w.label);
    expect(new Set(labels).size).toBe(labels.length);
    for (const l of labels) expect(l).toMatch(/[一-鿿]/);
  });
  it('the required semantics: staged = 观察期等人确认, blocking = 已拦截, no_web_acl = 仅给出规则, attention states warn', () => {
    expect(PLAN_STATE.staged.label).toContain('观察期');
    expect(PLAN_STATE.staged.label).toContain('等人确认');
    expect(PLAN_STATE.blocking.label).toBe('已拦截');
    expect(PLAN_STATE.no_web_acl.label).toBe('仅给出规则');
    for (const s of ['unchecked', 'too_old', 'group_counted'] as const) {
      expect(PLAN_STATE[s].tone).toBe('warn');
      expect(PLAN_STATE[s].label).toContain('需注意');
    }
  });
});

describe('MitigationPanel (event detail · 缓解（快路）)', () => {
  it('mitigation null / absent ⇒ no block at all (and no "all clear")', () => {
    expect(panel(null)).toBe('');
    expect(panel(undefined)).toBe('');
  });
  it('the note is always shown, verbatim', () => {
    const out = panel(sample);
    expect(out).toContain('缓解 ≠ 修复');
    expect(out).toContain(sample.note);
    // even with nothing else to show
    expect(panel({ ...sample, plans: [], dns: null, inspector: [] })).toContain(sample.note);
  });
  it('renders the plan: target, tier, group, rules, min version, reason, state label, detail, rule JSON + copy', () => {
    const out = panel(sample);
    const p = sample.plans[0];
    for (const s of [p.target_id, 'CVE 精确', p.group, p.group_label, ...p.rules, p.min_version!, p.reason, p.detail, PLAN_STATE[p.state].label]) {
      expect(out).toContain(s);
    }
    expect(out).toContain('<details');
    expect(out).toContain('ManagedRuleGroupStatement');
    expect(out).toContain('aria-label="复制规则 JSON"');
  });
  it('every state renders its own label', () => {
    for (const st of Object.keys(PLAN_STATE) as MitigationPlan['state'][]) {
      const out = panel({ ...sample, plans: [plan({ state: st, key: st })] });
      expect(out).toContain(PLAN_STATE[st].label);
      expect(out).toContain(`data-state="${st}"`);
    }
  });
  it('cwe tier says 仅建议，不自动下发; cve/product do not', () => {
    expect(panel({ ...sample, plans: [plan({ tier: 'cwe' })] })).toContain(ADVISORY_NOTE);
    expect(ADVISORY_NOTE).toContain('仅建议');
    expect(panel({ ...sample, plans: [plan({ tier: 'cve' })] })).not.toContain(ADVISORY_NOTE);
    expect(panel({ ...sample, plans: [plan({ tier: 'product' })] })).not.toContain(ADVISORY_NOTE);
  });
  it('DNS domains, state and action', () => {
    const out = panel(sample);
    expect(out).toContain('php2shell-loader.top');
    expect(out).toContain(DNS_STATE.in_place.label);
    expect(out).toContain('ALERT');
  });
  it('Inspector hits: package (purl decoded), CVE, severity, fixed version, file', () => {
    const out = panel({ ...sample, inspector: [doc.inspector[4].findings[7]] });
    const f = doc.inspector[4].findings[7];
    for (const s of ['@vitest/mocker@2.1.9', f.id, SEVERITY[f.severity].label, f.fixed!, f.file!]) expect(out).toContain(s);
  });
});

describe('MitigateView (缓解页)', () => {
  it('note, web ACL, DNS, applied history', () => {
    const out = view(doc);
    expect(out).toContain(doc.note);
    expect(out).toContain('security-radar-waf-demo');
    expect(out).toContain('radar-canary.security-radar.invalid');
    expect(out).toContain('AWSManagedRulesPHPRuleSet');
  });
  it('no_packages explains the runtime pin and never says 无漏洞', () => {
    const out = view({ ...doc, inspector: doc.inspector.filter(b => b.state === 'no_packages') });
    expect(out).toContain('只有运行时版本钉，Inspector 不判定运行时');
    expect(out).not.toContain('无漏洞');
    expect(out).not.toContain('没有已知漏洞');
  });
  for (const st of ['error', 'deferred', 'never'] as const) {
    it(`${st} reads as 没查/推迟, never 无漏洞`, () => {
      const out = view({ ...doc, inspector: [{ target_id: 't1', state: st, components: 0, scanned_on: null, findings: [] }] });
      expect(out).toMatch(/没查|推迟/);
      expect(out).not.toContain('无漏洞');
      expect(out).not.toContain('没有已知漏洞');
    });
  }
  it('errors are listed prominently and say the result is unknown', () => {
    const out = view({ ...doc, errors: [{ channel: 'inspector', what: 'ScanSbom demo-shop', error: 'AccessDenied' }] });
    expect(out).toContain('data-testid="mitigate-errors"');
    expect(out).toContain('没查成的项');
    expect(out).toContain('ScanSbom demo-shop');
    expect(out).toContain('AccessDenied');
    expect(view(doc)).not.toContain('data-testid="mitigate-errors"');
  });
  it('scanned with findings shows the table; scanned with none is the only "no known vuln" wording', () => {
    expect(view(doc)).toContain('CVE-2026-47429');
    const out = view({ ...doc, inspector: [{ target_id: 't', state: 'scanned', components: 3, scanned_on: '2026-10-23', findings: [] }] });
    expect(out).toContain('没有已知漏洞');
  });
});

describe('purlName', () => {
  it('decodes, strips the type prefix, keeps a bad escape raw', () => {
    expect(purlName('pkg:npm/%40vitest/mocker@2.1.9')).toBe('@vitest/mocker@2.1.9');
    expect(purlName('pkg:npm/vite@5.4.21')).toBe('vite@5.4.21');
    expect(purlName('pkg:npm/bad%ZZ@1')).toBe('bad%ZZ@1');
  });
});
