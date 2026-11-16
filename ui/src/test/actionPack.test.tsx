/** R4.5 — block → detect → verify → patch per code target, joined from what the event page already loads. */
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import fx from './fixtures/action-pack-php-cgi.json';
import type { Mitigation, Response } from '@/types/site-data';
import { actionPack } from '@/utils/actionPack';
import { ActionPackPanel } from '@/components/detail/ActionPackPanel';

const response = fx.response as unknown as Response;
const mitigation = fx.mitigation as unknown as Mitigation;

describe('the action pack of the live PHP-CGI event (CVE-2012-1823 / CVE-2024-4577, 2026-11-15)', () => {
  const rows = actionPack(response, mitigation);
  it('has a row per relevant target only — the three without PHP were skipped, not "safe"', () => {
    expect(rows.map(r => r.targetId).sort()).toEqual(['demo-shop', 'wp-storefront']);
  });
  it('reads each cell from its ledger', () => {
    const wp = rows.find(r => r.targetId === 'wp-storefront')!;
    expect(wp.block).toEqual({ tone: 'ok', text: 'WAF 拦截中 · PHP application' });          // MitigationPlan.state blocking
    expect(wp.verify).toEqual({ tone: 'loss', text: '受影响' });                                // ResponseTarget.verdict
    expect(wp.detect.text).toBe(`${response.findings.filter(f => f.target_id === 'wp-storefront').length} 条代码发现`);
    expect(wp.patch.text).toBe(`已生成 ${response.patches.filter(p => p.target_id === 'wp-storefront').length} 个补丁，待提 PR`);
  });
});

describe('cell rules', () => {
  const t = (verdict: string) => ({ target_id: 'x', name: 'x', relevant: true, verdict, detail: '', locations: [] });
  const resp = (verdict: string, extra: Partial<Response> = {}) =>
    ({ ...response, targets: [t(verdict)], findings: [], patches: [], ...extra }) as unknown as Response;
  const plan = (state: string) => ({ ...mitigation.plans[0], target_id: 'x', state });
  it('a counting rule waits for a human; a PR link wins over a bare patch; an unaffected target needs no patch', () => {
    expect(actionPack(resp('affected'), { ...mitigation, plans: [plan('staged')] } as Mitigation)[0].block.tone).toBe('warn');
    const withPr = resp('affected', { patches: [{ source: 'continuum', target_id: 'x', path: 'q', files_changed: [], summary: '' },     // a bare patch first
                                               { source: 'continuum', target_id: 'x', path: 'p', files_changed: [], summary: '', pr_url: 'https://example.com/pr/1' }] });
    expect(actionPack(withPr, null)[0].patch).toEqual({ tone: 'warn', text: '补丁 PR 待人审核合并', href: 'https://example.com/pr/1' });
    expect(actionPack(resp('not_affected'), null)[0].patch).toEqual({ tone: 'muted', text: '不需要' });
    expect(actionPack(resp('not_affected'), null)[0].block.text).toBe('无适用的 WAF 规则');
  });
  it('a target only the mitigate station planned for still gets a row', () => {
    expect(actionPack(null, { ...mitigation, plans: [plan('blocking')] } as Mitigation).map(r => [r.targetId, r.verify.text]))
      .toEqual([['x', '未核查']]);
  });
});

describe('the panel', () => {
  it('renders a table, and nothing at all without a target (never an empty "all clear")', () => {
    const html = renderToStaticMarkup(<ActionPackPanel response={response} mitigation={mitigation} />);
    expect(html).toContain('<table');
    expect(html).toContain('wp-storefront');
    expect(html).toContain('tone-loss');
    expect(renderToStaticMarkup(<ActionPackPanel response={null} mitigation={null} />)).toBe('');
  });
  it('links a PR only through safeHref', () => {
    const bad = { ...response, targets: [response.targets[0]], patches: [{ ...response.patches[0], target_id: response.targets[0].target_id, pr_url: 'javascript:alert(1)' }] } as Response;
    expect(renderToStaticMarkup(<ActionPackPanel response={bad} mitigation={null} />)).not.toContain('javascript:');
  });
});
