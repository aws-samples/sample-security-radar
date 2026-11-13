/**
 * 「响应决策」 block: every outcome of the schema has its own look, not_evaluated never reads like not_fire, rows keep
 * the table's order with scoped rows grouped, and an older document (no decisions) renders no block.
 */
import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import type { ResponseDecision } from '@/types/site-data';
import { DecisionsPanel } from '@/components/env/DecisionsPanel';
import { OUTCOME, groupDecisions, look, outcomeCounts, rowTime, scopeLabel } from '@/utils/decisions';

const schema = JSON.parse(readFileSync(resolve(__dirname, '../../../schemas/site-data.schema.json'), 'utf-8'));
const props = schema.$defs.ResponseDecision.properties;

const row = (over: Partial<ResponseDecision>): ResponseDecision => ({
  action: 'cn_scan', label: 'CreateCodeScan 环境扫描', service: 'continuum', scope: 's3', outcome: 'fire', gate: null,
  reason: '环境扫描已发起', at: '2026-10-23T18:00:00Z', paid: true, evaluated_by: 'respond', result: 'ok',
  result_at: '2026-10-23T18:00:00Z', ...over,
});

const ROWS: ResponseDecision[] = [
  row({ action: 'sa_requirement', label: 'Security Agent 规则同步', scope: null, paid: false, outcome: 'not_fire',
        gate: 'U_REQUIREMENT_CURRENT', reason: '规则未变，今日已重申' }),
  row({ outcome: 'blocked', gate: 'B_SCAN_INTERVAL', reason: '每个环境 24 小时最多一次扫描，时钟未到', limit: 24 }),
  row({ scope: 'github', outcome: 'not_evaluated', gate: 'N_CHANNEL_NOT_WIRED', reason: 'GitHub 渠道（集成 / 环境）未接通，没有评估' }),
  row({ action: 'sa_review', label: 'Security Agent 代码评审（付费）', service: 'security_agent', scope: 'demo-shop' }),
];
const html = (rows: ResponseDecision[] | undefined) => renderToStaticMarkup(<DecisionsPanel decisions={rows} />);

describe('outcome looks', () => {
  it('one look per schema outcome, no stale keys', () => {
    expect(Object.keys(OUTCOME).sort()).toEqual([...props.outcome.enum].sort());
  });
  it('not_evaluated differs from not_fire in glyph, word, tone and row class', () => {
    const a = OUTCOME.not_evaluated, b = OUTCOME.not_fire;
    expect(a.glyph).not.toBe(b.glyph);
    expect(a.word).not.toBe(b.word);
    expect(a.tone).not.toBe(b.tone);
    const out = html(ROWS);
    expect(out).toContain('class="dec-row is-not_evaluated"');
    expect(out).toContain('class="dec-row is-not_fire"');
    expect(out).toContain('未评估');
    expect(out).toContain('未触发');
    expect(out).toContain('被预算闸挡住');
  });
});

describe('DecisionsPanel', () => {
  it('older documents (no decisions) render no block; an empty list is still a block', () => {
    expect(html(undefined)).toBe('');
    expect(groupDecisions(undefined)).toBeNull();
    expect(html([])).toContain('响应决策');
  });
  it('rows keep the published (table) order; scoped rows of one action are grouped and labelled once', () => {
    const g = groupDecisions(ROWS)!;
    expect(g.map(x => x.action)).toEqual(['sa_requirement', 'cn_scan', 'sa_review']);
    expect(g[1].rows.map(r => r.scope)).toEqual(['s3', 'github']);
    const out = html(ROWS);
    expect(out.split('CreateCodeScan 环境扫描').length - 1).toBe(1);
    expect(out.indexOf('Security Agent 规则同步')).toBeLessThan(out.indexOf('CreateCodeScan'));
  });
  it('shows reason, gate code and time', () => {
    const out = html(ROWS);
    expect(out).toContain('B_SCAN_INTERVAL');
    expect(out).toContain('每个环境 24 小时最多一次扫描');
    expect(out).toContain('10-23 18:00');
  });
  it('counts and scope labels', () => {
    expect(outcomeCounts(ROWS)).toEqual({ fire: 1, not_fire: 1, blocked: 1, not_evaluated: 1 });
    expect(scopeLabel(null)).toBe('本事件');
    expect(scopeLabel('github')).toBe('GitHub 环境');
    expect(scopeLabel('demo-shop')).toBe('demo-shop');
  });
});

describe('a fire row carries the result of its call', () => {
  const failed = row({ action: 'cn_context', label: 'Continuum 知识文档', scope: null, paid: false, result: 'error',
                       error: 'continuum_unavailable', result_at: '2026-10-24T09:05:00Z' });
  it('a failed call never looks like a success; an unrecorded result is not a success either', () => {
    const ok = look(row({})), bad = look(failed), unknown = look(row({ result: undefined }));
    expect(bad.failed).toBe(true);
    expect([bad.glyph, bad.word, bad.tone]).not.toEqual([ok.glyph, ok.word, ok.tone]);
    expect(bad.tone).not.toBe('ok');
    expect(unknown.tone).not.toBe('ok');
    expect(unknown.word).not.toBe(ok.word);
    expect(look(row({ outcome: 'blocked', result: 'error' })).failed).toBe(false);   // only an issued call can fail
  });
  it('the panel says what failed and when it last failed', () => {
    const out = html([row({}), failed]);
    expect(out).toContain('执行失败');
    expect(out).toContain('continuum_unavailable');
    expect(out).toContain('10-24 09:05');
    expect(out).toContain('class="dec-row is-fire is-failed"');
    expect(out).toContain('其中执行失败 1');
    expect(rowTime(failed)).toBe('2026-10-24T09:05:00Z');
    expect(rowTime(row({ result_at: '2026-10-24T09:05:00Z' }))).toBe('2026-10-23T18:00:00Z');
  });
});
