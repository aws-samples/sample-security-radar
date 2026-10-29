/**
 * "在你的环境中" view logic (utils/response.ts). Fixture = the real 2026-10-23 PHP2Shell response in mock-data.
 * Liveness (mutate by hand, each must turn this file red):
 *   - resolveImpact: return `event` before `response`            ⇒ "response wins over event.impact" red
 *   - responseBluf: drop the `r === undefined` branch              ⇒ "undefined vs null" red
 *   - actionDuration: remove the `u < s` guard                      ⇒ "dirty timestamps" red
 *   - sameFile: drop the targetId prefix strip                      ⇒ "prefix" red
 *   - sortFindings: drop the requirement_hit key                    ⇒ "finding order" red
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import type { Response, PipelineStep } from '@/types/site-data';
import {
  impactView, impactFromResponse, resolveImpact, responseBluf, sortTargets, sortFindings,
  stripRequirementPrefix, actionDuration, sameFile, actionLanes, pipelineRows, pendingContinuumActions,
} from '@/utils/response';

const detail = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/events/ev_bb65db3b8694e5f4.json'), 'utf-8'));
const R: Response = detail.response;
const STEPS: PipelineStep[] = detail.pipeline_steps;
const clone = (): Response => JSON.parse(JSON.stringify(R));

describe('impactView', () => {
  it('affected / not_affected / running / failed labels', () => {
    expect(impactView({ status: 'affected', affected: 1, checked: 2 })).toMatchObject({ tone: 'loss', label: '命中 1/2' });
    expect(impactView({ status: 'not_affected', affected: 0, checked: 3 })).toMatchObject({ tone: 'ok', label: '未命中 0/3' });
    expect(impactView({ status: 'running', affected: 0, checked: 2 })).toMatchObject({ tone: 'info', live: true });
    expect(impactView({ status: 'queued', affected: 0, checked: 2 })).toMatchObject({ tone: 'info', live: false });
    expect(impactView({ status: 'failed', affected: 0, checked: 0 })).toMatchObject({ tone: 'warn', label: '检查失败' });
  });
  it('not_affected with checked=0 looked at nothing: muted 无可检查目标, never a green 未命中 0/0', () => {
    expect(impactView({ status: 'not_affected', affected: 0, checked: 0 })).toMatchObject({ tone: 'muted', label: '无可检查目标' });
    expect(impactView({ status: 'not_affected', affected: 0, checked: 0 }, 'detail')?.label).not.toMatch(/未命中/);
  });
  it('null and not_eligible: hidden in lists, explicit on the detail page', () => {
    expect(impactView(null)).toBeNull();
    expect(impactView(undefined, 'list')).toBeNull();
    expect(impactView(null, 'detail')?.label).toBe('未检查');
    expect(impactView({ status: 'not_eligible', affected: 0, checked: 0 })).toBeNull();
    expect(impactView({ status: 'not_eligible', affected: 0, checked: 0 }, 'detail')?.label).toBe('不适用');
  });
  it('affected with checked=0 is dirty data: shows 命中 ? and warns', () => {
    const w = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(impactView({ status: 'affected', affected: 1, checked: 0 })?.label).toBe('命中 ?');
    expect(w).toHaveBeenCalled();
    w.mockRestore();
  });
});

describe('resolveImpact', () => {
  it('response wins over event.impact and over the stale impact_match step, and says so', () => {
    const r = resolveImpact({ status: 'not_affected', affected: 0, checked: 1 }, R, STEPS);
    expect(r.source).toBe('response');
    expect(r.impact).toEqual({ status: 'affected', affected: 1, checked: 2 });
    expect(r.note).toContain('已以环境检查明细为准');
    expect(r.note).toContain('关注清单未配置');
  });
  it('agreeing event.impact produces no list-chip note', () => {
    const r = resolveImpact({ status: 'affected', affected: 1, checked: 2 }, R, []);
    expect(r.note).toBeNull();
  });
  it('falls back to event.impact, then to the pipeline step, then none', () => {
    expect(resolveImpact({ status: 'not_eligible', affected: 0, checked: 0 }, null, STEPS).source).toBe('event');
    expect(resolveImpact(null, null, [{ step: 'impact_match', status: 'failed', detail: 'x' }]).impact?.status).toBe('failed');
    const none = resolveImpact(null, null, STEPS);
    expect(none).toMatchObject({ impact: null, source: 'none', note: '关注清单未配置，未检查' });
  });
  it('impactFromResponse mirrors the publisher rule (checked = all targets)', () => {
    expect(impactFromResponse(R)).toEqual({ status: 'affected', affected: 1, checked: 2 });
    const r = clone(); r.targets[0].verdict = 'not_affected';
    expect(impactFromResponse(r)).toEqual({ status: 'not_affected', affected: 0, checked: 2 });
    r.targets[0].verdict = 'pending';
    expect(impactFromResponse(r).status).toBe('running');
    r.status = 'not_eligible';
    expect(impactFromResponse(r)).toEqual({ status: 'not_eligible', affected: 0, checked: 0 });
  });
});

describe('responseBluf — one template per state', () => {
  it('done + affected (live sample)', () => {
    const b = responseBluf(R);
    expect(b.tone).toBe('loss');
    expect(b.text).toBe('◆ 命中 1 / 2 个目标 · demo-shop 有 3 处钉在 php 8.3.30（修复版 8.3.36） · 已生成修复补丁');
  });
  it('live sample: done verdict while Continuum code_finding/code_scan still run ⇒ info tail, never a bare 命中', () => {
    expect(pendingContinuumActions(R)).toBe(2);
    expect(responseBluf(R).tail).toEqual({ tone: 'info', text: 'AWS Continuum 验证中（2 个动作未完成）' });
    const d = clone(); d.actions.forEach(a => { a.status = 'done'; });
    expect(responseBluf(d).tail).toBeUndefined();
    // Security Agent actions in flight do not count as Continuum validation
    const sa = clone(); sa.actions.forEach(a => { a.status = a.service === 'continuum' ? 'done' : 'running'; });
    expect(pendingContinuumActions(sa)).toBe(0);
    const sub = clone(); sub.actions.forEach(a => { a.status = a.service === 'continuum' ? 'submitted' : 'done'; });
    expect(pendingContinuumActions(sub)).toBe(3);
  });
  it('done + nothing affected mentions skipped targets', () => {
    const r = clone(); r.targets[0].verdict = 'not_affected'; r.targets[0].locations = [];
    expect(responseBluf(r)).toMatchObject({ tone: 'ok', text: '◇ 已检查 1 个相关目标，均未命中 · 另 1 个与产品无关已跳过' });
    expect(responseBluf(r).tail?.text).toContain('AWS Continuum 验证中');
    r.actions.forEach(a => { a.status = 'done'; });
    expect(responseBluf(r)).toEqual({ tone: 'ok', text: '◇ 已检查 1 个相关目标，均未命中 · 另 1 个与产品无关已跳过' });
  });
  it('undefined (key missing) vs null (not triggered) read differently', () => {
    expect(responseBluf(undefined).text).toContain('未接入');
    expect(responseBluf(null).text).toBe('该事件未触发环境检查');
  });
  it('failed / not_eligible / running', () => {
    const f = clone(); f.status = 'failed'; f.reason = 'code_review_timeout';
    expect(responseBluf(f)).toEqual({ tone: 'warn', text: '⚠ 环境检查失败 · code_review_timeout' });
    const n = clone(); n.status = 'not_eligible'; n.reason = 'P2 不触发';
    expect(responseBluf(n)).toEqual({ tone: 'muted', text: '不触发环境检查 · P2 不触发' });
    const q = clone(); q.status = 'running';
    expect(responseBluf(q).text).toBe(`◌ 检查中 · 已完成 4/6 个动作 · ${R.reason}`);
  });
});

describe('ordering', () => {
  it('targets: affected first, skipped last', () => {
    expect(sortTargets([...R.targets].reverse()).map(t => t.verdict)).toEqual(['affected', 'skipped']);
  });
  it('finding order = requirement hits first, then severity, then service (spec §4.6)', () => {
    expect(sortFindings(R.findings).map(f => f.finding_id))
      .toEqual(['0000f91399697955b82e470c405fb545', 'f-1', 'f-2', 'f-3']);
  });
  it('a requirement hit outranks a more severe non-hit', () => {
    const fs = [{ ...R.findings[1], finding_id: 'crit', severity: 'CRITICAL' }, { ...R.findings[0], finding_id: 'hit', severity: 'LOW' }];
    expect(sortFindings(fs).map(f => f.finding_id)).toEqual(['hit', 'crit']);
  });
  it('unknown severity sorts last but is kept', () => {
    const fs = [{ ...R.findings[2], severity: 'WEIRD', finding_id: 'w' }, { ...R.findings[2], severity: 'LOW', finding_id: 'l' }];
    expect(sortFindings(fs).map(f => f.finding_id)).toEqual(['l', 'w']);
  });
  it('requirement prefix stripped', () => {
    expect(stripRequirementPrefix(R.findings[0].title)).toBe('PHP runtime pinned to known-affected 8.3.30, below the fixed 8.3.36');
    expect(stripRequirementPrefix('Container runs as root')).toBe('Container runs as root');
  });
  it('action lanes: two services, chronological, failed first', () => {
    const lanes = actionLanes(R.actions);
    expect(lanes.map(l => l.service)).toEqual(['security_agent', 'continuum']);
    expect(lanes[0].actions.map(a => a.kind)).toEqual(['requirement', 'code_review', 'remediation']);
    expect(lanes[1].actions.map(a => a.kind)).toEqual(['code_scan', 'context', 'code_finding']);
    const acts = clone().actions; acts[5].status = 'failed';
    expect(actionLanes(acts)[0].actions[0].kind).toBe('remediation');
  });
});

describe('actionDuration', () => {
  it('normal action', () => {
    expect(actionDuration(R.actions[4])).toBe((27 * 60 + 6) * 1000);
  });
  it('dirty timestamps (updated < started) and missing start give null, never negative', () => {
    expect(actionDuration(R.actions[2])).toBeNull();
    expect(actionDuration({ started_at: null, updated_at: '2026-10-23T00:00:00Z' })).toBeNull();
  });
});

describe('sameFile', () => {
  it('strips the target prefix from either side', () => {
    expect(sameFile('Dockerfile', 'demo-shop/Dockerfile', 'demo-shop')).toBe(true);
    expect(sameFile('demo-shop/Dockerfile', 'Dockerfile', 'demo-shop')).toBe(true);
    expect(sameFile('.gitlab-ci.yml', 'demo-shop/.gitlab-ci.yml', 'demo-shop')).toBe(true);
  });
  it('different files / null never match', () => {
    expect(sameFile('Dockerfile', 'demo-shop/composer.json', 'demo-shop')).toBe(false);
    expect(sameFile(null, 'Dockerfile', 'demo-shop')).toBe(false);
    expect(sameFile('Dockerfile', 'other/Dockerfile', 'demo-shop')).toBe(false);
  });
});

describe('pipelineRows', () => {
  it('7 fixed rows; missing remediated shows 未接入 without response', () => {
    const rows = pipelineRows(STEPS, null);
    expect(rows.map(r => r.step)).toEqual(['collected', 'clustered', 'verified', 'analyzed', 'impact_match', 'notified', 'remediated']);
    expect(rows[6]).toMatchObject({ status: 'missing', detail: '未接入' });
    expect(rows[4]).toMatchObject({ status: 'not_configured', note: null });
  });
  it('response overrides impact_match and remediated, leaving a trace', () => {
    const rows = pipelineRows(STEPS, R);
    expect(rows[4]).toMatchObject({ status: 'done', detail: '命中 1/2' });
    expect(rows[4].note).toContain('关注清单未配置');
    expect(rows[4].note).toContain('AWS Continuum 验证中（2 个动作未完成）');
    const d = clone(); d.actions.forEach(a => { a.status = 'done'; });
    expect(pipelineRows(STEPS, d)[4].note).not.toContain('验证中');
    expect(rows[6]).toMatchObject({ status: 'done', detail: '补丁已生成 1', note: '由环境检查推出' });
    expect(rows[5].status).toBe('not_connected');
  });
});
