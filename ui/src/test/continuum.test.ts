/**
 * #/continuum view logic (utils/continuum.ts). Fixture = the real 2026-10-23 continuum.json in mock-data.
 * Liveness (mutate by hand, each must turn this file red):
 *   - coverageScore: count `wired` as live                 ⇒ "mock = 66%" + "wired is not integration" red
 *   - coverageScore: keep not_applicable in the denominator ⇒ "mock = 66%" + "all N/A ⇒ null" red
 *   - coverageScore: put needs_user back in the denominator ⇒ "same definition as coverage.py" red
 *   - coverageScore: Math.round instead of Math.floor       ⇒ "199/200 is not 100%" red
 *   - sortCapabilities: drop STATUS_ORDER                   ⇒ "missing first" red
 *   - recentImpact: map done ⇒ affected unconditionally     ⇒ "done + 0 ⇒ not_affected" red
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import type { Capability, ContinuumRecent, ContinuumTarget } from '@/types/site-data';
import {
  coverageScore, coverageSentence, sortCapabilities, capabilityColumns, remaining, recentImpact,
  resourcesByRegion, uploadAge, inventoryRows, kindWord, heroView, otherServicesLine, classifyContinuumResponse,
  statusChip, hhmm, RECENT_STATUS, costView, usd, channelLine,
} from '@/utils/continuum';

const doc = JSON.parse(readFileSync(resolve(__dirname, '../../mock-data/data/continuum.json'), 'utf-8'));
const COV: Capability[] = doc.coverage;
const cap = (status: Capability['status'], service: Capability['service'] = 'continuum', name = status): Capability =>
  ({ capability: name, service, status, detail: '' });

describe('coverageScore', () => {
  it('mock: 11 capabilities ⇒ 6 live / 3 wired / 1 needs_user / 1 N/A ⇒ 66% (6/9; needs_user beside, not in, the denominator)', () => {
    expect(coverageScore(COV)).toEqual({ live: 6, wired: 3, needsUser: 1, na: 1, applicable: 9, pct: 66, complete: false });
  });
  it('all live ⇒ 100% and complete', () => {
    const s = coverageScore([cap('live'), cap('live'), cap('not_applicable')]);
    expect(s).toMatchObject({ pct: 100, complete: true, applicable: 2 });
  });
  it('wired is not integration: all wired ⇒ 0%, not complete', () => {
    expect(coverageScore([cap('wired'), cap('wired')])).toMatchObject({ pct: 0, complete: false, live: 0 });
  });
  it('all N/A (or empty) ⇒ applicable 0, pct null (NoData, never NaN%)', () => {
    expect(coverageScore([cap('not_applicable')])).toMatchObject({ applicable: 0, pct: null, complete: false });
    expect(coverageScore([])).toMatchObject({ applicable: 0, pct: null, complete: false });
  });
  it('199/200 is not 100% (floor; 100 is reserved for live === applicable)', () => {
    const caps = [...Array(199).fill(cap('live')), cap('wired')];
    expect(coverageScore(caps)).toMatchObject({ pct: 99, complete: false });
  });
});

describe('coverageScore — same definition as src/radar/coverage.py percent()', () => {
  it('all automatable live + one OAuth click pending ⇒ 100% and the pending click is named, never hidden', () => {
    const s = coverageScore([cap('live'), cap('live'), cap('needs_user'), cap('not_applicable')]);
    expect(s).toMatchObject({ pct: 100, complete: true, applicable: 2, needsUser: 1 });
    expect(coverageSentence(s)).toBe('融入度 100%（2/2 项可自动化能力已上线） · 另 1 项需要你一次授权');
  });
});

describe('coverageSentence', () => {
  it('mock sentence names the gap', () => {
    expect(coverageSentence(coverageScore(COV))).toBe('融入度 66%（6/9 能力已上线） · 3 项已接线待线上验证 · 1 项需要你操作');
  });
  it('null ⇒ no-data sentence, not 0%', () => {
    expect(coverageSentence(coverageScore([]))).not.toMatch(/%/);
  });
});

describe('capability ordering', () => {
  it('missing first: needs_user → wired → live → not_applicable; first = GitHub, last = Collector', () => {
    const s = sortCapabilities(COV);
    expect(s.map(c => c.status)).toEqual([
      'needs_user', 'wired', 'wired', 'wired', 'live', 'live', 'live', 'live', 'live', 'live', 'not_applicable',
    ]);
    expect(s[0].capability).toMatch(/^GitHub 集成/);
    expect(s[s.length - 1].capability).toMatch(/Collector/);
  });
  it('columns in data-flow order with per-service score', () => {
    const cols = capabilityColumns(COV);
    expect(cols.map(c => c.service)).toEqual(['radar', 'security_agent', 'continuum']);
    expect(cols.map(c => c.caps.length)).toEqual([1, 3, 7]);
    expect(cols[2].score).toMatchObject({ live: 2, applicable: 5, pct: 40 });
    expect(cols[2].caps[0].status).toBe('needs_user');
  });
  it('remaining = wired + needs_user only', () => {
    expect(remaining(COV).map(c => c.status)).toEqual(['needs_user', 'wired', 'wired', 'wired']);
  });
});

describe('recentImpact', () => {
  const r = (status: ContinuumRecent['status'], affected: number): ContinuumRecent =>
    ({ event_id: 'e', title: 't', severity: 'P0', status, affected, checked: 2, updated_at: '2026-10-23T17:20:00Z' });
  it('done + affected>0 ⇒ affected; done + 0 ⇒ not_affected; others 1:1', () => {
    expect(recentImpact(r('done', 1))).toEqual({ status: 'affected', affected: 1, checked: 2 });
    expect(recentImpact(r('done', 0))).toEqual({ status: 'not_affected', affected: 0, checked: 2 });
    expect(recentImpact(r('running', 0)).status).toBe('running');
    expect(recentImpact(r('failed', 0)).status).toBe('failed');
  });
  it('an affected target wins even mid-run (same rule as impactFromResponse)', () => {
    expect(recentImpact(r('running', 1))).toEqual({ status: 'affected', affected: 1, checked: 2 });
    expect(recentImpact(r('queued', 1)).status).toBe('affected');
    expect(recentImpact(r('failed', 1)).status).toBe('failed');
  });
  it('done with checked=0 is not a green 未命中: not_affected/0 ⇒ impactView renders 无可检查目标', () => {
    const z: ContinuumRecent = { ...r('done', 0), checked: 0 };
    expect(recentImpact(z)).toEqual({ status: 'not_affected', affected: 0, checked: 0 });
  });
  it('done reads 定位完成, not 完成 (Recent has no per-service state)', () => {
    expect(RECENT_STATUS.done).toBe('定位完成');
  });
});

describe('heroView — "AWS Continuum 融入度" counts the Continuum column only', () => {
  it('mock: hero = Continuum 2/5 = 40%, equal to the Continuum column score, not the all-services 66%', () => {
    const h = heroView(COV);
    expect(h.service).toBe('continuum');
    expect(h.score).toEqual(capabilityColumns(COV).find(c => c.service === 'continuum')!.score);
    expect(h.score).toMatchObject({ live: 2, applicable: 5, pct: 40 });
    expect(h.score.pct).not.toBe(coverageScore(COV).pct);
    expect(coverageSentence(h.score)).toBe('融入度 40%（2/5 能力已上线） · 3 项已接线待线上验证 · 1 项需要你操作');
  });
  it('gap list = Continuum gaps only; other services reported beside the ring', () => {
    const h = heroView(COV);
    expect(h.gap.every(c => c.service === 'continuum')).toBe(true);
    expect(h.gap.map(c => c.status)).toEqual(['needs_user', 'wired', 'wired', 'wired']);
    expect(otherServicesLine(h.others)).toBe('Security Radar 1/1 · AWS Security Agent 3/3');
  });
  it('a non-Continuum gap never moves the hero number', () => {
    const h = heroView([cap('live'), cap('wired', 'security_agent'), cap('wired', 'radar')]);
    expect(h.score).toMatchObject({ pct: 100, complete: true });
    expect(otherServicesLine(h.others)).toBe('Security Radar 0/1 · AWS Security Agent 0/1');
  });
});

describe('classifyContinuumResponse — outage is not "unpublished"', () => {
  it('404/403 and 200+html (SPA fallback) ⇒ unpublished', () => {
    expect(classifyContinuumResponse(404, 'text/html')).toEqual({ kind: 'unpublished' });
    expect(classifyContinuumResponse(403, 'application/xml')).toEqual({ kind: 'unpublished' });
    expect(classifyContinuumResponse(200, 'text/html; charset=utf-8')).toEqual({ kind: 'unpublished' });
  });
  it('5xx html error pages ⇒ error with the real status', () => {
    for (const st of [500, 502, 503, 504]) expect(classifyContinuumResponse(st, 'text/html')).toEqual({ kind: 'error', status: st });
  });
  it('200 json ⇒ json', () => {
    expect(classifyContinuumResponse(200, 'application/json')).toEqual({ kind: 'json' });
  });
});

describe('statusChip — only fresh + ok may read LIVE', () => {
  const fresh = { kind: 'fresh' as const, dataAgeSecs: 10 };
  it('fresh + ok ⇒ LIVE', () => {
    expect(statusChip('ok', fresh)).toEqual({ cls: 'is-fresh', label: 'LIVE' });
  });
  it('every other combination is not LIVE', () => {
    const fs = [fresh, { kind: 'unknown' as const }, { kind: 'publish_stale' as const, dataAgeSecs: 3000 }, { kind: 'fetch_failing' as const, sinceFetchSecs: 300 }];
    for (const st of ['loading', 'unpublished', 'error', 'ok'] as const) for (const f of fs) {
      if (st === 'ok' && f.kind === 'fresh') continue;
      expect(statusChip(st, f).label).not.toBe('LIVE');
      expect(statusChip(st, f).cls).not.toBe('is-fresh');
    }
  });
  it('error within the first 120 s ⇒ 刷新失败; unknown ⇒ 发布时间未知', () => {
    expect(statusChip('error', fresh)).toEqual({ cls: 'is-error', label: '刷新失败' });
    expect(statusChip('ok', { kind: 'unknown' })).toEqual({ cls: 'is-unknown', label: '发布时间未知' });
    expect(statusChip('error', { kind: 'fetch_failing', sinceFetchSecs: 180 }).label).toBe('刷新失败 3 分钟');
  });
  it('hhmm degrades instead of crashing on a missing timestamp', () => {
    expect(hhmm('2026-10-23T17:20:00Z')).toBe('10-23 17:20 UTC');
    expect(hhmm(undefined)).toBe('未知');
    expect(hhmm(null)).toBe('未知');
  });
});

describe('resources / targets', () => {
  it('mock resources: two regions, sorted; us-east-1 holds all three channels (integration + environment each)', () => {
    const g = resourcesByRegion(doc.resources);
    expect(g.map(x => [x.region, x.resources.length])).toEqual([['ap-northeast-1', 2], ['us-east-1', 6]]);
  });
  it('channel chip: one line per channel, nothing for data without a channel', () => {
    expect(channelLine({ channel: 'gitlab' })).toBe('GitLab 环境 · 原生 MR');
    expect(channelLine({ channel: 's3' })).toBe('S3 环境 · 补丁文件');
    expect(channelLine({ channel: 'none' })).toBe('不送 Continuum · 仅 Security Agent 评审');
    expect(channelLine({})).toBeNull();
    for (const t of doc.targets as ContinuumTarget[]) expect(channelLine(t)).not.toBeNull();   // mock carries channels
  });
  it('unknown kind shown verbatim', () => {
    expect(kindWord('integration')).toBe('集成');
    expect(kindWord('collector')).toBe('collector');
  });
  it('uploadAge: missing / fresh / stale (> 7 d)', () => {
    const t: ContinuumTarget = doc.targets[0];
    const at = new Date(t.uploaded_at as string).getTime();
    expect(uploadAge(t, at + 3_600_000)).toEqual({ kind: 'fresh', days: 0 });
    expect(uploadAge(t, at + 8 * 86_400_000)).toEqual({ kind: 'stale', days: 8 });
    expect(uploadAge({ ...t, uploaded_at: null }, at)).toEqual({ kind: 'missing' });
  });
  it('inventoryRows: same product merged, target prefix stripped', () => {
    const rows = inventoryRows(doc.targets[0]);
    expect(rows.map(r => [r.file, r.span])).toEqual([['Dockerfile', 2], ['composer.json', 0]]);
    const other = inventoryRows(doc.targets[1]);
    expect(other.map(r => r.span)).toEqual([1, 1]);
  });
});

describe('costView (R4)', () => {
  const C = doc.ledger.cost;
  it('mock: totals split by service, inference units, the costliest day', () => {
    const v = costView(C)!;
    expect([v.totalUsd, v.continuumUsd, v.securityAgentUsd, v.units, v.days]).toEqual([1324.49, 1324.49, 0, 132.18, 4]);
    expect(v.peak).toEqual({ date: '2026-10-23', usd: 726.29 });
    expect(v.error).toBeNull();
  });
  it('a failed last read stays visible; no cost yet ⇒ null; all-zero window ⇒ no peak', () => {
    expect(costView({ ...C, error: 'AccessDenied' })!.error).toBe('AccessDenied');
    expect(costView(null)).toBeNull();
    const rev = { ...C, days: [...C.days].reverse() };  // costliest day not first ⇒ still found
    expect(costView(rev)!.peak).toEqual({ date: '2026-10-23', usd: 726.29 });
    expect(costView(undefined)).toBeNull();
    expect(costView({ ...C, days: [{ date: '2026-10-26', continuum_usd: 0, security_agent_usd: 0, continuum_inference_units: 0 }] })!.peak).toBeNull();
  });
  it('usd formats with thousands separators and cents', () => {
    expect(usd(1324.49)).toBe('$1,324.49');
    expect(usd(0)).toBe('$0.00');
  });
});
