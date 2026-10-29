/**
 * #/continuum — single-source view logic for the "AWS Continuum 融入" page (spec 01 §5).
 * Every number the page shows about integration coverage is computed here, once, so the page, the wall
 * mini-card and any future chip cannot each round or classify differently. Pure; tested in src/test/continuum.test.ts.
 *
 * Status semantics are the publisher's (src/radar/coverage.py, authority): live = success observed on the live
 * stack; wired = a code path exists but no success has been observed yet; needs_user = blocked on a one-time
 * human step; not_applicable = cannot apply here (reason in `detail`) and is excluded from the denominator.
 */
import type { Capability, ContinuumRecent, ContinuumResource, ContinuumTarget, CostDay, ImpactSummary, InventoryEntry, Ledger } from '@/types/site-data';
import type { Freshness } from '@/utils/staleness';

export type CapStatus = Capability['status'];
export type Service = Capability['service'];

export interface CoverageScore {
  live: number;
  wired: number;
  needsUser: number;
  na: number;
  /** live + wired + needs_user — the denominator (not_applicable is excluded). */
  applicable: number;
  /**
   * floor(live / applicable × 100). `null` when nothing is applicable (render NoData, never NaN% or 0%).
   * Floor, not round: 199/200 must read 99%, because "100%" is reserved for live === applicable.
   */
  pct: number | null;
  /** The ONLY criterion for "融入度 100%": every applicable capability is live (wired ≠ integrated). */
  complete: boolean;
}

/**
 * Integration coverage. Only `live` counts toward the percentage — a wired path that has never succeeded
 * on the live stack is not integration yet. not_applicable is out of the denominator.
 */
export function coverageScore(coverage: Capability[]): CoverageScore {
  let live = 0, wired = 0, needsUser = 0, na = 0;
  for (const c of coverage) {
    if (c.status === 'live') live++;
    else if (c.status === 'wired') wired++;
    else if (c.status === 'needs_user') needsUser++;
    else na++;
  }
  // Same definition as the backend authority (src/radar/coverage.py percent()): the denominator is what the system
  // can complete on its own (live + wired). needs_user is shown beside the score, never hidden, but a capability
  // that waits on a human OAuth click is not an integration gap the code can close.
  const applicable = live + wired;
  const pct = applicable === 0 ? null : Math.floor((live / applicable) * 100);
  return { live, wired, needsUser, na, applicable, pct, complete: applicable > 0 && live === applicable };
}

/** Reading order inside a service column: what is still missing first (spec 01 §5.2 "先看还差什么"). */
export const STATUS_ORDER: CapStatus[] = ['needs_user', 'wired', 'live', 'not_applicable'];

export const STATUS_META: Record<CapStatus, { word: string; glyph: string; hint: string }> = {
  needs_user:     { word: '需要你',  glyph: '◐', hint: '卡在一次人工操作' },
  wired:          { word: '已接线',  glyph: '◎', hint: '代码路径已就绪，线上未见成功' },
  live:           { word: '已上线',  glyph: '●', hint: '线上观察到成功' },
  not_applicable: { word: '不适用',  glyph: '–', hint: '不进分母，原因见说明' },
};

/** Data flow order: radar produces the rule → Security Agent reviews code → Continuum validates in the environment. */
export const SERVICE_ORDER: Service[] = ['radar', 'security_agent', 'continuum'];
export const SERVICE_WORD: Record<Service, string> = {
  radar: 'Security Radar',
  security_agent: 'AWS Security Agent',
  continuum: 'AWS Continuum',
};

export function sortCapabilities(caps: Capability[]): Capability[] {
  // stable: equal statuses keep publisher order
  return caps.map((c, i) => ({ c, i }))
    .sort((a, b) => STATUS_ORDER.indexOf(a.c.status) - STATUS_ORDER.indexOf(b.c.status) || a.i - b.i)
    .map(x => x.c);
}

export interface ServiceColumn { service: Service; caps: Capability[]; score: CoverageScore }

/** Three columns in data-flow order; each sorted needs_user → wired → live → n/a. Empty services are kept (shown as 未登记). */
export function capabilityColumns(coverage: Capability[]): ServiceColumn[] {
  return SERVICE_ORDER.map(service => {
    const caps = sortCapabilities(coverage.filter(c => c.service === service));
    return { service, caps, score: coverageScore(caps) };
  });
}

/** What still stands between today and 100%: every applicable capability that is not live, in reading order. */
export function remaining(coverage: Capability[]): Capability[] {
  return sortCapabilities(coverage.filter(c => c.status === 'wired' || c.status === 'needs_user'));
}

/** L0 sentence (code-templated, no LLM). */
export function coverageSentence(s: CoverageScore): string {
  if (s.pct === null) return '没有可计入的能力（全部不适用或未登记）';
  if (s.complete) {
    return `融入度 100%（${s.live}/${s.applicable} 项可自动化能力已上线）` +
      (s.needsUser ? ` · 另 ${s.needsUser} 项需要你一次授权` : '');
  }
  const parts = [`融入度 ${s.pct}%（${s.live}/${s.applicable} 能力已上线）`];
  if (s.wired) parts.push(`${s.wired} 项已接线待线上验证`);
  if (s.needsUser) parts.push(`${s.needsUser} 项需要你操作`);
  return parts.join(' · ');
}

/**
 * ContinuumRecent → the ImpactSummary chip it implies (so the shared ImpactChip wording applies).
 * Same rule as impactFromResponse() in utils/response.ts: an affected target wins even mid-run (otherwise the same
 * event reads 检查中 here and 命中 1/2 on its detail page). done + 0 affected + 0 checked is NOT "not affected" —
 * nothing was looked at — so it maps to not_affected with checked=0, which impactView renders as the muted
 * 无可检查目标 (never a green 未命中 0/0).
 */
export function recentImpact(r: ContinuumRecent): ImpactSummary {
  if (r.affected > 0 && r.status !== 'failed' && r.status !== 'not_eligible') {
    return { status: 'affected', affected: r.affected, checked: r.checked };
  }
  if (r.status === 'done') return { status: 'not_affected', affected: 0, checked: r.checked };
  return { status: r.status, affected: r.affected, checked: r.checked };
}

/** Recent-row status word. `done` = the radar's locator finished; ContinuumRecent carries no per-service state,
 * so it must not read as "AWS Continuum finished" (Continuum validation may still be running). */
export const RECENT_STATUS: Record<ContinuumRecent['status'], string> = {
  done: '定位完成', running: '检查中', queued: '排队', failed: '失败', not_eligible: '不适用',
};

/**
 * The hero ring is "AWS Continuum 融入度" — so it is computed from the Continuum column ONLY. Security Radar
 * (not an AWS product) and AWS Security Agent are reported beside it, never folded into the headline number
 * (2026-10-24 review: the all-services 60% was read as "Continuum is 60% integrated" while Continuum was 2/6).
 */
export const HERO_SERVICE: Service = 'continuum';
export interface HeroView { service: Service; score: CoverageScore; gap: Capability[]; others: ServiceColumn[] }
export function heroView(coverage: Capability[]): HeroView {
  const cols = capabilityColumns(coverage);
  const own = cols.find(c => c.service === HERO_SERVICE)!;
  return { service: HERO_SERVICE, score: own.score, gap: remaining(own.caps), others: cols.filter(c => c.service !== HERO_SERVICE) };
}

/** "Security Agent 3/3 · Security Radar 1/1" — the other services' live/applicable, shown under the ring. */
export function otherServicesLine(others: ServiceColumn[]): string {
  return others.map(c => `${SERVICE_WORD[c.service]} ${c.score.applicable === 0 ? '未登记' : `${c.score.live}/${c.score.applicable}`}`).join(' · ');
}

export type ContinuumFetchClass = { kind: 'unpublished' } | { kind: 'error'; status: number } | { kind: 'json' };

/**
 * How to read the HTTP answer for /data/continuum.json. 404/403 = not published. An HTML body is the dev/preview
 * or CloudFront SPA fallback ONLY when the status is 2xx — CloudFront/ALB 5xx error pages are text/html too, and
 * an outage must surface as an error, not as "尚未发布".
 */
export function classifyContinuumResponse(status: number, contentType: string): ContinuumFetchClass {
  const ok = status >= 200 && status < 300;
  if (status === 404 || status === 403 || (ok && contentType.includes('text/html'))) return { kind: 'unpublished' };
  if (!ok) return { kind: 'error', status };
  return { kind: 'json' };
}

export type StatusChip = { cls: 'is-fresh' | 'is-stale' | 'is-error' | 'is-unknown'; label: string };

/**
 * Top-right status chip. Every state is mapped explicitly (no default) — only a fresh doc with the latest fetch
 * OK may read LIVE. Without this a failed refresh shows LIVE + green dot for up to 60 s beside the 刷新失败 banner.
 */
export function statusChip(state: 'loading' | 'unpublished' | 'error' | 'ok', fresh: Freshness): StatusChip {
  if (fresh.kind === 'fetch_failing') return { cls: 'is-error', label: `刷新失败 ${Math.floor(fresh.sinceFetchSecs / 60)} 分钟` };
  if (state === 'error') return { cls: 'is-error', label: '刷新失败' };
  if (fresh.kind === 'publish_stale') return { cls: 'is-stale', label: `数据 ${Math.floor(fresh.dataAgeSecs / 60)} 分钟未更新` };
  if (fresh.kind === 'unknown') return { cls: 'is-unknown', label: '发布时间未知' };
  if (state === 'ok' && fresh.kind === 'fresh') return { cls: 'is-fresh', label: 'LIVE' };
  return { cls: 'is-unknown', label: '读取中' };
}

/** "10-23 17:20 UTC"; a missing timestamp degrades to 未知 instead of crashing the page on `.slice`. */
export const hhmm = (iso: string | null | undefined): string => iso ? `${iso.slice(5, 10)} ${iso.slice(11, 16)} UTC` : '未知';

export function sortRecent(recent: ContinuumRecent[]): ContinuumRecent[] {
  return [...recent].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
}

export interface RegionGroup { region: string; resources: ContinuumResource[] }

export function resourcesByRegion(resources: ContinuumResource[]): RegionGroup[] {
  const m = new Map<string, ContinuumResource[]>();
  for (const r of resources) m.set(r.region, [...(m.get(r.region) ?? []), r]);
  return [...m.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([region, rs]) => ({ region, resources: rs }));
}

export const KIND_WORD: Record<string, string> = {
  agent_space: '代理空间',
  requirement_pack: '规则包',
  integration: '集成',
  environment: '环境',
};
/** Each target lives in exactly ONE Continuum environment (src/radar/targets.py CHANNEL); the chip says which and
 * what comes back from it. Absent (data published before the channel field) ⇒ no chip, never a guess. */
export const CHANNEL_WORD: Record<NonNullable<ContinuumTarget['channel']>, { env: string; out: string }> = {
  s3: { env: 'S3 环境', out: '补丁文件' },
  github: { env: 'GitHub 环境', out: '原生 PR' },
  gitlab: { env: 'GitLab 环境', out: '原生 MR' },
  none: { env: '不送 Continuum', out: '仅 Security Agent 评审' },
};
export const channelLine = (t: Pick<ContinuumTarget, 'channel'>): string | null =>
  t.channel ? `${CHANNEL_WORD[t.channel].env} · ${CHANNEL_WORD[t.channel].out}` : null;
/** Unknown kinds are shown verbatim (a new resource kind must not disappear from the page). */
export const kindWord = (k: string): string => KIND_WORD[k] ?? k;

export const UPLOAD_STALE_DAYS = 7;

export type UploadAge =
  | { kind: 'missing' }
  | { kind: 'fresh'; days: number }
  | { kind: 'stale'; days: number };

/** Source snapshot age for a target card; > UPLOAD_STALE_DAYS ⇒ results may be out of date. */
export function uploadAge(t: ContinuumTarget, nowMs: number): UploadAge {
  if (!t.uploaded_at) return { kind: 'missing' };
  const ms = new Date(t.uploaded_at).getTime();
  if (Number.isNaN(ms)) return { kind: 'missing' };
  const days = Math.max(0, Math.floor((nowMs - ms) / 86_400_000));
  return days > UPLOAD_STALE_DAYS ? { kind: 'stale', days } : { kind: 'fresh', days };
}

export interface InventoryRow { entry: InventoryEntry; /** >0 on the first row of a product run = rowSpan; 0 = merged. */ span: number; file: string }

/**
 * Inventory table rows with consecutive same-product rows merged. File shown without the "<target_id>/" prefix
 * (the card already names the target). Dirty-data source: the publisher writes locator-style paths
 * ("demo-shop/Dockerfile"); without the strip every row repeats the card title.
 */
export function inventoryRows(t: ContinuumTarget): InventoryRow[] {
  const pre = `${t.target_id}/`;
  const rows: InventoryRow[] = [];
  t.inventory.forEach((e, i) => {
    const file = e.file.startsWith(pre) ? e.file.slice(pre.length) : e.file;
    if (i > 0 && t.inventory[i - 1].product === e.product) {
      rows.push({ entry: e, span: 0, file });
      const head = [...rows].reverse().find(r => r.span > 0);
      if (head) head.span++;
    } else rows.push({ entry: e, span: 1, file });
  });
  return rows;
}

/* ── R4: spend line under the ledger (Cost Explorer via the respond ledger) ───────────────── */

export interface CostView {
  totalUsd: number;
  continuumUsd: number;
  securityAgentUsd: number;
  units: number;
  peak: { date: string; usd: number } | null;  // the costliest day — the one a reader should ask about
  days: number;
  fetched: string;
  error: string | null;                        // last read failed: numbers are from `fetched`, say so
}

export function costView(cost: Ledger['cost'] | undefined): CostView | null {
  if (!cost) return null;
  const sum = (f: (d: CostDay) => number) => Math.round(cost.days.reduce((a, d) => a + f(d), 0) * 100) / 100;
  const peak = cost.days.reduce<CostDay | null>((p, d) => {
    const usd = d.continuum_usd + d.security_agent_usd;
    return usd > 0 && (!p || usd > p.continuum_usd + p.security_agent_usd) ? d : p;
  }, null);
  return {
    totalUsd: cost.total_usd, continuumUsd: sum(d => d.continuum_usd), securityAgentUsd: sum(d => d.security_agent_usd),
    units: sum(d => d.continuum_inference_units), days: cost.days.length, fetched: cost.fetched_at,
    peak: peak ? { date: peak.date, usd: Math.round((peak.continuum_usd + peak.security_agent_usd) * 100) / 100 } : null,
    error: cost.error ?? null,
  };
}

export const usd = (n: number): string => `$${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
