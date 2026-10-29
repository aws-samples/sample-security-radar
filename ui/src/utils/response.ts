/**
 * "在你的环境中" (AWS Continuum + AWS Security Agent) — single-source view logic for the event detail page.
 * Every wording/ordering decision about `event.response`, `event.impact` and the impact_match / remediated
 * pipeline steps is made here, once (degradation-and-guards §6), so the detail page, list chips and the wall
 * cannot each guess differently. Pure; tested in src/test/response.test.ts.
 */
import type {
  ImpactSummary, PipelineStep, Response, ResponseAction, ResponseFinding, ResponseTarget,
} from '@/types/site-data';

export type Tone = 'loss' | 'ok' | 'info' | 'warn' | 'muted';

export interface ImpactView {
  tone: Tone;
  glyph: string;
  label: string;
  /** Screen-reader sentence (the chip is double-encoded: glyph + text + colour). */
  sr: string;
  /** true while a check is in flight (breathing dot; static under reduced-motion). */
  live: boolean;
}

/**
 * Chip view of an ImpactSummary. `context='list'` renders nothing for null (absence is not news in a list);
 * `context='detail'` always renders and says 未检查 — on the detail page a missing check IS the answer.
 */
export function impactView(impact: ImpactSummary | null | undefined, context: 'list' | 'detail' = 'list'): ImpactView | null {
  if (!impact) {
    return context === 'detail'
      ? { tone: 'muted', glyph: '○', label: '未检查', sr: '在你的环境中：未检查', live: false }
      : null;
  }
  const { status, affected, checked } = impact;
  switch (status) {
    case 'affected':
      if (checked === 0) {
        // Dirty data: "affected" with zero targets checked is impossible. Seen when a publisher fills the chip
        // before counting targets. Without this the chip would read 命中 1/0. Show the uncertainty instead.
        console.warn('impactView: status=affected but checked=0', impact);
        return { tone: 'loss', glyph: '◆', label: '命中 ?', sr: '在你的环境中：命中（已检查数缺失）', live: false };
      }
      return { tone: 'loss', glyph: '◆', label: `命中 ${affected}/${checked}`, sr: `在你的环境中：命中 ${affected} / 已检查 ${checked}`, live: false };
    case 'not_affected':
      if (checked === 0) {
        // Nothing was looked at (no eligible target): a green 未命中 0/0 would read as "checked, clean".
        return { tone: 'muted', glyph: '○', label: '无可检查目标', sr: '在你的环境中：没有可检查的目标（未做判定）', live: false };
      }
      return { tone: 'ok', glyph: '◇', label: `未命中 0/${checked}`, sr: `在你的环境中：未命中，已检查 ${checked}`, live: false };
    case 'queued':
    case 'running':
      return { tone: 'info', glyph: '◌', label: `检查中 ·/${checked}`, sr: `在你的环境中：检查中，目标 ${checked} 个`, live: status === 'running' };
    case 'failed':
      return { tone: 'warn', glyph: '⚠', label: '检查失败', sr: '在你的环境中：检查失败', live: false };
    case 'not_eligible':
      return context === 'detail'
        ? { tone: 'muted', glyph: '–', label: '不适用', sr: '在你的环境中：不适用（不触发环境检查）', live: false }
        : null;
  }
}

/**
 * Response → the ImpactSummary it implies. Deliberately the same rule as the publisher's `impact()` in
 * src/radar/respond.py (authority; this copy exists so the detail page can reconcile a stale chip):
 * checked = every target considered (incl. skipped-as-irrelevant), an affected target wins even mid-run,
 * pending targets / queued|running ⇒ running.
 */
export function impactFromResponse(r: Response): ImpactSummary {
  if (r.status === 'not_eligible') return { status: 'not_eligible', affected: 0, checked: 0 };
  const affected = r.targets.filter(t => t.verdict === 'affected').length;
  const status: ImpactSummary['status'] =
    affected > 0 ? 'affected'
      : r.targets.some(t => t.verdict === 'pending') || r.status === 'running' || r.status === 'queued' ? 'running'
        : r.status === 'failed' ? 'failed' : 'not_affected';
  return { status, affected, checked: r.targets.length };
}

export interface ResolvedImpact {
  impact: ImpactSummary | null;
  source: 'response' | 'event' | 'pipeline' | 'none';
  /** Set when the sources disagree; rendered as small print so the override is never silent. */
  note: string | null;
}

/**
 * The one authority for "does it hit us" on the detail page: response > event.impact > pipeline_steps.impact_match.
 * Dirty-data source: the 2026-10-23 live sample has PHP2Shell with impact_match="not_configured" next to a
 * response.status="done" with 1 affected target (backend insights not yet wired to response). Without one
 * authority the page would say 未检查 and 命中 1/2 at the same time.
 */
export function resolveImpact(
  eventImpact: ImpactSummary | null | undefined,
  response: Response | null | undefined,
  steps: PipelineStep[] | undefined,
): ResolvedImpact {
  if (response) {
    const impact = impactFromResponse(response);
    const notes: string[] = [];
    if (eventImpact && (eventImpact.status !== impact.status || eventImpact.affected !== impact.affected || eventImpact.checked !== impact.checked)) {
      notes.push(`列表 chip 显示 ${eventImpact.affected}/${eventImpact.checked}，已以环境检查明细为准`);
    }
    const step = steps?.find(s => s.step === 'impact_match');
    if (step && step.status !== 'done' && step.status !== 'running') notes.push(`系统步骤原值「${step.detail}」已由环境检查覆盖`);
    return { impact, source: 'response', note: notes.length ? notes.join(' · ') : null };
  }
  if (eventImpact) return { impact: eventImpact, source: 'event', note: null };
  const step = steps?.find(s => s.step === 'impact_match');
  if (step?.status === 'failed') return { impact: { status: 'failed', affected: 0, checked: 0 }, source: 'pipeline', note: step.detail };
  if (step?.status === 'running') return { impact: { status: 'running', affected: 0, checked: 0 }, source: 'pipeline', note: step.detail };
  return { impact: null, source: 'none', note: step ? step.detail : null };
}

export interface Bluf {
  tone: Tone;
  text: string;
  /** Qualifier rendered after `text` in its own tone (e.g. "AWS Continuum 验证中" next to a 命中 verdict). */
  tail?: { tone: Tone; text: string };
}

/** Continuum actions still in flight. The done-verdict comes from the radar locator + Security Agent review;
 * while these are open, Continuum has NOT validated the hit yet (2026-10-23 sample: code_finding/code_scan running). */
export function pendingContinuumActions(r: Response): number {
  return r.actions.filter(a => a.service === 'continuum' && (a.status === 'submitted' || a.status === 'running')).length;
}

const continuumTail = (r: Response): Bluf['tail'] => {
  const n = pendingContinuumActions(r);
  return n > 0 ? { tone: 'info', text: `AWS Continuum 验证中（${n} 个动作未完成）` } : undefined;
};

/**
 * One templated sentence for the environment check (no LLM). `undefined` = backend did not emit the key at all
 * (older publisher); `null` = the event did not trigger a check. The two must read differently (BRIEF §3).
 */
export function responseBluf(r: Response | null | undefined): Bluf {
  if (r === undefined) return { tone: 'muted', text: '环境检查未接入（后端版本未产出 response）' };
  if (r === null) return { tone: 'muted', text: '该事件未触发环境检查' };
  switch (r.status) {
    case 'not_eligible':
      return { tone: 'muted', text: `不触发环境检查 · ${r.reason}` };
    case 'failed':
      return { tone: 'warn', text: `⚠ 环境检查失败 · ${r.reason}` };
    case 'queued':
    case 'running': {
      const done = r.actions.filter(a => a.status === 'done').length;
      return { tone: 'info', text: `◌ 检查中 · 已完成 ${done}/${r.actions.length} 个动作 · ${r.reason}` };
    }
    case 'done': {
      const { affected: a, checked: c } = impactFromResponse(r);
      if (a > 0) {
        const t = sortTargets(r.targets).find(x => x.verdict === 'affected')!;
        const loc = t.locations[0];
        const pinned = loc
          ? ` · ${t.name} 有 ${t.locations.length} 处钉在 ${r.product ?? '受影响产品'} ${loc.found_version}（修复版 ${loc.fixed_version ?? '未知'}）`
          : ` · ${t.name}（无代码位置）`;
        const tail = continuumTail(r);
        return { tone: 'loss', text: `◆ 命中 ${a} / ${c} 个目标${pinned} · ${r.patches.length > 0 ? '已生成修复补丁' : '尚无补丁'}`, ...(tail ? { tail } : {}) };
      }
      const skipped = r.targets.filter(t => !t.relevant).length;
      const tail = continuumTail(r);
      return { tone: 'ok', text: `◇ 已检查 ${c - skipped} 个相关目标，均未命中${skipped > 0 ? ` · 另 ${skipped} 个与产品无关已跳过` : ''}`, ...(tail ? { tail } : {}) };
    }
  }
}

const VERDICT_ORDER: Record<ResponseTarget['verdict'], number> = { affected: 0, pending: 1, unknown: 2, not_affected: 3, skipped: 4 };

/** Targets: what hits us first, skipped last (stable for equal verdicts). */
export function sortTargets(ts: ResponseTarget[]): ResponseTarget[] {
  return [...ts].sort((x, y) => VERDICT_ORDER[x.verdict] - VERDICT_ORDER[y.verdict]);
}

const SEV_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, INFORMATIONAL: 4 };

/** Findings: radar-requirement hits first, then severity (unknown values last, shown verbatim), then service. */
export function sortFindings(fs: ResponseFinding[]): ResponseFinding[] {
  const rank = (s: string) => SEV_RANK[s.toUpperCase()] ?? 9;
  return [...fs].sort((x, y) =>
    Number(Boolean(y.requirement_hit)) - Number(Boolean(x.requirement_hit))
    || rank(x.severity) - rank(y.severity)
    || x.service.localeCompare(y.service));
}

/** `[Requirement: …] title` → `title`; the prefix becomes a badge (requirement_hit), the original stays in title=. */
export function stripRequirementPrefix(title: string): string {
  return title.replace(/^\[Requirement:[^\]]*\]\s*/, '');
}

/**
 * Duration of an action in ms, or null when it cannot be stated honestly.
 * Dirty-data source: the live sample's code_finding / code_scan have updated_at 17:20 < started_at 17:26
 * (snapshot assembled from two clocks). Without this the lane would show a negative duration.
 */
export function actionDuration(a: Pick<ResponseAction, 'started_at' | 'updated_at'>): number | null {
  if (!a.started_at || !a.updated_at) return null;
  const s = Date.parse(a.started_at), u = Date.parse(a.updated_at);
  if (Number.isNaN(s) || Number.isNaN(u) || u < s) return null;
  return u - s;
}

/**
 * Same file? Findings use target-relative paths (`Dockerfile`), the locator uses prefixed ones
 * (`demo-shop/Dockerfile`) — dirty-data source: the two services report paths differently.
 */
export function sameFile(a: string | null | undefined, b: string | null | undefined, targetId: string | null | undefined): boolean {
  if (!a || !b) return false;
  const norm = (p: string) => {
    let q = p.replace(/^\.\//, '');
    if (targetId && q.startsWith(`${targetId}/`)) q = q.slice(targetId.length + 1);
    return q;
  };
  return norm(a) === norm(b);
}

export const ACTION_KIND_LABEL: Record<ResponseAction['kind'], string> = {
  requirement: '规则下发', context: '知识文档', code_finding: '提交 finding',
  code_scan: '环境扫描', code_review: '代码评审', remediation: '自动修复',
};

export const SERVICE_LABEL: Record<ResponseAction['service'], string> = {
  security_agent: 'AWS Security Agent', continuum: 'AWS Continuum',
};

/** Two lanes (one per service); within a lane failed first, then chronological by started_at ?? updated_at. */
export function actionLanes(actions: ResponseAction[]): { service: ResponseAction['service']; actions: ResponseAction[] }[] {
  const t = (a: ResponseAction) => Date.parse(a.started_at ?? a.updated_at);
  return (['security_agent', 'continuum'] as const).map(service => ({
    service,
    actions: actions.filter(a => a.service === service)
      .sort((x, y) => Number(y.status === 'failed') - Number(x.status === 'failed') || t(x) - t(y)),
  }));
}

export const PIPELINE_ORDER: PipelineStep['step'][] =
  ['collected', 'clustered', 'verified', 'analyzed', 'impact_match', 'notified', 'remediated'];

export const PIPELINE_LABEL: Record<PipelineStep['step'], string> = {
  collected: '采集', clustered: '聚类', verified: '判定', analyzed: '分析',
  impact_match: '影响匹配', notified: '推送', remediated: '修复',
};

export interface PipelineRow {
  step: PipelineStep['step'];
  label: string;
  /** `missing` = the contract has the step but this payload does not (shown as 未接入, not hidden). */
  status: PipelineStep['status'] | 'missing';
  detail: string;
  /** Present when the row was overridden from `response` (the override is never silent). */
  note: string | null;
}

/** The 7 fixed system-step rows, with impact_match / remediated reconciled against `response`. */
export function pipelineRows(steps: PipelineStep[] | undefined, response: Response | null | undefined): PipelineRow[] {
  const by = new Map((steps ?? []).map(s => [s.step, s]));
  return PIPELINE_ORDER.map(step => {
    const s = by.get(step);
    const base: PipelineRow = s
      ? { step, label: PIPELINE_LABEL[step], status: s.status, detail: s.detail, note: null }
      : { step, label: PIPELINE_LABEL[step], status: 'missing', detail: '未接入', note: null };
    if (!response) return base;
    if (step === 'impact_match') {
      const v = impactView(impactFromResponse(response), 'detail')!;
      const status: PipelineStep['status'] = response.status === 'done' ? 'done'
        : response.status === 'failed' ? 'failed' : response.status === 'not_eligible' ? 'skipped' : 'running';
      // 影响匹配 = the locator verdict; say so when Continuum validation is still open (never a bare 完成)
      const pend = status === 'done' ? pendingContinuumActions(response) : 0;
      const pendNote = pend > 0 ? `定位已完成，AWS Continuum 验证中（${pend} 个动作未完成）` : null;
      if (s && s.status === status) return pendNote ? { ...base, note: pendNote } : base;
      const over = s ? `已由环境检查覆盖（原：${s.detail}）` : '由环境检查推出';
      return { ...base, status, detail: v.label, note: pendNote ? `${over} · ${pendNote}` : over };
    }
    if (step === 'remediated' && response.patches.length > 0 && (!s || s.status !== 'done')) {
      return { ...base, status: 'done', detail: `补丁已生成 ${response.patches.length}`, note: s ? `已由环境检查覆盖（原：${s.detail}）` : '由环境检查推出' };
    }
    return base;
  });
}
