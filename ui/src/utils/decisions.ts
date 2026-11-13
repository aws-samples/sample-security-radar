/**
 * 「响应决策」 view logic. The rows come from radar.decisions (one table, src/radar/decisions.py): the page never
 * re-decides an outcome, it only renders it. Four outcomes, four looks — `not_evaluated` (nobody checked) must never
 * read like `not_fire` (checked, condition not met / already done): degradation-and-guards §1.
 */
import type { ResponseDecision } from '@/types/site-data';

export type Outcome = ResponseDecision['outcome'];

export const OUTCOME: Record<Outcome, { glyph: string; word: string; tone: string }> = {
  fire: { glyph: '●', word: '已触发', tone: 'ok' },
  not_fire: { glyph: '–', word: '未触发', tone: 'muted' },
  blocked: { glyph: '⏸', word: '被预算闸挡住', tone: 'warn' },
  not_evaluated: { glyph: '○', word: '未评估', tone: 'unevaluated' },
};

export interface Look { glyph: string; word: string; tone: string; failed: boolean }

/**
 * The look of one row: its outcome, and for a `fire` row the result of the call it issued. A fire whose call failed
 * (Continuum down, a submit / scan / review error, a notify channel error) must never read 已触发 in the ok tone; a
 * fire whose result was never recorded is not a success either (degradation-and-guards §1).
 */
export function look(r: ResponseDecision): Look {
  const o = OUTCOME[r.outcome];
  if (r.outcome !== 'fire') return { ...o, failed: false };
  if (r.result === 'error') return { glyph: '✕', word: '已触发 · 执行失败', tone: 'loss', failed: true };
  if (r.result !== 'ok') return { glyph: '●', word: '已触发 · 结果未记录', tone: 'warn', failed: false };
  return { ...o, failed: false };
}

/** The time a row shows: a failed call shows its latest attempt, everything else when the decision first held. */
export function rowTime(r: ResponseDecision): string | null | undefined {
  return r.result === 'error' && r.result_at ? r.result_at : r.at;
}

export const SCOPE_LABEL: Record<string, string> = { s3: 'S3 环境', github: 'GitHub 环境', gitlab: 'GitLab 环境' };

export interface DecisionGroup {
  action: ResponseDecision['action'];
  label: string;
  paid: boolean;
  rows: ResponseDecision[];
}

/**
 * Rows grouped by action, in the order publish emitted them (= the table's order); scoped rows of one action stay
 * together. Undefined (a document published before decisions existed) ⇒ null: the block is not rendered at all,
 * rather than shown empty as if nothing had been decided.
 */
export function groupDecisions(rows: ResponseDecision[] | undefined): DecisionGroup[] | null {
  if (!rows) return null;
  const out: DecisionGroup[] = [];
  for (const r of rows) {
    const g = out.find(x => x.action === r.action);
    if (g) g.rows.push(r);
    else out.push({ action: r.action, label: r.label, paid: r.paid, rows: [r] });
  }
  return out;
}

/** Counts per outcome, for the block's one-line summary. */
export function outcomeCounts(rows: ResponseDecision[]): Record<Outcome, number> {
  const c: Record<Outcome, number> = { fire: 0, not_fire: 0, blocked: 0, not_evaluated: 0 };
  for (const r of rows) c[r.outcome] += 1;
  return c;
}

export function scopeLabel(scope: string | null): string {
  if (scope === null) return '本事件';
  return SCOPE_LABEL[scope] ?? scope;
}
