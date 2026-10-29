/**
 * Event-detail evidence + progress helpers (pure; tested in src/test/evidence.test.ts).
 */
import type { ItemRef, ProgressStage } from '@/types/site-data';

export interface EvidenceGroup {
  group: number;
  /** Earliest item of the independent group — shown in full. */
  lead: ItemRef;
  /** Later items from the same origin (echoes / reposts) — folded behind "+N 转载". */
  echoes: ItemRef[];
}

const ts = (i: ItemRef) => Date.parse(i.published_at);

/**
 * Group by independent_group; each group led by its earliest item, groups ordered by their lead's time
 * (the reading order is "who said it first"). Ties keep input order.
 */
export function groupEvidence(items: ItemRef[]): EvidenceGroup[] {
  const by = new Map<number, ItemRef[]>();
  for (const it of items) {
    const g = by.get(it.independent_group);
    if (g) g.push(it); else by.set(it.independent_group, [it]);
  }
  return [...by.entries()]
    .map(([group, list]) => {
      const sorted = [...list].sort((a, b) => ts(a) - ts(b));
      return { group, lead: sorted[0], echoes: sorted.slice(1) };
    })
    .sort((a, b) => ts(a.lead) - ts(b.lead));
}

/**
 * Citation number per item: independent-source leads first (1..G, the numbers a reader sees with echoes folded),
 * then echoes (G+1..N) in group order. Numbering echoes inline would leave visible gaps ([2] → [13]).
 */
export function citationNumbers(groups: EvidenceGroup[]): Map<string, number> {
  const m = new Map<string, number>();
  let n = 1;
  for (const g of groups) m.set(g.lead.item_id, n++);
  for (const g of groups) for (const it of g.echoes) m.set(it.item_id, n++);
  return m;
}

export const STAGE_ORDER: ProgressStage['stage'][] =
  ['first_report', 'second_source', 'corroborated', 'confirmed', 'exploited', 'analyzed', 'finalized'];

export const STAGE_LABEL: Record<ProgressStage['stage'], string> = {
  first_report: '首报', second_source: '第二独立来源', corroborated: '证实 V2', confirmed: '官方确认 V3',
  exploited: '在野利用', analyzed: '分析完成', finalized: '定稿 V4',
};

/**
 * The 7 stages in fixed order (NOT sorted by time: a T1 first report is corroborated at the same instant,
 * before the second source — the stepper shows the process, times are labels). Missing stage ⇒ at=null.
 */
export function progressRows(progress: ProgressStage[]): { stage: ProgressStage['stage']; label: string; at: string | null }[] {
  const by = new Map(progress.map(p => [p.stage, p.at]));
  return STAGE_ORDER.map(stage => ({ stage, label: STAGE_LABEL[stage], at: by.get(stage) ?? null }));
}

/**
 * Time-to-corroborate = progress.corroborated.at − progress.first_report.at (UI-IA §2 timing rule).
 * NOT last_updated − first_seen (the old "Time to confirm" was that, which is wrong). null = cannot say.
 */
export function corroborationMs(progress: ProgressStage[] | undefined): number | null {
  if (!progress) return null;
  const at = (s: ProgressStage['stage']) => progress.find(p => p.stage === s)?.at ?? null;
  const a = at('first_report'), b = at('corroborated');
  if (!a || !b) return null;
  const d = Date.parse(b) - Date.parse(a);
  return Number.isNaN(d) ? null : Math.max(0, d);
}
