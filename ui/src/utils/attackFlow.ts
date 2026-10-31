import type { ItemRef } from '@/types/site-data';

export type Phase = NonNullable<ItemRef['phase']>;

/** Attack order (signals.PHASES minus "other"); the detail page draws the flow left → right in this order. */
export const PHASE_ORDER: Phase[] = ['prep', 'drain', 'laundering', 'freeze', 'statement', 'attribution', 'recovery', 'impact'];

export const PHASE_LABEL: Record<Phase, string> = {
  prep: '准备', drain: '转出', laundering: '洗钱', freeze: '冻结', statement: '官方回应',
  attribution: '归因', recovery: '追回', impact: '外溢影响', other: '其他',
};

export interface PhaseStep { phase: Phase; label: string; count: number; firstAt: string; firstItemId: string }

/** One step per phase that has at least one report, in attack order; the first report of a phase is its anchor. */
export function attackFlow(items: ItemRef[]): PhaseStep[] {
  const by = new Map<Phase, ItemRef[]>();
  for (const it of items) {
    const p = it.phase ?? 'other';
    if (p === 'other') continue;
    by.set(p, [...(by.get(p) ?? []), it]);
  }
  // evidence_at is the backend's timeline position (a date-only database entry is never before the first report);
  // published_at only for documents published before it existed
  const at = (it: ItemRef) => it.evidence_at ?? it.published_at;
  return PHASE_ORDER.filter(p => by.has(p)).map(p => {
    const its = [...by.get(p)!].sort((a, b) => at(a).localeCompare(at(b)));
    return { phase: p, label: PHASE_LABEL[p], count: its.length, firstAt: at(its[0]), firstItemId: its[0].item_id };
  });
}

/** Worth drawing when the story has two phases (a one-line advisory has no flow); a web3 incident from its first. */
export const showFlow = (steps: PhaseStep[], web3 = false) => steps.length >= (web3 ? 1 : 2);

/** The core phases of an incident story (prep and impact are optional) not reported yet — shown, not hidden, so a
 *  database-only incident reads in the same format as a fully reported one. */
const CORE: Phase[] = ['drain', 'laundering', 'freeze', 'statement', 'attribution', 'recovery'];
export const missingPhases = (steps: PhaseStep[]) => CORE.filter(p => !steps.some(s => s.phase === p)).map(p => PHASE_LABEL[p]);
