import type { ChainStage, ItemRef } from '@/types/site-data';
import { STAGES, STAGE_ALIASES, type StageDef, type StageId } from '@/generated/stages';

export type Phase = StageId;

const BY_ID = new Map<string, StageDef>(STAGES.map(s => [s.id, s]));

/** The stage of a published value: a legacy M4 value (drain, statement) maps on read, an unknown one is "other". */
export function canonicalStage(p: string | null | undefined): StageId {
  const v = (p && STAGE_ALIASES[p]) ?? p ?? 'other';
  return BY_ID.has(v) ? (v as StageId) : 'other';
}

export const stageLabel = (p: string | null | undefined) => BY_ID.get(canonicalStage(p))!.zh;
export const stageDef = (p: StageId) => BY_ID.get(p)!;

export interface PhaseStep {
  phase: Phase; label: string; segment: StageDef['segment'];
  /** reports of this stage and their earliest evidence time / item (null when only the chain evidences it) */
  count: number; reportAt: string | null; firstItemId: string | null;
  /** rows the chain itself confirms with their own block time (clock "chain") and the earliest of them */
  chain: number; chainAt: string | null;
  /** wallets the radar found in this state when it checked (clock "checked": an EIP-7702 delegation) and that check
   *  time — after the fact, never when it happened, so it is neither chainAt nor firstAt */
  checked: number; checkedAt: string | null;
  /** earliest of the event clocks (report, chain) — null when only a check evidences the stage */
  firstAt: string | null;
}

/** One step per stage that a report or a chain row evidences, in attack order; a report's first item is its anchor. */
export function attackFlow(items: ItemRef[], chain: ChainStage[] = []): PhaseStep[] {
  const by = new Map<Phase, ItemRef[]>();
  for (const it of items) {
    const p = canonicalStage(it.phase);
    if (!stageDef(p).inFlow) continue;
    by.set(p, [...(by.get(p) ?? []), it]);
  }
  const onChain = new Map<Phase, ChainStage[]>();
  for (const c of chain) {
    const p = canonicalStage(c.stage);
    if (stageDef(p).inFlow) onChain.set(p, [...(onChain.get(p) ?? []), c]);
  }
  // evidence_at is the backend's timeline position (a date-only database entry is never before the first report);
  // published_at only for documents published before it existed
  const at = (it: ItemRef) => it.evidence_at ?? it.published_at;
  return STAGES.filter(s => by.has(s.id) || onChain.has(s.id)).map(s => {
    const its = [...(by.get(s.id) ?? [])].sort((a, b) => at(a).localeCompare(at(b)));
    const all = onChain.get(s.id) ?? [];
    const cs = all.filter(c => c.clock === 'chain');
    const ck = all.filter(c => c.clock === 'checked');
    const reportAt = its.length ? at(its[0]) : null;
    const chainAt = cs.length ? cs.map(c => c.first_at).sort()[0] : null;
    const checkedAt = ck.length ? ck.map(c => c.first_at).sort()[0] : null;
    const firstAt = [reportAt, chainAt].filter((x): x is string => x !== null).sort()[0] ?? null;
    return { phase: s.id, label: s.zh, segment: s.segment, count: its.length, reportAt, firstItemId: its[0]?.item_id ?? null,
      chain: cs.reduce((n, c) => n + c.count, 0), chainAt,
      checked: ck.reduce((n, c) => n + c.count, 0), checkedAt, firstAt };
  });
}

/** Worth drawing when the story has two stages (a one-line advisory has no flow); a web3 incident from its first. */
export const showFlow = (steps: PhaseStep[], web3 = false) => steps.length >= (web3 ? 1 : 2);

/** The stages the domain's story is expected to have (StageDef.expected) that no report and no chain row evidences yet —
 *  shown, not hidden, so a database-only incident reads in the same format as a fully reported one. */
export const missingPhases = (steps: PhaseStep[], domain = 'web3') =>
  STAGES.filter(s => s.expected.includes(domain) && !steps.some(st => st.phase === s.id)).map(s => s.zh);
