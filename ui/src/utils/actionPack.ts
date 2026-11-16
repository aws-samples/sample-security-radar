/**
 * R4.5 action pack: per code target, one row of 拦截 → 检测 → 验证 → 修补 (block → detect → verify → patch).
 * A pure join over what the event page already loads (response, mitigation) — no new data, no second source of truth:
 * every cell's state is read from the ledger the panels below it show in full.
 *   block   the mitigate station's WAF plans for the target (MitigationPlan.state)
 *   detect  Security Agent / Continuum findings and Inspector dependency hits on the target
 *   verify  the code-impact verdict (ResponseTarget.verdict)
 *   patch   a patch PR (pr_url), else a generated patch, else nothing — not needed when the target is not affected
 */
import type { Mitigation, MitigationPlan, Response } from '@/types/site-data';

/** The page's tone classes (styles/detail.css .tone-*): ok = in place / safe · warn = waits for a human · loss = affected ·
 *  muted = nothing yet, or not needed */
export type Tone = 'ok' | 'warn' | 'loss' | 'muted';
export interface Cell { tone: Tone; text: string; href?: string }
export interface PackRow { targetId: string; name: string; block: Cell; detect: Cell; verify: Cell; patch: Cell }

const COUNTING: MitigationPlan['state'][] = ['staged', 'group_counted', 'rules_counted'];

function block(plans: MitigationPlan[]): Cell {
  const on = plans.find(p => p.state === 'blocking');
  if (on) return { tone: 'ok', text: `WAF 拦截中 · ${on.group_label}` };
  const counting = plans.find(p => COUNTING.includes(p.state));
  if (counting) return { tone: 'warn', text: `WAF 观察中（Count）· ${counting.group_label} · 需人确认后拦截` };
  if (plans.length) return { tone: 'muted', text: plans[0].detail || '已规划，未部署' };
  return { tone: 'muted', text: '无适用的 WAF 规则' };
}

const VERDICT: Record<string, Cell> = {
  affected: { tone: 'loss', text: '受影响' },
  not_affected: { tone: 'ok', text: '未受影响' },
  pending: { tone: 'muted', text: '核查中' },
  unknown: { tone: 'warn', text: '无法判定' },
};

export function actionPack(response: Response | null | undefined, mitigation: Mitigation | null | undefined): PackRow[] {
  const targets = (response?.targets ?? []).filter(t => t.relevant);
  // a target only the mitigate station planned for (no response yet) still gets its row
  const ids = [...new Set([...targets.map(t => t.target_id), ...(mitigation?.plans ?? []).map(p => p.target_id)])];
  return ids.map(id => {
    const t = targets.find(x => x.target_id === id);
    const plans = (mitigation?.plans ?? []).filter(p => p.target_id === id);
    const found = (response?.findings ?? []).filter(f => f.target_id === id).length;
    const insp = (mitigation?.inspector ?? []).filter(f => f.target_id === id).length;
    const detect: Cell = found + insp
      ? { tone: 'warn', text: [found && `${found} 条代码发现`, insp && `${insp} 个依赖命中（Inspector）`].filter(Boolean).join(' · ') }
      : { tone: 'muted', text: '无发现' };
    const verify = t ? (VERDICT[t.verdict] ?? { tone: 'muted', text: t.verdict }) : { tone: 'muted' as Tone, text: '未核查' };
    const patches = (response?.patches ?? []).filter(p => p.target_id === id);
    const pr = patches.find(p => p.pr_url)?.pr_url;
    const patch: Cell = pr ? { tone: 'warn', text: '补丁 PR 待人审核合并', href: pr }
      : patches.length ? { tone: 'warn', text: `已生成 ${patches.length} 个补丁，待提 PR` }
      : t?.verdict === 'not_affected' ? { tone: 'muted', text: '不需要' }
      : { tone: 'muted', text: '无补丁' };
    return { targetId: id, name: t?.name ?? id, block: block(plans), detect, verify, patch };
  });
}
