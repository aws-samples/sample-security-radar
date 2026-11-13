import type { ResponseDecision } from '@/types/site-data';
import { OUTCOME, groupDecisions, look, outcomeCounts, rowTime, scopeLabel, type Outcome } from '@/utils/decisions';
import { utcShort } from '@/utils/timeZh';

const ORDER: Outcome[] = ['fire', 'blocked', 'not_fire', 'not_evaluated'];

/**
 * 「响应决策」: every action of the radar.decisions table × its decision for this event — outcome, reason code + text,
 * and when. Absent decisions ⇒ not rendered (older documents).
 */
export function DecisionsPanel({ decisions }: { decisions: ResponseDecision[] | undefined }) {
  const groups = groupDecisions(decisions);
  if (!groups || !decisions) return null;
  const counts = outcomeCounts(decisions);
  const failed = decisions.filter(r => look(r).failed).length;   // a failed call is not counted as a plain 已触发
  const summary = ORDER.filter(o => counts[o]).map(o => `${OUTCOME[o].word} ${counts[o]}`);
  return (
    <section className="dt-section" id="decisions" aria-labelledby="dt-h-dec" data-testid="decisions-panel">
      <h2 className="dt-h2" id="dt-h-dec">响应决策 <span className="dt-en">Response decisions</span>
        <span className="dt-aside">{[...summary, ...(failed ? [`其中执行失败 ${failed}`] : [])].join(' · ')}</span></h2>
      <table className="env-table dec-table">
        <thead><tr><th>动作</th><th>范围</th><th>结果</th><th>原因</th><th>时间（UTC）</th></tr></thead>
        <tbody>
          {groups.flatMap(g => g.rows.map((r, i) => {
            const o = look(r);
            return (
              <tr key={`${r.action}:${r.scope ?? ''}`} className={`dec-row is-${r.outcome}${o.failed ? ' is-failed' : ''}`}
                data-outcome={r.outcome}>
                <td className="nowrap">{i === 0 ? <>{g.label}{g.paid && <span className="dec-paid"> · 付费</span>}</> : ''}</td>
                <td className="nowrap">{scopeLabel(r.scope)}</td>
                <td className={`nowrap tone-${o.tone}`}><span className="dec-glyph" aria-hidden="true">{o.glyph}</span> {o.word}</td>
                <td>{r.reason}{r.gate && <code className="dec-code"> {r.gate}</code>}
                  {o.failed && <span className="dec-error">（失败：{r.error ?? '未知错误'}）</span>}
                  {r.evaluated_by === 'publish' && r.outcome === 'not_evaluated' && <span className="dt-muted">（发布时判定）</span>}</td>
                <td className="nowrap">{utcShort(rowTime(r))}</td>
              </tr>
            );
          }))}
        </tbody>
      </table>
    </section>
  );
}
