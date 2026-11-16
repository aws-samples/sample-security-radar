import type { Mitigation, Response } from '@/types/site-data';
import { actionPack, type Cell } from '@/utils/actionPack';
import { safeHref } from '@/utils/safeHref';

const COLS = [['block', '拦截'], ['detect', '检测'], ['verify', '验证'], ['patch', '修补']] as const;

function Td({ c }: { c: Cell }) {
  const href = safeHref(c.href);
  return <td className={`ap-cell tone-${c.tone}`} data-tone={c.tone}>
    {href ? <a href={href} target="_blank" rel="noopener noreferrer">{c.text}</a> : c.text}
  </td>;
}

/**
 * R4.5: the four steps for each code target on one screen — the panels below hold the detail of each cell. No target
 * (an incident, or a vuln no target is relevant to) ⇒ nothing rendered, never an empty table that reads as "all clear".
 */
export function ActionPackPanel({ response, mitigation }: { response: Response | null | undefined; mitigation: Mitigation | null | undefined }) {
  const rows = actionPack(response, mitigation);
  if (!rows.length) return null;
  return (
    <section className="dt-section" id="action-pack" aria-labelledby="dt-h-ap" data-testid="action-pack">
      <h2 className="dt-h2" id="dt-h-ap">动作一览 <span className="dt-en">Block → detect → verify → patch</span></h2>
      <div className="ap-wrap" tabIndex={0} role="region" aria-label="每个代码目标的处置动作">
        <table className="ap-table">
          <thead><tr><th scope="col">代码目标</th>{COLS.map(([k, zh]) => <th key={k} scope="col">{zh}</th>)}</tr></thead>
          <tbody>{rows.map(r => (
            <tr key={r.targetId}><th scope="row" className="dt-mono">{r.name}</th>{COLS.map(([k]) => <Td key={k} c={r[k]} />)}</tr>
          ))}</tbody>
        </table>
      </div>
      <p className="dt-small dt-muted">拦截只在打补丁之前降低风险；修补（升级到修复版本）才是完整的修复。</p>
    </section>
  );
}
