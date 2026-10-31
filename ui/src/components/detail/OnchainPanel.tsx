import type { Onchain } from '@/types/site-data';
import { formatAmount, truncateHash } from '@/utils/formatters';
import { describe, hhmmss, summary, txUrl } from '@/utils/onchainView';
import { safeHref } from '@/utils/safeHref';
import { utcShort } from '@/utils/timeZh';

/** 链上复盘 (M4 D6): minute-level rows read from the chain by radar.onchain — every row has its transaction; what was not
 *  queried is listed under the table, never shown as "nothing happened". */
export function OnchainPanel({ onchain }: { onchain: Onchain | null }) {
  if (!onchain) return null;
  const s = summary(onchain);
  return (
    <div className="oc-panel" style={{ marginTop: 16 }}>
      <h3 className="dt-h3">链上复盘 <span className="dt-count">{onchain.rows.length}</span>
        <span className="dt-muted dt-small" style={{ fontWeight: 400, marginLeft: 8 }}>
          窗口 {utcShort(onchain.window[0])} – {utcShort(onchain.window[1])} UTC · 已查 {onchain.coverage.chains_checked.join(' / ') || '—'}
          {onchain.complete ? ' · 已完成' : ' · 持续跟进中'}
        </span></h3>
      <div className="oc-kpis">
        <div><span className="dt-muted dt-small">受害钱包流出（稳定币）</span>
          <b className="dt-mono">{s.outflow.length ? s.outflow.map(([t, v]) => `${formatAmount(v)} ${t}`).join(' · ') : '—'}</b></div>
        <div><span className="dt-muted dt-small">链上冻结</span>
          <b className="dt-mono">{s.freezes.length ? s.freezes.map(([i, n]) => `${i} ×${n}`).join(' · ') : '—'}</b></div>
        <div><span className="dt-muted dt-small">EIP-7702 委托（当前）</span>
          <b className="dt-mono">{s.checked ? (s.delegated ? `${s.delegated}/${s.checked} 仍被委托` : `0/${s.checked} 已无委托`) : '未查'}</b></div>
      </div>
      {onchain.rows.length > 0 && (
        <div className="oc-scroll" tabIndex={0} role="region" aria-label="链上复盘明细">
          <table className="kd-table oc-table">
            <thead><tr><th scope="col">时间 UTC</th><th scope="col">事件</th><th scope="col">链</th><th scope="col">地址</th>
              <th scope="col">金额</th><th scope="col">交易</th></tr></thead>
            <tbody>
              {onchain.rows.map(r => {
                const d = describe(r);
                const url = txUrl(r.chain, r.tx);
                return (
                  <tr key={r.id} className={`oc-${r.kind}`}>
                    <td className="dt-mono">{hhmmss(r.t)}</td>
                    <td><span className={`chip oc-chip-${r.kind}`}>{d.kind}</span></td>
                    <td className="dt-mono dt-muted">{r.chain}</td>
                    <td className="dt-small">{d.who}</td>
                    <td className="dt-mono">{r.kind === 'outflow' && r.amount != null ? `${formatAmount(r.amount)} ${r.token}` : r.token}</td>
                    <td>{url ? <a href={safeHref(url)} target="_blank" rel="noopener noreferrer" className="dt-mono">{truncateHash(r.tx)} ↗</a>
                      : <code className="dt-mono">{truncateHash(r.tx)}</code>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="dt-small dt-muted" style={{ marginTop: 8 }}>
        未查（公共节点 / 当前范围外）：{onchain.not_queried.join('；')}
      </p>
      {onchain.errors.length > 0 && (
        <p className="dt-small" style={{ color: 'var(--p1)', marginTop: 4 }}>
          ⚠ 最近 {onchain.errors.length} 次查询失败，下一轮重试（例：{onchain.errors[0].query.split('|').slice(0, 2).join(' · ')}）
        </p>
      )}
    </div>
  );
}
