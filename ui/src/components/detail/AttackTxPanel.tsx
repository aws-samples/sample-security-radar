import type { AttackTxs } from '@/types/site-data';
import { truncateHash } from '@/utils/formatters';
import { hhmmss, txUrl } from '@/utils/onchainView';
import { fmtAmount, senderTake, tokenName, who } from '@/utils/attackTxView';
import { safeHref } from '@/utils/safeHref';
import { utcShort } from '@/utils/timeZh';

/** 攻击交易拆解 (M4.1 E3): the ERC-20 transfers of each verified attack transaction (radar.attacktx), per token the
 *  largest net gainer and loser inside that transaction. What a receipt cannot show is stated under the table. */
export function AttackTxPanel({ data }: { data: AttackTxs | null }) {
  if (!data || data.txs.length === 0) return null;
  return (
    <div className="oc-panel" style={{ marginTop: 16 }}>
      <h3 className="dt-h3">攻击交易拆解 <span className="dt-count">{data.txs.length}</span>
        <span className="dt-muted dt-small" style={{ fontWeight: 400, marginLeft: 8 }}>交易回执里的 ERC-20 转账 · 每个代币的最大净流入 / 净流出（交易内）</span></h3>
      {data.txs.map(tx => {
        const url = txUrl(tx.chain, tx.tx);
        const take = senderTake(tx);
        return (
          <div key={tx.tx} className="atx-card">
            <p className="dt-small atx-head">
              <b className="dt-mono">{hhmmss(tx.t)}</b> <span className="dt-muted">UTC · {utcShort(tx.t).slice(0, 5)} · {tx.chain} · 区块 {tx.block}</span>
              <span className={`chip ${tx.status === 'success' ? 'oc-chip-outflow' : ''}`} style={{ marginLeft: 8 }}>{tx.status === 'success' ? '成功' : '已回滚'}</span>
              <span className="dt-muted" style={{ marginLeft: 8 }}>{tx.transfers} 次转账 · {tx.tokens_total} 种代币</span>
              <span style={{ marginLeft: 'auto' }}>{url ? <a href={safeHref(url)} target="_blank" rel="noopener noreferrer" className="dt-mono">{truncateHash(tx.tx)} ↗</a>
                : <code className="dt-mono">{truncateHash(tx.tx)}</code>}</span>
            </p>
            {tx.native && <p className="dt-small atx-take">交易本身转出原生币：<b className="dt-mono">{fmtAmount(tx.native.amount)} {tx.native.symbol}</b>（{truncateHash(tx.sender)} → {truncateHash(tx.target)}）</p>}
            {take.length > 0 && <p className="dt-small atx-take">发起地址 {truncateHash(tx.sender)} 在这笔交易中净得：<b className="dt-mono">{take.join(' · ')}</b></p>}
            {tx.tokens.length > 0 && (
              <div className="oc-scroll" tabIndex={0} role="region" aria-label={`攻击交易 ${truncateHash(tx.tx)} 的代币流向`}>
                <table className="kd-table oc-table">
                  <thead><tr><th scope="col">代币</th><th scope="col">转账</th><th scope="col">最大净流入</th><th scope="col">数量</th>
                    <th scope="col">最大净流出</th><th scope="col">数量</th></tr></thead>
                  <tbody>
                    {tx.tokens.map(t => (
                      <tr key={t.token}>
                        <td className="dt-mono" title={t.token}>{tokenName(t)}</td>
                        <td className="dt-mono dt-muted">{t.transfers}</td>
                        <td className="dt-small" title={t.gainer?.address}>{who(t.gainer)}</td>
                        <td className="dt-mono" title={t.gainer?.raw}>{fmtAmount(t.gainer?.amount)}</td>
                        <td className="dt-small" title={t.loser?.address}>{who(t.loser)}</td>
                        <td className="dt-mono" title={t.loser?.raw}>{fmtAmount(t.loser?.amount)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {tx.tokens_total > tx.tokens.length && <p className="dt-small dt-muted">另有 {tx.tokens_total - tx.tokens.length} 种代币未列出（按转账次数取前 {tx.tokens.length} 种）</p>}
          </div>
        );
      })}
      <p className="dt-small dt-muted" style={{ marginTop: 8 }}>未解码：{data.not_decoded.join('；')}</p>
      {data.errors.length > 0 && (
        <p className="dt-small" style={{ color: 'var(--p1)', marginTop: 4 }}>⚠ 最近 {data.errors.length} 笔交易读取失败，下一轮重试</p>
      )}
    </div>
  );
}
