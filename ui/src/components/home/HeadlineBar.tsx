import { Link } from 'react-router-dom';
import type { CorroborationView, FunnelAction, FunnelView } from '@/utils/home';
import { NoData } from '@/components/NoData';
import { formatAmount } from '@/utils/formatters';

interface Props {
  headline: string | null;
  funnel: FunnelView | null;
  /** Which funnel filter is currently applied to the monitor (pressed state). */
  activeAction: FunnelAction;
  onFunnel: (a: FunnelAction) => void;
  web3Loss: { usd: number; count: number };
  corroboration: CorroborationView;
}

/** L0 "现在怎么样": one code-templated sentence, then the 24 h funnel that produced it. */
export function HeadlineBar({ headline, funnel, activeAction, onFunnel, web3Loss, corroboration }: Props) {
  return (
    <section className="hl" aria-labelledby="hl-h1">
      <div className="hl-kicker"><span className="hl-step">L0</span> 现在怎么样 <span className="hl-en">SITUATION</span></div>
      {headline
        ? <h1 id="hl-h1" className="hl-h1" title={headline}>{headline}</h1>
        : <h1 id="hl-h1" className="hl-h1 is-absent">态势句未生成（后端未产出 headline）</h1>}

      <div className="hl-row">
        {funnel === null ? (
          <NoData>漏斗未生成（后端未产出 funnel）</NoData>
        ) : (
          <ol className="funnel" aria-label={`近 ${funnel.windowHours} 小时处理漏斗`}>
            {funnel.segments.map((s, i) => {
              const inner = (
                <>
                  <span className="fn-val tabular">{s.value.toLocaleString('en-US')}</span>
                  <span className="fn-lbl">{s.label}</span>
                  <span className="fn-bar" aria-hidden="true"><i style={{ width: `${Math.max(s.frac * 100, s.value > 0 ? 4 : 0)}%` }} /></span>
                </>
              );
              return (
                <li key={s.key} className={`fn-seg fn-${s.key}`}>
                  {i > 0 && <span className="fn-arrow" aria-hidden="true">→</span>}
                  {s.action ? (
                    <button type="button" className="fn-btn" aria-pressed={activeAction === s.action}
                      onClick={() => onFunnel(activeAction === s.action ? null : s.action)}
                      title={`在下方监控列表中筛选：${s.label}`}>
                      {inner}
                    </button>
                  ) : <span className="fn-static">{inner}</span>}
                </li>
              );
            })}
            <li className="fn-win" aria-hidden="true">{funnel.windowHours}h</li>
          </ol>
        )}
        <div className="hl-side" aria-label="P0/P1 已佐证率"
          title="P0/P1 中级别 ≥ V2 的比例：权威来源（KEV / PSIRT）、≥ 2 个独立来源，或攻击交易已在链上证实">
          <span className="hl-side-val tabular">{corroboration.pct === null ? '—' : `${corroboration.pct}%`}</span>
          <span className="hl-side-lbl">P0/P1 已佐证 · 单源待佐证 {corroboration.single}</span>
        </div>
        <div className="hl-side" aria-label="Web3 近 24 小时损失">
          <span className="hl-side-val tabular">{web3Loss.count ? formatAmount(web3Loss.usd) : '$0'}</span>
          <span className="hl-side-lbl">Web3 24h 损失 · {web3Loss.count} 起</span>
        </div>
      </div>
      {funnel?.blind && (
        <p className="hl-blind">采集为 0 · 漏斗是“看不见”而不是“很安静” · <Link to="/sources">检查源健康 →</Link></p>
      )}
    </section>
  );
}
