import type { EventSummary, ItemRef } from '@/types/site-data';
import { attackFlow, missingPhases, showFlow } from '@/utils/attackFlow';
import { utcShort } from '@/utils/timeZh';

const CONF: Record<'stated' | 'suspected', string> = {
  stated: '已有 T1/T2 来源明确点名',
  suspected: '仅快讯 / 社区提及，待确认',
};

/** "攻击过程" — the incident as a story (prep → drain → laundering → freeze → statement → attribution …), each step
 *  anchored on its earliest report (click ⇒ jump to that evidence). Phases come from signals.phase (code, not a model). */
export function AttackFlow({ event, items, onCite, children, step = '02' }: {
  step?: string;
  event: EventSummary; items: ItemRef[]; onCite: (itemId: string) => void; children?: React.ReactNode;
}) {
  const steps = attackFlow(items);
  const attr = event.attribution;
  const web3 = event.domain === 'web3';
  const shown = showFlow(steps, web3);
  if (!shown && !attr && !children) return null;
  const missing = web3 && shown ? missingPhases(steps) : [];
  return (
    <section className="dt-section" aria-labelledby="dt-h-flow">
      <h2 className="dt-h2" id="dt-h-flow"><span className="dt-step">{step}</span>攻击过程 <span className="dt-en">Attack flow</span>
        <span className="dt-aside">按报道标题归阶段（代码规则）· 点击跳到该阶段的第一条证据</span></h2>
      {attr && (
        <p className="dt-small" style={{ margin: '0 0 10px' }}>
          归因 <b>{attr.actor}</b>
          <span className={`chip tone-${attr.confidence === 'stated' ? 'warn' : 'muted'}`} style={{ marginLeft: 8, color: 'var(--tone)' }}>
            {attr.confidence === 'stated' ? '已点名' : '疑似'}
          </span>
          <span className="dt-muted" style={{ marginLeft: 8 }}>{CONF[attr.confidence]} · {attr.sources} 个来源 · 首次 {utcShort(attr.first_at)} UTC</span>
        </p>
      )}
      {shown && (
        <ol className="af-steps" aria-label={`攻击过程：${steps.length} 个阶段`}>
          {steps.map((s, i) => (
            <li key={s.phase} className={`af-step af-${s.phase}`}>
              <button type="button" className="af-btn" onClick={() => onCite(s.firstItemId)}
                aria-label={`${s.label}：${s.count} 条报道，最早 ${utcShort(s.firstAt)} UTC，跳到第一条证据`}>
                <span className="af-n dt-mono">{String(i + 1).padStart(2, '0')}</span>
                <span className="af-label">{s.label}</span>
                <span className="af-meta dt-mono">{utcShort(s.firstAt)} · {s.count} 条</span>
              </button>
            </li>
          ))}
        </ol>
      )}
      {missing.length > 0 && <p className="dt-small dt-muted af-missing">尚无报道的阶段：{missing.join(' · ')}</p>}
      {children}
    </section>
  );
}
