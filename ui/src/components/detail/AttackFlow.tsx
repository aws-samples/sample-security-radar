import { Children } from 'react';
import type { ChainStage, EventSummary, ItemRef } from '@/types/site-data';
import { EFFECT_ZH } from '@/generated/stages';
import { attackFlow, missingPhases, showFlow, stageDef, type PhaseStep } from '@/utils/attackFlow';
import { utcShort } from '@/utils/timeZh';

const CONF: Record<'stated' | 'suspected', string> = {
  stated: '已有 T1/T2 来源明确点名',
  suspected: '仅快讯 / 社区提及，待确认',
};

const CHAIN_ANCHOR = 'af-chain';

/** The clocks of a step: when the chain shows it happened, when the first report said so — and, apart, when the radar
 *  checked a state whose start it did not query (an EIP-7702 delegation): that is a check time, not an event time. */
function meta(s: PhaseStep): string {
  const parts = [];
  if (s.chainAt) parts.push(`链上 ${utcShort(s.chainAt)} · ${s.chain} 笔`);
  if (s.reportAt) parts.push(`${s.chainAt ? '报道 ' : ''}${utcShort(s.reportAt)} · ${s.count} 条`);
  if (s.checkedAt) parts.push(`${CHECKED} ${utcShort(s.checkedAt)} · ${s.checked} 个钱包（发生时间未查询）`);
  return parts.join(' / ');
}

const CHECKED = '核查时仍委托';

const when = (s: PhaseStep) => s.firstAt ? `最早 ${utcShort(s.firstAt)} UTC` : `发生时间未知，${CHECKED}于 ${utcShort(s.checkedAt!)} UTC`;

/** "攻击过程" — the incident as a story (recon → initial access … → asset transfer → laundering → freeze → disclosure …),
 *  each step anchored on its earliest report (click ⇒ jump to that evidence) or, when only the chain evidences it, on
 *  the on-chain tables. Stages come from radar.stages (code, not a model): report titles and confirmed chain rows. */
export function AttackFlow({ event, items, chain, onCite, children, step = '02' }: {
  step?: string;
  event: EventSummary; items: ItemRef[]; chain?: ChainStage[] | null; onCite: (itemId: string) => void; children?: React.ReactNode;
}) {
  const steps = attackFlow(items, chain ?? []);
  const attr = event.attribution;
  const web3 = event.domain === 'web3';
  const shown = showFlow(steps, web3);
  // children arrive as [null, null] when the page has neither panel (an array is truthy): count real ones — an empty
  // 「攻击过程」 section rendered, numbered like the section above it (seen with R9.5's attack path, 2026-11-19)
  if (!shown && !attr && Children.toArray(children).length === 0) return null;
  const missing = web3 && shown ? missingPhases(steps) : [];
  return (
    <section className="dt-section" aria-labelledby="dt-h-flow">
      <h2 className="dt-h2" id="dt-h-flow"><span className="dt-step">{step}</span>攻击过程 <span className="dt-en">Attack flow</span>
        <span className="dt-aside">按报道标题与链上记录归阶段（代码规则）· 点击跳到该阶段的第一条证据</span></h2>
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
            <li key={s.phase} className={`af-step af-seg-${s.segment} af-${s.phase}`}>
              <button type="button" className="af-btn"
                onClick={() => s.firstItemId ? onCite(s.firstItemId) : document.getElementById(CHAIN_ANCHOR)?.scrollIntoView({ block: 'start' })}
                aria-label={`${s.label}：${s.count} 条报道${s.chain ? `，链上 ${s.chain} 笔` : ''}${s.checked ? `，${CHECKED} ${s.checked} 个钱包` : ''}，${when(s)}，${s.firstItemId ? '跳到第一条证据' : '跳到链上记录'}`}>
                <span className="af-n dt-mono">{String(i + 1).padStart(2, '0')}</span>
                <span className="af-label">{s.label}</span>
                <span className="af-meta dt-mono">{meta(s)}</span>
              </button>
            </li>
          ))}
        </ol>
      )}
      {missing.length > 0 && <p className="dt-small dt-muted af-missing">尚无证据的阶段：{missing.join(' · ')}</p>}
      {shown && <Controls steps={steps} />}
      {children && <div id={CHAIN_ANCHOR}>{children}</div>}
    </section>
  );
}

/** The AWS controls that would have blocked / detected / bounded each evidenced stage (radar.stages, data). */
function Controls({ steps }: { steps: PhaseStep[] }) {
  const rows = steps.map(s => ({ s, def: stageDef(s.phase) })).filter(r => r.def.controls.length > 0);
  if (!rows.length) return null;
  return (
    <details className="af-controls dt-small">
      <summary>本可阻断 / 检测这些阶段的 AWS 控制（{rows.length} 个阶段）</summary>
      <dl>
        {rows.map(({ s, def }) => (
          <div key={s.phase} className="af-ctl">
            <dt>{s.label}</dt>
            <dd>{def.controls.map(c => <span key={c.service} className="af-ctl-item"><b>{c.service}</b> · {EFFECT_ZH[c.effect]}：{c.how}</span>)}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
