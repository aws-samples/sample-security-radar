import type { Analysis, Sentence } from '@/types/site-data';
import { NoData } from '@/components/NoData';

export const ISSUE_WORD: Record<Sentence['issues'][number], string> = {
  no_citation: '无引用', unknown_citation: '引用不存在', ungrounded_number: '数字未核实',
};

interface CiteProps {
  cite: (itemId: string) => number | undefined;
  onCite: (itemId: string) => void;
}

/** One analysis sentence + its [n] citation buttons (each jumps to and focuses the evidence item). */
export function SentenceText({ s, cite, onCite }: { s: Sentence } & CiteProps) {
  return (
    <span>
      {s.text}
      {s.cite.map(id => {
        const n = cite(id);
        return n === undefined
          ? <span key={id} className="an-issue" title={id}>[引用不存在]</span>
          : <button key={id} type="button" className="cite" onClick={() => onCite(id)} aria-label={`查看证据 ${n}`}>[{n}]</button>;
      })}
      {!s.grounded && <em className="an-issue">未通过校验：{s.issues.map(i => ISSUE_WORD[i] ?? i).join('、') || '原因未给出'}</em>}
    </span>
  );
}

const BLOCKS: { key: keyof Pick<Analysis, 'what' | 'impact' | 'exploitation' | 'actions' | 'unknowns'>; title: string }[] = [
  { key: 'what', title: '是什么' },
  { key: 'impact', title: '影响面' },
  { key: 'exploitation', title: '利用状态' },
  { key: 'actions', title: '处置建议' },
  { key: 'unknowns', title: '未知项' },
];

export function AnalysisCard({ analysis, cite, onCite }: { analysis: Analysis | null | undefined } & CiteProps) {
  if (!analysis) return <NoData>{analysis === undefined ? '分析未接入（后端未产出 analysis）' : '本事件没有分析卡（未生成或低于 P1）'}</NoData>;
  if (analysis.status === 'failed') return <NoData>分析生成失败（{analysis.reason ?? '未给原因'}）</NoData>;
  return (
    <>
      <div className="an-grid">
        {BLOCKS.map(b => (
          <div className="an-block" key={b.key}>
            <h3>{b.title}</h3>
            {analysis[b.key].length === 0
              ? <NoData>无</NoData>
              : (
                <ul>
                  {analysis[b.key].map((s, i) => (
                    <li key={i} className={s.grounded ? '' : 'is-ungrounded'}><SentenceText s={s} cite={cite} onCite={onCite} /></li>
                  ))}
                </ul>
              )}
          </div>
        ))}
      </div>
      <p className="dt-small dt-muted" style={{ marginTop: 10 }}>
        {analysis.model} · 生成于 {analysis.generated_at.replace('T', ' ').replace('Z', ' UTC')} · 每句均需引用可核对的证据；灰字 = 未通过代码校验
      </p>
    </>
  );
}
