import type { AttackPath, AttackPathSentence } from '@/types/site-data';

type Step = keyof AttackPath['steps'];
type Defense = AttackPath['defenses'][number];

/** R9.5: the four steps of an attack and the plain words for each (requirement 2026-11-18). */
export const STEPS: { key: Step; title: string; hint: string }[] = [
  { key: 'entry', title: '入口', hint: '攻击从哪里进来' },
  { key: 'condition', title: '前提', hint: '什么情况下才成立' },
  { key: 'trigger', title: '触发', hint: '输入在软件里做了什么' },
  { key: 'impact', title: '后果', hint: '攻击者得到什么' },
];
export const HORIZON: Record<Defense['horizon'], { word: string; tone: string }> = {
  block: { word: '立即拦截', tone: 'block' },
  temporary: { word: '临时缓解', tone: 'temp' },
  fix: { word: '长期修复', tone: 'fix' },
};
const SOURCE_WORD: Record<NonNullable<Defense['source']>, string> = { radar: '雷达', aws: 'AWS' };

interface CiteProps { cite: (itemId: string) => number | undefined; onCite: (itemId: string) => void }

function Cites({ ids, cite, onCite }: { ids: string[] } & CiteProps) {
  return <>{ids.map(id => {
    const n = cite(id);
    return n === undefined ? null
      : <button key={id} type="button" className="cite" onClick={() => onCite(id)} aria-label={`查看证据 ${n}`}>[{n}]</button>;
  })}</>;
}

function Line({ s, ...c }: { s: AttackPathSentence } & CiteProps) {
  return (
    <li>{s.text}<Cites ids={s.cite} {...c} />{!s.grounded && <em className="an-issue">未通过校验</em>}</li>
  );
}

/** How the vulnerability is attacked, step by step, with every defence placed under the step it stops. */
export function AttackPathPanel({ path, onEnv, ...c }: { path: AttackPath; onEnv?: () => void } & CiteProps) {
  const byStep = (k: Step) => path.defenses.filter(d => d.stage === k);
  return (
    <div className="ap" data-testid="attack-path">
      <ol className="ap-flow">
        {STEPS.map((st, i) => (
          <li key={st.key} className="ap-col">
            <div className={`ap-step${path.steps[st.key].length ? '' : ' is-empty'}`}>
              <div className="ap-step-h"><span className="ap-n">{i + 1}</span>{st.title}<span className="ap-hint">{st.hint}</span></div>
              {path.steps[st.key].length
                ? <ul className="ap-lines">{path.steps[st.key].map((s, j) => <Line key={j} s={s} {...c} />)}</ul>
                : <p className="ap-none">证据没有说明</p>}
            </div>
            <div className="ap-lane" role="group" aria-label={`在「${st.title}」这一步拦`}>
              {byStep(st.key).map((d, j) => (
                <div key={j} className={`ap-def tone-${HORIZON[d.horizon].tone}`}>
                  <span className="ap-def-tag">{HORIZON[d.horizon].word}{d.source && ` · ${SOURCE_WORD[d.source]}`}</span>
                  <span>{d.text}<Cites ids={d.cite ?? []} {...c} /></span>
                  {d.link === 'env' && onEnv && <button type="button" className="ap-def-go" onClick={onEnv}>看规则包 →</button>}
                </div>
              ))}
            </div>
          </li>
        ))}
      </ol>
      <p className="ap-legend">
        {(['block', 'temporary', 'fix'] as const).map(h => <span key={h} className={`ap-key tone-${HORIZON[h].tone}`}>{HORIZON[h].word}</span>)}
        <span className="dt-muted">每条处置放在它拦住的那一步下面 · 句子由模型按证据写、代码校验引用与数字</span>
      </p>
    </div>
  );
}
