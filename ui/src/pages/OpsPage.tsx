import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { AttentionItem } from '@/types/site-data';
import { formatDateTime } from '@/utils/formatters';

interface OpsDoc { kind: 'ops'; generated_at: string; attention: AttentionItem[]; counts: { error: number; warn: number; info: number } }
const LEVEL_WORD: Record<AttentionItem['level'], { label: string; cls: string }> = {
  error: { label: '出错', cls: 'is-error' }, warn: { label: '降级 / 需决定', cls: 'is-warn' }, info: { label: '等人', cls: 'is-info' },
};

/** D/M3 ops view: "what needs a human" — every row comes from a rule in radar/ops.py (RULES), errors first.
 *  Absent ops.json (older backend) ⇒ said so, never an empty "all good". */
export function OpsPage() {
  const [doc, setDoc] = useState<OpsDoc | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    fetch('./data/ops.json')
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then((d: OpsDoc) => { if (d.kind !== 'ops') throw new Error('unexpected data kind'); setDoc(d); })
      .catch((e: unknown) => setError(String(e)));
  }, []);
  return (
    <div className="ops-page" data-page="ops">
      <h1 className="ops-h1">需要人处理的事 <span className="ops-en">OPS</span></h1>
      {error && <p className="ops-error">运维数据不可用（{error}）—— 这不代表一切正常</p>}
      {doc && (
        <>
          <p className="ops-sub tabular">
            出错 {doc.counts.error} · 降级 / 需决定 {doc.counts.warn} · 等人 {doc.counts.info} · 生成于 {formatDateTime(doc.generated_at)}
          </p>
          {doc.attention.length === 0
            ? <p className="ops-ok">没有需要人处理的事（所有规则都没有触发）。</p>
            : (
              <ul className="ops-list">
                {doc.attention.map((it, i) => (
                  <li key={`${it.code}-${i}`} className={`ops-row ${LEVEL_WORD[it.level].cls}`}>
                    <span className="ops-lv">{LEVEL_WORD[it.level].label}</span>
                    <span className="ops-title">{it.link ? <Link to={it.link}>{it.title}</Link> : it.title}</span>
                    {it.detail && <span className="ops-detail">{it.detail}</span>}
                    <code className="ops-code">{it.code}{it.since ? ` · ${formatDateTime(it.since)}` : ''}</code>
                  </li>
                ))}
              </ul>
            )}
        </>
      )}
    </div>
  );
}
