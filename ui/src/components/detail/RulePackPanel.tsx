import { useState } from 'react';
import type { RulePack, RulePackRendering, RulePackRule } from '@/types/site-data';
import { CopyButton } from '@/components/CopyButton';
import { CAPACITY_STATE, CONFIDENCE, OFFLINE_STATE, POC_STATE, capacityText, downloadText, quoteView, ruleCount } from '@/utils/rulePack';
import { safeHref } from '@/utils/safeHref';
import { utcShort } from '@/utils/timeZh';

function DownloadButton({ r }: { r: RulePackRendering }) {
  const [st, setSt] = useState<'idle' | 'ok' | 'fail'>('idle');
  return (
    <button type="button" className="btn-ghost btn-tiny" aria-label={`下载${r.label}（${r.filename}）`}
      onClick={() => setSt(downloadText(r.filename, r.media_type, r.text) ? 'ok' : 'fail')}>
      {st === 'fail' ? '下载失败' : `下载 ${r.filename}`}
    </button>
  );
}

function RuleRow({ r }: { r: RulePackRule }) {
  const off = OFFLINE_STATE[r.verified.offline.state];
  const conf = CONFIDENCE[r.confidence];
  return (
    <li className={`mt-plan tone-${off.tone}`} data-rule={r.rule_id} data-offline={r.verified.offline.state}>
      <div className="mt-plan-head">
        <span className="mt-target dt-mono">{r.rule_id}</span>
        <span className={`mt-tier${r.confidence === 'heuristic' ? ' is-advisory' : ''}`} title={conf.hint}>{conf.label}</span>
        <span className="mt-state" title={off.hint}>{off.label}</span>
        <span className="dt-small dt-muted">Count</span>
      </div>
      <dl className="mt-kv">
        <dt>计数什么</dt><dd>{r.what ?? r.kind}</dd>
        <dt>为什么</dt>
        <dd><ul className="rp-quotes">{r.source_quotes.map((q, i) => {
          const v = quoteView(q);
          const href = safeHref(v.href);
          return <li key={i}>{href ? <a href={href} target="_blank" rel="noopener noreferrer">{v.text}</a> : v.text}</li>;
        })}</ul></dd>
        <dt>可能误伤</dt><dd>{r.false_positive_note}</dd>
        <dt>离线验证</dt><dd>{r.verified.offline.detail ?? off.hint}</dd>
      </dl>
    </li>
  );
}

/**
 * P2 「WAF 规则包」 block: one customer-owned RuleGroup for this event (radar.rulepack), five renderings to copy or
 * download. rulePack null / absent ⇒ nothing (older data, or no pack) — never an "all clear". The note (缓解 ≠ 修复)
 * comes first; rejected candidates and PoC outages are listed, not hidden.
 */
export function RulePackPanel({ rulePack, step = '03' }: { rulePack: RulePack | null | undefined; step?: string }) {
  const [shown, setShown] = useState(0);
  if (!rulePack) return null;
  const p = rulePack;
  const cap = CAPACITY_STATE[p.capacity.state];
  const renderings = p.renderings ?? [];
  const cur = renderings[Math.min(shown, Math.max(0, renderings.length - 1))];
  return (
    <section className="dt-section" id="rule-pack" aria-labelledby="dt-h-rp" data-testid="rule-pack-panel">
      <h2 className="dt-h2" id="dt-h-rp"><span className="dt-step">{step}</span>WAF 规则包 <span className="dt-en">Rule pack</span>
        {p.updated_at && <span className="dt-aside">更新 {utcShort(p.updated_at)} UTC</span>}</h2>
      <p className="mt-note" role="note">{p.note}</p>
      <p className="dt-small">
        客户自持规则组 <code className="dt-mono">{p.name}</code>：{ruleCount(p)} 条自定义 / 模板规则，全部 Count；
        托管规则组 {p.managed.length} 个。雷达不写你的资源 —— 复制或下载后由你挂到自己的 web ACL。
      </p>
      {/* nothing to deploy at the edge: why, in words (an empty pack said nothing — Neo 2026-11-19) */}
      {p.no_rule && <p className="note tone-warn" role="note" data-testid="rp-no-rule"><b>WAF 挡不了这个漏洞：</b>{p.no_rule}</p>}
      <p className={`dt-small tone-${cap.tone}`} data-testid="rp-capacity" data-state={p.capacity.state} title={cap.hint}>
        <span className="mt-state">{cap.label}</span> {capacityText(p.capacity)}
      </p>

      {p.poc.length > 0 && (
        <div className="mt-block">
          <h3 className="dt-h3">PoC 模板 <span className="dt-count">{p.poc.length} 个 CVE</span></h3>
          <ul className="rp-poc">{p.poc.map(x => {
            const w = POC_STATE[x.state];
            const href = safeHref(x.url);
            return (
              <li key={x.cve} className={`tone-${w.tone}`} data-state={x.state}>
                <span className="dt-mono">{x.cve}</span> <span className="mt-state" title={w.hint}>{w.label}</span>
                {href && <> · <a href={href} target="_blank" rel="noopener noreferrer">{x.path}@{x.sha?.slice(0, 10)}</a></>}
                {x.error && <span className="dt-small dt-muted"> · {x.error}</span>}
              </li>
            );
          })}</ul>
        </div>
      )}

      {p.managed.length > 0 && (
        <div className="mt-block">
          <h3 className="dt-h3">A · AWS 托管规则组 <span className="dt-count">{p.managed.length} 个</span></h3>
          <ul className="mt-plans">{p.managed.map(m => (
            <li key={`${m.tier}:${m.group}`} className="mt-plan tone-info" data-tier={m.tier}>
              <div className="mt-plan-head"><span className="mt-target">{m.group_label}</span>
                <code className="dt-mono">{m.group}</code>{!m.appliable && <span className="mt-advisory">仅建议</span>}</div>
              <p className="dt-small">{m.reason}{m.min_version ? `；需 ≥ ${m.min_version}` : ''}</p>
            </li>
          ))}</ul>
        </div>
      )}

      {p.custom.length > 0 && (
        <div className="mt-block">
          <h3 className="dt-h3">B · 自定义规则 <span className="dt-count">{p.custom.length} 条</span></h3>
          <ul className="mt-plans">{p.custom.map(r => <RuleRow key={r.rule_id} r={r} />)}</ul>
        </div>
      )}

      {p.templates.length > 0 && (
        <div className="mt-block">
          <h3 className="dt-h3">C · 模板（启发式，非证据规则） <span className="dt-count">{p.templates.length} 条</span></h3>
          <ul className="mt-plans">{p.templates.map(r => <RuleRow key={r.rule_id} r={r} />)}</ul>
        </div>
      )}

      {p.rejected.length > 0 && (
        <div className="mt-block" data-testid="rp-rejected">
          <h3 className="dt-h3">未生成的规则 <span className="dt-count">{p.rejected.length}</span></h3>
          <ul className="rp-rejected">{p.rejected.map((x, i) => (
            <li key={i} data-reason={x.reason}><span className="dt-mono">{x.cve ?? x.source}</span> · <code>{x.reason}</code>：{x.detail}</li>
          ))}</ul>
        </div>
      )}

      {cur && (
        <div className="mt-block" data-testid="rp-renderings">
          <h3 className="dt-h3">复制 / 下载</h3>
          <div className="rp-tabs" role="group" aria-label="规则包格式">
            {renderings.map((r, i) => (
              <button key={r.id} type="button" aria-pressed={r === cur} className={`btn-ghost btn-tiny${r === cur ? ' is-on' : ''}`}
                onClick={() => setShown(i)}>{r.label}</button>
            ))}
          </div>
          <div className="mt-json-bar"><CopyButton value={cur.text} label={cur.label} /> <DownloadButton r={cur} /></div>
          <pre className="mt-pre" tabIndex={0} aria-label={cur.label} data-rendering={cur.id}>{cur.text}</pre>
        </div>
      )}
    </section>
  );
}
