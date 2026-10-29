import { Link } from 'react-router-dom';
import type { Mitigation, MitigationPlan } from '@/types/mitigate';
import { CopyButton } from '@/components/CopyButton';
import { ADVISORY_NOTE, DNS_ACTION, DNS_STATE, PLAN_STATE, SEVERITY, TIER, purlName } from '@/utils/mitigate';
import { utcShort } from '@/utils/timeZh';

function PlanRow({ p }: { p: MitigationPlan }) {
  const st = PLAN_STATE[p.state];
  const tier = TIER[p.tier];
  const json = JSON.stringify(p.rule_json, null, 2);
  return (
    <li className={`mt-plan tone-${st.tone}`} data-state={p.state} data-tier={p.tier}>
      <div className="mt-plan-head">
        <span className="mt-target dt-mono">{p.target_id}</span>
        <span className={`mt-tier${tier.advisory ? ' is-advisory' : ''}`}>{tier.label}</span>
        {tier.advisory && <span className="mt-advisory">{ADVISORY_NOTE}</span>}
        <span className="mt-state" title={st.hint}>{st.label}</span>
      </div>
      <dl className="mt-kv">
        <dt>规则组</dt><dd>{p.group_label} <code className="dt-mono">{p.group}</code></dd>
        <dt>规则</dt><dd className="dt-mono">{p.rules.length ? p.rules.join('、') : '整组'}</dd>
        <dt>最低版本</dt><dd className="dt-mono">{p.min_version ?? '不限'}{p.version ? ` · 当前 ${p.version}` : ''}</dd>
        {p.web_acl && <><dt>web ACL</dt><dd className="dt-mono">{p.web_acl}</dd></>}
        <dt>依据</dt><dd>{p.reason}</dd>
        <dt>状态</dt><dd>{p.detail || st.hint}</dd>
      </dl>
      <details className="env-fold mt-json">
        <summary>规则 JSON（<span className="dt-mono">{p.rule ?? p.key}</span>）</summary>
        <div className="mt-json-bar"><CopyButton value={json} label="规则 JSON" /></div>
        <pre className="mt-pre" tabIndex={0} aria-label="规则 JSON">{json}</pre>
      </details>
    </li>
  );
}

/**
 * M3 "缓解（快路）" block on the event page. mitigation null / absent ⇒ nothing (older data, or the station had nothing
 * for this event) — never an "all clear". The note (缓解 ≠ 修复) is always the first thing shown.
 */
export function MitigationPanel({ mitigation }: { mitigation: Mitigation | null | undefined }) {
  if (!mitigation) return null;
  const { plans, dns } = mitigation;
  const inspector = mitigation.inspector ?? [];
  return (
    <section className="dt-section" id="mitigation" aria-labelledby="dt-h-mit" data-testid="mitigation-panel">
      <h2 className="dt-h2" id="dt-h-mit"><span className="dt-step">03b</span>缓解（快路） <span className="dt-en">Mitigation</span>
        <span className="dt-aside">更新 {utcShort(mitigation.updated_at)} UTC</span></h2>
      <p className="mt-note" role="note">{mitigation.note}</p>

      <div className="mt-block">
        <h3 className="dt-h3">A · WAF 虚拟补丁 <span className="dt-count">{plans.length} 条</span></h3>
        {plans.length === 0
          ? <p className="dt-small dt-muted">没有可用的 WAF 规则（AWS 托管规则未覆盖本事件）</p>
          : <ul className="mt-plans">{plans.map(p => <PlanRow key={p.key} p={p} />)}</ul>}
      </div>

      {dns && (
        <div className="mt-block">
          <h3 className="dt-h3">B · DNS Firewall 域名拦截 <span className="dt-count">{dns.domains.length} 个域名</span></h3>
          <p className={`mt-line tone-${DNS_STATE[dns.state].tone}`}>
            <span className="mt-state" title={DNS_STATE[dns.state].hint}>{DNS_STATE[dns.state].label}</span>
            <span className="dt-small">动作 {dns.action ? DNS_ACTION[dns.action] : '未设置'}</span>
          </p>
          {dns.domains.length > 0 && (
            <ul className="mt-domains">{dns.domains.map(d => <li key={d}><code className="dt-mono">{d}</code></li>)}</ul>
          )}
        </div>
      )}

      {inspector.length > 0 && (
        <div className="mt-block">
          <h3 className="dt-h3">C · Amazon Inspector 依赖判定 <span className="dt-count">{inspector.length} 条命中</span></h3>
          <table className="env-table mt-table">
            <thead><tr><th scope="col">包</th><th scope="col">漏洞</th><th scope="col">严重度</th><th scope="col">修复版本</th><th scope="col">文件</th></tr></thead>
            <tbody>
              {inspector.map((f, i) => (
                <tr key={`${f.id}-${f.purl}-${i}`}>
                  <td className="dt-mono">{purlName(f.purl)}</td>
                  <td className="dt-mono nowrap">{f.id}</td>
                  <td className={`nowrap mt-sev tone-${SEVERITY[f.severity].tone}`}>{SEVERITY[f.severity].label}</td>
                  <td className="dt-mono nowrap">{f.fixed ?? '未知'}</td>
                  <td className="dt-mono">{f.file ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="dt-small dt-muted mt-foot">全部目标的缓解状态与没查成的项见 <Link to="/mitigate">缓解页</Link>。</p>
    </section>
  );
}
