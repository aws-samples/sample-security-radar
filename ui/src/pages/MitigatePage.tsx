import { useEffect, useState } from 'react';
import type { MitigateDoc } from '@/types/mitigate';
import { BASELINE_STATE, DNS_STATE, SEVERITY, purlName } from '@/utils/mitigate';
import { formatDateTime } from '@/utils/formatters';
import '@/styles/detail.css';

type Load = { st: 'loading' } | { st: 'absent' } | { st: 'error'; error: string } | { st: 'ok'; doc: MitigateDoc };

const dnsWord = (state: string | undefined) =>
  state && state in DNS_STATE ? DNS_STATE[state as keyof typeof DNS_STATE] : { label: `未知状态（${state ?? '缺失'}）`, tone: 'warn' as const, hint: '' };

/** Pure view, exported for tests (the page fetches, this renders). */
export function MitigateView({ doc }: { doc: MitigateDoc }) {
  const dns = doc.dns;
  return (
    <>
      <p className="mt-note" role="note">{doc.note}</p>
      <p className="ops-sub tabular">
        上次运行 {doc.run_at ? formatDateTime(doc.run_at) : '从未运行'} · 生成于 {formatDateTime(doc.generated_at)}
      </p>

      {doc.errors.length > 0 && (
        <section className="mt-errors" aria-labelledby="mt-h-err" data-testid="mitigate-errors">
          <h2 className="mt-h2" id="mt-h-err">没查成的项 · {doc.errors.length} 项</h2>
          <p className="dt-small">以下检查本轮失败，对应结果未知 —— 不代表没问题。</p>
          <ul className="ops-list">
            {doc.errors.map((e, i) => (
              <li key={i} className="ops-row is-error">
                <span className="ops-lv">{e.channel ?? '未知通道'}</span>
                <span className="ops-title">{e.what ?? '未知检查'}</span>
                <code className="ops-detail">{e.error ?? '（没有错误信息）'}</code>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="dt-section" aria-labelledby="mt-h-acl">
        <h2 className="dt-h2" id="mt-h-acl">雷达自建 web ACL <span className="dt-en">AWS WAF</span></h2>
        {doc.web_acls.length === 0
          ? <p className="dt-small dt-muted">没有登记 web ACL —— WAF 计划只给出规则，不下发。</p>
          : (
            <table className="env-table">
              <thead><tr><th scope="col">目标</th><th scope="col">web ACL</th><th scope="col">ID</th></tr></thead>
              <tbody>{doc.web_acls.map((a, i) => (
                <tr key={`${a.name}-${i}`}><td className="dt-mono">{a.target_id ?? '—'}</td><td className="dt-mono">{a.name ?? '—'}</td><td className="dt-mono">{a.id ?? '—'}</td></tr>
              ))}</tbody>
            </table>
          )}
      </section>

      <section className="dt-section" aria-labelledby="mt-h-dns">
        <h2 className="dt-h2" id="mt-h-dns">Route 53 DNS Firewall <span className="dt-en">DNS</span></h2>
        {!dns
          ? <p className="dt-small">没有 DNS Firewall 状态（本轮没查或未接入）—— 不代表没有恶意域名。</p>
          : (
            <>
              <p className={`mt-line tone-${dnsWord(dns.state).tone}`}><span className="mt-state" title={dnsWord(dns.state).hint}>{dnsWord(dns.state).label}</span>
                <span className="dt-small">{(dns.domains ?? []).length} 个雷达拦截域名</span></p>
              {(dns.domains ?? []).length > 0 && <ul className="mt-domains">{(dns.domains ?? []).map(d => <li key={d}><code className="dt-mono">{d}</code></li>)}</ul>}
              {(dns.rules ?? []).length > 0 && (
                <table className="env-table">
                  <thead><tr><th scope="col">规则</th><th scope="col">动作</th></tr></thead>
                  <tbody>{(dns.rules ?? []).map((r, i) => <tr key={`${r.name}-${i}`}><td className="dt-mono">{r.name ?? '—'}</td><td className="dt-mono">{r.action ?? '未设置'}</td></tr>)}</tbody>
                </table>
              )}
            </>
          )}
      </section>

      <section className="dt-section" aria-labelledby="mt-h-insp">
        <h2 className="dt-h2" id="mt-h-insp">Amazon Inspector 依赖基线 <span className="dt-en">Inspector</span>
          <span className="dt-aside">只有"已判定"是结论</span></h2>
        {doc.inspector.length === 0
          ? <p className="dt-small">没有任何目标的依赖基线（尚未运行）—— 不代表没有漏洞。</p>
          : (
            <ul className="mt-plans">
              {doc.inspector.map(b => {
                const w = BASELINE_STATE[b.state];
                return (
                  <li key={b.target_id} className={`mt-plan tone-${w.tone}`} data-state={b.state}>
                    <div className="mt-plan-head">
                      <span className="mt-target dt-mono">{b.target_id}</span>
                      <span className="mt-state">{w.label}</span>
                      <span className="dt-small dt-muted">{b.scanned_on ? `查于 ${b.scanned_on}` : '从未查过'}{b.state === 'scanned' ? ` · ${b.components} 个组件` : ''}</span>
                    </div>
                    {b.state === 'scanned'
                      ? (b.findings.length === 0
                          ? <p className="dt-small">Inspector 判定：{b.components} 个组件中没有已知漏洞。</p>
                          : (
                            <table className="env-table mt-table">
                              <caption className="dt-small dt-muted" style={{ textAlign: 'left', paddingBottom: 4 }}>{b.findings.length} 条命中</caption>
                              <thead><tr><th scope="col">包</th><th scope="col">漏洞</th><th scope="col">严重度</th><th scope="col">修复版本</th><th scope="col">文件</th></tr></thead>
                              <tbody>{b.findings.map((f, i) => (
                                <tr key={`${f.id}-${f.purl}-${i}`}>
                                  <td className="dt-mono">{purlName(f.purl)}</td>
                                  <td className="dt-mono nowrap">{f.id}</td>
                                  <td className={`nowrap mt-sev tone-${SEVERITY[f.severity].tone}`}>{SEVERITY[f.severity].label}</td>
                                  <td className="dt-mono nowrap">{f.fixed ?? '未知'}</td>
                                  <td className="dt-mono">{f.file ?? '—'}</td>
                                </tr>
                              ))}</tbody>
                            </table>
                          ))
                      : <p className="dt-small">{w.hint}</p>}
                  </li>
                );
              })}
            </ul>
          )}
      </section>

      <section className="dt-section" aria-labelledby="mt-h-app">
        <h2 className="dt-h2" id="mt-h-app">下发历史 <span className="dt-en">Applied</span><span className="dt-aside">最近 {doc.applied.length} 次</span></h2>
        {doc.applied.length === 0
          ? <p className="dt-small dt-muted">还没有向 web ACL 下发过规则。</p>
          : (
            <table className="env-table">
              <thead><tr><th scope="col">时间</th><th scope="col">web ACL</th><th scope="col">规则组</th></tr></thead>
              <tbody>{[...doc.applied].reverse().map((a, i) => (
                <tr key={`${a.at}-${i}`}><td className="dt-mono nowrap">{a.at ? formatDateTime(a.at) : '—'}</td><td className="dt-mono">{a.web_acl ?? '—'}</td><td className="dt-mono">{(a.rules ?? []).join('、') || '—'}</td></tr>
              ))}</tbody>
            </table>
          )}
      </section>
    </>
  );
}

/** M3 mitigate station overview. Absent mitigate.json (older backend) ⇒ said so, never an empty "all good". */
export function MitigatePage() {
  const [load, setLoad] = useState<Load>({ st: 'loading' });
  useEffect(() => {
    let cancelled = false;
    fetch('./data/mitigate.json')
      .then(async r => {
        // a missing file falls through to index.html (dev/preview server, CloudFront SPA error page) — same rule as useEventDetail
        const ct = r.headers.get('content-type') ?? '';
        if (r.status === 404 || r.status === 403 || ct.includes('text/html')) return null;
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return (await r.json()) as MitigateDoc;
      })
      .then(d => {
        if (cancelled) return;
        if (d === null) { setLoad({ st: 'absent' }); return; }
        if (d.kind !== 'mitigate') throw new Error('unexpected data kind');
        setLoad({ st: 'ok', doc: d });
      })
      .catch((e: unknown) => { if (!cancelled) setLoad({ st: 'error', error: String(e) }); });
    return () => { cancelled = true; };
  }, []);
  return (
    // tabIndex: the page scrolls but may hold no focusable control ⇒ keyboard users must still be able to scroll it (axe scrollable-region-focusable)
    <div className="ops-page" data-page="mitigate" tabIndex={0} role="region" aria-label="缓解">
      <div className="dt-wrap">
        <h1 className="ops-h1">缓解 <span className="ops-en">MITIGATE</span></h1>
        {load.st === 'loading' && <p className="dt-muted dt-mono dt-small" aria-busy="true">正在加载缓解数据…</p>}
        {load.st === 'absent' && <p className="ops-error">后端尚未发布 mitigate.json —— 缓解站还没有运行过，这不代表没有需要缓解的事。</p>}
        {load.st === 'error' && <p className="ops-error">缓解数据不可用（{load.error}）—— 这不代表一切正常</p>}
        {load.st === 'ok' && <MitigateView doc={load.doc} />}
      </div>
    </div>
  );
}
