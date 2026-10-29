import { useId, useMemo } from 'react';
import { Link } from 'react-router-dom';
import type { ContinuumRecent, ContinuumTarget, Ledger } from '@/types/site-data';
import { Breadcrumbs } from '@/components/Breadcrumbs';
import { ImpactChip } from '@/components/ImpactChip';
import { NoData } from '@/components/NoData';
import { CopyButton } from '@/components/CopyButton';
import { useContinuum } from '@/hooks/useContinuum';
import { freshness } from '@/utils/staleness';
import {
  capabilityColumns, channelLine, costView, coverageSentence, heroView, hhmm, inventoryRows, kindWord, otherServicesLine, recentImpact,
  resourcesByRegion, sortRecent, statusChip, uploadAge, RECENT_STATUS, SERVICE_WORD, STATUS_META, UPLOAD_STALE_DAYS,
  usd, type CostView, type CoverageScore, type HeroView, type ServiceColumn,
} from '@/utils/continuum';
import '@/styles/detail.css';
import '@/styles/continuum.css';

/**
 * #/continuum — "AWS Continuum 融入" (spec 01 §5). Reading order is the page order:
 * L0 "和 AWS 融合到什么程度、还差什么？" (coverage ring + the gap list + ledger) →
 * capability flow Radar → Security Agent → Continuum ("哪一环还没上线？") →
 * L1 targets ("雷达在看护哪些代码、里面有什么？") →
 * L2 recent radar-triggered checks ("最近哪些事件打到了我们？" ⇒ #/events/:id?section=env) → resources ("跑在哪？").
 * All numbers come from utils/continuum.ts (single source).
 */
export function ContinuumPage() {
  const { state, doc, error, staleSecs } = useContinuum();
  const fresh = freshness(doc?.generatedAt ?? null, staleSecs, Date.now());
  const hero = useMemo(() => heroView(doc?.coverage ?? []), [doc]);
  const chip = statusChip(state, fresh);

  return (
    <div className="ct-page" data-page="continuum">
      <div className="ct-wrap">
        <div className="ct-top">
          <Breadcrumbs items={[{ label: '态势', to: '/' }, { label: 'AWS Continuum 融入' }]} />
          {doc && (
            <span className={`ct-status ${chip.cls}`} role="status">
              <span className="ct-dot" aria-hidden="true" />
              {chip.label}
              {' · '}发布 {hhmm(doc.generatedAt)}
            </span>
          )}
        </div>

        {state === 'error' && doc && (
          <p className="ct-banner" role="alert">刷新失败：{error} · 下方为上次成功读取的数据（发布于 {hhmm(doc.generatedAt)}）</p>
        )}

        {state === 'loading' && <Skeleton />}
        {state === 'unpublished' && <Unpublished />}
        {state === 'error' && !doc && (
          <section className="ct-hero is-empty">
            <h1 className="ct-h1">AWS Continuum 融入度</h1>
            <p className="ct-error" role="alert">continuum.json 读取失败：{error}（不是 0%：没有数据就不给数字）</p>
          </section>
        )}

        {doc && (
          <>
            <Hero hero={hero} ledger={doc.ledger} />
            <CapabilityFlow columns={capabilityColumns(doc.coverage)} />
            <Targets targets={doc.targets} />
            <Recent recent={doc.recent} />
            <Resources resources={doc.resources} />
          </>
        )}
      </div>
    </div>
  );
}

function Skeleton() {
  return (
    <section className="ct-hero is-loading" aria-busy="true" aria-label="加载融入度">
      <div className="ct-ring-skel" aria-hidden="true" />
      <div className="ct-hero-body">
        <h1 className="ct-h1">AWS Continuum 融入度</h1>
        <p className="ct-muted">正在读取 continuum.json…</p>
        <div className="ct-skel-row" aria-hidden="true" /><div className="ct-skel-row" aria-hidden="true" /><div className="ct-skel-row" aria-hidden="true" />
      </div>
    </section>
  );
}

function Unpublished() {
  return (
    <section className="ct-hero is-empty">
      <div className="ct-hero-body">
        <h1 className="ct-h1">AWS Continuum 融入度</h1>
        <p className="ct-sentence"><NoData>Continuum 数据尚未发布（/data/continuum.json 不存在）</NoData></p>
        <p className="ct-muted">发布方：respond station（见仓库 docs/design/CONTINUUM-INTEGRATION.md §5「覆盖度」）。未发布时不显示 0%。</p>
      </div>
    </section>
  );
}

/* ── L0: ring + sentence + gap list + ledger ─────────────────────────────── */

function Hero({ hero, ledger }: { hero: HeroView; ledger: Ledger | null }) {
  const { score, gap, others } = hero;
  return (
    <section className={`ct-hero${score.complete ? ' is-complete' : ''}`} aria-labelledby="ct-h1">
      <div className="ct-ring-col">
        <CoverageRing score={score} />
        <p className="ct-others">其他环节 · {otherServicesLine(others)}</p>
      </div>
      <div className="ct-hero-body">
        <div className="ct-kicker"><span className="ct-step">L0</span> 融入度 <span className="ct-en">INTEGRATION</span>
          <span className="ct-aside">只计 AWS Continuum 一列；只有「线上观察到成功」才计入；不适用项与等你授权的项不进分母（单列显示）</span></div>
        <h1 id="ct-h1" className="ct-h1">AWS Continuum 融入度</h1>
        <p className="ct-sentence">{coverageSentence(score)}</p>

        <ul className="ct-legend" aria-label="能力状态计数">
          <li className="st-live"><span aria-hidden="true">{STATUS_META.live.glyph}</span> 已上线 <b className="tabular">{score.live}</b></li>
          <li className="st-wired"><span aria-hidden="true">{STATUS_META.wired.glyph}</span> 已接线 <b className="tabular">{score.wired}</b></li>
          <li className="st-needs_user"><span aria-hidden="true">{STATUS_META.needs_user.glyph}</span> 需要你 <b className="tabular">{score.needsUser}</b></li>
          <li className="st-not_applicable"><span aria-hidden="true">{STATUS_META.not_applicable.glyph}</span> 不适用 <b className="tabular">{score.na}</b></li>
        </ul>

        {gap.length > 0 ? (
          <div className="ct-gap">
            <h2 className="ct-gap-h">{score.complete
              ? <>可自动化能力已全部上线 · 另有 <b className="tabular">{gap.length}</b> 项等你一次操作</>
              : <>到 100% 还差 <b className="tabular">{gap.length}</b> 项 <span className="ct-muted">· 先看需要你的</span></>}</h2>
            <ol className="ct-gap-list">
              {gap.map(c => (
                <li key={c.capability} className={`st-${c.status}`}>
                  <span className="ct-pill"><span aria-hidden="true">{STATUS_META[c.status].glyph}</span>{STATUS_META[c.status].word}</span>
                  <span className="ct-gap-name">{c.capability}</span>
                  <span className="ct-gap-svc">{SERVICE_WORD[c.service]}</span>
                  <span className="ct-gap-why">{c.status === 'needs_user' ? `下一步由你完成：${c.detail}` : `${STATUS_META.wired.hint} · ${c.detail}`}</span>
                </li>
              ))}
            </ol>
          </div>
        ) : score.complete ? (
          <p className="ct-done">全部可计入能力均已在线上观察到成功。</p>
        ) : null}

        <LedgerStrip ledger={ledger} />
      </div>
    </section>
  );
}

/** SVG ring (not 3D — spec 01 §5.2). Segments: live solid, wired hatched, needs_user amber thin; N/A out of the ring. */
function CoverageRing({ score }: { score: CoverageScore }) {
  const uid = useId().replace(/:/g, '');
  const total = score.applicable;
  const segs = total === 0 ? [] : [
    { key: 'live', len: (score.live / total) * 100 },
    { key: 'wired', len: (score.wired / total) * 100 },
    { key: 'needs_user', len: (score.needsUser / total) * 100 },
  ];
  let start = 0;
  const label = score.pct === null
    ? 'AWS Continuum 融入度：无可计入的能力'
    : `AWS Continuum 融入度 ${score.pct}%：已上线 ${score.live}，已接线 ${score.wired}，需要你 ${score.needsUser}，共 ${score.applicable} 项可计入；${score.na} 项不适用`;
  return (
    <figure className="ct-ring-fig">
      <svg className="ct-ring" viewBox="0 0 160 160" role="img" aria-label={label}>
        <defs>
          <pattern id={`hatch-${uid}`} width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="5" height="5" className="ring-hatch-bg" />
            <rect width="2.2" height="5" className="ring-hatch-fg" />
          </pattern>
          <mask id={`draw-${uid}`}>
            <circle className="ring-draw" cx="80" cy="80" r="64" pathLength={100} />
          </mask>
        </defs>
        <circle className="ring-track" cx="80" cy="80" r="64" />
        <g transform="rotate(-90 80 80)" mask={`url(#draw-${uid})`}>
          {segs.map(s => {
            const off = start; start += s.len;
            if (s.len <= 0) return null;
            // 0.6-unit gap between segments so adjacent states stay distinguishable
            const len = Math.max(0, s.len - (segs.filter(x => x.len > 0).length > 1 ? 0.6 : 0));
            return (
              <circle key={s.key} className={`ring-seg seg-${s.key}`} cx="80" cy="80" r="64" pathLength={100}
                strokeDasharray={`${len} ${100 - len}`} strokeDashoffset={-off}
                style={s.key === 'wired' ? { stroke: `url(#hatch-${uid})` } : undefined} />
            );
          })}
        </g>
        {score.pct === null ? (
          <text x="80" y="86" className="ring-na" textAnchor="middle">无数据</text>
        ) : (
          <>
            <text x="80" y="84" className="ring-pct" textAnchor="middle">{score.pct}<tspan className="ring-pct-u">%</tspan></text>
            <text x="80" y="106" className="ring-sub" textAnchor="middle">{score.live}/{score.applicable} 已上线</text>
          </>
        )}
      </svg>
      <figcaption className="ct-ring-cap">{score.na > 0 ? `${score.na} 项不适用，不进分母` : '无不适用项'}</figcaption>
    </figure>
  );
}

const LEDGER: { key: keyof Ledger; label: string; svc: string; sub?: keyof Ledger; subLabel?: string }[] = [
  { key: 'code_reviews_total', label: '代码评审', svc: 'Security Agent', sub: 'code_reviews_24h', subLabel: '24h' },
  { key: 'scans_total', label: '代码扫描', svc: 'Continuum' },
  { key: 'findings_submitted', label: '提交 finding', svc: 'Continuum' },
  { key: 'issues', label: 'Issues 回流', svc: 'Continuum' },
  { key: 'patches', label: '修复补丁', svc: 'Security Agent' },
];

function LedgerStrip({ ledger }: { ledger: Ledger | null }) {
  return (
    <div className="ct-ledger-wrap">
      <h2 className="ct-gap-h">账本 <span className="ct-muted">· 雷达驱动 AWS 做过的事（累计）</span></h2>
      {!ledger ? <NoData>账本未发布（ledger 缺失）</NoData> : (
        <ul className="ct-ledger">
          {LEDGER.map(t => {
            const v = ledger[t.key];
            const sub = t.sub ? ledger[t.sub] : undefined;
            return (
              <li key={t.key} className={`ct-tile${typeof v === 'number' && v > 0 ? ' is-nonzero' : ''}`}>
                <span className="ct-tile-v tabular">{typeof v === 'number' ? v : <NoData>—</NoData>}</span>
                <span className="ct-tile-l">{t.label}</span>
                <span className="ct-tile-s">{t.svc}{t.subLabel && typeof sub === 'number' ? ` · ${t.subLabel} ${sub}` : ''}</span>
              </li>
            );
          })}
        </ul>
      )}
      <CostLine view={costView(ledger?.cost)} />
    </div>
  );
}

/* R4: what the AWS side cost — the number a colleague asks first before trying it */
function CostLine({ view }: { view: CostView | null }) {
  if (!view) return <p className="ct-cost ct-muted">花费：尚未读取 Cost Explorer（每 6 小时一次）</p>;
  return (
    <p className="ct-cost" data-testid="ct-cost">
      <span className="ct-cost-k">AWS 花费 · 近 {view.days} 天</span>{' '}
      <strong className="tabular">{usd(view.totalUsd)}</strong>
      <span className="ct-muted">
        {' '}（Continuum {usd(view.continuumUsd)} · {view.units.toFixed(1)} 推理单位；Security Agent {usd(view.securityAgentUsd)}）
        {view.peak ? ` · 峰值 ${view.peak.date.slice(5)} ${usd(view.peak.usd)}` : ''} · 读于 {hhmm(view.fetched)}
      </span>
      {view.error ? <span className="ct-cost-err" role="status"> · 最近一次读取失败，数字停在上次：{view.error}</span> : null}
    </p>
  );
}

/* ── capability flow: Radar → Security Agent → Continuum ────────────────── */

function CapabilityFlow({ columns }: { columns: ServiceColumn[] }) {
  return (
    <section className="ct-sec" aria-labelledby="ct-cap-h2">
      <h2 id="ct-cap-h2" className="ct-h2"><span className="ct-step">L0′</span> 能力链路 <span className="ct-en">CAPABILITIES</span>
        <span className="ct-aside">按数据流从左到右；每列先列还差的</span></h2>
      {columns.every(c => c.caps.length === 0) ? <NoData>coverage 为空：发布方未登记任何能力</NoData> : (
        <ol className="ct-flow">
          {columns.map((col, i) => (
            <li key={col.service} className={`ct-col svc-${col.service}`}>
              <div className="ct-col-h">
                <h3 className="ct-col-name">{SERVICE_WORD[col.service]}</h3>
                <span className="ct-col-score tabular">
                  {col.score.pct === null ? '—' : `${col.score.live}/${col.score.applicable} 上线`}
                </span>
                <MiniBar score={col.score} />
                <span className="ct-col-role">{i === 0 ? '威胁 → 规则' : i === 1 ? '规则 → 代码评审 / 修复' : '环境验证 / 扫描 / 回流'}</span>
              </div>
              {col.caps.length === 0 ? <NoData>未登记</NoData> : (
                <ul className="ct-caps">
                  {col.caps.map(c => (
                    <li key={c.capability} className={`ct-cap st-${c.status}`}>
                      <span className="ct-pill" title={STATUS_META[c.status].hint}>
                        <span aria-hidden="true">{STATUS_META[c.status].glyph}</span>{STATUS_META[c.status].word}
                      </span>
                      <span className="ct-cap-name">{c.capability}</span>
                      <span className="ct-cap-detail">{c.detail}</span>
                      {c.evidence && <code className="ct-cap-ev">{c.evidence}</code>}
                    </li>
                  ))}
                </ul>
              )}
              {i < columns.length - 1 && <span className="ct-arrow" aria-hidden="true">→</span>}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function MiniBar({ score }: { score: CoverageScore }) {
  if (score.applicable === 0) return <span className="ct-mini is-empty" aria-hidden="true" />;
  const w = (n: number) => `${(n / score.applicable) * 100}%`;
  return (
    <span className="ct-mini" aria-hidden="true">
      <i className="seg-live" style={{ width: w(score.live) }} />
      <i className="seg-wired" style={{ width: w(score.wired) }} />
      <i className="seg-needs_user" style={{ width: w(score.needsUser) }} />
    </span>
  );
}

/* ── L1: targets ─────────────────────────────────────────────────────────── */

function Targets({ targets }: { targets: ContinuumTarget[] }) {
  const nowMs = Date.now();
  return (
    <section className="ct-sec" aria-labelledby="ct-tg-h2">
      <h2 id="ct-tg-h2" className="ct-h2"><span className="ct-step">L1</span> 看护的代码 <span className="ct-en">TARGETS</span>
        <span className="ct-aside">雷达事件命中时，就对这些仓库做评审与环境验证</span></h2>
      {targets.length === 0 ? <NoData>没有已接入的目标代码</NoData> : (
        <ul className="ct-targets">
          {targets.map(t => {
            const age = uploadAge(t, nowMs);
            const rows = inventoryRows(t);
            return (
              <li key={t.target_id} className="ct-target">
                <div className="ct-target-h">
                  <h3 className="ct-target-name">{t.name}</h3>
                  {channelLine(t) && <span className="ct-chan" data-channel={t.channel}>{channelLine(t)}</span>}
                  {t.channel_url
                    ? <a className="ct-target-prefix" href={t.channel_url} target="_blank" rel="noreferrer"><code>{t.prefix}</code></a>
                    : <code className="ct-target-prefix">{t.prefix}</code>}
                </div>
                <p className="ct-target-desc">{t.description}</p>
                <p className={`ct-target-up is-${age.kind}`}>
                  {age.kind === 'missing' ? '源码未上传 · 无法评审' :
                    `源码快照 ${hhmm(t.uploaded_at as string)}${age.kind === 'stale' ? ` · ${age.days} 天前（> ${UPLOAD_STALE_DAYS} 天），结果可能过期` : ''}`}
                </p>
                {rows.length === 0 ? <NoData>inventory 为空</NoData> : (
                  <table className="ct-inv">
                    <caption className="sr-only">{t.name} 的组件清单</caption>
                    <thead><tr><th scope="col">组件</th><th scope="col">版本</th><th scope="col">位置</th></tr></thead>
                    <tbody>
                      {rows.map(r => (
                        <tr key={`${r.entry.file}:${r.entry.line}`}>
                          {r.span > 0 && <th scope="row" rowSpan={r.span}>{r.entry.product}</th>}
                          <td className="tabular">{r.entry.version}</td>
                          <td><code>{r.file}:{r.entry.line}</code></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {targets.length > 0 && <p className="ct-foot">组件清单来自登记表；实际命中位置以事件详情「在你的环境中」为准。</p>}
    </section>
  );
}

/* ── L2: recent radar-triggered checks ───────────────────────────────────── */

function Recent({ recent }: { recent: ContinuumRecent[] }) {
  const rows = sortRecent(recent);
  return (
    <section className="ct-sec" aria-labelledby="ct-rc-h2">
      <h2 id="ct-rc-h2" className="ct-h2"><span className="ct-step">L2</span> 最近触发的环境检查 <span className="ct-en">RECENT</span>
        <span className="ct-aside">点事件 → 详情页「在你的环境中」</span></h2>
      {rows.length === 0 ? (
        <p className="ct-empty">最近没有雷达事件触发环境检查 · 触发条件：P0/P1 升级且规则可生成（见 CONTINUUM-INTEGRATION §2）</p>
      ) : (
        <ul className="ct-recent">
          {rows.map(r => (
            <li key={r.event_id} className={`ct-rec sev-${r.severity}`}>
              <span className={`ct-sev sev-${r.severity}`}>{r.severity}</span>
              <Link className="ct-rec-title" to={`/events/${encodeURIComponent(r.event_id)}?section=env`}
                title="查看该事件的环境检查明细 →">{r.title}</Link>
              <span className="ct-rec-st">{RECENT_STATUS[r.status]}</span>
              <ImpactChip impact={recentImpact(r)} context="detail" />
              <span className="ct-rec-at tabular">{hhmm(r.updated_at)}</span>
              <span className="ct-rec-go" aria-hidden="true">→</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/* ── resources by region ─────────────────────────────────────────────────── */

function Resources({ resources }: { resources: { kind: string; id: string; name: string; region: string; status: string; console_url?: string | null }[] }) {
  const groups = resourcesByRegion(resources);
  return (
    <section className="ct-sec" aria-labelledby="ct-rs-h2">
      <h2 id="ct-rs-h2" className="ct-h2"><span className="ct-step">L3</span> 运行在哪 <span className="ct-en">RESOURCES</span>
        <span className="ct-aside">Continuum 代码扫描在 ap-northeast-1 无端点，环境位于 us-east-1</span></h2>
      {groups.length === 0 ? <NoData>没有登记的 AWS 资源</NoData> : (
        <div className="ct-regions">
          {groups.map(g => (
            <div key={g.region} className="ct-region">
              <h3 className="ct-region-h"><code>{g.region}</code> <span className="ct-muted">{g.resources.length} 个资源</span></h3>
              <ul className="ct-res">
                {g.resources.map(r => (
                  <li key={`${r.kind}:${r.id}`} className="ct-res-row">
                    <span className="ct-res-kind">{kindWord(r.kind)}</span>
                    <span className="ct-res-name">{r.name}</span>
                    <code className="ct-res-id" title={r.id}>{r.id.length > 14 ? `${r.id.slice(0, 12)}…` : r.id}</code>
                    <CopyButton value={r.id} label={`${kindWord(r.kind)} ID`} />
                    <span className={`ct-res-st${/^(ACTIVE|ENABLED)$/.test(r.status) ? ' is-ok' : ''}`}>{r.status}</span>
                    {r.console_url && <a className="ct-res-link" href={r.console_url} target="_blank" rel="noreferrer noopener">控制台 ↗</a>}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
