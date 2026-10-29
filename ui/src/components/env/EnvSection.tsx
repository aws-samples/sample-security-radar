import { useState } from 'react';
import type { PipelineStep, Response, ResponseAction, ResponseFinding, ResponseTarget } from '@/types/site-data';
import { CopyButton } from '@/components/CopyButton';
import { PatchViewer } from '@/components/env/PatchViewer';
import {
  responseBluf, sortTargets, sortFindings, stripRequirementPrefix, actionDuration, sameFile, actionLanes,
  ACTION_KIND_LABEL, SERVICE_LABEL, type ResolvedImpact,
} from '@/utils/response';
import { durationZh, utcShort } from '@/utils/timeZh';

const VERDICT: Record<ResponseTarget['verdict'], { glyph: string; word: string; tone: string }> = {
  affected: { glyph: '◆', word: '命中', tone: 'loss' },
  pending: { glyph: '◌', word: '检查中', tone: 'info' },
  unknown: { glyph: '?', word: '无法判定', tone: 'warn' },
  not_affected: { glyph: '◇', word: '未命中', tone: 'ok' },
  skipped: { glyph: '–', word: '已跳过', tone: 'muted' },
};

const ACT_STATUS: Record<ResponseAction['status'], { glyph: string; word: string; tone: string }> = {
  submitted: { glyph: '↗', word: '已提交', tone: 'info' },
  running: { glyph: '◌', word: '进行中', tone: 'info' },
  done: { glyph: '✓', word: '完成', tone: 'ok' },
  failed: { glyph: '⚠', word: '失败', tone: 'warn' },
  skipped: { glyph: '–', word: '跳过', tone: 'muted' },
};

const SEV_TONE: Record<string, string> = { CRITICAL: 'loss', HIGH: 'loss', MEDIUM: 'warn', LOW: 'info', INFO: 'muted' };

const findingDomId = (i: number) => `env-finding-${i}`;
const short = (s: string, n = 12) => (s.length > n ? `${s.slice(0, n)}…` : s);

function flash(id: string) {
  const el = document.getElementById(id);
  if (!el) return;
  el.scrollIntoView({ block: 'center' });
  el.classList.add('is-flash');
  window.setTimeout(() => el.classList.remove('is-flash'), 1200);
}

interface Props {
  response: Response | null | undefined;
  steps: PipelineStep[] | undefined;
  impact: ResolvedImpact;
  /** ?section=env deep link ⇒ open the patch right away (the reader came here for it). */
  deepLinked: boolean;
}

/** L2' "在你的环境中": BLUF → A targets → B action lanes → C findings → D issues → E patches. */
export function EnvSection({ response, steps, impact, deepLinked }: Props) {
  const bluf = responseBluf(response);
  const [openPatch, setOpenPatch] = useState<Set<number>>(() => new Set(deepLinked && response ? response.patches.map((_, i) => i) : []));
  const [focus, setFocus] = useState<{ pi: number; file: string; n: number } | null>(null);

  const head = (
    <div className={`env-bluf tone-${bluf.tone}${response === undefined ? ' is-absent' : ''}`}>
      <div className="env-bluf-text">{bluf.text}{bluf.tail && <span className={`bluf-tail tone-${bluf.tail.tone}`}> · {bluf.tail.text}</span>}</div>
      {response && (
        <div className="env-bluf-meta">
          {response.requirement_name && (
            <span>规则 <code className="dt-mono">{short(response.requirement_name, 28)}</code> <CopyButton value={response.requirement_name} label="规则名" /></span>
          )}
          {response.product && <span>产品 <b className="dt-mono">{response.product}</b></span>}
          <span>原因：{response.reason}</span>
        </div>
      )}
      {/* without a response the note is the impact_match detail, already spelled out in the reason line below */}
      {response && impact.note && <div className="env-note">{impact.note}</div>}
    </div>
  );

  if (!response) {
    // null = not triggered: explain why with the system step's own words; undefined = not wired at all.
    const step = steps?.find(s => s.step === 'impact_match');
    return (
      <>
        {head}
        <p className="dt-small dt-muted" style={{ marginTop: 8 }}>
          {response === null
            ? <>原因：{step ? `${step.detail}（影响匹配步骤：${step.status}）` : '后端未给出影响匹配步骤'}。触发条件：P0/P1 升级且产品命中登记表、修复版本可从证据逐字抽取。</>
            : <>该数据由较早版本的发布器生成，不含环境检查字段；升级后端即会出现本区块。</>}
        </p>
      </>
    );
  }

  const targets = sortTargets(response.targets);
  const relevant = targets.filter(t => t.relevant);
  const skipped = targets.filter(t => !t.relevant);
  const findings = sortFindings(response.findings);
  const lanes = actionLanes(response.actions);
  const failedFirst = response.status === 'failed';

  const openFile = (pi: number, file: string) => {
    setOpenPatch(s => new Set(s).add(pi));
    setFocus(f => ({ pi, file, n: (f?.n ?? 0) + 1 }));
  };

  const targetCard = (t: ResponseTarget) => {
    const v = VERDICT[t.verdict];
    return (
      <div key={t.target_id} className={`env-target tone-${v.tone}`}>
        <div className="env-target-head">
          <span className="env-target-name">{t.name}</span>
          <span className="env-verdict"><span aria-hidden="true">{v.glyph} </span>{v.word}</span>
        </div>
        <div className="env-target-detail">{t.detail}</div>
        {t.locations.length > 0 && (
          <div style={{ overflowX: 'auto' }}>
          <table className="env-table">
            <caption className="dt-small dt-muted" style={{ textAlign: 'left', paddingBottom: 4 }}>{t.locations.length} 处代码位置</caption>
            <thead><tr><th scope="col">文件:行</th><th scope="col">当前</th><th scope="col">修复到</th><th scope="col">关联</th></tr></thead>
            <tbody>
              {t.locations.map(loc => {
                const fIdx = findings.map((f, i) => [f, i] as const)
                  .filter(([f]) => f.requirement_hit && (f.target_id ?? t.target_id) === t.target_id && sameFile(f.file, loc.file, t.target_id) && (f.line == null || f.line === loc.line));
                const patched = response.patches.map((p, pi) => [p, pi] as const)
                  .map(([p, pi]) => ({ pi, file: (p.target_id ?? t.target_id) === t.target_id ? p.files_changed.find(fc => sameFile(fc, loc.file, t.target_id)) : undefined }))
                  .find(x => x.file);
                return (
                  <tr key={`${loc.file}:${loc.line}`}>
                    <td className="dt-mono nowrap">{loc.file}:{loc.line}</td>
                    <td className="v-found nowrap">{loc.found_version}</td>
                    <td className={`nowrap ${loc.fixed_version ? 'v-fixed' : 'dt-muted'}`}>{loc.fixed_version ?? '未知'}</td>
                    <td>
                      {fIdx.map(([f, i]) => (
                        <button key={f.finding_id} type="button" className="env-linkchip" onClick={() => flash(findingDomId(i))} aria-label={`跳到 finding ${f.finding_id}`}>
                          finding {short(f.finding_id, 8)}
                        </button>
                      ))}
                      {patched && (
                        <button type="button" className="env-linkchip is-patched" onClick={() => openFile(patched.pi, patched.file!)} aria-label={`在补丁中查看 ${patched.file}`}>
                          ✓ 补丁已改
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          </div>
        )}
      </div>
    );
  };

  return (
    <>
      {head}
      <div className="env-grid">
        <div className="env-block">
          <h3 className="dt-h3">A · 目标判定 <span className="dt-count">{relevant.filter(t => t.verdict === 'affected').length}/{targets.length} 命中</span></h3>
          {targets.length === 0
            ? <p className="dt-small dt-muted">没有已接入的目标（在 AWS Continuum 中接入代码仓后才会检查）</p>
            : relevant.length === 0
              ? <p className="dt-small dt-muted">所有目标都与本产品无关，未评审</p>
              : relevant.map(targetCard)}
          {skipped.length > 0 && (
            <details className="env-fold">
              <summary>另 {skipped.length} 个目标与本产品无关，已跳过（省费用）</summary>
              {skipped.map(targetCard)}
            </details>
          )}
        </div>
        <div className="env-block">
          <h3 className="dt-h3">B · 动作时间线 <span className="dt-count">{response.actions.length} 个动作</span></h3>
          {response.actions.length === 0
            ? <p className="dt-small dt-muted">尚未发起任何动作</p>
            : (
              <div className="lanes">
                {lanes.map(l => (
                  <section key={l.service} className="lane" aria-label={`${SERVICE_LABEL[l.service]} 动作`}>
                    <h4 className="lane-h">{SERVICE_LABEL[l.service]} <span className="dt-count dt-mono dt-muted">{l.actions.length}</span></h4>
                    {l.actions.length === 0 ? <p className="dt-small dt-muted">无</p> : (
                      <ol>
                        {l.actions.map((a, i) => {
                          const s = ACT_STATUS[a.status];
                          const d = actionDuration(a);
                          return (
                            <li key={`${a.kind}-${i}`} className={`act tone-${s.tone}${a.status === 'failed' ? ' is-failed' : ''}`}>
                              <div className="act-top">
                                <span className="act-kind">{ACTION_KIND_LABEL[a.kind]}</span>
                                <span className="act-status">
                                  {a.status === 'running' ? <span className="live-dot" style={{ display: 'inline-block', marginRight: 4 }} aria-hidden="true" /> : <span aria-hidden="true">{s.glyph} </span>}
                                  {s.word}
                                </span>
                                {a.target_id && <span className="dt-mono dt-small dt-muted">{a.target_id}</span>}
                              </div>
                              <div className="act-detail">{a.detail}</div>
                              <div className="act-meta">
                                <span>开始 {utcShort(a.started_at)}</span>
                                <span title={d === null && a.started_at ? '时间戳不一致（updated_at 早于 started_at），不显示时长' : undefined}>耗时 {durationZh(d) ?? '—'}</span>
                                {a.external_id && <span className="dt-mono">{short(a.external_id)} <CopyButton value={a.external_id} label={`${ACTION_KIND_LABEL[a.kind]} ID`} /></span>}
                                {a.console_url && <a href={a.console_url} target="_blank" rel="noopener noreferrer">控制台 ↗</a>}
                              </div>
                            </li>
                          );
                        })}
                      </ol>
                    )}
                  </section>
                ))}
              </div>
            )}
          {failedFirst && <p className="env-note">检查失败：失败的动作已置顶</p>}
        </div>
      </div>

      <div className="env-block">
        <h3 className="dt-h3">C · Findings <span className="dt-count">{findings.length} 个 · 雷达规则命中 {findings.filter(f => f.requirement_hit).length}</span></h3>
        {findings.length === 0 ? <p className="dt-small dt-muted">尚无 finding</p> : (
          <ul className="findings">
            {findings.map((f: ResponseFinding, i) => {
              const tone = SEV_TONE[f.severity.toUpperCase()] ?? 'muted';
              return (
                <li key={`${f.service}-${f.finding_id}`} id={findingDomId(i)} className={`finding${f.requirement_hit ? ' is-hit' : ''}`}>
                  {f.requirement_hit ? <span className="hit-badge">◆ 雷达规则命中</span> : <span />}
                  <span className={`sev-tag tone-${tone}`}>{f.severity}</span>
                  <span className="finding-title" title={f.title}>{stripRequirementPrefix(f.title)}</span>
                  <span className="dt-mono dt-small dt-muted">{f.status}</span>
                  <span className="finding-sub">
                    <span>{SERVICE_LABEL[f.service]}</span>
                    <span className="dt-mono">{f.file ? `${f.file}${f.line != null ? `:${f.line}` : ''}` : '无代码位置'}</span>
                    <span className="dt-mono">{short(f.finding_id, 14)}</span>
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {response.issues.length > 0 ? (
        <div className="env-block">
          <h3 className="dt-h3">D · Issues <span className="dt-count">{response.issues.length}</span></h3>
          <div style={{ overflowX: 'auto' }}>
            <table className="env-table">
              <thead><tr><th scope="col">名称</th><th scope="col">严重度</th><th scope="col">阶段</th><th scope="col">状态</th><th scope="col">可利用</th><th scope="col">补丁</th></tr></thead>
              <tbody>
                {response.issues.map(is => (
                  <tr key={is.issue_id}>
                    <td>{is.name}{is.synopsis && <div className="dt-small dt-muted">{is.synopsis}</div>}{is.effect && <div className="dt-small">影响：<span className="dt-mono">{is.effect}</span></div>}</td>
                    <td className="dt-mono">{is.severity}</td>
                    <td>{is.phase}</td>
                    <td className="dt-mono">{is.status}</td>
                    <td>{is.exploitable ?? '—'}</td>
                    <td>{is.patch_status ?? '—'}{is.patch_path && <div className="dt-small dt-mono dt-muted">{is.patch_path}</div>}
                      {is.pr_url && (/^https:\/\/github\.com\//.test(is.pr_url)
                        ? <div className="dt-small"><a href={is.pr_url} target="_blank" rel="noopener noreferrer">GitHub PR #{is.pr_url.split('/').pop()}</a></div>
                        : null)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <p className="dt-small dt-muted env-block">D · Issues 0（Continuum 验证尚未产出 issue）</p>
      )}

      <div className="env-block">
        <h3 className="dt-h3">E · 修复补丁 <span className="dt-count">{response.patches.length}</span></h3>
        {response.patches.length === 0 ? <p className="dt-small dt-muted">尚无补丁</p> : response.patches.map((p, pi) => (
          <PatchViewer
            key={p.path}
            patch={p}
            pi={pi}
            open={openPatch.has(pi)}
            onToggle={() => setOpenPatch(s => { const n = new Set(s); if (n.has(pi)) n.delete(pi); else n.add(pi); return n; })}
            targetName={targets.find(t => t.target_id === p.target_id)?.name ?? p.target_id ?? null}
            focusFile={focus?.pi === pi ? focus.file : null}
            focusKey={focus?.n ?? 0}
          />
        ))}
      </div>
    </>
  );
}
