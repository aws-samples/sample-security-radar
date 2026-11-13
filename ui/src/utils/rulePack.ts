import type { RulePack, RulePackCapacity, RulePackPoc, RulePackRule } from '@/types/site-data';
import type { StateWord } from '@/utils/mitigate';

/**
 * P2 WAF rule pack view words. Record<> makes tsc fail on a new schema state; rulePack.test.tsx also checks each map
 * against the schema enum at runtime. The backend decides every state — these only word them.
 */
export const CAPACITY_STATE: Record<RulePackCapacity['state'], StateWord> = {
  pass:        { label: 'WCU 已核',       tone: 'ok',   hint: 'AWS CheckCapacity（只读）已算出 WCU，规则语法被 AWS 接受' },
  over_budget: { label: 'WCU 超预算',     tone: 'warn', hint: '规则包的 WCU 超过雷达设定的上限，挂上前先删减规则' },
  fail:        { label: 'AWS 拒绝了规则', tone: 'loss', hint: 'CheckCapacity 报错：有规则 AWS 不接受（原因见下）' },
  unchecked:   { label: 'WCU 未检查',     tone: 'warn', hint: '本轮没有调用 CheckCapacity 或调用失败 —— 不是 0 WCU' },
};

export const POC_STATE: Record<RulePackPoc['state'], StateWord> = {
  found:       { label: '有模板',             tone: 'ok',    hint: 'nuclei-templates 有这个 CVE 的模板，已按 commit SHA 钉住' },
  no_template: { label: '暂无模板',           tone: 'muted', hint: 'nuclei-templates 的索引里还没有这个 CVE（模板通常晚于 CVE 约两周）' },
  unavailable: { label: 'PoC 来源暂不可用',   tone: 'warn',  hint: '没读到 nuclei-templates 索引 —— 不是「没有模板」' },
  too_large:   { label: '模板过大未读',       tone: 'warn',  hint: '模板超过雷达的大小上限，未解析' },
  error:       { label: '读取失败 · 需注意',  tone: 'warn',  hint: '取模板失败（见原因），下一轮重试' },
};

export const CONFIDENCE: Record<RulePackRule['confidence'], { label: string; hint: string }> = {
  exact:     { label: '逐字', hint: '特征逐字取自模板 / 证据，字段明确' },
  heuristic: { label: '启发式', hint: '模板默认值或 AWS 签名（SqliMatch / 速率），误报风险更高，观察期加倍' },
};

export const OFFLINE_STATE: Record<'pass' | 'fail' | 'unchecked', StateWord> = {
  pass:      { label: '离线验证通过', tone: 'ok',   hint: '正样本全中、负样本全不中（雷达离线 WAF 语义匹配器）' },
  fail:      { label: '离线验证失败', tone: 'loss', hint: '样本与规则矛盾 —— 不会出现在规则包里' },
  unchecked: { label: '离线无法验证', tone: 'warn', hint: 'AWS 维护的签名（SqliMatch / 速率）离线无法判定，需线上回放' },
};

/** Capacity line: a WCU number only when the backend has one — unchecked never reads as 0. */
export function capacityText(c: RulePackCapacity): string {
  if (c.wcu === null || c.wcu === undefined) return `${CAPACITY_STATE[c.state].label}：${c.detail}`;
  return c.state === 'over_budget' ? `${c.wcu} WCU（上限 ${c.max_wcu ?? '?'}）` : `${c.wcu} WCU`;
}

export interface QuoteView { text: string; href: string | undefined }

/**
 * One source quote as the page shows it: template pointer (repo@sha path:line + token) or the evidence sentence.
 * The link is the backend's (rulepack.quote_href: pinned commit with a gated path / an http(s) item URL) — never
 * rebuilt here from feed-controlled path / url fields. No href ⇒ plain text, no link.
 */
export function quoteView(q: RulePackRule['source_quotes'][number]): QuoteView {
  const href = q.href ?? undefined;
  if ('repo' in q) return { text: `${q.repo}@${q.sha.slice(0, 10)} ${q.path}:${q.line} · 「${q.token}」`, href };
  return { text: `「${q.sentence}」`, href };
}

export function ruleCount(p: RulePack): number {
  return p.custom.length + p.templates.length;
}

/** Download a rendering as a file. Returns false (shown to the user) when the browser refuses — never a silent no-op. */
export function downloadText(filename: string, mediaType: string, text: string): boolean {
  try {
    const url = URL.createObjectURL(new Blob([text], { type: `${mediaType};charset=utf-8` }));
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    return true;
  } catch {
    return false;
  }
}
