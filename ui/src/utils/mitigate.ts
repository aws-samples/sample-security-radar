import type { InspectorBaselineState, InspectorFinding, MitigateDoc, MitigationDns, MitigationPlan } from '@/types/mitigate';

/** Tone classes come from detail.css (.tone-*); every tone is paired with a text label, never colour alone. */
export type Tone = 'ok' | 'info' | 'warn' | 'loss' | 'muted';
export interface StateWord { label: string; tone: Tone; hint: string }

/**
 * WAF plan state ⇒ 中文. Record<> makes tsc fail on a new schema state; mitigate.test.ts also checks the schema enum
 * at runtime (so a schema edit without regenerating types still goes red).
 */
export const PLAN_STATE: Record<MitigationPlan['state'], StateWord> = {
  staged:        { label: '观察期 · 等人确认', tone: 'info',  hint: '规则以 Count 暂存，确认无误报后切 Block' },
  blocking:      { label: '已拦截',           tone: 'ok',    hint: '规则生效（Block）' },
  absent:        { label: '尚未下发',         tone: 'warn',  hint: 'web ACL 里还没有这个规则组' },
  too_old:       { label: '版本过低 · 需注意', tone: 'warn',  hint: '规则组版本低于覆盖该漏洞的最低版本' },
  group_counted: { label: '整组 Count · 需注意', tone: 'warn', hint: '整个规则组被设为 Count，不拦截' },
  unchecked:     { label: '本轮没查 · 需注意', tone: 'warn',  hint: '读取 web ACL 失败，状态未知（不是"没问题"）' },
  no_web_acl:    { label: '仅给出规则',       tone: 'muted', hint: '目标前没有登记 web ACL，规则由你决定挂在哪里' },
};

export const TIER: Record<MitigationPlan['tier'], { label: string; advisory: boolean }> = {
  cve:     { label: 'CVE 精确', advisory: false },
  product: { label: '产品',     advisory: false },
  cwe:     { label: '通用提示', advisory: true },
};
/** Shown next to every cwe-tier plan: the station never auto-applies these. */
export const ADVISORY_NOTE = '仅建议，不自动下发';

export const DNS_STATE: Record<MitigationDns['state'], StateWord> = {
  in_place:        { label: '已就位',            tone: 'ok',    hint: 'DNS Firewall 规则已在雷达自建规则组中' },
  unchecked:       { label: '本轮没查 · 需注意', tone: 'warn',  hint: '读取 DNS Firewall 失败，状态未知' },
  no_dns_firewall: { label: '未接 DNS Firewall', tone: 'muted', hint: '没有可用的 DNS Firewall 规则组，只列出域名' },
};

export const DNS_ACTION: Record<NonNullable<MitigationDns['action']>, string> = {
  ALERT: 'ALERT（只告警，确认后切 BLOCK）',
  BLOCK: 'BLOCK（已拦截）',
};

/**
 * Inspector dependency baseline per target. Only `scanned` is a verdict; every other state must read as
 * "not judged", never as "no vulnerabilities".
 */
export const BASELINE_STATE: Record<InspectorBaselineState, StateWord> = {
  scanned:     { label: '已判定',   tone: 'ok',    hint: 'Inspector 已对依赖清单做了判定' },
  no_packages: { label: '未判定',   tone: 'muted', hint: '只有运行时版本钉，Inspector 不判定运行时 —— 不代表没有漏洞' },
  deferred:    { label: '推迟',     tone: 'warn',  hint: '本轮推迟，没查 —— 不代表没有漏洞' },
  error:       { label: '没查成',   tone: 'loss',  hint: 'Inspector 调用失败，没查 —— 不代表没有漏洞（见下方"没查成的项"）' },
  never:       { label: '从未查过', tone: 'warn',  hint: '还没有做过依赖判定（没查）—— 不代表没有漏洞' },
};

export const SEVERITY: Record<InspectorFinding['severity'], { label: string; tone: Tone }> = {
  critical: { label: '严重', tone: 'loss' },
  high:     { label: '高',   tone: 'loss' },
  medium:   { label: '中',   tone: 'warn' },
  low:      { label: '低',   tone: 'muted' },
  none:     { label: '无评级', tone: 'muted' },
  unknown:  { label: '未知', tone: 'muted' },
};

/** pkg:npm/%40vitest/mocker@2.1.9 ⇒ "@vitest/mocker@2.1.9" (purl names are percent-encoded; bad escapes stay raw). */
export function purlName(purl: string): string {
  const body = purl.replace(/^pkg:[^/]+\//, '');
  try { return decodeURIComponent(body); } catch { return body; }
}

/**
 * GET mitigate.json. null = not published yet (older backend): a missing file falls through to index.html on the
 * dev/preview server and the CloudFront SPA error page — same rule as useEventDetail. Throws on any other failure.
 */
export async function fetchMitigateDoc(): Promise<MitigateDoc | null> {
  const r = await fetch('./data/mitigate.json');
  const ct = r.headers.get('content-type') ?? '';
  if (r.status === 404 || r.status === 403 || ct.includes('text/html')) return null;
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const d = (await r.json()) as MitigateDoc;
  if (d.kind !== 'mitigate') throw new Error('unexpected data kind');
  return d;
}

/** One edge channel on the wall's shield ring. unknown = not read (≠ off): drawn dashed, never as "protected". */
export type ShieldState = 'on' | 'off' | 'error' | 'unknown';
export interface ShieldChannel { key: 'WAF' | 'DNS' | 'INSPECTOR'; state: ShieldState; detail: string }

/** Station channel names in mitigate.json errors[].channel (radar/mitigate_station.py). */
const CHANNEL_OF: Record<ShieldChannel['key'], string> = { WAF: 'waf', DNS: 'dns', INSPECTOR: 'inspector' };

export function shieldChannels(doc: MitigateDoc | null | undefined): ShieldChannel[] {
  if (!doc) {
    return (['WAF', 'DNS', 'INSPECTOR'] as const).map(key => ({ key, state: 'unknown' as const, detail: '未读取' }));
  }
  const failed = (k: ShieldChannel['key']) => doc.errors.some(e => e.channel === CHANNEL_OF[k]);
  // applied[] is a write log (last 50, oldest first); each write carries the ACL's full radar rule set at that time
  // ⇒ the newest entry per ACL is its current state (an older union would keep showing groups since removed).
  const latest = new Map<string, string[]>();
  for (const a of doc.applied) latest.set(a.web_acl ?? '', a.rules ?? []);
  const groups = new Set([...latest.values()].flat());
  const dnsRules = doc.dns?.rules ?? [];
  const scanned = doc.inspector.filter(b => b.state === 'scanned').length;
  const pick = (k: ShieldChannel['key'], on: boolean, onDetail: string, offDetail: string): ShieldChannel =>
    failed(k) ? { key: k, state: 'error', detail: '本轮失败' }
      : { key: k, state: on ? 'on' : 'off', detail: on ? onDetail : offDetail };
  return [
    pick('WAF', groups.size > 0, `${groups.size} 规则组`, '未下发'),
    pick('DNS', doc.dns?.state === 'in_place', `${dnsRules.length} 条规则`, '未就位'),
    pick('INSPECTOR', scanned > 0, `${scanned}/${doc.inspector.length} 目标`, '未扫描'),
  ];
}
