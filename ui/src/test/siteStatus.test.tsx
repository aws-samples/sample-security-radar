import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { SiteStatusView } from '@/components/SiteStatus';
import { readStatus } from '@/hooks/useSiteStatus';
import { judgedAgo, newVersion, statusLine } from '@/utils/siteStatus';
import { freshness, PUBLISH_STALE_SECS } from '@/utils/staleness';

const NOW = Date.parse('2026-11-15T04:00:00Z');
const ago = (s: number) => new Date(NOW - s * 1000).toISOString();

describe('R3.3 the site-wide status line', () => {
  it('says how old the data is, the same way on every page', () => {
    expect(statusLine(freshness(ago(20), 0, NOW))).toEqual({ tone: 'ok', text: '数据刚更新' });
    expect(statusLine(freshness(ago(7 * 60), 0, NOW))).toEqual({ tone: 'ok', text: '数据 7 分钟前更新' });
    expect(statusLine(freshness(ago(PUBLISH_STALE_SECS + 60), 0, NOW)).tone).toBe('warn');
    expect(statusLine(freshness(ago(60), 600, NOW))).toEqual({ tone: 'error', text: '刷新失败 10 分钟' });
    expect(statusLine(freshness(null, null, NOW)).tone).toBe('muted');
  });

  it('offers a reload only when the deployed build differs from the running one', () => {
    expect(newVersion('abc1234', 'abc1234')).toBe(false);
    expect(newVersion('def5678', 'abc1234')).toBe(true);
    expect(newVersion(null, 'abc1234')).toBe(false);          // no version.json: nothing claimed
  });
});

describe('SiteStatus', () => {
  const fake = (bodies: Record<string, unknown>, urls: string[]) => ((url: string) => {
    urls.push(url);
    const b = Object.entries(bodies).find(([k]) => url.includes(k))?.[1];
    return Promise.resolve({ ok: b !== undefined, json: () => Promise.resolve(b) });
  }) as unknown as typeof fetch;

  it('polls the beacon and the deployed build — not the 400 KB listing', async () => {
    const urls: string[] = [];
    const r = await readStatus(fake({ 'status.json': { kind: 'status', generated_at: ago(30) }, 'version.json': { build: 'b2' } }, urls));
    expect(r).toEqual({ generatedAt: ago(30), build: 'b2' });
    expect(urls.sort()).toEqual(['./data/status.json', './version.json']);
  });

  it('a missing or wrong file is null, never a made-up time or build', async () => {
    const r = await readStatus(fake({ 'status.json': { kind: 'events', generated_at: ago(1) } }, []));
    expect(r).toEqual({ generatedAt: null, build: null });
  });

  it('shows the line and offers a reload only when a newer build is live', () => {
    const html = renderToStaticMarkup(<SiteStatusView line={{ tone: 'warn', text: '数据已 31 分钟未更新' }} stale />);
    expect(html).toContain('数据已 31 分钟未更新');
    expect(html).toContain('data-tone="warn"');
    expect(html).toContain('页面有新版本');
    expect(renderToStaticMarkup(<SiteStatusView line={{ tone: 'ok', text: '数据刚更新' }} stale={false} />)).not.toContain('页面有新版本');
  });
});

describe('audit 03 4.8: a detail page says when it judged', () => {
  it('is silent for a fresh page and names hours, then days', () => {
    expect(judgedAgo(ago(30 * 60), NOW)).toBeNull();
    expect(judgedAgo(ago(59 * 60), NOW)).toBeNull();
    expect(judgedAgo(ago(3 * 3600), NOW)).toBe('3 小时前判定');
    expect(judgedAgo(ago(47 * 3600), NOW)).toBe('47 小时前判定');
    expect(judgedAgo(ago(15 * 86400), NOW)).toBe('15 天前判定');
    expect(judgedAgo(null, NOW)).toBeNull();
    expect(judgedAgo('not a date', NOW)).toBeNull();
  });
});

describe('the verdict panel carries the age of its judgement', () => {
  it('renders 「N 天前判定」 next to the lifecycle word of an old page', async () => {
    const { VerdictPanel } = await import('@/components/detail/VerdictPanel');
    const { resolveImpact } = await import('@/utils/response');
    const fs = await import('fs');
    const ev = { ...JSON.parse(fs.readFileSync('mock-data/data/events.json', 'utf8')).events[0], lifecycle: 'active' };
    const props = { event: ev, analysis: null, progress: undefined, response: null, impact: resolveImpact(undefined, null, undefined),
                    cite: () => undefined, onCite: () => {}, onEnv: () => {} };
    const old = renderToStaticMarkup(<VerdictPanel {...props} generatedAt={new Date(Date.now() - 15 * 86400_000).toISOString()} />);
    expect(old).toContain('15 天前判定');
    expect(renderToStaticMarkup(<VerdictPanel {...props} generatedAt={new Date().toISOString()} />)).not.toContain('前判定');
    // the page hands its own time to the panel (the hook reads generated_at from the detail document)
    const page = fs.readFileSync('src/pages/EventDetailPage.tsx', 'utf8');
    expect(page).toContain('generatedAt={d.generatedAt}');
  });
});
