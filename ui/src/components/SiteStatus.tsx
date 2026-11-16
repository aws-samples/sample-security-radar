import { useSiteStatus } from '@/hooks/useSiteStatus';
import { freshness } from '@/utils/staleness';
import { newVersion, statusLine, type StatusLine } from '@/utils/siteStatus';

const TONE = { ok: 'var(--status-ok)', warn: 'var(--status-degraded)', error: 'var(--status-failing)',
               muted: 'var(--status-never)' } as const;

/** R3.3 — the one freshness indicator, in the sidebar of every page, plus a reload offer after a UI deploy. */
export function SiteStatus() {
  const s = useSiteStatus();
  return <SiteStatusView line={statusLine(freshness(s.generatedAt, s.sinceFetchSecs, Date.now()))}
                         stale={newVersion(s.deployedBuild, __BUILD_ID__)} />;
}

export function SiteStatusView({ line, stale }: { line: StatusLine; stale: boolean }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
      <span role="status" data-testid="site-status" data-tone={line.tone}
            style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
        <span aria-hidden="true" style={{ width: 7, height: 7, borderRadius: '50%', background: TONE[line.tone], flexShrink: 0 }} />
        {line.text}
      </span>
      {stale && (
        <button type="button" onClick={() => window.location.reload()} data-testid="reload-offer"
                style={{ fontSize: 11, padding: '2px 8px', borderRadius: 12, border: '1px solid var(--border)',
                         background: 'var(--bg-surface-2)', color: 'var(--text-primary)', cursor: 'pointer', textAlign: 'left' }}>
          页面有新版本 · 刷新
        </button>
      )}
    </div>
  );
}
