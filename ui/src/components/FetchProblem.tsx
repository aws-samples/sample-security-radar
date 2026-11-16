/** R3.2 (audit 03 4.1-row): a page that already shows data must not turn into a red error screen because one poll
 *  failed — the hooks keep the last data, so say that above it. Only a page with nothing loaded gets the full error. */
export function FetchProblem({ error, hasData }: { error: string; hasData: boolean }) {
  if (hasData) {
    return (
      <p role="status" data-testid="fetch-problem" data-kind="stale"
         style={{ margin: '8px 16px', fontSize: 12, color: 'var(--status-degraded)' }}>
        最近一次刷新失败（{error}）—— 下面是上次读到的数据
      </p>
    );
  }
  return (
    <div role="alert" data-testid="fetch-problem" data-kind="empty"
         style={{ padding: 40, color: 'var(--sev-p0)', fontFamily: 'var(--font-mono)' }}>
      数据加载失败：{error}
    </div>
  );
}
