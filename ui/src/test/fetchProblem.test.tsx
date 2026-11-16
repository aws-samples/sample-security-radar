import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { FetchProblem } from '@/components/FetchProblem';

describe('R3.2 one failed poll does not blank a page that has data', () => {
  it('keeps the data with a notice, and only an empty page gets the error screen', () => {
    const stale = renderToStaticMarkup(<FetchProblem error="HTTP 503" hasData />);
    expect(stale).toContain('data-kind="stale"');
    expect(stale).toContain('上次读到的数据');
    expect(renderToStaticMarkup(<FetchProblem error="HTTP 503" hasData={false} />)).toContain('data-kind="empty"');
  });

  it('every page with a whole-page error branch goes through it', async () => {
    const fs = await import('fs');
    for (const page of ['VulnPage', 'Web3Page', 'SourcesPage', 'AnnouncementsPage', 'SearchPage']) {
      const src = fs.readFileSync(`src/pages/${page}.tsx`, 'utf8');
      expect(src, page).not.toMatch(/if \(error\)\s*(return|\{)/);
    }
  });
});
