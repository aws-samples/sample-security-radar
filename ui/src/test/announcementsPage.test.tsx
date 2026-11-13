/**
 * #/announcements links come verbatim from exchanges' JSON: only http(s) may become an href (research/action/05 #2,
 * 06 B2 — the one third-party link in the UI that bypassed safeHref; React 18 does not block javascript: URLs).
 */
import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import type { Notice } from '@/types/site-data';

const notice = (title: string, url: string): Notice => ({ source_id: 'ex_okx', exchange: 'OKX', title, url, kind: 'other',
                                                          category: null, published_at: '2026-11-10T00:00:00Z', seen_at: '2026-11-10T00:00:00Z' });
vi.mock('@/hooks/useAnnouncements', () => ({
  useAnnouncements: () => ({
    notices: [notice('poisoned', 'javascript:alert(document.domain)'), notice('fine', 'https://www.okx.com/help/1')],
    boards: [], counts: {}, generatedAt: null, loading: false, error: null,
  }),
}));

describe('announcement links', () => {
  it('a javascript: notice URL is not rendered as a link; an https one is', async () => {
    const { AnnouncementsPage } = await import('@/pages/AnnouncementsPage');
    const html = renderToStaticMarkup(<AnnouncementsPage />);
    expect(html).not.toContain('javascript:');
    expect(html).toContain('href="https://www.okx.com/help/1"');
    expect(html).toContain('poisoned');
  });
});
