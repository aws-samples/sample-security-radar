import { useEffect, useState } from 'react';
import type { FeedEntry } from '@/types/site-data';

export interface FeedsState { feeds: FeedEntry[]; generatedAt: string | null; loading: boolean; error: string | null }

export function useFeeds(): FeedsState {
  const [s, set] = useState<FeedsState>({ feeds: [], generatedAt: null, loading: true, error: null });
  useEffect(() => {
    fetch('./data/feeds/index.json')
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(d => {
        if (d.kind !== 'feeds') throw new Error('Unexpected data kind');
        set({ feeds: d.feeds, generatedAt: d.generated_at, loading: false, error: null });
      })
      .catch((e: unknown) => set(x => ({ ...x, loading: false, error: String(e) })));
  }, []);
  return s;
}
