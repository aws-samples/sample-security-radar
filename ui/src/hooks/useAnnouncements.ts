import { useEffect, useState } from 'react';
import type { Notice } from '@/types/site-data';

export interface Board { source_id: string; exchange: string; url: string; last_notice: string | null }
export interface AnnouncementsState {
  notices: Notice[]; boards: Board[]; counts: Record<string, number>;
  generatedAt: string | null; loading: boolean; error: string | null;
}

export function useAnnouncements(): AnnouncementsState {
  const [s, set] = useState<AnnouncementsState>({ notices: [], boards: [], counts: {}, generatedAt: null, loading: true, error: null });
  useEffect(() => {
    const load = () => fetch('./data/announcements.json')
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(d => {
        if (d.kind !== 'announcements') throw new Error('Unexpected data kind');
        set({ notices: d.notices, boards: d.boards, counts: d.counts, generatedAt: d.generated_at, loading: false, error: null });
      })
      .catch((e: unknown) => set(x => ({ ...x, loading: false, error: String(e) })));
    load();
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  }, []);
  return s;
}
