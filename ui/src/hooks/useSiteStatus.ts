import { useEffect, useRef, useState } from 'react';

const POLL_MS = 60_000;

export interface SiteStatusState {
  generatedAt: string | null;
  /** seconds since status.json was last read successfully; null before the first read */
  sinceFetchSecs: number | null;
  deployedBuild: string | null;
}

/** One poll: data/status.json (the publish beacon, a few bytes — not the 400 KB listing) and version.json (the
 *  deployed UI build), both no-store. A failed read yields null for that half; the caller keeps what it had. */
export async function readStatus(fetchFn: typeof fetch = fetch): Promise<{ generatedAt: string | null; build: string | null }> {
  const json = (url: string) => fetchFn(url, { cache: 'no-store' }).then(r => (r.ok ? r.json() : null)).catch(() => null);
  const [st, ver] = await Promise.all([json('./data/status.json'), json('./version.json')]);
  return {
    generatedAt: st && st.kind === 'status' && typeof st.generated_at === 'string' ? st.generated_at : null,
    build: ver && typeof ver.build === 'string' ? ver.build : null,
  };
}

export function useSiteStatus(): SiteStatusState {
  const [s, set] = useState<SiteStatusState>({ generatedAt: null, sinceFetchSecs: null, deployedBuild: null });
  const last = useRef<number | null>(null);
  useEffect(() => {
    const read = () => readStatus().then(r => {
      if (r.generatedAt) last.current = Date.now();
      // a failed status read keeps the old time: its age keeps growing into 刷新失败, never a silent "fresh"
      set(p => ({ generatedAt: r.generatedAt ?? p.generatedAt, deployedBuild: r.build ?? p.deployedBuild,
                  sinceFetchSecs: last.current === null ? null : Math.floor((Date.now() - last.current) / 1000) }));
    });
    read();
    const poll = setInterval(read, POLL_MS);
    const tick = setInterval(() => {
      if (last.current !== null) set(p => ({ ...p, sinceFetchSecs: Math.floor((Date.now() - (last.current ?? 0)) / 1000) }));
    }, 5_000);
    return () => { clearInterval(poll); clearInterval(tick); };
  }, []);
  return s;
}
