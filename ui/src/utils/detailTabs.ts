/** Event page tabs: 事件跟踪 (default — the incident itself) and 在你的环境中 (what the radar and the AWS agents did in
 *  your code). `?tab=env`, and the older `?section=env` deep link, open the environment tab; `?section=evidence` and
 *  anything else open the incident. */
export type DetailTab = 'track' | 'env';

export const TABS: { id: DetailTab; label: string; en: string }[] = [
  { id: 'track', label: '事件跟踪', en: 'Incident' },
  { id: 'env', label: '在你的环境中', en: 'Your environment' },
];

export function detailTab(params: URLSearchParams): DetailTab {
  return params.get('tab') === 'env' || params.get('section') === 'env' ? 'env' : 'track';
}

/** Arrow keys move between tabs (WAI-ARIA tabs pattern), wrapping at both ends. */
export function nextTab(cur: DetailTab, key: string): DetailTab | null {
  const i = TABS.findIndex(t => t.id === cur);
  if (key === 'ArrowRight') return TABS[(i + 1) % TABS.length].id;
  if (key === 'ArrowLeft') return TABS[(i - 1 + TABS.length) % TABS.length].id;
  if (key === 'Home') return TABS[0].id;
  if (key === 'End') return TABS[TABS.length - 1].id;
  return null;
}
