import type { ListingWindow } from '@/hooks/useEvents';

/** What the home list is out of: 「列出 500 / 4,348 个（60 天内），其余用搜索」 when the listing was cut, nothing
 *  when it holds the whole window (audit 03 6.2: a cut list read as the whole). */
export function cutNote(w: ListingWindow | null): string | null {
  if (!w || w.listed >= w.total) return null;
  const n = (x: number) => x.toLocaleString('en-US');
  return `列出 ${n(w.listed)} / ${n(w.total)} 个（${w.days} 天内）：近 24 小时有更新的都在，其余 ${n(w.total - w.listed)} 个用搜索`;
}
