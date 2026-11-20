/**
 * Where a dot's tip goes (Neo 2026-11-19: 「当前给到的这个标签会和我点击这些圆圈上展示的标签有覆盖效果…看不到我点击的
 * 这个圆圈所体现的标签，因为你会把当前呈现的三个标签置顶」). The tip is drawn ABOVE the NOW labels, beside its dot,
 * flipped to stay inside the stage. Pure — tested.
 */
export const TIP = { w: 220, h: 58, gap: 12, pad: 6 } as const;

export function tipPlacement(ax: number, ay: number, box: { w: number; h: number }): { left: number; top: number; side: 'left' | 'right' } {
  const right = ax + TIP.gap + TIP.w <= box.w - TIP.pad;              // room on the right of the dot?
  const left = right ? ax + TIP.gap : Math.max(TIP.pad, ax - TIP.gap - TIP.w);
  const top = Math.min(Math.max(TIP.pad, ay - TIP.h / 2), Math.max(TIP.pad, box.h - TIP.h - TIP.pad));
  return { left, top, side: right ? 'right' : 'left' };
}

/** 「3h 前」 / 「2d 前」 from a first-seen time. */
export function ageWord(firstSeen: string, nowMs: number = Date.now()): string {
  const h = (nowMs - Date.parse(firstSeen)) / 3_600_000;
  if (!Number.isFinite(h)) return '';
  return h < 1 ? `${Math.max(1, Math.round(h * 60))} 分钟前` : h < 24 ? `${Math.round(h)} 小时前` : `${Math.round(h / 24)} 天前`;
}
