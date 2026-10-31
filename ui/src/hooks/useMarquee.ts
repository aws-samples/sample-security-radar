/**
 * Seamless vertical marquee for the wall's live feed and ticker.
 *
 * Why this exists (user report 2026-10-30: 「实时事件流像是卡住了，从来不滚动，只是上下抖动」): the old loops did
 * `scrollTop += 0.4` on a flex column whose cards shrank to fit — only ~57 px ever overflowed, so the list crept
 * 57 px and snapped back to 0 every ~2 s. Now: items sit in a non-shrinking copy, a second inert copy follows it, and
 * the offset wraps by exactly one copy's period, so the loop has no visible seam. Offset is a float accumulator
 * (scrollTop rounds to device pixels; adding sub-pixel steps to it read back can stall).
 */
import { useEffect, useLayoutEffect, useRef, useState } from 'react';

/** Next scroll offset: advance by speed·dt and wrap by one copy's period (the second copy makes the wrap invisible). */
export function marqueeOffset(acc: number, dtMs: number, pxPerSec: number, period: number): number {
  if (period <= 0) return 0;
  const next = acc + (pxPerSec * Math.min(dtMs, 100)) / 1000;   // clamp: a background tab must not jump a page
  return next >= period ? next % period : next;
}

/** `loop` ⇒ render the second copy (aria-hidden + inert) after the first; refs go on viewport / first / second copy. */
export function useMarquee(paused: boolean, pxPerSec: number, contentKey: unknown) {
  const viewport = useRef<HTMLDivElement>(null);
  const first = useRef<HTMLDivElement>(null);
  const second = useRef<HTMLDivElement>(null);
  const [loop, setLoop] = useState(false);

  // Loop only when one copy is taller than the viewport; otherwise a duplicate would show the list twice.
  useLayoutEffect(() => {
    const v = viewport.current, a = first.current;
    if (!v || !a) return;
    const measure = () => setLoop(a.offsetHeight > v.clientHeight + 1);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(v);
    ro.observe(a);
    return () => ro.disconnect();
  }, [contentKey]);

  useEffect(() => {
    const v = viewport.current;
    if (!v) return;
    if (!loop) { v.scrollTop = 0; return; }
    if (paused || window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
    let acc = v.scrollTop, last = performance.now(), raf = 0;
    const tick = (now: number) => {
      const a = first.current, b = second.current;
      if (a && b) {
        acc = marqueeOffset(acc, now - last, pxPerSec, b.offsetTop - a.offsetTop);
        v.scrollTop = acc;
      }
      last = now;
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [loop, paused, pxPerSec, contentKey]);

  return { viewport, first, second, loop };
}

/** Props for the duplicate copy: hidden from AT and unfocusable (React 18 has no typed `inert`). */
export const CLONE_PROPS = { 'aria-hidden': true, inert: '' } as Record<string, unknown>;
