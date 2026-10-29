/**
 * ScopeWithLabels — the 2D wall radar (CI / software GL / reduced-motion path): RadarScope centred in the stage,
 * plus the same NOW leader labels as the 3D dome (spec 01 §6.4 step 3). Anchors come from utils/radarLayout
 * scopePointPx, the geometry RadarScope itself draws with, so a label always points at its dot.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import type { RadarDot } from '@/utils/radarLayout';
import { scopePointPx } from '@/utils/radarLayout';
import { LeaderLabels } from '@/components/radar/LeaderLabels';
import type { LeaderLabelItem } from '@/components/radar/LeaderLabels';

interface Props {
  scope: ReactNode;
  /** Unclustered dots (a NOW dot inside a cluster still has its own position). */
  dots: RadarDot[];
  size: number;
  labels: LeaderLabelItem[];
  onSelect: (eventId: string) => void;
}

export function ScopeWithLabels({ scope, dots, size, labels, onSelect }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [box, setBox] = useState({ w: 0, h: 0 });

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setBox({ w: Math.floor(e.contentRect.width), h: Math.floor(e.contentRect.height) }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const anchors = useMemo(() => {
    const ox = (box.w - size) / 2;
    const oy = (box.h - size) / 2;
    const byId = new Map(dots.map(d => [d.eventId, d]));
    const out: Record<string, { x: number; y: number; visible: boolean }> = {};
    for (const l of labels) {
      const d = byId.get(l.id);
      if (!d) continue; // not on the radar (>7 d) ⇒ rail label says so
      const p = scopePointPx(d.angleDeg, d.radiusFrac, size);
      out[l.id] = { x: ox + p.x, y: oy + p.y, visible: true };
    }
    return out;
  }, [dots, labels, size, box.w, box.h]);

  return (
    <div ref={ref} className="scope-stage">
      {scope}
      {box.w > 0 && labels.length > 0 && (
        <LeaderLabels items={labels} anchors={anchors} width={box.w} height={box.h} onSelect={onSelect} />
      )}
    </div>
  );
}
