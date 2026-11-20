/**
 * ScopeWithLabels — the 2D wall radar (CI / software GL / reduced-motion path): RadarScope centred in the stage,
 * plus the same NOW leader labels as the 3D dome (spec 01 §6.4 step 3). Anchors come from utils/radarLayout
 * scopePointPx, the geometry RadarScope itself draws with, so a label always points at its dot.
 */
import { cloneElement, isValidElement, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactElement, ReactNode } from 'react';
import { DotTip } from '@/components/radar/DotTip';
import type { RadarDot } from '@/utils/radarLayout';
import { SCOPE, scopePointPx } from '@/utils/radarLayout';

/** The scope's outer rim (RadarScope R_RIM = 200 in the 520 viewBox) plus its sector capsules' reach. */
const SCOPE_RIM = 212;
import { LeaderLabels } from '@/components/radar/LeaderLabels';
import type { LeaderLabelItem } from '@/components/radar/LeaderLabels';

interface Props {
  scope: ReactNode;
  /** Unclustered dots (a NOW dot inside a cluster still has its own position). */
  dots: RadarDot[];
  size: number;
  labels: LeaderLabelItem[];
  onSelect: (eventId: string) => void;
  /** The event open in the drawer: its label stays, the others dim. */
  selectedId?: string | null;
}

export function ScopeWithLabels({ scope, dots, size, labels, onSelect, selectedId = null }: Props) {
  const [hovered, setHovered] = useState<RadarDot | null>(null);
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

  // the dot under the pointer: its tip is drawn here, above the NOW labels (it was inside the SVG, below them)
  const tipAt = useMemo(() => {
    if (!hovered) return null;
    const p = scopePointPx(hovered.angleDeg, hovered.radiusFrac, size);
    return { x: (box.w - size) / 2 + p.x, y: (box.h - size) / 2 + p.y };
  }, [hovered, size, box.w, box.h]);
  const focusId = hovered?.eventId ?? selectedId;
  // the scope's circle in stage px: the NOW badges go outside it (Neo 2026-11-19: they covered the centre)
  const circle = useMemo(() => ({ cx: (box.w - size) / 2 + (size * SCOPE.cx) / SCOPE.viewBox,
    cy: (box.h - size) / 2 + (size * SCOPE.cy) / SCOPE.viewBox, r: (size * SCOPE_RIM) / SCOPE.viewBox }), [box.w, box.h, size]);
  const scopeEl = isValidElement(scope)
    ? cloneElement(scope as ReactElement<{ onHoverDot?: (d: RadarDot | null) => void }>, { onHoverDot: setHovered })
    : scope;

  return (
    <div ref={ref} className="scope-stage">
      {scopeEl}
      {box.w > 0 && labels.length > 0 && (
        <LeaderLabels items={labels} anchors={anchors} width={box.w} height={box.h} onSelect={onSelect} focusId={focusId} outside={circle} />
      )}
      {hovered && tipAt && <DotTip dot={hovered} x={tipAt.x} y={tipAt.y} box={box} />}
    </div>
  );
}
