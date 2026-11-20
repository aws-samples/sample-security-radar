import { ageWord, tipPlacement } from '@/utils/dotTip';

export interface TipDot { title: string; severity: string; level: string; sourcesCount: number; firstSeen: string }

/** The hovered / selected dot's own label — above the NOW labels (which dim meanwhile), beside its dot. */
export function DotTip({ dot, x, y, box }: { dot: TipDot; x: number; y: number; box: { w: number; h: number } }) {
  const p = tipPlacement(x, y, box);
  return (
    <div className={`dot-tip side-${p.side}`} data-testid="dot-tip" role="status" style={{ left: p.left, top: p.top }}>
      <div className="dot-tip-title">{dot.title}</div>
      <div className="dot-tip-meta">
        <b className={`sev-${dot.severity}`}>{dot.severity}</b> · {dot.level} · {dot.sourcesCount} 个独立来源 · {ageWord(dot.firstSeen)}
      </div>
    </div>
  );
}
