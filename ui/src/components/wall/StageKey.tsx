import { useState } from 'react';
import { stageKeyRows, type KeyRow, type StageMode } from '@/utils/stageKey';

/** The glyph each key row explains, drawn like the stage draws it (2D dot shapes / 3D pillar, sphere, link, ring). */
function Glyph({ g, mode }: { g: KeyRow['glyph']; mode: StageMode }) {
  const s = { width: 22, height: 14, flexShrink: 0 } as const;
  switch (g) {
    case 'position': return (<svg {...s} viewBox="0 0 22 14" aria-hidden="true"><path d="M2 13 A10 10 0 0 1 20 13" fill="none" stroke="var(--text-3)" strokeWidth="1.2" /><path d="M6 13 A6 6 0 0 1 16 13" fill="none" stroke="var(--text-3)" strokeWidth="1.2" /><circle cx="11" cy="13" r="1.6" fill="var(--accent)" /></svg>);
    case 'mark': return mode === '2d'
      ? (<svg {...s} viewBox="0 0 22 14" aria-hidden="true"><circle cx="4" cy="7" r="3" fill="none" stroke="var(--p1)" strokeWidth="1.3" /><circle cx="11" cy="7" r="3" fill="var(--p1)" /><path d="M18 3.5 L21 7 L18 10.5 L15 7 Z" fill="var(--p0)" /></svg>)
      : (<svg {...s} viewBox="0 0 22 14" aria-hidden="true"><rect x="3" y="7" width="3" height="7" fill="var(--text-3)" /><rect x="9" y="4" width="3" height="10" fill="var(--p1)" /><rect x="15" y="0" width="3.5" height="14" fill="var(--p0)" /></svg>);
    case 'core': return (<svg {...s} viewBox="0 0 22 14" aria-hidden="true"><circle cx="11" cy="7" r="5.5" fill="none" stroke="var(--accent)" strokeWidth="1.2" /><path d="M5.5 7 H16.5 M11 1.5 V12.5" stroke="var(--accent)" strokeWidth="0.8" /></svg>);
    case 'link': return (<svg {...s} viewBox="0 0 22 14" aria-hidden="true"><path d="M1 4 H21" stroke="var(--p0)" strokeWidth="2" /><path d="M1 10 H21" stroke="var(--accent)" strokeWidth="1.6" strokeDasharray="3 2.5" /></svg>);
    case 'ring': return (<svg {...s} viewBox="0 0 22 14" aria-hidden="true"><path d="M3 11 A9 9 0 0 1 9 3.6" fill="none" stroke="var(--status-ok)" strokeWidth="2" /><path d="M11 3 A9 9 0 0 1 17 5" fill="none" stroke="var(--text-3)" strokeWidth="2" /><path d="M18.5 6.5 A9 9 0 0 1 19.5 11" fill="none" stroke="var(--p1)" strokeWidth="2" /></svg>);
  }
}

/** R9.4: a persistent key — how to read the stage, in words, over its top-left corner; foldable (folded on a phone). */
export function StageKey({ mode, defaultOpen = true }: { mode: StageMode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const rows = stageKeyRows(mode);
  if (rows.length === 0) return null;        // 2D: the strip says it all
  return (
    <div className="stage-key" data-testid="stage-key" data-open={open}>
      <button type="button" className="stage-key-head" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        怎么读这张图 <span aria-hidden="true">{open ? '−' : '+'}</span>
      </button>
      {open && (
        <dl className="stage-key-rows">
          {rows.map(r => (
            <div key={r.title} className="stage-key-row">
              <dt><Glyph g={r.glyph} mode={mode} /><span>{r.title}</span></dt>
              <dd>{r.text}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}
