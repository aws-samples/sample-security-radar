import { legendItems, type LegendItem } from '@/utils/stageKey';

/** The swatch of a legend item, drawn as the scope draws dots (colour = severity, size, distance, shape). */
function Swatch({ k }: { k: LegendItem['key'] }) {
  const s = { height: 12, flexShrink: 0 } as const;
  switch (k) {
    case 'color': return (<svg {...s} width={36} viewBox="0 0 36 12" aria-hidden="true"><circle cx="5" cy="6" r="4" fill="var(--p0)" /><circle cx="17" cy="6" r="4" fill="var(--p1)" /><circle cx="29" cy="6" r="4" fill="var(--p2)" /></svg>);
    case 'size': return (<svg {...s} width={30} viewBox="0 0 30 12" aria-hidden="true"><circle cx="4" cy="6" r="2.2" fill="var(--text-3)" /><circle cx="12" cy="6" r="3.4" fill="var(--text-3)" /><circle cx="23" cy="6" r="5.5" fill="var(--text-3)" /></svg>);
    case 'distance': return (<svg {...s} width={26} viewBox="0 0 26 12" aria-hidden="true"><path d="M1 11 A12 12 0 0 1 25 11" fill="none" stroke="var(--text-3)" strokeWidth="1.1" /><path d="M7 11 A6 6 0 0 1 19 11" fill="none" stroke="var(--text-3)" strokeWidth="1.1" /><circle cx="13" cy="11" r="1.8" fill="var(--accent)" /></svg>);
    case 'shape': return (<svg {...s} width={34} viewBox="0 0 34 12" aria-hidden="true"><circle cx="5" cy="6" r="3.6" fill="none" stroke="var(--text-3)" strokeWidth="1.3" /><circle cx="16" cy="6" r="3.6" fill="var(--text-3)" /><path d="M28 1.8 L32 6 L28 10.2 L24 6 Z" fill="var(--text-3)" /></svg>);
  }
}

/** R9.4: one always-visible line under the scope — what a dot's colour, size, distance and shape mean. */
export function StageLegend() {
  return (
    <ul className="stage-legend" data-testid="stage-legend" aria-label="雷达图例">
      {legendItems().map(it => (
        <li key={it.key}><Swatch k={it.key} /><b>{it.label}</b><span>{it.text}</span></li>
      ))}
    </ul>
  );
}
