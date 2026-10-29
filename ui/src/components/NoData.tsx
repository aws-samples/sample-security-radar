/** Unified "no data" block: hatched + italic so it can never be mistaken for a real 0 (BRIEF §3). */
export function NoData({ children }: { children: React.ReactNode }) {
  return <span className="nodata">{children}</span>;
}
