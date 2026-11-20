/**
 * The navigation's own icon set (R9.1): one 20 px grid, one 1.6 stroke, round caps — in the collapsed rail the icon is
 * the only identifier, and the Unicode glyphs it replaces (⬡ ◈ ◎ ⊞ …) rendered at different sizes and weights per font.
 */
const PATHS: Record<string, string> = {
  radar: 'M10 10 L15.5 4.5 M10 2.5a7.5 7.5 0 1 0 7.5 7.5 M10 6a4 4 0 1 0 4 4',
  vuln: 'M10 2.5 L17 6.5 V13.5 L10 17.5 L3 13.5 V6.5 Z M10 7 V10.5 M10 13 V13.2',
  web3: 'M6 4.5 L10 2.5 L14 4.5 V9 L10 11 L6 9 Z M6 9 V14 L10 16 L14 14 V9 M10 11 V16',
  wall: 'M2.5 4 H17.5 V13 H2.5 Z M7 16.5 H13 M10 13 V16.5',
  continuum: 'M15.5 7 A6 6 0 1 0 16 11 M15.5 3.5 V7 H12',
  search: 'M8.5 3 a5.5 5.5 0 1 0 0 11 a5.5 5.5 0 1 0 0 -11 M12.5 12.5 L17 17',
  announce: 'M3 8 V12 H6 L13 15.5 V4.5 L6 8 Z M15.5 7.5 a3 3 0 0 1 0 5',
  subscribe: 'M4 4 a12 12 0 0 1 12 12 M4 8.5 a7.5 7.5 0 0 1 7.5 7.5 M4.5 15.5 h.01',
  sources: 'M10 3 a7 7 0 1 0 0 14 a7 7 0 1 0 0 -14 M3 10 H17 M10 3 c-2.5 2.4 -2.5 11.6 0 14 M10 3 c2.5 2.4 2.5 11.6 0 14',
  ops: 'M4 17.5 V3 M4 3.5 H14 L12 7 L14 10.5 H4',
  mitigate: 'M10 2.5 L16 5 V10 c0 3.6 -2.6 6.4 -6 7.5 c-3.4 -1.1 -6 -3.9 -6 -7.5 V5 Z M7.5 10 L9.3 11.8 L12.8 8.3',
  collapse: 'M12.5 5 L7.5 10 L12.5 15',
  expand: 'M7.5 5 L12.5 10 L7.5 15',
  menu: 'M3.5 6 H16.5 M3.5 10 H16.5 M3.5 14 H16.5',
  close: 'M5 5 L15 15 M15 5 L5 15',
  fullscreen: 'M3 7.5 V3 H7.5 M12.5 3 H17 V7.5 M17 12.5 V17 H12.5 M7.5 17 H3 V12.5',
  shrink: 'M7.5 3 V7.5 H3 M17 7.5 H12.5 V3 M12.5 17 V12.5 H17 M3 12.5 H7.5 V17',
  moon: 'M15.5 12.5 A6.5 6.5 0 1 1 7.5 4.5 A5 5 0 0 0 15.5 12.5 Z',
  sun: 'M10 6.5 a3.5 3.5 0 1 0 0 7 a3.5 3.5 0 1 0 0 -7 M10 2.5 V4 M10 16 V17.5 M2.5 10 H4 M16 10 H17.5 M4.7 4.7 L5.8 5.8 M14.2 14.2 L15.3 15.3 M4.7 15.3 L5.8 14.2 M14.2 5.8 L15.3 4.7',
};

export type NavIconName = keyof typeof PATHS;

export function NavIcon({ name, size = 18 }: { name: NavIconName; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth={1.6}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" style={{ flexShrink: 0 }}>
      <path d={PATHS[name]} />
    </svg>
  );
}
