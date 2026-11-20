/** R9.1: the sidebar is expanded ('full') or an icon rail ('rail'). One definition of the default and the storage. */
export type NavMode = 'full' | 'rail';
const KEY = 'sr-nav';
export const RAIL_BELOW_PX = 1100;    // with no stored choice: a rail below this width (iPad), expanded above

export function initialNavMode(width: number = typeof window === 'undefined' ? 1440 : window.innerWidth,
                               stored: string | null = readStored()): NavMode {
  if (stored === 'full' || stored === 'rail') return stored;   // anything else (a hand edit, old value) ⇒ the default
  return width < RAIL_BELOW_PX ? 'rail' : 'full';
}

function readStored(): string | null {
  try { return localStorage.getItem(KEY); } catch { return null; }   // storage blocked (private mode): the default
}

export function storeNavMode(m: NavMode): void {
  try { localStorage.setItem(KEY, m); } catch { /* storage blocked: the choice lasts this page only */ }
}

/** The wall's route (#/wall, with or without a query): it opens with the sidebar collapsed. */
export function isWallPath(pathname: string): boolean {
  return pathname === '/wall' || pathname.startsWith('/wall/');
}
