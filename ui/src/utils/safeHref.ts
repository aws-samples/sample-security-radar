/**
 * Links to the outside world come from third-party data (feed item URLs, explorer links, console / PR URLs echoed
 * back by AWS APIs). Only http(s) is rendered as a link: a `javascript:` or `data:` URL in a feed would otherwise be
 * one click from script execution on the radar's own origin (semgrep react-href-var, Probe 2026-10-29).
 * undefined ⇒ the <a> renders without href (not a link, not focusable).
 */
export function safeHref(url: string | null | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : undefined;
  } catch {
    return undefined;   // relative or malformed: external links are always absolute
  }
}
