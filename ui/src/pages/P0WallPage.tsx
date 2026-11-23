import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { eventsOf, fetchP0, teamLine, wallMarks, visibleGroups, type P0Doc, type P0Event, type P0Tile } from '@/utils/p0wall';
import { formatDateTime, formatRelative } from '@/utils/formatters';
import '@/styles/detail.css';
import '@/styles/p0wall.css';

type Load = { st: 'loading' } | { st: 'absent' } | { st: 'error'; error: string } | { st: 'ok'; doc: P0Doc };

export const EXPLOIT: Record<P0Event['exploitation'], string> = { confirmed: '在野利用', reported: '报道有利用', poc: '公开 PoC', none: '' };

function TileButton({ t, mark, open, onPick }: { t: P0Tile; mark: string; open: boolean; onPick: () => void }) {
  const empty = t.count === 0;
  return (
    <li>
      <button type="button" className={`p0-tile${empty ? ' is-empty' : ''}${open ? ' is-open' : ''}`} onClick={onPick}
        aria-pressed={open} aria-controls={open ? `p0-list-${t.product}` : undefined} disabled={empty}
        aria-label={`${t.label}：${empty ? '暂无 P0' : `${t.count} 个 P0`}${t.exploited ? `，${t.exploited} 个在野利用` : ''}`}>
        <span className="p0-mark" aria-hidden="true">{mark}</span>
        <span className="p0-name">{t.label}</span>
        <span className="p0-count tabular" aria-hidden="true">{empty ? '—' : t.count}</span>
        {(t.exploited > 0 || t.poc > 0) && (
          <span className="p0-flags" aria-hidden="true">
            {t.exploited > 0 && <span className="p0-flag is-wild">在野 {t.exploited}</span>}
            {t.poc > 0 && <span className="p0-flag">PoC {t.poc}</span>}
          </span>
        )}
      </button>
    </li>
  );
}

function TileList({ t, events }: { t: P0Tile; events: P0Event[] }) {
  return (
    <div className="p0-list" id={`p0-list-${t.product}`} role="region" aria-label={`${t.label} 的 P0`}>
      <h3 className="p0-list-h">{t.label} <span className="tabular">· {events.length} 个 P0</span>
        {!t.registered && <span className="p0-note">分类表里没有这个产品，按标题单独成块</span>}</h3>
      <ul>
        {events.map(e => {
          const team = teamLine(e);
          return (
            <li key={e.event_id} className="p0-row">
              <Link className="p0-row-title" to={`/events/${encodeURIComponent(e.event_id)}`}>{e.title}</Link>
              <span className="p0-row-meta">
                <span className={`p0-sev${e.severity === 'P0' ? ' is-p0' : ''}`}>{e.severity === 'P0' ? 'P0' : `已降为 ${e.severity}`}</span>
                <time dateTime={e.p0_at} title={formatRelative(e.p0_at)} className="tabular">升 P0 {formatDateTime(e.p0_at)}</time>
                {EXPLOIT[e.exploitation] && <span className={e.exploitation === 'poc' ? '' : 'p0-wild'}>{EXPLOIT[e.exploitation]}</span>}
                {e.cves.length > 0 && <span className="dt-mono">{e.cves.slice(0, 3).join(' · ')}{e.cves.length > 3 ? ` +${e.cves.length - 3}` : ''}</span>}
                <span className={`p0-team is-${team.tone}`} title={team.reason ?? undefined}>{team.word}{team.reason ? `：${team.reason}` : ''}</span>
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** Pure view, exported for tests (the page fetches, this renders). The open tile is in the URL (?tile=) so a link to
 *  「all MySQL P0s」 can be shared. */
export function P0WallView({ doc }: { doc: P0Doc }) {
  const [params, setParams] = useSearchParams();
  const open = params.get('tile');
  const [firedOnly, setFiredOnly] = useState(false);
  const [cloudOnly, setCloudOnly] = useState(false);
  const groups = useMemo(() => visibleGroups(doc.groups, { firedOnly, cloudOnly }), [doc.groups, firedOnly, cloudOnly]);
  // marks are decided over the whole wall (not the filtered one): a tile keeps its mark when a filter is switched
  const marks = useMemo(() => wallMarks(doc.groups.flatMap(g => g.tiles.map(t => t.label))), [doc.groups]);
  const picked = useRef(false);          // a click (not a shared ?tile= link) brings the opened list into view
  useEffect(() => {
    if (!picked.current || !open) return;
    picked.current = false;
    document.getElementById(`p0-list-${open}`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [open]);
  const pick = (id: string) => {
    picked.current = true;
    const next = new URLSearchParams(params);
    if (open === id) next.delete('tile'); else next.set('tile', id);
    setParams(next, { replace: true });
  };
  const fired = doc.groups.reduce((n, g) => n + g.tiles.filter(t => t.count > 0).length, 0);
  return (
    <>
      <p className="p0-sub">
        近 {doc.window_days} 天 {doc.total} 个漏洞 P0（现仍为 P0 {doc.now_p0}）· 落在 {fired} 个产品上 · 云组件 {doc.cloud} ·
        团队群仲裁通过 {doc.team_send} · 分类表 {doc.products} 个产品 · 生成于 {formatDateTime(doc.generated_at)}
      </p>
      <div className="p0-tools" role="group" aria-label="筛选">
        <button type="button" className="p0-toggle" aria-pressed={firedOnly} onClick={() => setFiredOnly(v => !v)}>只看有 P0 的产品</button>
        <button type="button" className="p0-toggle" aria-pressed={cloudOnly} onClick={() => setCloudOnly(v => !v)}>只看云组件</button>
        <span className="p0-hint">点一个产品，看它的全部 P0 · 灰色方块 = 在监控、近 {doc.window_days} 天没有 P0 · Web3 被盗事件见 <Link to="/web3">Web3</Link></span>
      </div>
      {groups.map(g => {
        const openTile = g.tiles.find(t => t.product === open);
        return (
          <section key={g.id} className="p0-group" aria-labelledby={`p0-g-${g.id}`}>
            <h2 className="p0-group-h" id={`p0-g-${g.id}`}>
              {g.label} <span className="tabular p0-group-n">{g.count}</span>
              {g.cloud && <span className="p0-cloud">云组件 · 进团队群仲裁</span>}
            </h2>
            <ul className="p0-tiles">
              {g.tiles.map(t => <TileButton key={t.product} t={t} mark={marks.get(t.label) ?? '?'} open={t.product === open} onPick={() => pick(t.product)} />)}
            </ul>
            {openTile && <TileList t={openTile} events={eventsOf(doc.events, openTile.product)} />}
          </section>
        );
      })}
      {groups.length === 0 && <p className="dt-muted dt-small">没有符合筛选的产品</p>}
    </>
  );
}

/** #/p0 — the P0 wall (Neo 2026-11-22). Absent p0.json (older backend) ⇒ said so, never an empty wall. */
export function P0WallPage() {
  const [load, setLoad] = useState<Load>({ st: 'loading' });
  useEffect(() => {
    let cancelled = false;
    fetchP0()
      .then(d => { if (!cancelled) setLoad(d === null ? { st: 'absent' } : { st: 'ok', doc: d }); })
      .catch((e: unknown) => { if (!cancelled) setLoad({ st: 'error', error: String(e) }); });
    return () => { cancelled = true; };
  }, []);
  return (
    <div className="ops-page" data-page="p0" tabIndex={0} role="region" aria-label="P0 分类墙">
      <div className="dt-wrap p0-wrap">
        <h1 className="ops-h1">P0 分类墙 <span className="ops-en">P0 WALL</span></h1>
        {load.st === 'loading' && <p className="dt-muted dt-mono dt-small" aria-busy="true">正在加载 P0…</p>}
        {load.st === 'absent' && <p className="ops-error">后端尚未发布 p0.json —— 这不代表没有 P0，请看漏洞页。</p>}
        {load.st === 'error' && <p className="ops-error">P0 数据不可用（{load.error}）—— 这不代表没有 P0</p>}
        {load.st === 'ok' && <P0WallView doc={load.doc} />}
      </div>
    </div>
  );
}
