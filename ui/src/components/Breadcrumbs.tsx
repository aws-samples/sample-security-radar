import { Link } from 'react-router-dom';

export interface Crumb { label: string; to?: string }

/** UI-IA §1 rule 2: every page shows its place in 态势 › 必须处理 › 事件 › 证据; the last crumb is the current page. */
export function Breadcrumbs({ items }: { items: Crumb[] }) {
  return (
    <nav className="crumbs" aria-label="面包屑">
      <ol>
        {items.map((c, i) => {
          const last = i === items.length - 1;
          return (
            <li key={`${c.label}-${i}`}>
              {last || !c.to
                ? <span aria-current={last ? 'page' : undefined} title={c.label}>{c.label}</span>
                : <Link to={c.to}>{c.label}</Link>}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
