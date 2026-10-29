import { useEffect, useMemo, useRef } from 'react';
import type { ResponsePatch } from '@/types/site-data';
import { usePatch } from '@/hooks/usePatch';
import { parseUnifiedDiff, diffStats, safeDataPath, PATCH_LIMITS, type DiffFile } from '@/utils/diff';
import { SERVICE_LABEL } from '@/utils/response';

/** DOM id of a file block inside patch `pi` — shared with the target table's "✓ 补丁已改" links. */
export const patchFileId = (pi: number, file: string) => `patch-${pi}-${file.replace(/[^A-Za-z0-9_-]/g, '_')}`;

const SIGN: Record<string, string> = { add: '+', del: '-', ctx: ' ', hunk: '', meta: '' };

/** Pure renderer of parsed files: React text nodes only (no innerHTML), +/- kept as visible characters. */
export function DiffViewer({ files, pi, flashFile }: { files: DiffFile[]; pi: number; flashFile: string | null }) {
  return (
    <>
      {files.map(f => {
        const id = patchFileId(pi, f.path);
        return (
          <details key={id} id={id} className={`diff-file${flashFile === f.path ? ' is-flash' : ''}`} open>
            <summary>
              <span>{f.path}</span>
              <span className="diff-stat-add">+{f.added}</span>
              <span className="diff-stat-del">−{f.removed}</span>
            </summary>
            <pre className="diff-pre" tabIndex={0} aria-label={`补丁 diff：${f.path}，新增 ${f.added} 行，删除 ${f.removed} 行`}>
              {f.lines.map((l, i) => (
                <span key={i} className={`diff-line diff-${l.kind}`}>
                  <span className="diff-ln" aria-hidden="true">{l.oldNo ?? ''}</span>
                  <span className="diff-ln" aria-hidden="true">{l.newNo ?? ''}</span>
                  <span className="diff-sign">{SIGN[l.kind]}</span>
                  <span>{l.text}</span>
                </span>
              ))}
            </pre>
          </details>
        );
      })}
    </>
  );
}

interface Props {
  patch: ResponsePatch;
  pi: number;
  open: boolean;
  onToggle: () => void;
  targetName: string | null;
  /** File to scroll to / flash once the diff is rendered (set by the target table). */
  focusFile: string | null;
  /** Bumped on every request so clicking the same link twice scrolls again. */
  focusKey: number;
}

export function PatchViewer({ patch, pi, open, onToggle, targetName, focusFile, focusKey }: Props) {
  const st = usePatch(patch.path, open);
  const files = useMemo(() => (st.state === 'ok' ? parseUnifiedDiff(st.text) : []), [st]);
  const stats = diffStats(files);
  const safe = safeDataPath(patch.path);
  const bodyId = `patch-body-${pi}`;
  const scrolled = useRef<string | null>(null);

  // Scroll to the requested file once its block exists. focusFile is a files_changed entry (target-relative,
  // same form as the diff's own paths); the caller maps prefixed locator paths to it with sameFile().
  useEffect(() => {
    const want = `${focusFile}#${focusKey}`;
    if (!focusFile || st.state !== 'ok' || scrolled.current === want) return;
    const f = files.find(x => x.path === focusFile);
    if (!f) return;
    const el = document.getElementById(patchFileId(pi, f.path)) as HTMLDetailsElement | null;
    if (el) { el.open = true; el.scrollIntoView({ block: 'start' }); scrolled.current = want; }
  }, [focusFile, focusKey, st.state, files, pi]);

  return (
    <div className="patch">
      <div className="patch-head">
        <span className="patch-summary">{patch.summary}</span>
        <span className="dt-small dt-muted">{SERVICE_LABEL[patch.source]}{targetName ? ` · ${targetName}` : ''}</span>
        <span>{patch.files_changed.map(f => <code key={f} className="env-linkchip">{f}</code>)}</span>
        <span style={{ marginLeft: 'auto', display: 'inline-flex', gap: 6 }}>
          <button type="button" className="btn-ghost" aria-expanded={open} aria-controls={bodyId} onClick={onToggle}>{open ? '收起 diff' : '查看 diff'}</button>
          {safe && <a className="btn-ghost" href={`./data/${patch.path}`} download>下载</a>}
        </span>
      </div>
      <div id={bodyId} className="patch-body" hidden={!open}>
        {open && (
          st.state === 'rejected' ? <p className="dt-small" style={{ color: 'var(--p1)' }}>⚠ 补丁路径不合法，已拒绝加载：<code>{patch.path}</code></p>
            : st.state === 'loading' || st.state === 'idle' ? <p className="dt-small dt-muted" aria-busy="true">加载补丁…</p>
              : st.state === 'error' ? <p className="dt-small" style={{ color: 'var(--p1)' }}>⚠ {st.message}{safe ? ' · 可尝试下载原文件' : ''}</p>
                : (
                  <>
                    <p className="dt-small dt-muted" style={{ margin: '0 0 8px' }}>
                      {stats.files} 个文件 · <span className="diff-stat-add">+{stats.added}</span> <span className="diff-stat-del">−{stats.removed}</span>
                      {st.truncated && <span style={{ color: 'var(--p1)' }}> · 已截断：只显示前 {PATCH_LIMITS.truncatedLines} 行（原文 {Math.round(st.bytes / 1024)} KB），请下载完整文件</span>}
                    </p>
                    {files.length === 0 ? <p className="dt-small dt-muted">补丁为空或不是 unified diff 格式</p> : <DiffViewer files={files} pi={pi} flashFile={focusFile} />}
                  </>
                )
        )}
      </div>
    </div>
  );
}
