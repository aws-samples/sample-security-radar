import { useState } from 'react';

/** Copy-to-clipboard with a visible + announced outcome (a failed copy says so; it is not silently "done"). */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [st, setSt] = useState<'idle' | 'ok' | 'fail'>('idle');
  const onClick = () => {
    if (!navigator.clipboard) { setSt('fail'); return; }
    navigator.clipboard.writeText(value).then(() => setSt('ok'), () => setSt('fail'));
  };
  return (
    <>
      <button type="button" className="btn-ghost btn-tiny" onClick={onClick} aria-label={`复制${label}`}>
        {st === 'ok' ? '已复制' : st === 'fail' ? '复制失败' : '复制'}
      </button>
      <span className="sr-only" aria-live="polite" style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>
        {st === 'ok' ? `已复制${label}` : st === 'fail' ? `复制${label}失败` : ''}
      </span>
    </>
  );
}
