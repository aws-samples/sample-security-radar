import type { PipelineStep, ProgressStage, Response } from '@/types/site-data';
import { NoData } from '@/components/NoData';
import { progressRows } from '@/utils/evidence';
import { pipelineRows, type PipelineRow } from '@/utils/response';
import { utcShort } from '@/utils/timeZh';

const STEP_STATUS: Record<PipelineRow['status'], { glyph: string; word: string; tone: string }> = {
  done: { glyph: '✓', word: '完成', tone: 'ok' },
  running: { glyph: '◌', word: '进行中', tone: 'info' },
  pending: { glyph: '·', word: '等待', tone: 'muted' },
  failed: { glyph: '⚠', word: '失败', tone: 'warn' },
  skipped: { glyph: '–', word: '跳过', tone: 'muted' },
  not_configured: { glyph: '○', word: '未配置', tone: 'muted' },
  not_connected: { glyph: '⊘', word: '未接入', tone: 'muted' },
  missing: { glyph: '⊘', word: '未接入', tone: 'muted' },
};

/** 7-stage stepper (fixed order, times are labels) + the 7 system-step rows. */
export function ProgressPanel({ progress, steps, response }: { progress: ProgressStage[] | undefined; steps: PipelineStep[] | undefined; response: Response | null | undefined }) {
  const rows = progress ? progressRows(progress) : null;
  const reached = rows?.filter(r => r.at).length ?? 0;
  return (
    <>
      {rows
        ? (
          <ol className="stepper" aria-label={`事件进展：7 个阶段，已到达 ${reached} 个`}>
            {rows.map((r, i) => (
              <li key={r.stage} className={`${r.at ? 'is-reached' : ''}${r.stage === 'exploited' ? ' is-exploited' : ''}`}>
                <span className="node" aria-hidden="true">{r.at ? (r.stage === 'exploited' ? '!' : '✓') : i + 1}</span>
                <span className="lbl">{r.label}</span>
                <span className="at">{r.at ? `${utcShort(r.at)} UTC` : '未到达'}</span>
              </li>
            ))}
          </ol>
        )
        : <NoData>进展未生成（后端未产出 progress）</NoData>}
      <ul className="psteps" aria-label="系统处理步骤">
        {pipelineRows(steps, response).map(r => {
          const st = STEP_STATUS[r.status];
          return (
            <li key={r.step}>
              <span className="ps-top">{r.label} <span className={`ps-status tone-${st.tone}`}><span aria-hidden="true">{st.glyph}</span> {st.word}</span></span>
              <span className="ps-detail">{r.detail}</span>
              {r.note && <span className="ps-note">{r.note}</span>}
            </li>
          );
        })}
      </ul>
    </>
  );
}
