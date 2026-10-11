import { STAGE_LABELS, STAGE_ORDER } from '../../types/scan.js'
import StatusBadge from '../common/StatusBadge.jsx'

// "out" means different things per stage: most stages output items, but the
// Report row outputs files (2 findings in → 1 report file out). Label each
// row with its real units so "2 in → 1 out" never reads as lost findings.
function countLabel(stageId, count) {
  if (stageId === 'report_generation') {
    return `${count.inputs} finding${count.inputs === 1 ? '' : 's'} → ${count.outputs} report`
  }
  if (stageId === 'ai_analysis') {
    return `${count.inputs} verified → ${count.outputs} finding${count.outputs === 1 ? '' : 's'}`
  }
  return `${count.inputs} in → ${count.outputs} out`
}

export default function StageStepper({ stages, summary }) {
  const byId = Object.fromEntries((stages || []).map((s) => [s.stage, s]))
  const counts = Object.fromEntries(
    ((summary && summary.stages) || []).map((s) => [s.stage, s]),
  )
  return (
    <ol className="stepper" aria-label="Pipeline progress">
      {STAGE_ORDER.map((stageId) => {
        const stage = byId[stageId]
        const status = stage ? stage.status : 'pending'
        const count = counts[stageId]
        return (
          <li key={stageId} className={`step step-${status}`}>
            <span className="step-name">{STAGE_LABELS[stageId]}</span>
            <StatusBadge value={status} />
            {count && (count.inputs > 0 || count.outputs > 0) ? (
              <span className="step-counts">
                {countLabel(stageId, count)}
              </span>
            ) : null}
            {stage && stage.error ? (
              <span className="step-error">{stage.error}</span>
            ) : null}
          </li>
        )
      })}
    </ol>
  )
}
