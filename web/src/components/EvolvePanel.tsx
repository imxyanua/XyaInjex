import { EvolveResult } from "../types";
import { formatEvolveReport } from "../report";
import { CopyButton } from "./CopyButton";
import { ReportActions } from "./ReportActions";
import { RiskBadge } from "./RiskBadge";

export function EvolvePanel({
  result,
  onOpenInDifferential,
  onPick,
}: {
  result: EvolveResult;
  onOpenInDifferential?: (template: string, payload: string) => void;
  onPick?: (template: string, payload: string) => void;
}) {
  return (
    <div className="mutation">
      <div className="mutation-summary">
        <span>
          Parser divergence evolution — {result.found} novel
          {result.found === 1 ? " discovery" : " discoveries"} in {result.rounds_run}{" "}
          round{result.rounds_run === 1 ? "" : "s"} ({result.candidates_tried}{" "}
          candidates)
        </span>
        <ReportActions
          markdown={formatEvolveReport(result)}
          json={result}
          basename={`xyainjex-evolve-${result.lang}`}
        />
      </div>
      <p className="muted mono">Dialects: {result.dialects.join(", ")}</p>
      {result.stopped_reason && (
        <p className="muted">Stopped early: {result.stopped_reason}</p>
      )}

      {!result.discoveries.length ? (
        <p className="muted">No novel divergences beyond the benchmark corpus.</p>
      ) : (
        <div className="diff-table benchmark-table" role="table">
          <div className="diff-row diff-head" role="row">
            <span>Round</span>
            <span>Score</span>
            <span>Strategy</span>
            <span>Metric</span>
            <span>Actions</span>
          </div>
          {result.discoveries.map((item, index) => {
            const snippet = result.corpus_snippets?.[index]?.snippet;
            return (
              <details className="benchmark-case" key={`${item.round}-${index}`}>
                <summary className="diff-row hit">
                  <span className="mono">{item.round}</span>
                  <span className="mono">{item.score.toFixed(0)}</span>
                  <span className="mono">{item.strategy}</span>
                  <span>{item.metric}</span>
                  <span className="yes">new</span>
                </summary>
                <p className="muted case-note mono">template: {item.template}</p>
                <p className="muted case-note mono">payload: {item.payload}</p>
                <div className="benchmark-actions">
                  {onPick && (
                    <button
                      className="copy"
                      onClick={() => onPick(item.template, item.payload)}
                    >
                      Use as payload
                    </button>
                  )}
                  {onOpenInDifferential && (
                    <button
                      className="copy"
                      onClick={() =>
                        onOpenInDifferential(item.template, item.payload)
                      }
                    >
                      Open in Differential
                    </button>
                  )}
                  {snippet && (
                    <CopyButton text={snippet} label="Copy CorpusCase" />
                  )}
                </div>
                <div className="diff-table nested" role="table">
                  <div className="diff-row diff-head" role="row">
                    <span>Dialect</span>
                    <span>Injects</span>
                    <span>Risk</span>
                    <span>Context</span>
                  </div>
                  {Object.entries(item.per_dialect).map(([dialect, info]) => (
                    <div
                      className={`diff-row ${info.command_injected ? "hit" : ""}`}
                      role="row"
                      key={dialect}
                    >
                      <span className="mono">{dialect}</span>
                      <span className={info.command_injected ? "yes" : "no"}>
                        {info.command_injected ? "yes" : "no"}
                      </span>
                      <span>
                        <RiskBadge risk={info.risk} />
                      </span>
                      <span className="mono muted">{info.context}</span>
                    </div>
                  ))}
                </div>
                {snippet && (
                  <pre className="mono corpus-snippet">{snippet}</pre>
                )}
              </details>
            );
          })}
        </div>
      )}
    </div>
  );
}
