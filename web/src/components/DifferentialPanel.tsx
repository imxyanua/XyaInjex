import { DifferentialResult } from "../types";
import { RiskBadge } from "./RiskBadge";

export function DifferentialPanel({ result }: { result: DifferentialResult }) {
  const dialects = Object.keys(result.per_dialect);
  return (
    <div className="mutation">
      <div className="mutation-summary">
        {result.divergent ? (
          <span className="divergent">
            Parser divergence: the same payload is code to one dialect and data to
            another.
          </span>
        ) : (
          <>No divergence: every dialect agrees on this payload.</>
        )}
      </div>

      <div className="diff-table" role="table">
        <div className="diff-row diff-head" role="row">
          <span>Dialect</span>
          <span>Injects</span>
          <span>Risk</span>
          <span>Context</span>
        </div>
        {dialects.map((d) => {
          const v = result.per_dialect[d];
          return (
            <div
              className={`diff-row ${v.command_injected ? "hit" : ""}`}
              role="row"
              key={d}
            >
              <span className="mono">{d}</span>
              <span className={v.command_injected ? "yes" : "no"}>
                {v.command_injected ? "yes" : "no"}
              </span>
              <span>
                <RiskBadge risk={v.risk} />
              </span>
              <span className="mono muted">{v.context}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
