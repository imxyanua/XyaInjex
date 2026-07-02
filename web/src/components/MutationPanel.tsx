import { MutationResult } from "../types";
import { RiskBadge } from "./RiskBadge";

export function MutationPanel({
  result,
  onPick,
}: {
  result: MutationResult;
  onPick: (payload: string) => void;
}) {
  return (
    <div className="mutation">
      <div className="mutation-summary">
        Generated {result.generated}, {result.valid} inject in context{" "}
        <strong>{result.context}</strong>
      </div>
      <div className="candidates">
        {result.candidates.slice(0, 15).map((c, i) => (
          <button
            className="candidate"
            key={i}
            onClick={() => onPick(c.payload)}
            title={`${c.strategy}${c.syntax_valid ? ", balanced" : ", unbalanced"}`}
          >
            <RiskBadge risk={c.risk} />
            <code>{c.payload}</code>
            <span className="strategy">{c.strategy}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
