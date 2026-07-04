import { SuggestResult } from "../types";
import { RiskBadge } from "./RiskBadge";

export function SuggestPanel({
  result,
  onPick,
}: {
  result: SuggestResult;
  onPick: (payload: string) => void;
}) {
  return (
    <div className="mutation">
      <div className="mutation-summary">
        Provider proposed {result.proposed}, {result.valid} validated by the
        engine.
      </div>
      {result.validated.length === 0 ? (
        <div className="empty">No proposed payload achieved a breakout.</div>
      ) : (
        <div className="candidates">
          {result.validated.map((s, i) => (
            <button
              className="candidate"
              key={i}
              onClick={() => onPick(s.payload)}
              title={s.context}
            >
              <RiskBadge risk={s.risk} />
              <code>{s.payload}</code>
              <span className="strategy">{s.context}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
