import { FuzzResult } from "../types";
import { RiskBadge } from "./RiskBadge";

export function FuzzPanel({
  result,
  onPick,
}: {
  result: FuzzResult;
  onPick: (payload: string) => void;
}) {
  return (
    <div className="mutation">
      <div className="mutation-summary">
        Generated {result.generated}, {result.valid} reached a breakout.
        {result.contexts_reached.length > 0 && (
          <> Contexts: {result.contexts_reached.join(", ")}.</>
        )}
      </div>

      {result.strategies.length > 0 && (
        <div className="chips">
          {result.strategies.map((s) => (
            <span className="chip" key={s}>
              {s}
            </span>
          ))}
        </div>
      )}

      {result.paths.length === 0 ? (
        <div className="empty">No exploit path found.</div>
      ) : (
        <div className="candidates">
          {result.paths.slice(0, 20).map((p, i) => (
            <button
              className="candidate path"
              key={i}
              onClick={() => onPick(p.payload)}
              title={`${p.context}${p.syntax_valid ? ", balanced" : ", unbalanced"}`}
            >
              <RiskBadge risk={p.risk} />
              <code>{p.payload}</code>
              <span className="stages">{p.stages.join(" → ")}</span>
              <span className="strategy">{p.strategy}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
