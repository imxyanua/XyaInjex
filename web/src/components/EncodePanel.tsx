import { formatEncodeReport } from "../report";
import { EncodeResult } from "../types";
import { ReportActions } from "./ReportActions";
import { RiskBadge } from "./RiskBadge";

export function EncodePanel({
  result,
  onPick,
}: {
  result: EncodeResult;
  onPick: (payload: string) => void;
}) {
  const validated = result.template !== null;
  return (
    <div className="mutation">
      <div className="mutation-summary">
        <span>
          {result.total} variants
          {validated ? `, ${result.surviving} still break out` : ""}.
        </span>
        <ReportActions
          markdown={formatEncodeReport(result)}
          json={result}
          basename="xyainjex-encode"
        />
      </div>
      <div className="candidates">
        {result.variants.map((v, i) => (
          <button
            className={`candidate ${v.validated === false ? "filtered" : ""}`}
            key={i}
            onClick={() => onPick(v.payload)}
            title={v.strategy}
          >
            {v.validated === null ? (
              <span className="badge">enc</span>
            ) : v.validated ? (
              v.risk ? (
                <RiskBadge risk={v.risk} />
              ) : (
                <span className="badge ok">ok</span>
              )
            ) : (
              <span className="badge warn">filtered</span>
            )}
            <code>{v.payload}</code>
            <span className="strategy">{v.strategy}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
