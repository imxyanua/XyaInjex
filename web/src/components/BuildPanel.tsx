import { formatBuildReport } from "../report";
import { BuildResult } from "../types";
import { CopyButton } from "./CopyButton";
import { ReportActions } from "./ReportActions";
import { RiskBadge } from "./RiskBadge";

export function BuildPanel({
  result,
  onPick,
}: {
  result: BuildResult;
  onPick: (payload: string) => void;
}) {
  return (
    <div className="result">
      <div className="badges">
        <RiskBadge risk={result.risk} />
        <span className={`badge ${result.validated ? "ok" : "warn"}`}>
          {result.validated ? "breakout confirmed" : "best effort"}
        </span>
        <span className="badge">{result.context}</span>
        <span className="badge">{result.strategy}</span>
        <span className="badge">{result.tried} tried</span>
        <ReportActions
          markdown={formatBuildReport(result)}
          json={result}
          basename="xyainjex-build"
        />
      </div>

      <div className="rendered">
        <div className="rendered-head">
          <span className="rendered-label">Built payload</span>
          <CopyButton text={result.payload} />
        </div>
        <div className="mono">{result.payload}</div>
      </div>

      <div className="rendered">
        <div className="rendered-head">
          <span className="rendered-label">Rendered</span>
          <CopyButton text={result.rendered} />
        </div>
        <div className="mono">{result.rendered}</div>
      </div>

      <div className="row" style={{ marginTop: "12px" }}>
        <button className="copy" onClick={() => onPick(result.payload)}>
          Use as payload
        </button>
      </div>

      {result.notes.length > 0 && (
        <ul className="notes">
          {result.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
