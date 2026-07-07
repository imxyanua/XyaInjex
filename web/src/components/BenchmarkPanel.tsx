import { BenchmarkResult } from "../types";
import { RiskBadge } from "./RiskBadge";

export function BenchmarkPanel({ result }: { result: BenchmarkResult }) {
  return (
    <div className="mutation">
      <div className="mutation-summary">
        Parser divergence benchmark — {result.passed}/{result.total} passed
        {result.failed > 0 && (
          <span className="divergent"> ({result.failed} failed)</span>
        )}
      </div>
      <p className="muted mono">
        Dialects: {result.dialects.join(", ")}
      </p>

      <div className="diff-table benchmark-table" role="table">
        <div className="diff-row diff-head" role="row">
          <span>Case</span>
          <span>Expected</span>
          <span>Actual</span>
          <span>Status</span>
        </div>
        {result.results.map((caseResult) => (
          <details className="benchmark-case" key={caseResult.case_id}>
            <summary className={`diff-row ${caseResult.passed ? "" : "fail"}`}>
              <span className="mono">{caseResult.case_id}</span>
              <span>{caseResult.expected_divergent ? "divergent" : "uniform"}</span>
              <span>{caseResult.actual_divergent ? "divergent" : "uniform"}</span>
              <span className={caseResult.passed ? "yes" : "no"}>
                {caseResult.passed ? "pass" : "fail"}
              </span>
            </summary>
            {caseResult.note && <p className="muted case-note">{caseResult.note}</p>}
            <div className="diff-table nested" role="table">
              <div className="diff-row diff-head" role="row">
                <span>Dialect</span>
                <span>Injects</span>
                <span>Risk</span>
                <span>Context</span>
              </div>
              {Object.entries(caseResult.per_dialect).map(([dialect, info]) => (
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
          </details>
        ))}
      </div>
    </div>
  );
}
