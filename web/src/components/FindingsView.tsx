import { formatAgentReport, formatPromptReport } from "../report";
import { AgentResult, Finding, PromptResult } from "../types";
import { ReportActions } from "./ReportActions";
import { RiskBadge } from "./RiskBadge";

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="finding">
      <div className="finding-head">
        <RiskBadge risk={finding.severity} />
        <span className="finding-threat">{finding.threat}</span>
        <span className="finding-title">{finding.title}</span>
      </div>
      <div className="finding-evidence mono">{finding.evidence}</div>
    </div>
  );
}

export function FindingsView({
  result,
}: {
  result: PromptResult | AgentResult;
}) {
  const meta =
    result.kind === "prompt"
      ? { label: "Role", value: result.role_context }
      : { label: "Source", value: result.source };

  return (
    <div className="result">
      <div className="badges">
        <RiskBadge risk={result.risk} />
        <span className="badge">
          {meta.label}: {meta.value}
        </span>
        <span className="badge">{result.findings.length} finding(s)</span>
        <ReportActions
          markdown={
            result.kind === "prompt"
              ? formatPromptReport(result)
              : formatAgentReport(result)
          }
          json={result}
          basename={
            result.kind === "prompt" ? "xyainjex-prompt" : "xyainjex-agent"
          }
        />
      </div>

      {result.findings.length === 0 ? (
        <div className="empty">No findings.</div>
      ) : (
        <div className="findings">
          {result.findings.map((f, i) => (
            <FindingCard finding={f} key={i} />
          ))}
        </div>
      )}

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
