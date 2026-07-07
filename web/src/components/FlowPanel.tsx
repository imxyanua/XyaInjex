import { FlowResult } from "../types";
import { ReportActions } from "./ReportActions";
import { RiskBadge } from "./RiskBadge";
import { TrustGraph } from "./TrustGraph";

export function FlowPanel({ result }: { result: FlowResult }) {
  return (
    <div className="result">
      <div className="badges">
        <RiskBadge risk={result.risk} />
        <span className="badge">{result.steps.length} hop(s)</span>
        <ReportActions
          markdown={formatFlowReport(result)}
          json={result}
          basename="xyainjex-flow"
        />
      </div>

      <TrustGraph graph={result.graph} />

      {result.notes.length > 0 && (
        <ul className="notes">
          {result.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}

      {result.steps.map((step, i) => (
        <div className="flow-step" key={i}>
          <div className="flow-step-head">
            <span className="rendered-label">
              Hop {i + 1}: {step.source}
            </span>
            <RiskBadge risk={step.risk} />
          </div>
          <div className="mono flow-step-content">{step.content}</div>
          {step.findings.length > 0 && (
            <div className="findings compact">
              {step.findings.map((f, j) => (
                <div className="finding" key={j}>
                  <div className="finding-head">
                    <RiskBadge risk={f.severity} />
                    <span className="finding-title">{f.title}</span>
                  </div>
                  <div className="finding-evidence mono">{f.evidence}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function formatFlowReport(result: FlowResult): string {
  const lines = [
    "# XyaInjex agent flow report",
    "",
    `- Risk: **${result.risk}**`,
    `- Hops: ${result.steps.length}`,
    "",
    "## Trust graph",
    ...result.graph.nodes.map(
      (n) =>
        `- ${n.label} (${n.source}) — ${n.risk}${n.compromised ? " [compromised]" : ""}`,
    ),
    "",
    "## Notes",
    ...result.notes.map((n) => `- ${n}`),
  ];
  return lines.join("\n");
}
