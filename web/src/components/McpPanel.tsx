import { McpResult } from "../types";
import { ReportActions } from "./ReportActions";
import { RiskBadge } from "./RiskBadge";

export function McpPanel({ result }: { result: McpResult }) {
  return (
    <div className="result">
      <div className="badges">
        <RiskBadge risk={result.risk} />
        <span className="badge">{result.findings.length} finding(s)</span>
        <span className="badge">{result.tool_calls.length} tool call(s)</span>
        <ReportActions
          markdown={formatMcpReport(result)}
          json={result}
          basename="xyainjex-mcp"
        />
      </div>

      {result.tool_calls.length > 0 && (
        <div className="mcp-calls">
          <span className="rendered-label">Detected tool calls</span>
          {result.tool_calls.map((c, i) => (
            <div className="mcp-call" key={i}>
              <code>{c.name}</code>
              {c.dangerous ? (
                <span className="badge warn">dangerous</span>
              ) : c.allowed === false ? (
                <span className="badge warn">unknown</span>
              ) : c.allowed ? (
                <span className="badge ok">allowed</span>
              ) : (
                <span className="badge">detected</span>
              )}
              <span className="mono muted">{c.raw}</span>
            </div>
          ))}
        </div>
      )}

      {result.findings.length === 0 ? (
        <div className="empty">No MCP findings.</div>
      ) : (
        <div className="findings">
          {result.findings.map((f, i) => (
            <div className="finding" key={i}>
              <div className="finding-head">
                <RiskBadge risk={f.severity} />
                <span className="finding-threat">{f.kind}</span>
                <span className="finding-title">{f.title}</span>
              </div>
              <div className="finding-evidence mono">{f.evidence}</div>
            </div>
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

function formatMcpReport(result: McpResult): string {
  const lines = [
    "# XyaInjex MCP analysis report",
    "",
    `- Risk: **${result.risk}**`,
    "",
    "## Findings",
  ];
  for (const f of result.findings) {
    lines.push(`- [${f.severity}] ${f.kind}: ${f.title}`, `  - ${f.evidence}`);
  }
  if (result.tool_calls.length) {
    lines.push("", "## Tool calls");
    for (const c of result.tool_calls) {
      lines.push(`- ${c.name} (dangerous=${c.dangerous}, allowed=${c.allowed})`);
    }
  }
  return lines.join("\n");
}
