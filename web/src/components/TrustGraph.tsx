import { TrustGraph as TrustGraphData } from "../types";
import { RiskBadge } from "./RiskBadge";

const KIND_ICON: Record<string, string> = {
  user: "user",
  tool: "tool",
  agent: "agent",
  memory: "mem",
  mcp: "mcp",
  document: "doc",
  web: "web",
  system: "sys",
};

export function TrustGraph({ graph }: { graph: TrustGraphData }) {
  const hops = graph.nodes.filter((n) => n.hop > 0);
  const agent = graph.nodes.find((n) => n.id === "agent");

  return (
    <div className="trust-graph">
      <div className="trust-chain">
        {hops.map((node, i) => (
          <div className="trust-hop" key={node.id}>
            <div
              className={`trust-node ${node.compromised ? "compromised" : ""}`}
              title={node.source}
            >
              <span className="trust-kind">{KIND_ICON[node.kind] ?? node.kind}</span>
              <span className="trust-label">{node.label}</span>
              <RiskBadge risk={node.risk} />
            </div>
            {i < hops.length - 1 || agent ? (
              <span className="trust-arrow">──▶</span>
            ) : null}
          </div>
        ))}
        {agent && (
          <div className={`trust-node agent ${agent.compromised ? "compromised" : ""}`}>
            <span className="trust-kind">agent</span>
            <span className="trust-label">{agent.label}</span>
            <RiskBadge risk={agent.risk} />
          </div>
        )}
      </div>

      {graph.edges.some((e) => e.compromised) && (
        <p className="trust-warn">
          Compromised hop(s) may feed attacker-controlled instructions downstream.
        </p>
      )}
    </div>
  );
}
