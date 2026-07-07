import { useState } from "react";
import { Breakout } from "../types";

const STAGE_LABELS: Record<string, string> = {
  context: "Original context",
  "quote-closure": "Quote closure",
  injection: "Command injection",
  substitution: "Substitution injection",
  "comment-truncation": "Comment truncation",
  EXEC: "Execution",
  contained: "Contained",
};

function buildStages(breakout: Breakout, injected: boolean): string[] {
  const stages: string[] = ["context"];
  if (breakout.quote_closed) stages.push("quote-closure");
  if (breakout.command_injected) stages.push("injection");
  if (breakout.substitution_injected) stages.push("substitution");
  if (breakout.comment_terminated) stages.push("comment-truncation");
  stages.push(injected ? "EXEC" : "contained");
  return stages;
}

export function FlowDiagram({
  breakout,
  injected,
}: {
  breakout: Breakout;
  injected: boolean;
}) {
  const [mode, setMode] = useState<"horizontal" | "vertical">("horizontal");
  const stages = buildStages(breakout, injected);

  return (
    <div className="flow-wrap">
      <div className="flow-head">
        <span className="rendered-label">Execution flow</span>
        <button
          className="copy flow-toggle"
          onClick={() =>
            setMode(mode === "horizontal" ? "vertical" : "horizontal")
          }
        >
          {mode === "horizontal" ? "Graph view" : "Linear view"}
        </button>
      </div>

      {mode === "horizontal" ? (
        <div className="flow">
          {stages.map((stage, i) => {
            const last = i === stages.length - 1;
            return (
              <span className="flow-node" key={i}>
                <span
                  className={`flow-stage ${last && injected ? "danger" : ""}`}
                >
                  {STAGE_LABELS[stage] ?? stage}
                </span>
                {!last && <span className="flow-sep">──▶</span>}
              </span>
            );
          })}
        </div>
      ) : (
        <div className="flow-graph" aria-label="Breakout execution graph">
          {stages.map((stage, i) => {
            const last = i === stages.length - 1;
            return (
              <div className="flow-graph-step" key={i}>
                <span
                  className={`flow-stage ${last && injected ? "danger" : ""}`}
                >
                  {STAGE_LABELS[stage] ?? stage}
                </span>
                {!last && <span className="flow-graph-arrow">│</span>}
                {!last && <span className="flow-graph-arrow">▼</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
