import { Breakout } from "../types";

export function FlowDiagram({
  breakout,
  injected,
}: {
  breakout: Breakout;
  injected: boolean;
}) {
  const stages: string[] = ["Original context"];
  if (breakout.quote_closed) stages.push("Quote closure");
  if (injected) stages.push("Command injection");
  if (breakout.comment_terminated) stages.push("Comment truncation");
  stages.push(injected ? "Execution" : "No breakout");

  return (
    <div className="flow">
      {stages.map((stage, i) => (
        <div className="flow-item" key={i}>
          <div className={`flow-box ${i === stages.length - 1 && injected ? "danger" : ""}`}>
            {stage}
          </div>
          {i < stages.length - 1 && <div className="flow-arrow">↓</div>}
        </div>
      ))}
    </div>
  );
}
