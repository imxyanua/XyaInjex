import { Breakout } from "../types";

export function FlowDiagram({
  breakout,
  injected,
}: {
  breakout: Breakout;
  injected: boolean;
}) {
  const stages: string[] = ["context"];
  if (breakout.quote_closed) stages.push("quote-closure");
  if (breakout.command_injected) stages.push("injection");
  if (breakout.substitution_injected) stages.push("substitution");
  if (breakout.comment_terminated) stages.push("comment-truncation");
  stages.push(injected ? "EXEC" : "contained");

  return (
    <div className="flow">
      {stages.map((stage, i) => {
        const last = i === stages.length - 1;
        return (
          <span className="flow-node" key={i}>
            <span className={`flow-stage ${last && injected ? "danger" : ""}`}>
              {stage}
            </span>
            {!last && <span className="flow-sep">──▶</span>}
          </span>
        );
      })}
    </div>
  );
}
