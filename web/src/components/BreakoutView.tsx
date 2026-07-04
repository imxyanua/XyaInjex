import { BreakoutResult } from "../types";
import { RiskBadge } from "./RiskBadge";
import { FlowDiagram } from "./FlowDiagram";

function Caret({ rendered, index }: { rendered: string; index: number | null }) {
  if (index === null || index > rendered.length) return null;
  return (
    <div className="caret-line">
      {" ".repeat(index)}
      <span className="caret">^ breakout point</span>
    </div>
  );
}

function Rendered({ rendered, payload }: { rendered: string; payload: string }) {
  const at = payload ? rendered.indexOf(payload) : -1;
  if (at < 0) {
    return <div className="mono">{rendered || " "}</div>;
  }
  return (
    <div className="mono">
      {rendered.slice(0, at)}
      <span className="payload-hl">{payload}</span>
      {rendered.slice(at + payload.length)}
    </div>
  );
}

export function BreakoutView({ result }: { result: BreakoutResult }) {
  const b = result.breakout;
  return (
    <div className="result">
      <div className="badges">
        <RiskBadge risk={result.risk} />
        {result.dialect && <span className="badge">{result.dialect}</span>}
        <span className="badge">{result.context}</span>
        <span className={`badge ${result.syntax_valid ? "ok" : "warn"}`}>
          {result.syntax_valid ? "syntax valid" : "syntax invalid"}
        </span>
      </div>

      <div className="rendered">
        <Rendered rendered={result.rendered} payload={result.payload} />
        <Caret rendered={result.rendered} index={b.breakout_index} />
      </div>

      <div className="facts">
        <Fact label="Quote closed" value={b.quote_closed} />
        <Fact label="Command injected" value={b.command_injected} />
        <Fact label="Substitution injected" value={b.substitution_injected} />
        <Fact label="Comment terminated" value={b.comment_terminated} />
        <Fact
          label="Separators"
          value={b.separators.length ? b.separators.join(" ") : "-"}
        />
      </div>

      <FlowDiagram
        breakout={b}
        injected={b.command_injected || b.substitution_injected}
      />

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

function Fact({ label, value }: { label: string; value: boolean | string }) {
  const text = typeof value === "boolean" ? (value ? "yes" : "no") : value;
  const cls = typeof value === "boolean" ? (value ? "yes" : "no") : "";
  return (
    <div className="fact">
      <span className="fact-label">{label}</span>
      <span className={`fact-value ${cls}`}>{text}</span>
    </div>
  );
}
