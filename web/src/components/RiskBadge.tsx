import { Risk } from "../types";

export function RiskBadge({ risk }: { risk: Risk }) {
  return <span className={`badge risk-${risk}`}>[{risk}]</span>;
}
