export type Lang =
  | "shell"
  | "sql"
  | "template"
  | "xpath"
  | "ldap"
  | "nosql"
  | "xml"
  | "yaml"
  | "graphql"
  | "orm"
  | "redis"
  | "el"
  | "csv"
  | "ssi"
  | "xss"
  | "ssrf"
  | "path"
  | "mail"
  | "host"
  | "xxe"
  | "prototype"
  | "argument"
  | "deserialize"
  | "code"
  | "crlf"
  | "prompt"
  | "agent";

export type Risk = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Breakout {
  context: string;
  quote_closed: boolean;
  command_injected: boolean;
  comment_terminated: boolean;
  separators: string[];
  commands_created: number;
  breakout_index: number | null;
  substitution_injected: boolean;
}

export interface Balance {
  quotes_balanced: boolean;
  single_quote_open: boolean;
  double_quote_open: boolean;
  backtick_open: boolean;
  unbalanced_pairs: Record<string, number>;
}

export interface BreakoutResult {
  kind: "breakout";
  template: string;
  payload: string;
  rendered: string;
  dialect: string | null;
  context: string;
  breakout: Breakout;
  balance: Balance;
  risk: Risk;
  notes: string[];
  syntax_valid: boolean;
}

export interface Finding {
  threat: string;
  severity: Risk;
  title: string;
  evidence: string;
  start: number | null;
  end: number | null;
  source?: string;
}

export interface PromptResult {
  kind: "prompt";
  template: string;
  payload: string;
  rendered: string;
  role_context: string;
  risk: Risk;
  findings: Finding[];
  notes: string[];
}

export interface AgentResult {
  kind: "agent";
  content: string;
  source: string;
  risk: Risk;
  findings: Finding[];
  notes: string[];
}

export interface TrustNode {
  id: string;
  label: string;
  kind: string;
  source: string;
  risk: Risk;
  compromised: boolean;
  hop: number;
}

export interface TrustEdge {
  from: string;
  to: string;
  label: string;
  risk: Risk;
  compromised: boolean;
}

export interface TrustGraph {
  nodes: TrustNode[];
  edges: TrustEdge[];
}

export interface FlowStepResult {
  content: string;
  source: string;
  risk: Risk;
  findings: Finding[];
  notes: string[];
}

export interface FlowResult {
  risk: Risk;
  steps: FlowStepResult[];
  notes: string[];
  graph: TrustGraph;
}

export interface McpFinding {
  kind: string;
  severity: Risk;
  title: string;
  evidence: string;
  tool_name: string | null;
}

export interface McpToolCall {
  name: string;
  raw: string;
  allowed: boolean | null;
  dangerous: boolean;
}

export interface McpResult {
  content: string;
  tools: Record<string, unknown>[] | null;
  risk: Risk;
  findings: McpFinding[];
  tool_calls: McpToolCall[];
  notes: string[];
}

export type AgentMode = "message" | "flow" | "mcp";

export type AnalysisResult = BreakoutResult | PromptResult | AgentResult;

export interface MutationCandidate {
  payload: string;
  risk: Risk;
  command_injected: boolean;
  syntax_valid: boolean;
  strategy: string;
}

export interface MutationResult {
  template: string;
  dialect?: string;
  engine?: string;
  context: string;
  generated: number;
  valid: number;
  high_probability: string[];
  candidates: MutationCandidate[];
}

export interface ExploitPath {
  payload: string;
  risk: Risk;
  context: string;
  syntax_valid: boolean;
  strategy: string;
  stages: string[];
}

export interface FuzzResult {
  template: string;
  lang: string;
  dialect: string | null;
  generated: number;
  valid: number;
  contexts_reached: string[];
  strategies: string[];
  paths: ExploitPath[];
}

export interface DialectVerdict {
  risk: Risk;
  command_injected: boolean;
  context: string;
}

export interface DifferentialResult {
  template: string;
  payload: string;
  lang: string;
  divergent: boolean;
  per_dialect: Record<string, DialectVerdict>;
}

export interface BenchmarkCaseResult {
  case_id: string;
  template: string;
  payload: string;
  expected_divergent: boolean;
  actual_divergent: boolean;
  passed: boolean;
  per_dialect: Record<string, DialectVerdict>;
  note: string;
}

export interface BenchmarkResult {
  lang: string;
  dialects: string[];
  total: number;
  passed: number;
  failed: number;
  results: BenchmarkCaseResult[];
}

export interface Suggestion {
  payload: string;
  risk: Risk;
  context: string;
  command_injected: boolean;
  substitution_injected: boolean;
}

export interface SuggestResult {
  template: string;
  lang: string;
  dialect: string | null;
  proposed: number;
  valid: number;
  validated: Suggestion[];
}

export interface ExplainResult {
  explanation: string;
}

export interface BuildResult {
  template: string;
  lang: string;
  dialect: string | null;
  goal: string | null;
  payload: string;
  rendered: string;
  validated: boolean;
  risk: Risk;
  context: string;
  strategy: string;
  tried: number;
  notes: string[];
}

export interface EncodeVariant {
  payload: string;
  strategy: string;
  validated: boolean | null;
  risk: Risk | null;
}

export interface EncodeResult {
  payload: string;
  lang: string;
  dialect: string | null;
  template: string | null;
  total: number;
  surviving: number;
  variants: EncodeVariant[];
}

export function classify(raw: Record<string, unknown>): AnalysisResult {
  if ("findings" in raw && "role_context" in raw) {
    return { kind: "prompt", ...(raw as object) } as PromptResult;
  }
  if ("findings" in raw && "source" in raw) {
    return { kind: "agent", ...(raw as object) } as AgentResult;
  }
  return { kind: "breakout", ...(raw as object) } as BreakoutResult;
}
