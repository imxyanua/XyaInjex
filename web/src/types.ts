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

export function classify(raw: Record<string, unknown>): AnalysisResult {
  if ("findings" in raw && "role_context" in raw) {
    return { kind: "prompt", ...(raw as object) } as PromptResult;
  }
  if ("findings" in raw && "source" in raw) {
    return { kind: "agent", ...(raw as object) } as AgentResult;
  }
  return { kind: "breakout", ...(raw as object) } as BreakoutResult;
}
