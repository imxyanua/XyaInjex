import {
  AnalysisResult,
  BuildResult,
  BenchmarkResult,
  DifferentialResult,
  EncodeResult,
  ExplainResult,
  FlowResult,
  FuzzResult,
  Lang,
  McpResult,
  MutationResult,
  SuggestResult,
  classify,
} from "./types";

const BASE = (import.meta.env.VITE_API_BASE as string) || "http://localhost:8000";

interface AnalyzeArgs {
  lang: Lang;
  template: string;
  payload: string;
  dialect?: string;
  source?: string;
}

async function post(path: string, body: unknown): Promise<Record<string, unknown>> {
  const resp = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data?.detail || `request failed (${resp.status})`);
  }
  return data;
}

export async function analyze(args: AnalyzeArgs): Promise<AnalysisResult> {
  const body: Record<string, unknown> = {
    template: args.template,
    payload: args.payload,
    lang: args.lang,
  };
  if (args.dialect) body.dialect = args.dialect;
  if (args.source) body.source = args.source;
  return classify(await post("/analyze", body));
}

export async function mutate(args: AnalyzeArgs): Promise<MutationResult> {
  const body: Record<string, unknown> = { template: args.template, lang: args.lang };
  if (args.dialect) body.dialect = args.dialect;
  return (await post("/mutate", body)) as unknown as MutationResult;
}

export async function fuzz(args: AnalyzeArgs): Promise<FuzzResult> {
  const body: Record<string, unknown> = { template: args.template, lang: args.lang };
  if (args.dialect) body.dialect = args.dialect;
  return (await post("/fuzz", body)) as unknown as FuzzResult;
}

export async function build(
  args: AnalyzeArgs,
  goal: string,
): Promise<BuildResult> {
  const body: Record<string, unknown> = {
    template: args.template,
    lang: args.lang,
  };
  if (goal) body.goal = goal;
  if (args.dialect) body.dialect = args.dialect;
  return (await post("/build", body)) as unknown as BuildResult;
}

export async function encode(args: AnalyzeArgs): Promise<EncodeResult> {
  const body: Record<string, unknown> = {
    payload: args.payload,
    lang: args.lang,
    template: args.template,
  };
  if (args.dialect) body.dialect = args.dialect;
  return (await post("/encode", body)) as unknown as EncodeResult;
}

export async function benchmark(lang: Lang): Promise<BenchmarkResult> {
  const resp = await fetch(`${BASE}/benchmark/${lang}`);
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data?.detail || `request failed (${resp.status})`);
  }
  return data as BenchmarkResult;
}

export async function differential(
  args: AnalyzeArgs,
  dialects: string[],
): Promise<DifferentialResult> {
  const body = {
    template: args.template,
    payload: args.payload,
    lang: args.lang,
    dialects,
  };
  return (await post("/differential", body)) as unknown as DifferentialResult;
}

export async function suggest(
  args: AnalyzeArgs,
  provider: string,
): Promise<SuggestResult> {
  const body: Record<string, unknown> = {
    template: args.template,
    lang: args.lang,
    provider,
  };
  if (args.dialect) body.dialect = args.dialect;
  return (await post("/suggest", body)) as unknown as SuggestResult;
}

export async function explain(
  args: AnalyzeArgs,
  provider: string,
): Promise<ExplainResult> {
  const body: Record<string, unknown> = {
    template: args.template,
    payload: args.payload,
    lang: args.lang,
    provider,
  };
  if (args.dialect) body.dialect = args.dialect;
  return (await post("/explain", body)) as unknown as ExplainResult;
}

export async function analyzeFlow(stepsJson: string): Promise<FlowResult> {
  const steps = JSON.parse(stepsJson) as { source: string; content: string }[];
  return (await post("/flow", { steps })) as unknown as FlowResult;
}

export async function analyzeMcp(
  content: string,
  toolsJson: string,
): Promise<McpResult> {
  const body: Record<string, unknown> = { content };
  const trimmed = toolsJson.trim();
  if (trimmed) body.tools = JSON.parse(trimmed);
  return (await post("/mcp", body)) as unknown as McpResult;
}

export { BASE as API_BASE };

export interface ApiHealth {
  status: string;
  version?: string;
  features?: string[];
}

const REQUIRED_FEATURES = ["flow", "mcp", "benchmark", "evolve"] as const;

/** Fail fast when the backend is down or running an outdated build without new routes. */
export async function ensureApiReady(): Promise<ApiHealth> {
  let resp: Response;
  try {
    resp = await fetch(`${BASE}/health`);
  } catch {
    throw new Error(
      `Cannot reach API at ${BASE}. Start it with: uvicorn xyainjex.api:app --reload --port 8000`,
    );
  }
  const data = (await resp.json()) as ApiHealth;
  if (!resp.ok) {
    throw new Error(data?.status || `API health check failed (${resp.status})`);
  }
  const missing = REQUIRED_FEATURES.filter((f) => !data.features?.includes(f));
  if (missing.length > 0) {
    throw new Error(
      `API server is outdated (missing ${missing.join(", ")}). Restart with: uvicorn xyainjex.api:app --reload --port 8000`,
    );
  }
  return data;
}
