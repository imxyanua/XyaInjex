import { AnalysisResult, Lang, MutationResult, classify } from "./types";

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

export { BASE as API_BASE };
