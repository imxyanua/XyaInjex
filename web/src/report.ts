import {
  AgentResult,
  AnalysisResult,
  BenchmarkResult,
  BreakoutResult,
  BuildResult,
  EncodeResult,
  EvolveResult,
  FuzzResult,
  PromptResult,
} from "./types";

function breakoutFlow(b: BreakoutResult["breakout"], injected: boolean): string[] {
  const stages = ["Original context"];
  if (b.quote_closed) stages.push("Quote closure");
  if (b.command_injected) stages.push("Command injection");
  if (b.substitution_injected) stages.push("Substitution injection");
  if (b.comment_terminated) stages.push("Comment truncation");
  stages.push(injected ? "Execution" : "No breakout");
  return stages;
}

export function formatBreakoutReport(result: BreakoutResult): string {
  const b = result.breakout;
  const injected = b.command_injected || b.substitution_injected;
  const lines = [
    "# XyaInjex analysis report",
    "",
    "## Inputs",
    `- Template: \`${result.template}\``,
    `- Payload: \`${result.payload}\``,
    `- Dialect: ${result.dialect ?? "default"}`,
    "",
    "## Verdict",
    `- Risk: **${result.risk}**`,
    `- Context: ${result.context}`,
    `- Syntax valid: ${result.syntax_valid ? "yes" : "no"}`,
    "",
    "## Rendered",
    "```",
    result.rendered,
    "```",
  ];
  if (b.breakout_index !== null) {
    lines.push(
      "",
      "```",
      " ".repeat(b.breakout_index) + "^ breakout point",
      "```",
    );
  }
  lines.push(
    "",
    "## Breakout facts",
    `- Quote closed: ${b.quote_closed}`,
    `- Command injected: ${b.command_injected}`,
    `- Substitution injected: ${b.substitution_injected}`,
    `- Comment terminated: ${b.comment_terminated}`,
    `- Separators: ${b.separators.join(" ") || "-"}`,
    "",
    "## Execution flow",
    ...breakoutFlow(b, injected).flatMap((s, i) =>
      i === 0 ? [s] : ["  |", "  v", s],
    ),
  );
  if (result.notes.length) {
    lines.push("", "## Notes", ...result.notes.map((n) => `- ${n}`));
  }
  return lines.join("\n");
}

export function formatPromptReport(result: PromptResult): string {
  const lines = [
    "# XyaInjex prompt analysis report",
    "",
    `- Role: ${result.role_context}`,
    `- Risk: **${result.risk}**`,
    `- Findings: ${result.findings.length}`,
    "",
    "## Findings",
  ];
  if (!result.findings.length) {
    lines.push("- None");
  } else {
    for (const f of result.findings) {
      lines.push(
        `- [${f.severity}] ${f.threat}: ${f.title}`,
        `  - Evidence: \`${f.evidence}\``,
      );
    }
  }
  if (result.notes.length) {
    lines.push("", "## Notes", ...result.notes.map((n) => `- ${n}`));
  }
  return lines.join("\n");
}

export function formatAgentReport(result: AgentResult): string {
  const lines = [
    "# XyaInjex agent analysis report",
    "",
    `- Source: ${result.source}`,
    `- Risk: **${result.risk}**`,
    `- Findings: ${result.findings.length}`,
    "",
    "## Findings",
  ];
  if (!result.findings.length) {
    lines.push("- None");
  } else {
    for (const f of result.findings) {
      lines.push(
        `- [${f.severity}] ${f.threat}: ${f.title}`,
        `  - Evidence: \`${f.evidence}\``,
      );
    }
  }
  if (result.notes.length) {
    lines.push("", "## Notes", ...result.notes.map((n) => `- ${n}`));
  }
  return lines.join("\n");
}

export function formatAnalysisReport(result: AnalysisResult): string {
  if (result.kind === "prompt") return formatPromptReport(result);
  if (result.kind === "agent") return formatAgentReport(result);
  return formatBreakoutReport(result);
}

export function formatBuildReport(result: BuildResult): string {
  const lines = [
    "# XyaInjex payload build report",
    "",
    `- Lang: ${result.lang}`,
    `- Goal: ${result.goal ?? "(default)"}`,
    `- Validated: ${result.validated ? "yes" : "no (best effort)"}`,
    `- Risk: **${result.risk}**`,
    `- Strategy: ${result.strategy}`,
    `- Tried: ${result.tried} candidates`,
    "",
    "## Payload",
    "```",
    result.payload,
    "```",
    "",
    "## Rendered",
    "```",
    result.rendered,
    "```",
  ];
  if (result.notes.length) {
    lines.push("", "## Notes", ...result.notes.map((n) => `- ${n}`));
  }
  return lines.join("\n");
}

export function formatEncodeReport(result: EncodeResult): string {
  const lines = [
    "# XyaInjex payload encode report",
    "",
    `- Original: \`${result.payload}\``,
    `- Variants: ${result.total}`,
    `- Surviving breakouts: ${result.surviving}`,
    "",
    "## Variants",
  ];
  for (const v of result.variants) {
    const tag =
      v.validated === null ? "raw" : v.validated ? `[${v.risk ?? "ok"}]` : "[filtered]";
    lines.push(`- ${tag} (${v.strategy}): \`${v.payload}\``);
  }
  return lines.join("\n");
}

export function formatFuzzReport(result: FuzzResult): string {
  const lines = [
    "# XyaInjex fuzz report",
    "",
    `- Generated: ${result.generated}`,
    `- Valid paths: ${result.valid}`,
    `- Contexts: ${result.contexts_reached.join(", ") || "-"}`,
    "",
    "## Top exploit paths",
  ];
  for (const p of result.paths.slice(0, 20)) {
    lines.push(
      `- [${p.risk}] \`${p.payload}\` (${p.strategy})`,
      `  - ${p.stages.join(" → ")}`,
    );
  }
  return lines.join("\n");
}

export function formatBenchmarkReport(result: BenchmarkResult): string {
  const lines = [
    "# XyaInjex benchmark report",
    "",
    `- Language: ${result.lang}`,
    `- Dialects: ${result.dialects.join(", ")}`,
    `- Passed: ${result.passed}/${result.total}`,
    `- Failed: ${result.failed}`,
    "",
    "## Cases",
  ];
  for (const c of result.results) {
    const mark = c.passed ? "pass" : "FAIL";
    const metric = c.metric ?? "command_injected";
    lines.push(
      `### ${c.case_id} (${mark})`,
      `- Expected divergent (${metric}): ${c.expected_divergent}`,
      `- Actual divergent: ${c.actual_divergent}`,
      `- Template: \`${c.template}\``,
      `- Payload: \`${c.payload}\``,
    );
    if (c.note) lines.push(`- Note: ${c.note}`);
    for (const [dialect, info] of Object.entries(c.per_dialect)) {
      lines.push(
        `  - ${dialect}: inject=${info.command_injected} risk=${info.risk} context=${info.context}`,
      );
    }
    lines.push("");
  }
  return lines.join("\n");
}

export function formatEvolveReport(result: EvolveResult): string {
  const lines = [
    "# XyaInjex evolve report",
    "",
    `- Language: ${result.lang}`,
    `- Template: ${result.template ?? "(all corpus seeds)"}`,
    `- Dialects: ${result.dialects.join(", ")}`,
    `- Rounds: ${result.rounds_run}`,
    `- Candidates tried: ${result.candidates_tried}`,
    `- Discoveries: ${result.found}`,
    "",
  ];
  if (result.stopped_reason) {
    lines.push(`- Stopped early: ${result.stopped_reason}`, "");
  }
  if (!result.discoveries.length) {
    lines.push("No novel parser divergences beyond the benchmark corpus.");
    return lines.join("\n");
  }
  lines.push("## Discoveries");
  for (const d of result.discoveries) {
    lines.push(
      `### Round ${d.round} — ${d.strategy} (score ${d.score.toFixed(0)})`,
      `- Metric: ${d.metric}`,
      `- Template: \`${d.template}\``,
      `- Payload: \`${d.payload}\``,
    );
    for (const [dialect, info] of Object.entries(d.per_dialect)) {
      lines.push(
        `  - ${dialect}: inject=${info.command_injected} risk=${info.risk}`,
      );
    }
    lines.push("");
  }
  if (result.corpus_snippets?.length) {
    lines.push("## Corpus snippets");
    for (const item of result.corpus_snippets) {
      lines.push("```python", item.snippet, "```", "");
    }
  }
  return lines.join("\n");
}

export function downloadText(filename: string, content: string, mime = "text/plain") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadJson(filename: string, data: unknown) {
  downloadText(filename, JSON.stringify(data, null, 2), "application/json");
}
