import { useState } from "react";
import { analyze, mutate, API_BASE } from "./api";
import {
  DIALECTS,
  EXAMPLES,
  LANGS,
  SOURCES,
  supportsMutation,
} from "./constants";
import { AnalysisResult, Lang, MutationResult } from "./types";
import { BreakoutView } from "./components/BreakoutView";
import { FindingsView } from "./components/FindingsView";
import { MutationPanel } from "./components/MutationPanel";

export default function App() {
  const [lang, setLang] = useState<Lang>("shell");
  const [dialect, setDialect] = useState<string>(DIALECTS.shell[0]);
  const [source, setSource] = useState<string>(SOURCES[0]);
  const [template, setTemplate] = useState<string>(EXAMPLES.shell.template);
  const [payload, setPayload] = useState<string>(EXAMPLES.shell.payload);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [mutation, setMutation] = useState<MutationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function switchLang(next: Lang) {
    setLang(next);
    setDialect(DIALECTS[next][0] ?? "");
    setSource(SOURCES[0]);
    setTemplate(EXAMPLES[next].template);
    setPayload(EXAMPLES[next].payload);
    setResult(null);
    setMutation(null);
    setError(null);
  }

  async function run(action: "analyze" | "mutate") {
    setBusy(true);
    setError(null);
    try {
      const args = { lang, template, payload, dialect, source };
      if (action === "analyze") {
        setMutation(null);
        setResult(await analyze(args));
      } else {
        setResult(null);
        setMutation(await mutate(args));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const isAgent = lang === "agent";
  const templateLabel = isAgent
    ? "Untrusted content"
    : lang === "prompt"
      ? "Prompt template — mark input with {INPUT}"
      : "Template — mark input with {INPUT}";

  return (
    <div className="app">
      <header>
        <h1>XyaInjex</h1>
        <p className="tagline">Injection context and breakout analyzer</p>
      </header>

      <div className="tabs">
        {LANGS.map((l) => (
          <button
            key={l.value}
            className={`tab ${lang === l.value ? "active" : ""}`}
            onClick={() => switchLang(l.value)}
          >
            {l.label}
          </button>
        ))}
      </div>

      <div className="controls">
        <label className="field">
          <span>{templateLabel}</span>
          <textarea
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
            spellCheck={false}
            rows={2}
          />
        </label>

        {!isAgent && (
          <label className="field">
            <span>{lang === "prompt" ? "Untrusted input" : "Payload"}</span>
            <textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              spellCheck={false}
              rows={2}
            />
          </label>
        )}

        <div className="row">
          {DIALECTS[lang].length > 0 && (
            <label className="inline">
              <span>Dialect</span>
              <select value={dialect} onChange={(e) => setDialect(e.target.value)}>
                {DIALECTS[lang].map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>
            </label>
          )}

          {isAgent && (
            <label className="inline">
              <span>Source</span>
              <select value={source} onChange={(e) => setSource(e.target.value)}>
                {SOURCES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
          )}

          <button className="primary" onClick={() => run("analyze")} disabled={busy}>
            Analyze
          </button>
          {supportsMutation(lang) && (
            <button onClick={() => run("mutate")} disabled={busy}>
              Mutate
            </button>
          )}
        </div>
      </div>

      {error && <div className="error">Error: {error}</div>}

      {result?.kind === "breakout" && <BreakoutView result={result} />}
      {(result?.kind === "prompt" || result?.kind === "agent") && (
        <FindingsView result={result} />
      )}
      {mutation && (
        <MutationPanel result={mutation} onPick={(p) => setPayload(p)} />
      )}

      <footer>
        API: <code>{API_BASE}</code>
      </footer>
    </div>
  );
}
