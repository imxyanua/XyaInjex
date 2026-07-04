import { KeyboardEvent, useEffect, useState } from "react";
import { analyze, differential, fuzz, mutate, API_BASE } from "./api";
import {
  DIALECTS,
  EXAMPLES,
  LANGS,
  SOURCES,
  supportsDifferential,
  supportsFuzz,
  supportsMutation,
} from "./constants";
import {
  AnalysisResult,
  DifferentialResult,
  FuzzResult,
  Lang,
  MutationResult,
} from "./types";
import { readUrlState, shareLink, writeUrlState } from "./url";
import { BreakoutView } from "./components/BreakoutView";
import { CopyButton } from "./components/CopyButton";
import { DifferentialPanel } from "./components/DifferentialPanel";
import { FindingsView } from "./components/FindingsView";
import { FuzzPanel } from "./components/FuzzPanel";
import { MutationPanel } from "./components/MutationPanel";

const initial = readUrlState();
const initialLang = initial.lang ?? "shell";

export default function App() {
  const [lang, setLang] = useState<Lang>(initialLang);
  const [dialect, setDialect] = useState<string>(
    initial.dialect ?? DIALECTS[initialLang][0] ?? "",
  );
  const [source, setSource] = useState<string>(initial.source ?? SOURCES[0]);
  const [template, setTemplate] = useState<string>(
    initial.template ?? EXAMPLES[initialLang].template,
  );
  const [payload, setPayload] = useState<string>(
    initial.payload ?? EXAMPLES[initialLang].payload,
  );
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [mutation, setMutation] = useState<MutationResult | null>(null);
  const [fuzzResult, setFuzzResult] = useState<FuzzResult | null>(null);
  const [diff, setDiff] = useState<DifferentialResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Mirror the current inputs into the URL so the analysis is shareable.
  useEffect(() => {
    writeUrlState({ lang, dialect, source, template, payload });
  }, [lang, dialect, source, template, payload]);

  function clearOutputs() {
    setResult(null);
    setMutation(null);
    setFuzzResult(null);
    setDiff(null);
  }

  function switchLang(next: Lang) {
    setLang(next);
    setDialect(DIALECTS[next][0] ?? "");
    setSource(SOURCES[0]);
    setTemplate(EXAMPLES[next].template);
    setPayload(EXAMPLES[next].payload);
    clearOutputs();
    setError(null);
  }

  async function run(action: "analyze" | "mutate" | "fuzz" | "differential") {
    setBusy(true);
    setError(null);
    try {
      const args = { lang, template, payload, dialect, source };
      clearOutputs();
      if (action === "analyze") {
        setResult(await analyze(args));
      } else if (action === "mutate") {
        setMutation(await mutate(args));
      } else if (action === "fuzz") {
        setFuzzResult(await fuzz(args));
      } else {
        setDiff(await differential(args, DIALECTS[lang]));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && !busy) {
      e.preventDefault();
      run("analyze");
    }
  }

  const shareUrl = shareLink({ lang, dialect, source, template, payload });
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
            onKeyDown={onKey}
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
              onKeyDown={onKey}
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
          {!isAgent && supportsFuzz(lang) && (
            <button onClick={() => run("fuzz")} disabled={busy}>
              Fuzz
            </button>
          )}
          {supportsDifferential(lang) && (
            <button onClick={() => run("differential")} disabled={busy}>
              Differential
            </button>
          )}
          <CopyButton text={shareUrl} label="Copy link" />
        </div>
        <p className="hint">Press ⌘/Ctrl + Enter to analyze.</p>
      </div>

      {error && <div className="error">Error: {error}</div>}

      {result?.kind === "breakout" && <BreakoutView result={result} />}
      {(result?.kind === "prompt" || result?.kind === "agent") && (
        <FindingsView result={result} />
      )}
      {mutation && (
        <MutationPanel result={mutation} onPick={(p) => setPayload(p)} />
      )}
      {fuzzResult && (
        <FuzzPanel result={fuzzResult} onPick={(p) => setPayload(p)} />
      )}
      {diff && <DifferentialPanel result={diff} />}

      <footer>
        API: <code>{API_BASE}</code>
      </footer>
    </div>
  );
}
