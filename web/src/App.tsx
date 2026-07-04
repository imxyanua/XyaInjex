import { KeyboardEvent, useEffect, useState } from "react";
import { analyze, differential, explain, fuzz, mutate, suggest } from "./api";
import {
  DIALECTS,
  EXAMPLES,
  LANG_GROUPS,
  PROVIDERS,
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
  SuggestResult,
} from "./types";
import { initialTheme, applyTheme, Theme } from "./theme";
import { readUrlState, shareLink, writeUrlState } from "./url";
import { BreakoutView } from "./components/BreakoutView";
import { CopyButton } from "./components/CopyButton";
import { DifferentialPanel } from "./components/DifferentialPanel";
import { FindingsView } from "./components/FindingsView";
import { FuzzPanel } from "./components/FuzzPanel";
import { MutationPanel } from "./components/MutationPanel";
import { SuggestPanel } from "./components/SuggestPanel";

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
  const [provider, setProvider] = useState<string>(PROVIDERS[0]);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [mutation, setMutation] = useState<MutationResult | null>(null);
  const [fuzzResult, setFuzzResult] = useState<FuzzResult | null>(null);
  const [diff, setDiff] = useState<DifferentialResult | null>(null);
  const [suggestion, setSuggestion] = useState<SuggestResult | null>(null);
  const [explanation, setExplanation] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [theme, setTheme] = useState<Theme>(initialTheme);

  // Mirror the current inputs into the URL so the analysis is shareable.
  useEffect(() => {
    writeUrlState({ lang, dialect, source, template, payload });
  }, [lang, dialect, source, template, payload]);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  function clearOutputs() {
    setResult(null);
    setMutation(null);
    setFuzzResult(null);
    setDiff(null);
    setSuggestion(null);
    setExplanation(null);
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

  type Action =
    | "analyze"
    | "mutate"
    | "fuzz"
    | "differential"
    | "suggest"
    | "explain";

  async function run(action: Action) {
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
      } else if (action === "differential") {
        setDiff(await differential(args, DIALECTS[lang]));
      } else if (action === "suggest") {
        setSuggestion(await suggest(args, provider));
      } else {
        setExplanation((await explain(args, provider)).explanation);
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
  const hasOutput =
    result !== null ||
    mutation !== null ||
    fuzzResult !== null ||
    diff !== null ||
    suggestion !== null ||
    explanation !== null;
  const isAgent = lang === "agent";
  const templateLabel = isAgent
    ? "Untrusted content"
    : lang === "prompt"
      ? "Prompt template — mark input with {INPUT}"
      : "Template — mark input with {INPUT}";

  return (
    <div className="app">
      <header className="term-bar">
        <span className="dots" aria-hidden="true">
          <i />
          <i />
          <i />
        </span>
        <h1 className="term-title">xyainjex</h1>
        <button
          className="copy theme-toggle"
          onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          title="Toggle theme"
        >
          {theme === "dark" ? "light" : "dark"}
        </button>
      </header>
      <p className="prompt">
        <span className="prompt-user">root@xyainjex</span>
        <span className="prompt-sep">:</span>
        <span className="prompt-path">~</span>
        <span className="prompt-sep">$</span> injection breakout analyzer
        <span className="cursor" aria-hidden="true">
          ▋
        </span>
      </p>

      <div className="tab-groups">
        {LANG_GROUPS.map((group) => (
          <div className="tab-group" key={group.title}>
            <span className="tab-group-title">{group.title}</span>
            <div className="tabs" role="tablist" aria-label={group.title}>
              {group.langs.map((l) => (
                <button
                  key={l.value}
                  className={`tab ${lang === l.value ? "active" : ""}`}
                  onClick={() => switchLang(l.value)}
                >
                  {l.label}
                </button>
              ))}
            </div>
          </div>
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

        {!isAgent && supportsFuzz(lang) && (
          <div className="row ai-row">
            <label className="inline">
              <span>LLM provider</span>
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
              >
                {PROVIDERS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </label>
            <button onClick={() => run("suggest")} disabled={busy}>
              AI Suggest
            </button>
            <button
              onClick={() => run("explain")}
              disabled={busy || !payload}
            >
              AI Explain
            </button>
          </div>
        )}

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
      {suggestion && (
        <SuggestPanel result={suggestion} onPick={(p) => setPayload(p)} />
      )}
      {explanation !== null && (
        <div className="result explain">
          <div className="rendered-head">
            <span className="rendered-label">AI explanation</span>
            <CopyButton text={explanation} />
          </div>
          <p className="explain-text">
            {explanation || "The provider returned no text."}
          </p>
        </div>
      )}

      {!hasOutput && !error && (
        <div className="result empty-state">
          <span className="muted">awaiting analysis</span>
          <span className="cursor" aria-hidden="true">
            ▋
          </span>
        </div>
      )}
    </div>
  );
}
