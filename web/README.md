# XyaInjex web

A small React (Vite + TypeScript) frontend for the XyaInjex analyzer. It calls
the FastAPI backend and visualizes the breakout: the rendered command with the
injected payload highlighted and a caret at the breakout point, context and risk
badges, an execution flow diagram, prompt and agent findings, and ranked payload
mutations. It also runs the fuzzing engine (ranked exploit paths with their
breakout stages), the cross-dialect differential (a per-dialect table that
highlights a parser divergence), and the LLM-assisted suggest / explain (with an
engine-validated payload list and a natural-language write-up, backed by the
`/suggest` and `/explain` endpoints). The current inputs are mirrored into the
URL, so an analysis is shareable by link (Ctrl / Cmd + Enter analyzes), and a
light / dark theme toggle is provided.

## Prerequisites

Run the backend with CORS allowing the dev server origin:

```bash
pip install -e ".[api]"
uvicorn xyainjex.api:app --port 8000
```

The backend allows `http://localhost:5173` by default. Override with the
`XYAINJEX_CORS_ORIGINS` environment variable (comma separated).

## Development

```bash
cd web
npm install
npm run dev      # serves on http://localhost:5173
```

Point the app at a non-default backend with a `.env` file:

```
VITE_API_BASE=http://localhost:8000
```

## Build and typecheck

```bash
npm run build      # tsc --noEmit then vite build, output in dist/
npm run typecheck  # types only
```

## What it does

- Tabs select the injection language: shell, SQL, template (SSTI), prompt, and
  agent / MCP.
- Enter a template with the `{INPUT}` marker and a payload (for agent analysis
  the single field is the untrusted content and the source is chosen instead).
- Analyze renders the verdict. For shell, SQL, and template it shows the
  rendered string with a breakout caret, the context and risk, a flow diagram,
  and notes. For prompt and agent it lists the findings.
- Mutate (shell, SQL, template) lists ranked breakout payloads; clicking one
  loads it into the payload field.
