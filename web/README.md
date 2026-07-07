# XyaInjex web

A React (Vite + TypeScript) frontend for the XyaInjex analyzer. It calls the
FastAPI backend and visualizes injection breakouts across **26 languages**.

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

## Features

### Analysis

- **26 injection languages** grouped by category (Command/Query, Markup/Web,
  Serialization, Web request, LLM).
- Enter a template with the `{INPUT}` marker and a payload (for agent analysis
  the single field is untrusted content and the source is chosen instead).
- **Analyze** renders the verdict: breakout caret, context/risk badges, an
  execution flow diagram (linear or vertical graph view), and notes.
- Prompt and agent modes list scored findings.
- **Agent / MCP modes:** single message, multi-hop **Flow** (trust graph), or
  **MCP** (tool catalog + hijacking analysis).

### Payload tools

| Action | Description |
|--------|-------------|
| **Mutate** | Ranked breakout payloads for the current context |
| **Build** | Inverse analyzer — construct a payload from a **goal** (command, SQL union, URL, path, header…) |
| **Encode** | WAF/filter evasion variants; marks which still break out when a template is given |
| **Fuzz** | Ranked exploit paths with breakout stages |
| **Differential** | Per-dialect parser divergence table |
| **Benchmark** | Run built-in shell/SQL divergence regression corpus |
| **AI Suggest / Explain** | LLM-assisted payloads and explanations (engine-validated) |

### Reporting

Every result panel includes **Export MD** and **Export JSON** buttons. Markdown
reports include rendered output, breakout facts, execution flow, and notes.

### UX

- Shareable analyses: language, dialect, template, and payload are mirrored into
  the URL; **Copy link** restores the exact inputs.
- **Ctrl / Cmd + Enter** runs Analyze.
- Light / dark theme toggle (persisted, honors system preference).

## Supported build languages

`shell`, `sql`, `template`, `code`, `xss`, `ssrf`, `path`, `redis`, `xxe`,
`crlf`, `mail` — each accepts an optional goal; sensible defaults apply when
empty.

## API endpoints used

`POST /analyze`, `/mutate`, `/build`, `/encode`, `/fuzz`, `/differential`,
`/suggest`, `/explain`, `/flow`, `/mcp`, `GET /benchmark/{lang}`
