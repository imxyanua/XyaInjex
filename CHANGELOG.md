# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- XPath injection analyzer: classifies the string-literal and expression
  contexts, detects injected logic tokens (`or`, `and`, `]`, `|`, `=`), scores
  the breakout, and mutates boolean-tautology and node-union payloads. Wired
  into the CLI (`--lang xpath`), the HTTP API, and the web frontend. Analysis
  results now allow a null dialect for languages without one.

## [0.2.0] - 2026-07-02

### Added

- Template engines: Blade, Mako, Razor, Go templates, EJS, and Thymeleaf, with
  their delimiters and name aliases.
- SQL dialect Oracle, plus dialect-specific quoting: MSSQL bracket identifiers
  `[col]`, PostgreSQL dollar-quoted strings `$tag$...$tag$` (positional
  parameters like `$1` are not treated as quotes), Oracle alternative quoting
  `q'[...]'`, and `#` line comments restricted to MySQL.
- Shell dialect fish, where command substitution is bare parentheses
  `(command)` (and `$(command)`), with context and mutation support.

## [0.1.0] - 2026-07-02

First tagged release. XyaInjex analyzes injection as a context breakout problem:
it locates where untrusted input lands, classifies the surrounding context, and
reports how a payload escapes it and what execution path the breakout creates.

### Added

- Core engine and shared models: a lexical scanner foundation (`scan.py`) with a
  quoting stack, command separators, comment detection, bracket balance, and
  minimum-depth tracking, plus the `AnalysisResult`, `Breakout`, `Balance`, and
  `Risk` models and a JSON and ASCII breakout report.
- Shell command injection: a POSIX scanner covering single and double quotes,
  backticks, command substitution `$(...)`, arithmetic `$((...))`, parameter
  expansion `${...}`, and here-documents (`<<EOF`, `<<-`, quoted delimiters).
  Detects quote closure, injected command separators at the top level, comment
  truncation, here-document terminator injection, and command substitution
  introduced by the payload (`$(...)` or backticks). A syntax balance engine and
  a context and dialect aware payload mutation engine.
- Shell dialects: POSIX (bash, sh, zsh), Windows cmd.exe (caret escaping, no
  `;` separator, no inline comment), and PowerShell (backtick escaping,
  subexpressions `$(...)` and `@(...)`, line and block comments).
- SQL injection: a scanner for string literals, quoted identifiers, and
  comments (`--`, `#`, `/* */`) across MySQL, PostgreSQL, MSSQL, SQLite, and
  ANSI, with dialect-specific double-quote and backslash rules. Detects string
  closure, injected SQL tokens at the top level, stacked queries, and comment
  truncation, with boolean, union, time based, and stacked payload mutation.
- Template injection (SSTI): a region based analyzer for Jinja2, Twig, Liquid,
  Nunjucks, Freemarker, ERB, Handlebars, and Velocity. Classifies text,
  expression, statement, comment, and expression-string contexts, and detects
  opening an executable region, injection already inside evaluated code, and
  escaping an expression string literal.
- Prompt injection and hidden prompt detection: detectors for instruction
  override, role and turn delimiter breakout, tool and function-call hijacking,
  memory poisoning, and system prompt disclosure, scored by the embedding role;
  and hidden content detectors for zero-width characters, the Unicode Tags block
  (decoded), bidirectional overrides, homoglyphs, base64 encoded instructions,
  and hidden HTML.
- Agent and multi-agent (MCP) security: provenance aware analysis (tool output,
  another agent, memory, MCP resource, retrieved document, web, user) that
  reuses the prompt and hidden detectors and escalates untrusted trust-boundary
  crossings, with agent-specific threats (cross-agent injection, tool output
  injection, memory poisoning, MCP exploitation, delegation abuse, planning
  corruption, recursive injection) and a multi-agent flow analyzer.
- Differential fuzzing and exploit-path discovery: deterministic obfuscation
  mutators (case, whitespace, SQL inline comments, percent encoding) expand seed
  payloads, every variant is analyzed, and the injecting ones are returned as
  ranked exploit paths with their breakout stages; a differential mode runs one
  payload across dialects to reveal parser divergence.
- Optional LLM-assisted analysis: an LLM proposes payloads that the deterministic
  engine validates (so only real breakouts are returned) and can explain a
  result, with OpenAI, Claude, Ollama, and a deterministic mock provider.
- Interfaces: a `xyainjex` command line interface with analyze, `--mutate`,
  `--fuzz`, `--ai-suggest`, and `--ai-explain` modes across all languages; an
  optional FastAPI HTTP API (`/analyze`, `/mutate`, `/fuzz`, `/differential`)
  with configurable CORS; and a React (Vite + TypeScript) web frontend that
  visualizes the breakout, findings, and payload mutations.
- Tooling: a src-layout package with `api`, `llm`, and `dev` extras, ruff lint
  and format configuration, a GitHub Actions CI workflow, and a test suite of
  233 cases.

[Unreleased]: https://github.com/imxyanua/XyaInjex/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/imxyanua/XyaInjex/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/imxyanua/XyaInjex/releases/tag/v0.1.0
