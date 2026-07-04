# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- HTTP API endpoints `/suggest` and `/explain` expose the LLM-assisted payload
  suggestion and explanation (previously CLI-only). Both take a `provider` name
  (mock, openai, claude, ollama); the engine still validates every suggested
  payload, and an unknown provider or a non-breakout language returns 400.
- Web frontend now surfaces the fuzzing and differential engine features that
  were previously API-only: a Fuzz action (for every breakout language) lists the
  ranked exploit paths with their strategy and breakout stages, and a
  Differential action (for the dialect-selecting languages) shows a per-dialect
  table that highlights a parser divergence. The breakout view also highlights
  the injected payload within the rendered output.
- Web frontend: shareable analyses. The language, dialect, template, and payload
  are mirrored into the URL query, so a link restores the exact inputs; a
  "Copy link" button and a copy button on the rendered output are provided, and
  Ctrl / Cmd + Enter runs the analysis.
- Web frontend: LLM-assisted panels. An **AI Suggest** action lists the
  engine-validated payloads a chosen provider proposes, and an **AI Explain**
  action shows a natural-language write-up of the current breakout, backed by the
  new `/suggest` and `/explain` endpoints. A light / dark theme toggle (persisted
  and honoring the system preference) was added, and the API base URL footer was
  removed.

## [0.7.0] - 2026-07-04

### Changed

- Exploit-path fuzzing (`--fuzz`, `/fuzz`) now works for every breakout analyzer
  (xpath, ldap, nosql, xml, yaml, graphql, el, csv, ssi, xss, ssrf, path, mail,
  code, crlf) rather than only shell / sql / template, seeding from each
  language's mutation engine. Added obfuscation mutators where they survive the
  analyzer: case folding for xss / ssrf / xpath / ldap / el and percent-encoding
  for path (whose analyzer decodes it).
- Cross-dialect differential analysis (`/differential`) now covers the
  dialect-selecting languages code and crlf in addition to shell / sql /
  template; a no-dialect analyzer is rejected with a clear message since it has a
  single parser and nothing to compare.
- LLM-assisted suggestion (`--ai-suggest`) and explanation (`--ai-explain`) now
  work for every breakout analyzer rather than only shell / sql / template; the
  engine still validates each suggestion, so a payload is only kept when it
  actually breaks out.

### Fixed

- The LLM suggestion parser stripped a leading `.` while removing list markers,
  which mangled path-traversal payloads (`../../etc/passwd`); it now strips only
  genuine list markers (`- `, `* `, `1. `).

### Internal

- Extracted the per-language analyze / seed dispatch into a single
  `xyainjex.dispatch` module shared by the fuzzing engine and the LLM suggester,
  replacing three copies of the same dispatch.

## [0.6.0] - 2026-07-04

### Added

- SSRF (server-side request forgery) analyzer: classifies whether the input is
  the whole fetched URL, the host, the path, or a query-string value, parses the
  effective target, and detects redirection to a cloud metadata endpoint, a
  loopback or private / link-local host, a dangerous scheme (`file`, `gopher`,
  `dict`, ...), an `@` authority override, a protocol-relative or absolute URL,
  and obfuscated (decimal / hex / octal) IP encodings, with payload mutation and
  CLI (`--lang ssrf`), HTTP API, and web frontend support.
- Path traversal / LFI analyzer: classifies whether the input is the whole path,
  a base directory, or a path with a fixed suffix, and detects a `../` traversal
  (including percent-encoded and `....//` filter-bypass forms), an absolute path,
  a null-byte extension bypass, a remote scheme (RFI), and a PHP / stream wrapper
  (`php://filter`, `php://input`, `expect://`, `data://`, ...), with payload
  mutation and CLI (`--lang path`), HTTP API, and web frontend support.
- Email header / SMTP injection analyzer: classifies whether the input is an
  email header value, the message body, or a raw SMTP command line, and detects
  a line break that injects a new header (a silent `Bcc` / `Cc` recipient or a
  spoofed header), overrides the body, smuggles an SMTP command (`RCPT TO`,
  `MAIL FROM`, `DATA`), or sends a lone `.` line that ends the DATA phase,
  including encoded CR/LF, with payload mutation and CLI (`--lang mail`), HTTP
  API, and web frontend support.

## [0.5.0] - 2026-07-04

### Added

- Expression language (EL / OGNL / SpEL / JNDI) injection analyzer: classifies
  literal-text, in-expression, and expression-string contexts across the
  `${...}`, `#{...}`, and `%{...}` interpolations, detects opening an evaluated
  expression from text, a `${jndi:...}` lookup (Log4Shell), and RCE gadgets, with
  payload mutation and CLI (`--lang el`), HTTP API, and web frontend support.
- CSV / spreadsheet formula injection analyzer: detects when a cell begins with a
  formula trigger (`=`, `+`, `-`, `@`) at the cell start or via a new cell
  injected mid-row, flags command (DDE) and exfiltration functions, with payload
  mutation and CLI (`--lang csv`), HTTP API, and web frontend support.
- Server-Side Includes (SSI) injection analyzer: detects an injected SSI
  directive (`#exec` for command execution, `#include` for file read, and
  `#echo`/`#printenv`/`#config` for information disclosure), with payload
  mutation and CLI (`--lang ssi`), HTTP API, and web frontend support.
- HTML / XSS injection analyzer: classifies element text, attribute, script
  block, and comment contexts, detects breakout out of a quoted attribute or
  comment, injection of a new element, an `on*` event handler, a `<script>`
  element or `</script>` close, and a `javascript:` URL, distinguishing script
  execution from plain markup injection, with payload mutation and CLI
  (`--lang xss`), HTTP API, and web frontend support.

## [0.4.0] - 2026-07-03

### Added

- CRLF (HTTP header / log) injection analyzer: detects raw carriage-return /
  line-feed breakout (header injection, response splitting via a blank line, and
  log forging) and encoded CR/LF sequences, with a header or log sink kind,
  payload mutation, and CLI (`--lang crlf`), HTTP API, and web frontend support.
- XML injection analyzer: classifies element text, attribute, CDATA, and comment
  contexts, detects new-element injection, attribute and tag escape, CDATA and
  comment escape, entity references, and `<!DOCTYPE`/`<!ENTITY>` (possible XXE),
  with payload mutation and CLI (`--lang xml`), HTTP API, and web frontend
  support.
- YAML injection analyzer: classifies plain and quoted scalar contexts, detects
  a deserialization tag (`!!python/object/...`, RCE under an unsafe loader), a
  new mapping key, and a line break after escaping a quoted scalar, with payload
  mutation and CLI (`--lang yaml`), HTTP API, and web frontend support (block
  indentation is out of scope).
- GraphQL injection analyzer: classifies the string-argument and argument/value
  contexts, detects escaping a string argument and injecting query structure (a
  field selection, argument list, or directive) or an introspection field, with
  payload mutation and CLI (`--lang graphql`), HTTP API, and web frontend
  support.

## [0.3.0] - 2026-07-03

### Added

- XPath injection analyzer: classifies the string-literal and expression
  contexts, detects injected logic tokens (`or`, `and`, `]`, `|`, `=`), scores
  the breakout, and mutates boolean-tautology and node-union payloads. Wired
  into the CLI (`--lang xpath`), the HTTP API, and the web frontend. Analysis
  results now allow a null dialect for languages without one.
- LDAP injection analyzer: detects filter breakout where the payload closes the
  enclosing assertion and opens a new one (`*)(uid=*`), or injects a `*`
  wildcard, with parenthesis balance and backslash-escape handling, filter
  payload mutation, and CLI (`--lang ldap`), HTTP API, and web frontend support.
- NoSQL (MongoDB) injection analyzer: classifies the JSON string and value
  contexts, detects injected MongoDB operators (`$ne`, `$where`, `$regex`, and
  more, including operator keys inside strings) and new query fields, with
  object and string balance, operator payload mutation, and CLI (`--lang
  nosql`), HTTP API, and web frontend support.
- Code (eval sink) injection analyzer for Python, JavaScript, and PHP:
  classifies the string-literal, JavaScript template-literal, and expression
  contexts, detects statement and sink-identifier injection, `${...}` template
  substitution, and comment truncation (`#`, `//`), with sink payload mutation
  and CLI (`--lang code`), HTTP API, and web frontend support.

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

[Unreleased]: https://github.com/imxyanua/XyaInjex/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/imxyanua/XyaInjex/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/imxyanua/XyaInjex/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/imxyanua/XyaInjex/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/imxyanua/XyaInjex/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/imxyanua/XyaInjex/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/imxyanua/XyaInjex/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/imxyanua/XyaInjex/releases/tag/v0.1.0
