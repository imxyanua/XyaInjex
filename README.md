# XyaInjex

Real-time injection context and breakout analyzer.

XyaInjex does not only answer "did the payload execute". It answers the harder
question: where was user input embedded, what context did the payload escape
from, and what execution path did the breakout create.

Every injection vulnerability is treated as a context breakout problem.

## Status

This repository is under active development. It currently covers command
injection across shell dialects, SQL injection, server-side template injection,
and prompt injection for LLM systems.

Prompt injection and hidden prompt detection:

- Injection detectors for instruction override, role and turn delimiter
  breakout, tool and function-call hijacking, memory poisoning, and system
  prompt disclosure, scored by the role the input is embedded in.
- Hidden content detectors for zero-width and invisible characters, the Unicode
  Tags block (decoded), bidirectional overrides, homoglyphs, base64 encoded
  instructions, and hidden HTML.

Template injection:

- Region based analyzer that classifies the injection point as literal text, an
  expression, a statement, a comment, or a string literal inside an expression.
- Engines: Jinja2, Twig, Liquid, Nunjucks, Freemarker, ERB, Handlebars, and
  Velocity.
- Breakout detector that reports whether the payload opens an executable region
  from text, is already inside evaluated code, or escapes an expression string
  literal, plus a risk rating.
- Payload mutation for text, expression, string, and comment contexts.

SQL injection:

- Context analyzer that classifies the injection point as a string literal,
  quoted identifier, or numeric/expression position.
- Dialects: MySQL, PostgreSQL, MSSQL, SQLite, and ANSI (double quotes are
  string literals in MySQL, identifiers elsewhere; backslash escaping in
  MySQL).
- Breakout detector that reports string closure, injected SQL tokens at the top
  level (OR, AND, UNION, stacked `;`, and more), comment truncation (`--`, `#`,
  `/* */`), and a risk rating.
- Payload mutation for boolean, union, time based, and stacked strategies.

Command injection:

- Context analyzer that locates the injection point inside a command template
  and classifies its lexical context (single quote, double quote, backtick,
  command substitution, arithmetic expansion, parameter expansion, or
  unquoted).
- Multiple dialects: POSIX shell (bash, sh, zsh), Windows cmd.exe (with caret
  escaping), and PowerShell (with backtick escaping, subexpressions, and block
  comments).
- Syntax balance engine that tracks quote, parenthesis, brace, and bracket
  balance across the rendered command, plus open substitutions and expansions.
- Breakout detector that reports quote closure, injected command separators at
  the shell top level, comment truncation, and an overall risk rating.
- Payload mutation engine that generates context and dialect aware payloads.
- Report generator producing a JSON verdict and an ASCII breakout diagram.
- Command line interface and an optional HTTP API.

Heredoc support for POSIX shells is not implemented yet and is tracked as a
follow-up.

## Install

```bash
pip install -e .          # core engine and CLI
pip install -e ".[api]"   # also install the HTTP API dependencies
pip install -e ".[dev]"   # test and API dependencies
```

## Command line usage

Templates mark the injection point with the `{INPUT}` placeholder.

```bash
xyainjex 'curl "{INPUT}"' '"; id ; #'
```

Produce a JSON report instead of the human readable diagram:

```bash
xyainjex --json 'grep "{INPUT}" file.txt' '"; id ; #'
```

Generate context aware payload mutations for a template:

```bash
xyainjex --mutate 'curl "{INPUT}"'
```

Select a dialect with `--dialect` / `-d` (`posix` default, `cmd`, `powershell`):

```bash
xyainjex -d cmd 'ping "{INPUT}"' '" & whoami'
xyainjex -d powershell 'Get-Content "{INPUT}"' '"; whoami #'
```

Analyze SQL injection with `--lang sql` (`-d` selects the SQL dialect):

```bash
xyainjex -l sql "SELECT * FROM users WHERE name = '{INPUT}'" "' OR 1=1 -- "
xyainjex -l sql -d postgres 'SELECT * FROM t WHERE a = "{INPUT}"' '" OR 1=1 -- '
```

Analyze template injection with `--lang template` (`-d` selects the engine):

```bash
xyainjex -l template 'Hello {INPUT}' '{{7*7}}'
xyainjex -l template -d freemarker 'Hello {INPUT}' '${7*7}'
```

Analyze prompt injection with `--lang prompt` (use the `{INPUT}` template to
mark where untrusted content is embedded):

```bash
xyainjex -l prompt '<user>{INPUT}</user>' 'ignore all previous instructions'
```

## Library usage

```python
from xyainjex import analyze, Dialect

result = analyze('curl "{INPUT}"', '"; id ; #')
print(result.context.name)          # DOUBLE_QUOTE
print(result.breakout.command_injected)  # True
print(result.risk.value)            # CRITICAL

cmd = analyze('ping {INPUT}', '& whoami', Dialect.CMD)
print(cmd.risk.value)               # CRITICAL

from xyainjex import analyze_sql, SqlDialect

sql = analyze_sql("SELECT * FROM users WHERE name = '{INPUT}'", "' OR 1=1 -- ")
print(sql.context.value)            # sql_string
print(sql.risk.value)               # CRITICAL

from xyainjex import analyze_template

ssti = analyze_template("Hello {INPUT}", "{{7*7}}")
print(ssti.context.value)           # template_text
print(ssti.risk.value)              # CRITICAL

from xyainjex import analyze_prompt

prompt = analyze_prompt("{INPUT}", "ignore all previous instructions")
print(prompt.risk.value)            # HIGH
print(prompt.findings[0].threat.value)  # instruction_override
```

## HTTP API

```bash
uvicorn xyainjex.api:app --reload
```

```bash
curl -s localhost:8000/analyze \
  -H 'content-type: application/json' \
  -d '{"template": "curl \"{INPUT}\"", "payload": "\"; id ; #"}'
```

## License

For security research, education, and authorized defensive testing only. Use
responsibly and only on systems you own or are authorized to test. See LICENSE.
