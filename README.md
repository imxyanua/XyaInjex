# XyaInjex

Real-time injection context and breakout analyzer.

XyaInjex does not only answer "did the payload execute". It answers the harder
question: where was user input embedded, what context did the payload escape
from, and what execution path did the breakout create.

Every injection vulnerability is treated as a context breakout problem.

## Status

This repository is under active development. The current milestone is Phase 1,
covering command injection across shell dialects:

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

## Library usage

```python
from xyainjex import analyze, Dialect

result = analyze('curl "{INPUT}"', '"; id ; #')
print(result.context.name)          # DOUBLE_QUOTE
print(result.breakout.command_injected)  # True
print(result.risk.value)            # CRITICAL

cmd = analyze('ping {INPUT}', '& whoami', Dialect.CMD)
print(cmd.risk.value)               # CRITICAL
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
