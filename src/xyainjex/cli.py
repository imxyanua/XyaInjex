"""Command line interface for XyaInjex."""

from __future__ import annotations

import argparse
import json
import sys

from .agent import analyze_agent, parse_source
from .analyzer import analyze
from .dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from .fuzz import fuzz
from .mutation import mutate
from .prompt import analyze_prompt
from .report import to_json, visualize
from .sql import analyze_sql, mutate_sql
from .template import analyze_template, mutate_template


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xyainjex",
        description="Injection context and breakout analyzer.",
    )
    parser.add_argument(
        "template",
        help="command template with the {INPUT} marker, e.g. 'curl \"{INPUT}\"'",
    )
    parser.add_argument(
        "payload",
        nargs="?",
        help="payload to inject (omit when using --mutate)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a JSON report instead of the diagram",
    )
    parser.add_argument(
        "--mutate",
        action="store_true",
        help="generate and rank breakout payloads for the template",
    )
    parser.add_argument(
        "--fuzz",
        action="store_true",
        help="expand and test payloads to discover exploit paths (shell/sql/template)",
    )
    parser.add_argument(
        "--command",
        default="id",
        help="demonstration command embedded in mutated payloads (default: id)",
    )
    parser.add_argument(
        "--lang",
        "-l",
        default="shell",
        help="injection language: shell (default), sql, template, prompt, or agent",
    )
    parser.add_argument(
        "--source",
        "-s",
        default="tool_output",
        help=(
            "for --lang agent, the provenance of the content: tool_output "
            "(default), agent_message, memory, mcp_resource, "
            "retrieved_document, web, user"
        ),
    )
    parser.add_argument(
        "--dialect",
        "-d",
        default=None,
        help=(
            "dialect within the language. shell: posix (default), cmd, "
            "powershell. sql: mysql (default), postgres, mssql, sqlite, ansi. "
            "template: jinja2 (default), twig, freemarker, erb, handlebars, ..."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    lang = args.lang.strip().lower()
    if lang not in ("shell", "sql", "template", "prompt", "agent"):
        parser.error("--lang must be 'shell', 'sql', 'template', 'prompt', or 'agent'")

    try:
        if args.fuzz:
            if lang not in ("shell", "sql", "template"):
                parser.error("--fuzz supports --lang shell, sql, or template")
            result = fuzz(
                args.template, lang=lang, dialect=args.dialect, command=args.command
            )
            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                print(_render_fuzz(result))
            return 0 if result.valid == 0 else 2

        if lang == "agent":
            if args.mutate:
                parser.error("--mutate is not supported for --lang agent")
            # The content is the untrusted blob; templates are not used here.
            result = analyze_agent(args.template, parse_source(args.source))
            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                print(_render_agent(result))
            return 0 if result.risk.value in ("NONE", "LOW") else 2

        if lang == "prompt":
            if args.mutate:
                parser.error("--mutate is not supported for --lang prompt")
            if args.payload is None:
                parser.error("payload is required")
            result = analyze_prompt(args.template, args.payload)
            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                print(_render_prompt(result))
            return 0 if result.risk.value in ("NONE", "LOW") else 2

        if lang == "sql":
            dialect = parse_sql_dialect(args.dialect or "mysql")
            if args.mutate:
                _emit_mutation(mutate_sql(args.template, dialect=dialect), args.json)
                return 0
            if args.payload is None:
                parser.error("payload is required unless --mutate is used")
            result = analyze_sql(args.template, args.payload, dialect)
        elif lang == "template":
            engine = parse_template_engine(args.dialect or "jinja2")
            if args.mutate:
                _emit_mutation(mutate_template(args.template, engine), args.json)
                return 0
            if args.payload is None:
                parser.error("payload is required unless --mutate is used")
            result = analyze_template(args.template, args.payload, engine)
        else:
            dialect = parse_dialect(args.dialect or "posix")
            if args.mutate:
                result = mutate(args.template, command=args.command, dialect=dialect)
                _emit_mutation(result, args.json)
                return 0
            if args.payload is None:
                parser.error("payload is required unless --mutate is used")
            result = analyze(args.template, args.payload, dialect)

        if args.json:
            print(to_json(result))
        else:
            print(visualize(result))
        return 0 if result.risk.value in ("NONE", "LOW") else 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _emit_mutation(result, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_mutation(result)


def _render_fuzz(result) -> str:
    lines = ["XyaInjex fuzzing", "=" * 40]
    lines.append(f"Template : {result.template}")
    lines.append(f"Lang     : {result.lang}  Dialect: {result.dialect or 'default'}")
    lines.append(f"Generated: {result.generated}   Exploit paths: {result.valid}")
    lines.append(f"Strategies: {', '.join(result.strategies) or '-'}")
    lines.append(f"Contexts : {', '.join(result.contexts_reached) or '-'}")
    lines.append("")
    lines.append("Top exploit paths:")
    for p in result.paths[:12]:
        lines.append(f"  [{p.risk.value:8}] {p.payload!r}  ({p.strategy})")
        lines.append(f"             {' -> '.join(p.stages)}")
    return "\n".join(lines)


def _render_agent(result) -> str:
    lines = ["XyaInjex agent analysis", "=" * 40]
    lines.append(f"Content : {result.content}")
    lines.append(f"Source  : {result.source.value}")
    lines.append(f"Risk    : {result.risk.value}")
    lines.append("")
    if result.findings:
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity.value:8}] {f.threat.value}: {f.title}")
            lines.append(f"             {f.evidence}")
    else:
        lines.append("No findings.")
    if result.notes:
        lines.append("")
        lines.append("Notes:")
        for note in result.notes:
            lines.append(f"  - {note}")
    return "\n".join(lines)


def _render_prompt(result) -> str:
    lines = ["XyaInjex prompt analysis", "=" * 40]
    lines.append(f"Template : {result.template}")
    lines.append(f"Payload  : {result.payload}")
    lines.append(f"Role     : {result.role_context}")
    lines.append(f"Risk     : {result.risk.value}")
    lines.append("")
    if result.findings:
        lines.append("Findings:")
        for f in result.findings:
            lines.append(f"  [{f.severity.value:8}] {f.threat.value}: {f.title}")
            lines.append(f"             {f.evidence}")
    else:
        lines.append("No findings.")
    if result.notes:
        lines.append("")
        lines.append("Notes:")
        for note in result.notes:
            lines.append(f"  - {note}")
    return "\n".join(lines)


def _print_mutation(result) -> None:
    label = getattr(result, "dialect", None) or getattr(result, "engine", None)
    print(f"Template : {result.template}")
    print(f"Dialect  : {label.value}")
    print(f"Context  : {result.context.value}")
    print(f"Generated: {result.generated}")
    print(f"Valid    : {result.valid}")
    print("")
    print("High probability payloads:")
    for c in result.candidates[:10]:
        print(f"  [{c.risk.value:8}] {c.payload!r}  ({c.strategy})")


if __name__ == "__main__":
    raise SystemExit(main())
