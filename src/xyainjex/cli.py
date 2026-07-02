"""Command line interface for XyaInjex."""

from __future__ import annotations

import argparse
import json
import sys

from .analyzer import analyze
from .dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from .mutation import mutate
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
        "--command",
        default="id",
        help="demonstration command embedded in mutated payloads (default: id)",
    )
    parser.add_argument(
        "--lang",
        "-l",
        default="shell",
        help="injection language: shell (default), sql, or template",
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
    if lang not in ("shell", "sql", "template"):
        parser.error("--lang must be 'shell', 'sql', or 'template'")

    try:
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
