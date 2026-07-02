"""Command line interface for XyaInjex."""

from __future__ import annotations

import argparse
import json
import sys

from .analyzer import analyze
from .mutation import mutate
from .report import to_json, visualize


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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.mutate:
            result = mutate(args.template, command=args.command)
            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                _print_mutation(result)
            return 0

        if args.payload is None:
            parser.error("payload is required unless --mutate is used")

        result = analyze(args.template, args.payload)
        if args.json:
            print(to_json(result))
        else:
            print(visualize(result))
        return 0 if result.risk.value in ("NONE", "LOW") else 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _print_mutation(result) -> None:
    print(f"Template : {result.template}")
    print(f"Context  : {result.context.value}")
    print(f"Generated: {result.generated}")
    print(f"Valid    : {result.valid}")
    print("")
    print("High probability payloads:")
    for c in result.candidates[:10]:
        print(f"  [{c.risk.value:8}] {c.payload!r}  ({c.strategy})")


if __name__ == "__main__":
    raise SystemExit(main())
