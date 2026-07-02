"""Registry mapping each :class:`~xyainjex.models.Dialect` to its scanner and
context conventions, so the analysis engine stays dialect agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Context, Dialect, SqlDialect
from .scan import (
    ARITH,
    BACKTICK,
    CMDSUB,
    DOUBLE,
    PARAM,
    SINGLE,
    SUBEXPR,
    BaseScanner,
)
from .shell.scanner import ShellScanner
from .windows.cmd import CmdScanner
from .windows.powershell import PowerShellScanner


@dataclass(frozen=True)
class DialectSpec:
    dialect: Dialect
    scanner_cls: type[BaseScanner]
    frame_to_context: dict[str, Context]
    supports_comment: bool

    def scanner(self) -> BaseScanner:
        return self.scanner_cls()

    def context_of(self, frame_kind: str | None) -> Context:
        return self.frame_to_context.get(frame_kind, Context.UNQUOTED)


_POSIX_MAP = {
    SINGLE: Context.SINGLE_QUOTE,
    DOUBLE: Context.DOUBLE_QUOTE,
    BACKTICK: Context.BACKTICK,
    CMDSUB: Context.COMMAND_SUBSTITUTION,
    ARITH: Context.ARITHMETIC,
    PARAM: Context.PARAMETER_EXPANSION,
}

_CMD_MAP = {
    DOUBLE: Context.DOUBLE_QUOTE,
}

_POWERSHELL_MAP = {
    SINGLE: Context.SINGLE_QUOTE,
    DOUBLE: Context.DOUBLE_QUOTE,
    SUBEXPR: Context.COMMAND_SUBSTITUTION,
    PARAM: Context.PARAMETER_EXPANSION,
}

_SPECS: dict[Dialect, DialectSpec] = {
    Dialect.POSIX: DialectSpec(
        Dialect.POSIX, ShellScanner, _POSIX_MAP, supports_comment=True
    ),
    Dialect.CMD: DialectSpec(Dialect.CMD, CmdScanner, _CMD_MAP, supports_comment=False),
    Dialect.POWERSHELL: DialectSpec(
        Dialect.POWERSHELL, PowerShellScanner, _POWERSHELL_MAP, supports_comment=True
    ),
}


def get_spec(dialect: Dialect) -> DialectSpec:
    return _SPECS[dialect]


def parse_dialect(name: str) -> Dialect:
    """Resolve a user supplied dialect name, with a few friendly aliases."""
    key = name.strip().lower()
    aliases = {
        "sh": Dialect.POSIX,
        "bash": Dialect.POSIX,
        "zsh": Dialect.POSIX,
        "posix": Dialect.POSIX,
        "cmd": Dialect.CMD,
        "bat": Dialect.CMD,
        "batch": Dialect.CMD,
        "powershell": Dialect.POWERSHELL,
        "pwsh": Dialect.POWERSHELL,
        "ps": Dialect.POWERSHELL,
        "ps1": Dialect.POWERSHELL,
    }
    if key not in aliases:
        valid = ", ".join(sorted(aliases))
        raise ValueError(f"unknown dialect {name!r}; valid values: {valid}")
    return aliases[key]


def parse_sql_dialect(name: str) -> SqlDialect:
    """Resolve a user supplied SQL dialect name, with friendly aliases."""
    key = name.strip().lower()
    aliases = {
        "mysql": SqlDialect.MYSQL,
        "mariadb": SqlDialect.MYSQL,
        "postgres": SqlDialect.POSTGRES,
        "postgresql": SqlDialect.POSTGRES,
        "pg": SqlDialect.POSTGRES,
        "mssql": SqlDialect.MSSQL,
        "sqlserver": SqlDialect.MSSQL,
        "sqlite": SqlDialect.SQLITE,
        "ansi": SqlDialect.ANSI,
        "sql": SqlDialect.MYSQL,
    }
    if key not in aliases:
        valid = ", ".join(sorted(aliases))
        raise ValueError(f"unknown SQL dialect {name!r}; valid values: {valid}")
    return aliases[key]
