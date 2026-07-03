"""Core data models shared across the XyaInjex engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Dialect(Enum):
    """Command language whose lexical rules govern shell analysis."""

    POSIX = "posix"
    CMD = "cmd"
    POWERSHELL = "powershell"
    FISH = "fish"


class SqlDialect(Enum):
    """SQL dialect whose lexical rules govern SQL injection analysis."""

    MYSQL = "mysql"
    POSTGRES = "postgres"
    MSSQL = "mssql"
    SQLITE = "sqlite"
    ANSI = "ansi"
    ORACLE = "oracle"


class CodeLang(Enum):
    """Programming language whose eval sink is being analyzed."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    PHP = "php"


class CrlfKind(Enum):
    """Sink kind for CRLF (carriage-return line-feed) injection."""

    HEADER = "header"
    LOG = "log"


class TemplateEngine(Enum):
    """Template engine whose delimiter syntax governs SSTI analysis."""

    JINJA2 = "jinja2"
    TWIG = "twig"
    LIQUID = "liquid"
    NUNJUCKS = "nunjucks"
    FREEMARKER = "freemarker"
    ERB = "erb"
    HANDLEBARS = "handlebars"
    VELOCITY = "velocity"
    BLADE = "blade"
    MAKO = "mako"
    RAZOR = "razor"
    GOTEMPLATE = "gotemplate"
    EJS = "ejs"
    THYMELEAF = "thymeleaf"


class Context(Enum):
    """Lexical context that surrounds the injection point."""

    UNQUOTED = "unquoted"
    SINGLE_QUOTE = "single_quote"
    DOUBLE_QUOTE = "double_quote"
    BACKTICK = "backtick"
    COMMAND_SUBSTITUTION = "command_substitution"
    ARITHMETIC = "arithmetic"
    PARAMETER_EXPANSION = "parameter_expansion"
    HEREDOC = "heredoc"
    # SQL contexts
    SQL_STRING = "sql_string"
    SQL_IDENTIFIER = "sql_identifier"
    SQL_NUMERIC = "sql_numeric"
    # Template contexts
    TEMPLATE_TEXT = "template_text"
    TEMPLATE_EXPRESSION = "template_expression"
    TEMPLATE_STATEMENT = "template_statement"
    TEMPLATE_COMMENT = "template_comment"
    TEMPLATE_STRING = "template_string"
    # XPath contexts
    XPATH_STRING = "xpath_string"
    XPATH_EXPRESSION = "xpath_expression"
    # LDAP context
    LDAP_FILTER = "ldap_filter"
    # NoSQL (MongoDB) contexts
    NOSQL_STRING = "nosql_string"
    NOSQL_VALUE = "nosql_value"
    # Code (eval sink) contexts
    CODE_STRING = "code_string"
    CODE_TEMPLATE = "code_template"
    CODE_EXPRESSION = "code_expression"
    # CRLF contexts
    HTTP_HEADER = "http_header"
    LOG_LINE = "log_line"
    # XML contexts
    XML_TEXT = "xml_text"
    XML_ATTR = "xml_attr"
    XML_CDATA = "xml_cdata"
    XML_COMMENT = "xml_comment"
    # YAML contexts
    YAML_PLAIN = "yaml_plain"
    YAML_SINGLE = "yaml_single"
    YAML_DOUBLE = "yaml_double"
    # GraphQL contexts
    GQL_STRING = "gql_string"
    GQL_ARG = "gql_arg"
    # Expression language (EL / OGNL / SpEL) contexts
    EL_TEXT = "el_text"
    EL_EXPRESSION = "el_expression"
    EL_STRING = "el_string"
    # CSV / spreadsheet formula contexts
    CSV_CELL = "csv_cell"
    CSV_MIDCELL = "csv_midcell"
    # Server-Side Includes context
    SSI_TEXT = "ssi_text"
    # HTML / XSS contexts
    HTML_TEXT = "html_text"
    HTML_ATTR = "html_attr"
    HTML_SCRIPT = "html_script"
    HTML_COMMENT = "html_comment"
    # SSRF / URL contexts
    SSRF_URL = "ssrf_url"
    SSRF_HOST = "ssrf_host"
    SSRF_PATH = "ssrf_path"
    SSRF_QUERY = "ssrf_query"

    @property
    def quote_char(self) -> str | None:
        """The character that closes this context, if any."""
        return {
            Context.SINGLE_QUOTE: "'",
            Context.DOUBLE_QUOTE: '"',
            Context.BACKTICK: "`",
            Context.SQL_STRING: "'",
        }.get(self)


class Risk(Enum):
    """Overall severity of an analyzed injection."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Balance:
    """Result of the syntax balance engine over a rendered command."""

    quotes_balanced: bool
    single_quote_open: bool
    double_quote_open: bool
    backtick_open: bool
    unbalanced_pairs: dict[str, int] = field(default_factory=dict)

    @property
    def syntax_valid(self) -> bool:
        return self.quotes_balanced and not self.unbalanced_pairs


@dataclass
class Breakout:
    """Description of how, and whether, the payload escaped its context."""

    context: Context
    quote_closed: bool
    command_injected: bool
    comment_terminated: bool
    separators: list[str] = field(default_factory=list)
    commands_created: int = 0
    breakout_index: int | None = None
    # Payload opened a command substitution that executes code even without a
    # top level command separator (e.g. $(id) or `id`).
    substitution_injected: bool = False


@dataclass
class AnalysisResult:
    """Full verdict produced by :func:`xyainjex.analyze`."""

    template: str
    payload: str
    rendered: str
    dialect: Dialect | SqlDialect | TemplateEngine | CodeLang | CrlfKind | None
    context: Context
    breakout: Breakout
    balance: Balance
    risk: Risk
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["dialect"] = self.dialect.value if self.dialect is not None else None
        data["context"] = self.context.value
        data["risk"] = self.risk.value
        data["breakout"]["context"] = self.breakout.context.value
        data["syntax_valid"] = self.balance.syntax_valid
        return data
