"""Shell parser-divergence regression cases."""

from __future__ import annotations

from .models import CorpusCase

SHELL_DIALECTS = ["posix", "cmd", "powershell", "fish"]

SHELL_CASES: tuple[CorpusCase, ...] = (
    CorpusCase(
        id="semicolon-unquoted",
        template="ping {INPUT}",
        payload="; whoami",
        note="Semicolon separates commands in posix, powershell, and fish but not cmd.",
        divergent=True,
    ),
    CorpusCase(
        id="double-quote-curl",
        template='curl "{INPUT}"',
        payload='"; id ; #',
        note="Close a double-quoted argument and inject; cmd lacks # comment truncation.",
        divergent=True,
    ),
    CorpusCase(
        id="semicolon-echo-unquoted",
        template="echo {INPUT}",
        payload="; whoami",
        note="Same semicolon divergence on an unquoted echo sink.",
        divergent=True,
    ),
    CorpusCase(
        id="single-quote-grep",
        template="grep '{INPUT}' file.txt",
        payload="'; id ; #",
        note="Break out of a single-quoted grep argument.",
        divergent=True,
    ),
    CorpusCase(
        id="double-quote-ping",
        template='ping "{INPUT}"',
        payload='"; whoami ; #',
        note="Close a quoted ping host and inject a trailing command.",
        divergent=True,
    ),
    CorpusCase(
        id="powershell-c-separator",
        template="powershell -c ping {INPUT}",
        payload="; whoami",
        note="Semicolon after an inline powershell -c command.",
        divergent=True,
    ),
    CorpusCase(
        id="hash-newline-cmd",
        template="ping {INPUT}",
        payload="#\nwhoami",
        note="A newline after # starts a comment in cmd only among these dialects.",
        divergent=True,
    ),
    CorpusCase(
        id="bash-c-single-quote",
        template="bash -c 'echo {INPUT}'",
        payload="'; id ; #",
        note="Escape a single-quoted bash -c string.",
        divergent=True,
    ),
    CorpusCase(
        id="bash-c-double-quote",
        template='sh -c "echo {INPUT}"',
        payload='"; id ; #',
        note="Escape a double-quoted sh -c string.",
        divergent=True,
    ),
    CorpusCase(
        id="ampersand-unquoted",
        template="ping {INPUT}",
        payload="& whoami",
        note="Ampersand chaining is recognized by every shell dialect here.",
        divergent=False,
    ),
    CorpusCase(
        id="or-chain",
        template="ping {INPUT}",
        payload="|| whoami",
        note="OR chaining behaves consistently across dialects.",
        divergent=False,
    ),
    CorpusCase(
        id="and-chain",
        template="ping {INPUT}",
        payload="&& whoami",
        note="AND chaining behaves consistently across dialects.",
        divergent=False,
    ),
    CorpusCase(
        id="pipe-unquoted",
        template="nslookup {INPUT}",
        payload="| whoami",
        note="Pipe to a second command at the top level.",
        divergent=False,
    ),
    CorpusCase(
        id="pipe-echo",
        template="echo {INPUT}",
        payload="| whoami",
        note="Pipe after an unquoted echo argument.",
        divergent=False,
    ),
    CorpusCase(
        id="heredoc-terminator",
        template="cat <<EOF\n{INPUT}\nEOF",
        payload="EOF\nid",
        note="Close a heredoc with its delimiter line and inject a command.",
        divergent=False,
    ),
    CorpusCase(
        id="heredoc-quoted-delim",
        template="cat <<'EOF'\n{INPUT}\nEOF",
        payload="EOF\nid",
        note="Quoted heredoc delimiter; terminator injection still reaches top level.",
        divergent=False,
    ),
    CorpusCase(
        id="cmd-ampersand",
        template="cmd /c ping {INPUT}",
        payload="& whoami",
        note="Cmd-style ampersand after cmd /c.",
        divergent=False,
    ),
    CorpusCase(
        id="quoted-pipe",
        template='ping "{INPUT}"',
        payload='"| whoami',
        note="Close quotes then pipe; all dialects agree on injection.",
        divergent=False,
    ),
    CorpusCase(
        id="substitution-in-quotes-no-break",
        template='wget "{INPUT}"',
        payload="$(id)",
        note="Command substitution inside quotes stays contained.",
        divergent=False,
    ),
    CorpusCase(
        id="backtick-unquoted-contained",
        template="ping {INPUT}",
        payload="`whoami`",
        note="Backticks in an unquoted word are not breakout for these analyzers.",
        divergent=False,
    ),
)
