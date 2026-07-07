"""Tests for the optional tree-sitter bash parser spike."""

from __future__ import annotations

import pytest

from xyainjex.shell import treesitter


pytestmark = pytest.mark.skipif(
    not treesitter.available(), reason="tree-sitter optional extra not installed"
)


def test_top_level_command_count():
    assert treesitter.top_level_command_count("ping 127.0.0.1") == 1
    assert treesitter.top_level_command_count("ping 127.0.0.1; whoami") == 2


@pytest.mark.parametrize(
    ("template", "payload", "injected"),
    [
        ("ping {INPUT}", "; whoami", True),
        ("ping {INPUT}", "127.0.0.1", False),
        ('curl "{INPUT}"', '"; id ; #', True),
        ("ping {INPUT}", "`whoami`", False),
    ],
)
def test_compare_posix_param(template, payload, injected):
    result = treesitter.compare_posix(template, payload)
    assert result is not None
    assert result.lexical_injected is injected
    assert result.treesitter_injected is injected
    assert result.agrees
