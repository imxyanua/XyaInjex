"""Tests for optional tree-sitter notes in POSIX shell analysis."""

from __future__ import annotations

import pytest

from xyainjex import analyze
from xyainjex.dialects import Dialect
from xyainjex.shell import treesitter


pytestmark = pytest.mark.skipif(
    not treesitter.available(), reason="tree-sitter optional extra not installed"
)


def test_analyze_posix_adds_treesitter_disagreement_note():
    result = analyze("ping {INPUT}", "|| whoami", Dialect.POSIX)
    assert any("Tree-sitter bash disagrees" in n for n in result.notes)
