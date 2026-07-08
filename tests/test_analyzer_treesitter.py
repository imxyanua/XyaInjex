"""Tests for optional tree-sitter notes in POSIX shell analysis."""

from __future__ import annotations

import pytest

from xyainjex import analyze
from xyainjex.dialects import Dialect
from xyainjex.models import Risk
from xyainjex.shell import treesitter

pytestmark = pytest.mark.skipif(
    not treesitter.available(), reason="tree-sitter optional extra not installed"
)


def test_analyze_posix_downgrades_risk_on_treesitter_disagreement():
    result = analyze("ping {INPUT}", "|| whoami", Dialect.POSIX)
    assert result.risk == Risk.HIGH
    assert result.breakout.command_injected
    assert any("Tree-sitter bash disagrees" in n for n in result.notes)
    assert any("parse-tree verdict" in n for n in result.notes)


def test_analyze_posix_keeps_risk_when_treesitter_agrees():
    result = analyze("ping {INPUT}", "; whoami", Dialect.POSIX)
    assert result.risk == Risk.CRITICAL
    assert not any("Tree-sitter bash disagrees" in n for n in result.notes)


def test_adjust_risk_escalates_when_treesitter_injects():
    cmp = treesitter.TreesitterCompareResult(
        template="t",
        payload="p",
        rendered="t",
        baseline_commands=1,
        actual_commands=2,
        lexical_injected=False,
        treesitter_injected=True,
        agrees=False,
    )
    assert treesitter.adjust_risk(Risk.LOW, cmp) == Risk.HIGH
    assert treesitter.adjust_risk(Risk.MEDIUM, cmp) == Risk.HIGH
    assert treesitter.adjust_risk(Risk.HIGH, cmp) == Risk.HIGH


def test_adjust_risk_downgrades_when_lexical_overcalls():
    cmp = treesitter.TreesitterCompareResult(
        template="t",
        payload="p",
        rendered="t",
        baseline_commands=1,
        actual_commands=1,
        lexical_injected=True,
        treesitter_injected=False,
        agrees=False,
    )
    assert treesitter.adjust_risk(Risk.CRITICAL, cmp) == Risk.HIGH
    assert treesitter.adjust_risk(Risk.HIGH, cmp) == Risk.MEDIUM
