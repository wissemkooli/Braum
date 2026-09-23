"""Smoke test: the package imports and its component boundaries exist.

This is scaffolding-level only. It exists so CI has something real to run and so a
broken package layout fails fast; it asserts nothing about the defense, which is not
implemented yet.
"""

import importlib

import tekmor

COMPONENTS = [
    "defense",
    "provenance",
    "policy",
    "observability",
    "simulator",
    "runtime",
]


def test_version_is_set():
    assert tekmor.__version__


def test_components_import():
    for name in COMPONENTS:
        assert importlib.import_module(f"tekmor.{name}") is not None
