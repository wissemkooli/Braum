#!/usr/bin/env python3
"""Run the whole test suite with the standard library only: `python3 run_tests.py`."""
import sys
import unittest

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover("tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
