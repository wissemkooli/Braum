"""SENTINEL defense layer.

This package is the *defense solution*. It is deliberately isolated from the
evaluation harness and from scenario metadata: nothing in here may import
harness code, read a scenario file, or reference a scenario identifier,
reference plan, success condition or forbidden-effect list.

`tests/test_no_oracle.py` enforces that isolation mechanically.
"""

__version__ = "1.0.0"
