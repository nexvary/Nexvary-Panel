"""Compatibility entrypoint for the Advanced Hosting Ops schema.

The canonical implementation lives in :mod:`panel.ops_schema`.  Keeping this
small alias makes installer/file-integrity checks and future upgrades tolerant
of the earlier development filename without duplicating schema logic.
"""

from .ops_schema import ensure_ops_schema

__all__ = ["ensure_ops_schema"]
