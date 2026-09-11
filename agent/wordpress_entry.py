#!/usr/bin/env python3
from __future__ import annotations

import wordpress_agent as wp
import wordpress_components as components

_original_dispatch = wp.dispatch


def dispatch(req: dict) -> dict:
    component_result = components.dispatch(wp, req)
    if component_result is not None:
        return component_result
    if str(req.get("action", "")) == "status":
        result = _original_dispatch(req)
        capabilities = dict(result.get("capabilities") or {})
        capabilities.update({
            "component_check": True,
            "component_update": True,
            "component_rollback": True,
        })
        result["capabilities"] = capabilities
        return result
    return _original_dispatch(req)


wp.dispatch = dispatch

if __name__ == "__main__":
    wp.main()
