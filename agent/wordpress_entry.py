#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

import wordpress_agent as wp
import wordpress_components as components
import wordpress_staging as staging

_original_dispatch = wp.dispatch
_SELECTIVE_SCOPES = {"plugins_themes": ("plugins", "themes")}


def _snapshot_for_selective(live_domain: str, staging_domain: str, scope: str) -> tuple[str, Path, dict]:
    live_root = wp._wordpress_root(live_domain)
    live = staging._config_meta(live_root)
    snapshot_id = f"{int(time.time()):010d}-{os.urandom(4).hex()}"
    snapshot = staging._publish_dir(wp, live_domain, snapshot_id)
    snapshot.mkdir(mode=0o700)
    try:
        staging._scan_tree(live_root)
        shutil.copytree(live_root, snapshot / "files", symlinks=False)
        staging._dump_db(live["db_name"], snapshot / "database.sql")
        manifest = {
            "live_domain": live_domain,
            "staging_domain": staging_domain,
            "live_db": live["db_name"],
            "db_user": live["db_user"],
            "created_at": int(time.time()),
            "scope": scope,
        }
        manifest_path = snapshot / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
        os.chmod(manifest_path, 0o600)
        return snapshot_id, snapshot, manifest
    except Exception:
        shutil.rmtree(snapshot, ignore_errors=True)
        raise


def _prepare_component(stage_root: Path, live_root: Path, name: str) -> Path:
    stage_dir = stage_root / "wp-content" / name
    live_parent = live_root / "wp-content"
    if not stage_dir.is_dir() or stage_dir.is_symlink():
        raise ValueError(f"wordpress-staging-{name}-unavailable")
    if not live_parent.is_dir() or live_parent.is_symlink():
        raise ValueError("wordpress-live-content-unavailable")
    staging._scan_tree(stage_dir)
    temp = live_parent / f".nvp-wp-selective-{name}-{os.urandom(5).hex()}"
    shutil.copytree(stage_dir, temp, symlinks=False)
    staging._chown_www(temp)
    return temp


def selective_publish(live_domain: str, staging_domain: str, scope: str) -> dict:
    live_domain = wp._domain(live_domain)
    staging_domain = wp._domain(staging_domain)
    scope = str(scope or "").strip().lower()
    names = _SELECTIVE_SCOPES.get(scope)
    if not names:
        raise ValueError("unsupported-wordpress-selective-publish-scope")
    if live_domain == staging_domain:
        raise ValueError("staging-target-must-differ")

    live_root = wp._wordpress_root(live_domain)
    stage_root = wp._wordpress_root(staging_domain)
    snapshot_id, snapshot, manifest = _snapshot_for_selective(live_domain, staging_domain, scope)
    prepared: dict[str, Path] = {}
    previous: dict[str, Path | None] = {}
    published_counts: dict[str, int] = {}
    try:
        for name in names:
            prepared[name] = _prepare_component(stage_root, live_root, name)
            published_counts[name] = staging._scan_tree(prepared[name])[0]

        for name in names:
            live_dir = live_root / "wp-content" / name
            old: Path | None = None
            if live_dir.exists() or live_dir.is_symlink():
                if not live_dir.is_dir() or live_dir.is_symlink():
                    raise ValueError(f"wordpress-live-{name}-unsafe")
                old = live_dir.parent / f".nvp-wp-previous-{name}-{os.urandom(5).hex()}"
                os.replace(live_dir, old)
            try:
                os.replace(prepared[name], live_dir)
            except Exception:
                if old and old.exists():
                    os.replace(old, live_dir)
                raise
            previous[name] = old

        check = wp.inventory(live_domain)
        if not check.get("ok"):
            raise RuntimeError("wordpress-selective-publish-validation-failed")
        for old in previous.values():
            if old and old.exists():
                shutil.rmtree(old, ignore_errors=True)
        return {
            "ok": True,
            "live_domain": live_domain,
            "staging_domain": staging_domain,
            "snapshot_id": snapshot_id,
            "scope": scope,
            "version": str(check.get("version", ""))[:40],
            "published": published_counts,
            "database_changed": False,
            "uploads_changed": False,
            "safety": "rollback-ready",
        }
    except Exception:
        for temp in prepared.values():
            if temp.exists():
                shutil.rmtree(temp, ignore_errors=True)
        try:
            staging._restore_publish(wp, live_domain, snapshot, manifest)
        except Exception:
            pass
        raise


def dispatch(req: dict) -> dict:
    if str(req.get("action", "")) == "staging-publish-selective":
        return selective_publish(
            req.get("source_domain", ""),
            req.get("target_domain", ""),
            req.get("scope", ""),
        )
    staging_result = staging.dispatch(wp, req)
    if staging_result is not None:
        return staging_result
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
            "staging_clone": True,
            "staging_preview": True,
            "staging_publish": True,
            "staging_publish_selective": True,
            "staging_publish_rollback": True,
        })
        result["capabilities"] = capabilities
        return result
    return _original_dispatch(req)


wp.dispatch = dispatch

if __name__ == "__main__":
    wp.main()
