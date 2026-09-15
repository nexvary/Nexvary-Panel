from __future__ import annotations

import time

from flask import jsonify, request

from .core import audit, db
from .routes_wordpress_staging import SNAPSHOT_RE, _mapping_row, _source_context
from .security import role_required, step_up_required
from .wordpress_client import wordpress_call

_ALLOWED_SCOPES = {"plugins_themes"}


def _history_rows(conn, source: str) -> list[dict]:
    # `id` is the control-plane causal order. `created_at` is retained for display,
    # but can legitimately skew (restored/imported rows, second-resolution clocks,
    # or provider timestamps). Rollback eligibility must follow the last committed
    # publish operation, not a wall-clock value supplied by another path.
    rows = conn.execute(
        "SELECT id,source_domain,target_domain,snapshot_id,scope,status,version,detail,created_at,rolled_back_at "
        "FROM wordpress_publish_history WHERE source_domain=? ORDER BY id DESC LIMIT 20",
        (source,),
    ).fetchall()
    latest = conn.execute(
        "SELECT id FROM wordpress_publish_history WHERE source_domain=? AND status='published' ORDER BY id DESC LIMIT 1",
        (source,),
    ).fetchone()
    latest_id = int(latest["id"]) if latest else 0
    return [dict(row) | {"can_rollback": int(row["id"]) == latest_id and str(row["status"]) == "published"} for row in rows]


def _context(source: str):
    with db() as conn:
        site, instance, role = _source_context(conn, source)
        mapping = _mapping_row(conn, source) if site and instance else None
        if not site or not instance or not mapping:
            return None
        if role is None:
            return "policy"
        return {
            "owner": str(site["owner"]),
            "target": str(mapping["target_domain"]),
            "version": str(instance["version"] or ""),
        }


def register_wordpress_publish_routes(app):
    @app.get("/api/wordpress/staging/history")
    @role_required("admin", "operator", "viewer")
    def wordpress_publish_history():
        source = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        context = _context(source)
        if context == "policy":
            return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
        if not context:
            return jsonify(ok=False, error="staging mapping not found or outside your scope"), 404
        with db() as conn:
            history = _history_rows(conn, source)
        return jsonify(ok=True, source_domain=source, target_domain=context["target"], history=history)

    @app.post("/api/wordpress/staging/publish-selective")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_publish_selective():
        data = request.get_json(silent=True) or {}
        source = str(data.get("source_domain", "")).strip().lower().rstrip(".")
        scope = str(data.get("scope", "")).strip().lower()
        if scope not in _ALLOWED_SCOPES:
            return jsonify(ok=False, error="unsupported selective publish scope"), 400
        context = _context(source)
        if context == "policy":
            return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
        if not context:
            return jsonify(ok=False, error="staging mapping not found or outside your scope"), 404
        target = str(context["target"])
        result = wordpress_call(
            {"action": "staging-publish-selective", "source_domain": source, "target_domain": target, "scope": scope},
            timeout=300,
        )
        if not result.get("ok"):
            audit("wordpress-staging-selective-publish", f"source={source} target={target} scope={scope} status=failed")
            return jsonify(ok=False, error=str(result.get("error", "selective publish failed"))[:180]), 503
        snapshot = str(result.get("snapshot_id", ""))[:32]
        if not SNAPSHOT_RE.fullmatch(snapshot):
            return jsonify(ok=False, error="selective publish completed without a valid rollback snapshot"), 502
        version = str(result.get("version", ""))[:40]
        published = result.get("published") if isinstance(result.get("published"), dict) else {}
        detail = f"plugins={int(published.get('plugins',0))};themes={int(published.get('themes',0))};database=unchanged;uploads=unchanged"
        now = int(time.time())
        with db() as conn:
            conn.execute(
                "INSERT INTO wordpress_publish_history(source_domain,target_domain,snapshot_id,scope,status,version,detail,created_at,rolled_back_at) VALUES(?,?,?,?,?,?,?,?,0)",
                (source, target, snapshot, scope, "published", version, detail, now),
            )
            conn.execute("UPDATE wordpress_staging SET status='selective-published',updated_at=? WHERE source_domain=?", (now, source))
            conn.execute("UPDATE wordpress_instances SET version=?,updated_at=? WHERE domain=?", (version, now, source))
            history = _history_rows(conn, source)
        audit("wordpress-staging-selective-publish", f"source={source} target={target} scope={scope} snapshot={snapshot}")
        return jsonify(
            ok=True,
            source_domain=source,
            target_domain=target,
            snapshot_id=snapshot,
            scope=scope,
            version=version,
            published=published,
            database_changed=False,
            uploads_changed=False,
            safety="rollback-ready",
            history=history,
        )

    @app.post("/api/wordpress/staging/history/<snapshot>/rollback")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_publish_history_rollback(snapshot: str):
        snapshot = str(snapshot or "").strip().lower()
        if not SNAPSHOT_RE.fullmatch(snapshot):
            return jsonify(ok=False, error="invalid WordPress publish snapshot"), 400
        data = request.get_json(silent=True) or {}
        source = str(data.get("source_domain", "")).strip().lower().rstrip(".")
        context = _context(source)
        if context == "policy":
            return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
        if not context:
            return jsonify(ok=False, error="staging mapping not found or outside your scope"), 404
        with db() as conn:
            row = conn.execute(
                "SELECT id,status FROM wordpress_publish_history WHERE source_domain=? AND snapshot_id=?",
                (source, snapshot),
            ).fetchone()
            latest = conn.execute(
                "SELECT id,snapshot_id FROM wordpress_publish_history WHERE source_domain=? AND status='published' ORDER BY id DESC LIMIT 1",
                (source,),
            ).fetchone()
            if not row:
                return jsonify(ok=False, error="publish snapshot is not tracked for this site"), 404
            if str(row["status"]) != "published" or not latest or str(latest["snapshot_id"]) != snapshot:
                return jsonify(ok=False, error="only the latest active publish snapshot can be rolled back"), 409
        result = wordpress_call({"action": "staging-publish-rollback", "source_domain": source, "snapshot_id": snapshot}, timeout=240)
        if not result.get("ok"):
            audit("wordpress-staging-history-rollback", f"source={source} snapshot={snapshot} status=failed")
            return jsonify(ok=False, error=str(result.get("error", "publish rollback failed"))[:180]), 503
        version = str(result.get("version", ""))[:40]
        now = int(time.time())
        with db() as conn:
            conn.execute("UPDATE wordpress_publish_history SET status='rolled-back',rolled_back_at=? WHERE source_domain=? AND snapshot_id=?", (now, source, snapshot))
            conn.execute("UPDATE wordpress_instances SET version=?,updated_at=? WHERE domain=?", (version, now, source))
            mapping = _mapping_row(conn, source)
            if mapping and str(mapping["last_publish_snapshot"]) == snapshot:
                conn.execute("UPDATE wordpress_staging SET status='rolled-back',updated_at=? WHERE source_domain=?", (now, source))
            history = _history_rows(conn, source)
        audit("wordpress-staging-history-rollback", f"source={source} snapshot={snapshot}")
        return jsonify(ok=True, source_domain=source, snapshot_id=snapshot, version=version, rolled_back=True, history=history)
