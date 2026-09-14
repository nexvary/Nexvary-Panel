from __future__ import annotations

import re
import time

from flask import jsonify, request

from .core import audit, db
from .routes_wordpress_publish import _history_rows
from .routes_wordpress_staging import SNAPSHOT_RE, _mapping_row, _source_context
from .security import role_required, step_up_required
from .wordpress_client import wordpress_call

KIND_SET = {"plugin", "theme"}
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
ACTIVE_STATES = {"preview", "verified"}


def _provider_error(result: dict, fallback: str = "wordpress smart update provider unavailable"):
    error = str(result.get("error", fallback))[:180]
    status = 404 if error in {"wordpress-component-not-installed", "wordpress-not-detected", "wordpress-root-unavailable"} else 409 if "validation" in error or "invalid" in error else 503
    return jsonify(ok=False, error=error), status


def _context(conn, source: str):
    site, instance, role = _source_context(conn, source)
    mapping = _mapping_row(conn, source) if site and instance else None
    if not site or not instance or not mapping:
        return None
    if role is None:
        return "policy"
    target = str(mapping["target_domain"])
    stage = conn.execute("SELECT domain,status,owner FROM wordpress_instances WHERE domain=?", (target,)).fetchone()
    if not stage or str(stage["owner"]) != str(site["owner"]):
        return None
    return {
        "owner": str(site["owner"]),
        "source": source,
        "target": target,
        "source_version": str(instance["version"] or ""),
        "stage_status": str(stage["status"] or ""),
    }


def _component(data: dict) -> tuple[str, str, str] | None:
    source = str(data.get("source_domain", "")).strip().lower().rstrip(".")
    kind = str(data.get("kind", "")).strip().lower()
    slug = str(data.get("slug", "")).strip().lower()
    if kind not in KIND_SET or not SLUG_RE.fullmatch(slug) or not source:
        return None
    return source, kind, slug


def _candidate(conn, candidate_id: int):
    row = conn.execute("SELECT * FROM wordpress_update_guard WHERE id=?", (candidate_id,)).fetchone()
    if not row:
        return None
    context = _context(conn, str(row["source_domain"]))
    if not context or context == "policy" or str(context["owner"]) != str(row["owner"]):
        return None
    return row, context


def _rows(conn, source: str) -> list[dict]:
    rows = conn.execute(
        """SELECT id,source_domain,staging_domain,kind,slug,installed_version,target_version,
                  staging_snapshot,production_snapshot,status,detail,owner,created_at,updated_at,verified_at,published_at
           FROM wordpress_update_guard WHERE source_domain=? ORDER BY id DESC LIMIT 30""",
        (source,),
    ).fetchall()
    return [dict(row) for row in rows]


def _mark(conn, candidate_id: int, *, status: str, detail: str = "", staging_snapshot: str | None = None,
          production_snapshot: str | None = None, verified_at: int | None = None, published_at: int | None = None) -> None:
    now = int(time.time())
    current = conn.execute("SELECT staging_snapshot,production_snapshot,verified_at,published_at FROM wordpress_update_guard WHERE id=?", (candidate_id,)).fetchone()
    if not current:
        return
    conn.execute(
        """UPDATE wordpress_update_guard SET status=?,detail=?,staging_snapshot=?,production_snapshot=?,
             updated_at=?,verified_at=?,published_at=? WHERE id=?""",
        (
            status, detail[:1000],
            staging_snapshot if staging_snapshot is not None else str(current["staging_snapshot"] or ""),
            production_snapshot if production_snapshot is not None else str(current["production_snapshot"] or ""),
            now,
            verified_at if verified_at is not None else int(current["verified_at"] or 0),
            published_at if published_at is not None else int(current["published_at"] or 0),
            candidate_id,
        ),
    )


def register_wordpress_smart_guard_routes(app):
    @app.get("/api/wordpress/smart-guard")
    @role_required("admin", "operator", "viewer")
    def wordpress_smart_guard_status():
        source = str(request.args.get("domain", "")).strip().lower().rstrip(".")
        with db() as conn:
            context = _context(conn, source)
            if context == "policy":
                return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
            if not context:
                return jsonify(ok=False, error="staging mapping not found or outside your scope"), 404
            rows = _rows(conn, source)
        return jsonify(ok=True, source_domain=source, staging_domain=context["target"], candidates=rows,
                       policy={"staging_required": True, "verify_before_guarded_publish": True, "post_publish_integrity": True, "automatic_rollback_on_failed_postcheck": True})

    @app.post("/api/wordpress/smart-guard/preview")
    @role_required("admin", "operator")
    def wordpress_smart_guard_preview():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(ok=False, error="invalid request"), 400
        parsed = _component(data)
        if not parsed:
            return jsonify(ok=False, error="invalid Smart Update component"), 400
        source, kind, slug = parsed
        with db() as conn:
            context = _context(conn, source)
            if context == "policy":
                return jsonify(ok=False, error="software.wordpress disabled by hosting policy"), 403
            if not context:
                return jsonify(ok=False, error="staging mapping not found or outside your scope"), 404
            target = str(context["target"])
            owner = str(context["owner"])
        checked = wordpress_call({"action": "component-check", "domain": target, "kind": kind, "slug": slug}, timeout=35)
        if not checked.get("ok"):
            return _provider_error(checked)
        installed = str(checked.get("installed_version", ""))[:80]
        latest = str(checked.get("latest_version", ""))[:80]
        update_available = bool(checked.get("update_available"))
        status = "preview" if update_available else "not-needed"
        detail = "Update candidate ready for staging verification" if update_available else "Staging component is already current"
        now = int(time.time())
        with db() as conn:
            if update_available:
                conn.execute(
                    "UPDATE wordpress_update_guard SET status='superseded',updated_at=? WHERE source_domain=? AND kind=? AND slug=? AND status IN ('preview','verified')",
                    (now, source, kind, slug),
                )
            cur = conn.execute(
                """INSERT INTO wordpress_update_guard(source_domain,staging_domain,kind,slug,installed_version,target_version,status,detail,owner,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (source, target, kind, slug, installed, latest, status, detail, owner, now, now),
            )
            candidate_id = int(cur.lastrowid)
            row = conn.execute("SELECT * FROM wordpress_update_guard WHERE id=?", (candidate_id,)).fetchone()
        audit("wordpress-smart-guard-preview", f"source={source} staging={target} kind={kind} slug={slug} update={int(update_available)}")
        return jsonify(ok=True, candidate=dict(row), check=checked), 201

    @app.post("/api/wordpress/smart-guard/<int:candidate_id>/verify")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_smart_guard_verify(candidate_id: int):
        with db() as conn:
            found = _candidate(conn, candidate_id)
            if not found:
                return jsonify(ok=False, error="Smart Update candidate not found or outside your scope"), 404
            row, context = found
            if str(row["status"]) != "preview":
                return jsonify(ok=False, error="candidate is not awaiting staging verification"), 409
            target = str(context["target"])
            kind, slug = str(row["kind"]), str(row["slug"])

        result = wordpress_call({"action": "component-update", "domain": target, "kind": kind, "slug": slug}, timeout=150)
        if not result.get("ok"):
            with db() as conn:
                _mark(conn, candidate_id, status="failed", detail=str(result.get("error", "staging update failed")))
            audit("wordpress-smart-guard-verify", f"id={candidate_id} source={row['source_domain']} status=update-failed")
            return _provider_error(result, "staging update failed")

        snapshot = str(result.get("snapshot_id", ""))[:32]
        if not SNAPSHOT_RE.fullmatch(snapshot):
            with db() as conn:
                _mark(conn, candidate_id, status="failed", detail="staging update returned no valid rollback snapshot")
            return jsonify(ok=False, error="staging update returned no valid rollback snapshot"), 502

        integrity = wordpress_call({"action": "integrity", "domain": target}, timeout=90)
        after = wordpress_call({"action": "component-check", "domain": target, "kind": kind, "slug": slug}, timeout=35)
        integrity_ok = bool(integrity.get("ok") and integrity.get("integrity_ok"))
        component_ok = bool(after.get("ok") and not after.get("update_available") and str(after.get("installed_version", "")) == str(after.get("latest_version", "")))
        if not (integrity_ok and component_ok):
            rollback = wordpress_call({"action": "component-rollback", "domain": target, "snapshot_id": snapshot}, timeout=90)
            rolled = bool(rollback.get("ok"))
            status = "failed-rolled-back" if rolled else "failed-rollback-error"
            detail = f"post-update verification failed; integrity={int(integrity_ok)} component={int(component_ok)} rollback={int(rolled)}"
            with db() as conn:
                _mark(conn, candidate_id, status=status, detail=detail, staging_snapshot=snapshot)
            audit("wordpress-smart-guard-verify", f"id={candidate_id} source={row['source_domain']} status={status}")
            return jsonify(ok=False, error="staging verification failed", rolled_back=rolled, integrity=integrity, component=after), (409 if rolled else 503)

        now = int(time.time())
        with db() as conn:
            _mark(conn, candidate_id, status="verified", detail="staging update verified by component state and official core integrity", staging_snapshot=snapshot, verified_at=now)
            candidate = conn.execute("SELECT * FROM wordpress_update_guard WHERE id=?", (candidate_id,)).fetchone()
        audit("wordpress-smart-guard-verify", f"id={candidate_id} source={row['source_domain']} staging={target} status=verified snapshot={snapshot}")
        return jsonify(ok=True, candidate=dict(candidate), integrity=integrity, component=after, publish_ready=True)

    @app.post("/api/wordpress/smart-guard/<int:candidate_id>/publish")
    @role_required("admin", "operator")
    @step_up_required
    def wordpress_smart_guard_publish(candidate_id: int):
        with db() as conn:
            found = _candidate(conn, candidate_id)
            if not found:
                return jsonify(ok=False, error="Smart Update candidate not found or outside your scope"), 404
            row, context = found
            if str(row["status"]) != "verified":
                return jsonify(ok=False, error="candidate must be verified on staging before guarded publish"), 409
            source = str(context["source"])
            target = str(context["target"])
            cohort = conn.execute(
                "SELECT id FROM wordpress_update_guard WHERE source_domain=? AND staging_domain=? AND status='verified' ORDER BY id",
                (source, target),
            ).fetchall()
            cohort_ids = [int(item["id"]) for item in cohort]

        result = wordpress_call({"action": "staging-publish-selective", "source_domain": source, "target_domain": target, "scope": "plugins_themes"}, timeout=300)
        if not result.get("ok"):
            audit("wordpress-smart-guard-publish", f"id={candidate_id} source={source} status=publish-failed")
            return _provider_error(result, "guarded production publish failed")
        snapshot = str(result.get("snapshot_id", ""))[:32]
        if not SNAPSHOT_RE.fullmatch(snapshot):
            return jsonify(ok=False, error="guarded publish completed without a valid production rollback snapshot"), 502

        inventory = wordpress_call({"action": "inventory", "domain": source}, timeout=45)
        integrity = wordpress_call({"action": "integrity", "domain": source}, timeout=90)
        post_ok = bool(inventory.get("ok") and integrity.get("ok") and integrity.get("integrity_ok"))
        if not post_ok:
            rollback = wordpress_call({"action": "staging-publish-rollback", "source_domain": source, "snapshot_id": snapshot}, timeout=240)
            rolled = bool(rollback.get("ok"))
            status = "publish-failed-rolled-back" if rolled else "publish-failed-rollback-error"
            with db() as conn:
                for guard_id in cohort_ids:
                    _mark(conn, guard_id, status=status, detail="production post-publish verification failed", production_snapshot=snapshot)
            audit("wordpress-smart-guard-publish", f"id={candidate_id} source={source} status={status} snapshot={snapshot}")
            return jsonify(ok=False, error="production post-publish verification failed", rolled_back=rolled, inventory=inventory, integrity=integrity), (409 if rolled else 503)

        now = int(time.time())
        version = str(inventory.get("version", ""))[:40]
        published = result.get("published") if isinstance(result.get("published"), dict) else {}
        detail = f"smart-guard cohort={','.join(map(str,cohort_ids))};plugins={int(published.get('plugins',0))};themes={int(published.get('themes',0))};postcheck=verified"
        with db() as conn:
            conn.execute(
                "INSERT INTO wordpress_publish_history(source_domain,target_domain,snapshot_id,scope,status,version,detail,created_at,rolled_back_at) VALUES(?,?,?,?,?,?,?,?,0)",
                (source, target, snapshot, "plugins_themes", "published", version, detail, now),
            )
            conn.execute("UPDATE wordpress_staging SET status='selective-published',last_publish_snapshot=?,updated_at=? WHERE source_domain=?", (snapshot, now, source))
            conn.execute("UPDATE wordpress_instances SET version=?,updated_at=? WHERE domain=?", (version, now, source))
            for guard_id in cohort_ids:
                _mark(conn, guard_id, status="published", detail="verified staging cohort published and production integrity passed", production_snapshot=snapshot, published_at=now)
            history = _history_rows(conn, source)
        audit("wordpress-smart-guard-publish", f"id={candidate_id} source={source} cohort={len(cohort_ids)} snapshot={snapshot} status=verified")
        return jsonify(ok=True, source_domain=source, staging_domain=target, cohort_ids=cohort_ids, snapshot_id=snapshot, published=published, inventory=inventory, integrity=integrity, safety="postchecked-rollback-ready", history=history)
