from __future__ import annotations

import json

from flask import jsonify, session

from .core import db
from .security import role_required


def _scope(column: str = "owner") -> tuple[str, tuple]:
    if session.get("role") == "admin":
        return "1=1", ()
    return f"{column}=?", (str(session.get("user", ""))[:64],)


def _dns_events(conn) -> list[dict]:
    where, args = _scope("owner")
    rows = conn.execute(
        f"""SELECT id,domain,operation,record_type,record_name,status,snapshot_json,owner,created_at,applied_at
            FROM dns_changes WHERE {where} ORDER BY id DESC LIMIT 40""",
        args,
    ).fetchall()
    events: list[dict] = []
    for row in rows:
        status = str(row["status"])
        snapshot = {}
        if row["snapshot_json"]:
            try:
                parsed = json.loads(row["snapshot_json"])
                snapshot = parsed if isinstance(parsed, dict) else {}
            except Exception:
                snapshot = {}
        if status == "preview":
            safety, reversible, touched = "preview", True, False
            guidance = "لم يُطبّق على مزود DNS بعد؛ راجع المعاينة قبل Apply."
        elif status == "applied" and snapshot:
            safety, reversible, touched = "reversible", True, True
            guidance = "التغيير مطبق وله Snapshot مستخدم بواسطة DNS Rollback."
        elif status == "rolled_back":
            safety, reversible, touched = "verified-rollback", True, True
            guidance = "تم تنفيذ Rollback لهذا التغيير."
        else:
            safety, reversible, touched = "attention", False, status != "preview"
            guidance = "لا توجد إشارة Rollback كافية؛ راجع التغيير يدويًا."
        events.append({
            "kind": "dns",
            "id": int(row["id"]),
            "domain": str(row["domain"]),
            "label": f"{row['operation']} {row['record_type']} {row['record_name']}",
            "state": status,
            "safety": safety,
            "reversible": reversible,
            "external_state_touched": touched,
            "guidance": guidance,
            "owner": str(row["owner"]),
            "created_at": int(row["created_at"] or 0),
            "changed_at": int(row["applied_at"] or row["created_at"] or 0),
        })
    return events


def _ssl_events(conn) -> list[dict]:
    where, args = _scope("owner")
    rows = conn.execute(
        f"""SELECT id,domain,action,status,owner,created_at,updated_at
            FROM ssl_jobs WHERE {where} ORDER BY id DESC LIMIT 25""",
        args,
    ).fetchall()
    events: list[dict] = []
    for row in rows:
        success = str(row["status"]).lower() == "success"
        events.append({
            "kind": "ssl",
            "id": int(row["id"]),
            "domain": str(row["domain"]),
            "label": f"SSL {row['action']}",
            "state": str(row["status"]),
            "safety": "verified" if success else "attention",
            "reversible": False,
            "external_state_touched": True,
            "guidance": "الشهادة تحققت بنجاح؛ الرجوع يتم بإعادة إصدار/ربط شهادة صالحة." if success else "راجع نتيجة مهمة SSL قبل أي إجراء جديد.",
            "owner": str(row["owner"]),
            "created_at": int(row["created_at"] or 0),
            "changed_at": int(row["updated_at"] or row["created_at"] or 0),
        })
    return events


def _migration_events(conn) -> list[dict]:
    where, args = _scope("owner")
    rows = conn.execute(
        f"""SELECT id,domain,archive,status,owner,created_at
            FROM migration_bundles WHERE {where} ORDER BY id DESC LIMIT 25""",
        args,
    ).fetchall()
    return [
        {
            "kind": "migration",
            "id": int(row["id"]),
            "domain": str(row["domain"]),
            "label": "Migration bundle",
            "state": str(row["status"]),
            "safety": "snapshot-ready" if str(row["status"]) == "ready" else "attention",
            "reversible": str(row["status"]) == "ready",
            "external_state_touched": False,
            "guidance": "Bundle محفوظ مع SHA256؛ Restore ينشئ Rollback snapshot قبل تبديل الموقع." if str(row["status"]) == "ready" else "تحقق من حالة Migration bundle قبل Restore.",
            "owner": str(row["owner"]),
            "created_at": int(row["created_at"] or 0),
            "changed_at": int(row["created_at"] or 0),
        }
        for row in rows
    ]


def _doctor_events(conn) -> list[dict]:
    where, args = _scope("actor")
    rows = conn.execute(
        f"""SELECT id,check_name,service_name,status,actor,created_at,updated_at
            FROM doctor_remediations WHERE {where} ORDER BY id DESC LIMIT 25""",
        args,
    ).fetchall()
    events: list[dict] = []
    for row in rows:
        verified = str(row["status"]) == "verified"
        events.append({
            "kind": "doctor",
            "id": int(row["id"]),
            "domain": "",
            "label": str(row["check_name"]),
            "state": str(row["status"]),
            "safety": "verified" if verified else "attention",
            "reversible": True,
            "external_state_touched": True,
            "guidance": f"Allow-listed restart لـ {row['service_name']} ثم إعادة فحص Doctor." if verified else "الإصلاح لم يُثبت كحالة سليمة؛ راجع الخدمة.",
            "owner": str(row["actor"]),
            "created_at": int(row["created_at"] or 0),
            "changed_at": int(row["updated_at"] or row["created_at"] or 0),
        })
    return events


def _score(events: list[dict]) -> dict:
    touched = [event for event in events if event["external_state_touched"]]
    protected = [event for event in touched if event["reversible"] or event["safety"] in {"verified", "verified-rollback"}]
    attention = [event for event in events if event["safety"] == "attention"]
    pending = [event for event in events if event["safety"] == "preview"]
    score = 100 if not touched else round(len(protected) * 100 / len(touched))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {
        "score": score,
        "grade": grade,
        "recent": len(events),
        "external_changes": len(touched),
        "protected_changes": len(protected),
        "attention": len(attention),
        "pending_previews": len(pending),
    }


def register_change_safety_routes(app):
    @app.get("/api/change-safety")
    @role_required("admin", "operator", "viewer")
    def change_safety():
        with db() as conn:
            events = _dns_events(conn) + _ssl_events(conn) + _migration_events(conn) + _doctor_events(conn)
        events.sort(key=lambda item: int(item.get("changed_at", 0)), reverse=True)
        events = events[:80]
        return jsonify(
            ok=True,
            posture=_score(events),
            events=events,
            policy={
                "preview_before_mutation": True,
                "step_up_for_sensitive_writes": True,
                "rollback_preferred": True,
                "manual_when_unsafe": True,
            },
        )
