from __future__ import annotations
from flask import abort, flash, redirect, render_template, request, session, url_for
from .branding import get_branding, save_branding
from .licensing import LICENSE_FILE, server_fingerprint, verify_license
from .core import audit, login_required
from .security import step_up_active

FIELDS=("company_name","product_name","logo_url","favicon_url","hero_url","website","email","facebook","youtube","x")

def register_white_label_routes(app):
    @app.get("/license")
    @login_required
    def license_center():
        if session.get("role")!="admin": abort(403)
        return render_template("license_center.html", license_state=verify_license(), fingerprint=server_fingerprint(), brand=get_branding())

    @app.post("/license/install")
    @login_required
    def license_install():
        if session.get("role")!="admin": abort(403)
        if not step_up_active():
            abort(428)
        raw=request.form.get("license_json","")
        if len(raw)>65536: abort(413)
        LICENSE_FILE.parent.mkdir(parents=True,exist_ok=True)
        tmp=LICENSE_FILE.with_suffix(".tmp"); tmp.write_text(raw,encoding="utf-8"); tmp.replace(LICENSE_FILE)
        state=verify_license()
        audit("license-install", state.status)
        flash("تم التحقق من الترخيص." if state.valid else "الترخيص غير صالح.", "success" if state.valid else "error")
        return redirect(url_for("license_center"))

    @app.route("/branding", methods=["GET","POST"])
    @login_required
    def branding_center():
        if session.get("role")!="admin": abort(403)
        state=verify_license()
        if not state.feature("white_label"): abort(403)
        if request.method=="POST":
            if not step_up_active(): abort(428)
            values={k:request.form.get(k,"") for k in FIELDS}
            brand=save_branding(values); audit("branding-update", brand.get("company_name",""))
            flash("تم حفظ هوية White-Label.", "success")
            return redirect(url_for("branding_center"))
        return render_template("branding_center.html", brand=get_branding(), license_state=state)
