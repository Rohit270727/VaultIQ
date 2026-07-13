from strength_checker import check_strength
from flask import jsonify
from flask import Flask, render_template, request, redirect, session, jsonify
from database import (
    init_db, save_master, get_master, add_entry, get_all_entries,
    delete_entry, log_action, get_audit_log
)
from crypto_utils import hash_master_password, verify_master_password, derive_key, encrypt_password, decrypt_password
from strength_checker import check_strength, check_breach, analyze_vault_health
import os, secrets, string, pyotp, qrcode, io, base64
from datetime import timedelta
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from api import api

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
app.config["JWT_SECRET_KEY"] = os.urandom(24)
jwt = JWTManager(app)
app.register_blueprint(api)
init_db()

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

app.permanent_session_lifetime = timedelta(minutes=5)

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    master = get_master()
    if request.method == "POST":
        pw = request.form["password"]
        if master is None:
            salt = os.urandom(16)
            totp_secret = pyotp.random_base32()
            save_master(hash_master_password(pw), salt, totp_secret)
            session["pending_key"] = derive_key(pw, salt).decode()
            session["setup_2fa"] = True
            return redirect("/setup-2fa")
        else:
            stored_hash, salt, totp_secret = master
            if verify_master_password(pw, stored_hash):
                session["pending_key"] = derive_key(pw, salt).decode()
                log_action("login_success", ip_address=request.remote_addr)
                return redirect("/verify-2fa")
            log_action("login_failed", ip_address=request.remote_addr)
            return render_template("login.html", first_time=False, error="Incorrect master password. Try again.")
    return render_template("login.html", first_time=(master is None), error=None)

@app.route("/setup-2fa")
def setup_2fa():
    if not session.get("setup_2fa"):
        return redirect("/")
    master = get_master()
    totp_secret = master[2]
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name="VaultIQ User", issuer_name="VaultIQ")

    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("setup_2fa.html", qr_b64=qr_b64, secret=totp_secret)

@app.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def verify_2fa():
    if "pending_key" not in session:
        return redirect("/")
    master = get_master()
    totp_secret = master[2]

    if request.method == "POST":
        code = request.form["code"].strip()
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(code, valid_window=1):
            session["key"] = session.pop("pending_key")
            session.pop("setup_2fa", None)
            log_action("2fa_success", ip_address=request.remote_addr)
            return redirect("/dashboard")
        log_action("2fa_failed", ip_address=request.remote_addr)
        return render_template("verify_2fa.html", error="Invalid code. Try again.")
    return render_template("verify_2fa.html", error=None)

@app.route("/check-strength", methods=["POST"])
def check_strength_route():
    data = request.get_json()
    password = data.get("password", "")
    strength, entropy, suggestions = check_strength(password)
    breach_count = check_breach(password)
    return jsonify({
        "strength": strength,
        "entropy": entropy,
        "suggestions": suggestions,
        "breach_count": breach_count
    })

@app.route("/lock")
def lock():
    log_action("vault_locked", ip_address=request.remote_addr)
    session.pop("key", None)
    session.pop("pending_key", None)
    return redirect("/")

@app.route("/strength-checker")
def strength_checker_page():
    return render_template("strength_check.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "key" not in session: return redirect("/")
    key = session["key"].encode()

    just_added = False
    if request.method == "POST":
        site = request.form["site"]
        username = request.form["username"]
        pw = request.form["password"]
        encrypted = encrypt_password(pw, key)
        add_entry(site, username, encrypted)
        log_action("entry_added", detail=site, ip_address=request.remote_addr)
        just_added = True

    entries = get_all_entries()
    decrypted_entries = []
    for e in entries:
        pw = decrypt_password(e[3], key)
        strength, _, _ = check_strength(pw)
        decrypted_entries.append((e[0], e[1], e[2], pw, e[4], strength))

    health = analyze_vault_health([(e[0], e[1], e[2], e[3], e[4]) for e in decrypted_entries])
    return render_template("dashboard.html", entries=decrypted_entries, health=health, just_added=just_added)

@app.route("/delete/<int:entry_id>")
def delete(entry_id):
    delete_entry(entry_id)
    log_action("entry_deleted", detail=str(entry_id), ip_address=request.remote_addr)
    return redirect("/dashboard")

@app.route("/audit-log")
def audit_log_page():
    if "key" not in session: return redirect("/")
    logs = get_audit_log()
    return render_template("audit_log.html", logs=logs)


@app.route("/generate")
def generate():
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(16))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)