"""
Abuyog Community College - Consultation System
Stack: Flask + SQLite + Jinja2 HTML templates
Roles (RBAC): student | medical_expert | super_admin
"""
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "consultation.db")

app = Flask(__name__)
app.config.update(
    # SECURITY: set SECRET_KEY in the environment so sessions survive restarts.
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,      # JavaScript cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",     # blocks most cross-site request forgery
    SESSION_COOKIE_SECURE=os.environ.get("APP_ENV") == "production",  # HTTPS only in prod
    PERMANENT_SESSION_LIFETIME=1800,   # auto logout after 30 minutes
    MAX_CONTENT_LENGTH=1024 * 1024,    # reject request bodies over 1 MB
)

ROLES = ("student", "medical_expert", "super_admin")
CATEGORIES = ("General Health", "Mental Health", "Dental", "Nutrition", "Other")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ---------------------------------------------------------------- DATABASE ---
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student','medical_expert','super_admin')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS consultations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expert_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    category TEXT NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','declined','completed','cancelled')),
    scheduled_at TEXT,
    expert_notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
"""


def get_db():
    """Open one SQLite connection per request and reuse it (stored on flask.g)."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row          # access columns by name
        g.db.execute("PRAGMA foreign_keys = ON")  # enforce relations
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    """Always close the connection when the request ends."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed the first Super Admin (only if none exists)."""
    db = sqlite3.connect(DATABASE)
    db.executescript(SCHEMA)
    if not db.execute("SELECT 1 FROM users WHERE role='super_admin'").fetchone():
        pwd = os.environ.get("ADMIN_PASSWORD", "ChangeMe@123")
        db.execute(
            "INSERT INTO users (full_name,email,password_hash,role) VALUES (?,?,?,?)",
            ("System Administrator", "admin@abuyogcc.edu.ph",
             generate_password_hash(pwd), "super_admin"))
        db.commit()
        print("Seeded admin: admin@abuyogcc.edu.ph  -> CHANGE THE PASSWORD!")
    db.close()


# ---------------------------------------------------------------- SECURITY ---
@app.before_request
def load_user():
    """Attach the logged-in user to g.user; drop sessions of disabled/deleted users."""
    g.user = None
    uid = session.get("user_id")
    if uid:
        row = get_db().execute(
            "SELECT id, full_name, email, role, is_active FROM users WHERE id=?",
            (uid,)).fetchone()
        if row and row["is_active"]:
            g.user = row
        else:
            session.clear()


@app.before_request
def csrf_protect():
    """Reject every POST that lacks the per-session CSRF token."""
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        real = session.get("_csrf", "")
        if not real or not secrets.compare_digest(sent, real):
            abort(400)


@app.context_processor
def inject_helpers():
    """Expose csrf_token() to every template: {{ csrf_token() }}."""
    def csrf_token():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_hex(16)
        return session["_csrf"]
    return {"csrf_token": csrf_token}


@app.after_request
def security_headers(resp):
    """Browser-side protections: CSP, anti-clickjacking, no MIME sniffing."""
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; frame-ancestors 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if g.get("user"):  # never cache private pages
        resp.headers["Cache-Control"] = "no-store"
    return resp


def role_required(*roles):
    """RBAC decorator: 401-style redirect if logged out, 403 if wrong role."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# Simple brute-force protection: 5 failed logins -> 5 minute lock per IP+email.
FAILED = {}  # key -> [count, locked_until_timestamp]


def is_locked(key):
    rec = FAILED.get(key)
    return bool(rec and rec[0] >= 5 and time.time() < rec[1])


def record_failure(key):
    rec = FAILED.setdefault(key, [0, 0])
    rec[0] += 1
    rec[1] = time.time() + 300


def valid_password(pw):
    """Min 8 chars with at least one letter and one number."""
    return len(pw) >= 8 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)


def validate_account(name, email, pw):
    """Shared validation for registration and expert creation. Returns error or None."""
    if not 2 <= len(name) <= 80:
        return "Full name must be 2-80 characters."
    if not EMAIL_RE.match(email) or len(email) > 120:
        return "Enter a valid email address."
    if not valid_password(pw):
        return "Password needs 8+ characters with letters and numbers."
    return None


# ------------------------------------------------------------ PUBLIC ROUTES ---
@app.route("/")
def index():
    """Landing page."""
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Public sign-up. Always creates a STUDENT (role is never taken from the form)."""
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        if pw != request.form.get("confirm", ""):
            flash("Passwords do not match.", "error")
        elif (err := validate_account(name, email, pw)):
            flash(err, "error")
        else:
            try:
                get_db().execute(
                    "INSERT INTO users (full_name,email,password_hash,role) VALUES (?,?,?,'student')",
                    (name, email, generate_password_hash(pw)))
                get_db().commit()
                flash("Account created. You can log in now.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Verify credentials, rotate the session, then route by role."""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        key = f"{request.remote_addr}|{email}"
        if is_locked(key):
            flash("Too many attempts. Try again in 5 minutes.", "error")
            return render_template("login.html")
        user = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        # Same message for unknown email / wrong password (no user enumeration).
        if user and user["is_active"] and check_password_hash(user["password_hash"], pw):
            FAILED.pop(key, None)
            session.clear()                 # prevents session fixation
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(url_for("dashboard"))
        record_failure(key)
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    """Logout is POST-only (CSRF protected) so links cannot log users out."""
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@role_required(*ROLES)
def dashboard():
    """Send each role to its own dashboard."""
    target = {"student": "student_home", "medical_expert": "expert_home",
              "super_admin": "admin_home"}[g.user["role"]]
    return redirect(url_for(target))


# ----------------------------------------------------------------- STUDENT ---
@app.route("/student")
@role_required("student")
def student_home():
    """Student sees only THEIR consultations."""
    rows = get_db().execute(
        """SELECT c.*, e.full_name AS expert_name FROM consultations c
           LEFT JOIN users e ON e.id = c.expert_id
           WHERE c.student_id=? ORDER BY c.created_at DESC""", (g.user["id"],)).fetchall()
    return render_template("student.html", rows=rows, categories=CATEGORIES)


@app.route("/student/book", methods=["POST"])
@role_required("student")
def student_book():
    """Create a consultation request (status starts as 'pending')."""
    category = request.form.get("category", "")
    subject = request.form.get("subject", "").strip()
    message = request.form.get("message", "").strip()
    if category not in CATEGORIES:
        flash("Choose a valid category.", "error")
    elif not 3 <= len(subject) <= 120 or not 10 <= len(message) <= 1000:
        flash("Subject: 3-120 characters. Details: 10-1000 characters.", "error")
    else:
        get_db().execute(
            "INSERT INTO consultations (student_id,category,subject,message) VALUES (?,?,?,?)",
            (g.user["id"], category, subject, message))
        get_db().commit()
        flash("Request sent. An expert will respond soon.", "success")
    return redirect(url_for("student_home"))


@app.route("/student/cancel/<int:cid>", methods=["POST"])
@role_required("student")
def student_cancel(cid):
    """Cancel own pending request. The WHERE clause enforces ownership (anti-IDOR)."""
    db = get_db()
    db.execute("UPDATE consultations SET status='cancelled' "
               "WHERE id=? AND student_id=? AND status='pending'", (cid, g.user["id"]))
    db.commit()
    flash("Request cancelled.", "success")
    return redirect(url_for("student_home"))


# ------------------------------------------------------------------ EXPERT ---
@app.route("/expert")
@role_required("medical_expert")
def expert_home():
    """Open (unassigned) requests plus consultations assigned to this expert."""
    db = get_db()
    base = """SELECT c.*, s.full_name AS student_name FROM consultations c
              JOIN users s ON s.id = c.student_id """
    pending = db.execute(base + "WHERE c.status='pending' ORDER BY c.created_at").fetchall()
    mine = db.execute(base + "WHERE c.expert_id=? ORDER BY c.created_at DESC",
                      (g.user["id"],)).fetchall()
    return render_template("expert.html", pending=pending, mine=mine)


@app.route("/expert/update/<int:cid>", methods=["POST"])
@role_required("medical_expert")
def expert_update(cid):
    """Accept / decline / complete. Experts can only touch pending or their own items."""
    db = get_db()
    c = db.execute("SELECT * FROM consultations WHERE id=?", (cid,)).fetchone()
    if not c or c["expert_id"] not in (None, g.user["id"]):
        abort(404)
    action = request.form.get("action")
    notes = request.form.get("expert_notes", "").strip()[:1000]

    if action == "accept" and c["status"] == "pending":
        try:
            when = datetime.strptime(request.form.get("scheduled_at", ""), "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Pick a valid schedule date and time.", "error")
            return redirect(url_for("expert_home"))
        db.execute("UPDATE consultations SET status='approved', expert_id=?, scheduled_at=?, "
                   "expert_notes=? WHERE id=?",
                   (g.user["id"], when.strftime("%Y-%m-%d %H:%M"), notes, cid))
    elif action == "decline" and c["status"] == "pending":
        db.execute("UPDATE consultations SET status='declined', expert_id=?, expert_notes=? "
                   "WHERE id=?", (g.user["id"], notes, cid))
    elif action == "complete" and c["status"] == "approved" and c["expert_id"] == g.user["id"]:
        db.execute("UPDATE consultations SET status='completed', expert_notes=? WHERE id=?",
                   (notes, cid))
    else:
        abort(400)
    db.commit()
    flash("Consultation updated.", "success")
    return redirect(url_for("expert_home"))


# ------------------------------------------------------------------- ADMIN ---
@app.route("/admin")
@role_required("super_admin")
def admin_home():
    """Stats, user management and every consultation in the system."""
    db = get_db()
    stats = {
        "students": db.execute("SELECT COUNT(*) FROM users WHERE role='student'").fetchone()[0],
        "experts": db.execute("SELECT COUNT(*) FROM users WHERE role='medical_expert'").fetchone()[0],
        "pending": db.execute("SELECT COUNT(*) FROM consultations WHERE status='pending'").fetchone()[0],
        "completed": db.execute("SELECT COUNT(*) FROM consultations WHERE status='completed'").fetchone()[0],
    }
    users = db.execute("SELECT id,full_name,email,role,is_active,created_at FROM users "
                       "ORDER BY role, full_name").fetchall()
    consults = db.execute(
        """SELECT c.*, s.full_name AS student_name, e.full_name AS expert_name
           FROM consultations c JOIN users s ON s.id=c.student_id
           LEFT JOIN users e ON e.id=c.expert_id ORDER BY c.created_at DESC LIMIT 100""").fetchall()
    return render_template("admin.html", stats=stats, users=users, consults=consults)


@app.route("/admin/experts", methods=["POST"])
@role_required("super_admin")
def admin_create_expert():
    """Only the Super Admin can create Medical Expert accounts."""
    name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    pw = request.form.get("password", "")
    if (err := validate_account(name, email, pw)):
        flash(err, "error")
    else:
        try:
            get_db().execute(
                "INSERT INTO users (full_name,email,password_hash,role) VALUES (?,?,?,'medical_expert')",
                (name, email, generate_password_hash(pw)))
            get_db().commit()
            flash("Medical expert account created.", "success")
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "error")
    return redirect(url_for("admin_home"))


@app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@role_required("super_admin")
def admin_toggle(uid):
    """Enable/disable a non-admin account (disabled users are logged out instantly)."""
    db = get_db()
    db.execute("UPDATE users SET is_active = 1 - is_active WHERE id=? AND role!='super_admin'", (uid,))
    db.commit()
    return redirect(url_for("admin_home"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@role_required("super_admin")
def admin_delete(uid):
    """Delete a non-admin account (admins can never be deleted from the UI)."""
    db = get_db()
    db.execute("DELETE FROM users WHERE id=? AND role!='super_admin'", (uid,))
    db.commit()
    flash("User deleted.", "success")
    return redirect(url_for("admin_home"))


# ------------------------------------------------------------------ ERRORS ---
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def handle_error(err):
    """Friendly error page that never leaks stack traces."""
    msgs = {400: "That request could not be verified. Go back and try again.",
            403: "Your role does not have access to this page.",
            404: "We could not find that page."}
    return render_template("error.html", code=err.code, msg=msgs[err.code]), err.code


init_db()

if __name__ == "__main__":
    # debug=False on purpose: the Werkzeug debugger allows remote code execution.
    app.run(host="127.0.0.1", port=5000, debug=False)
