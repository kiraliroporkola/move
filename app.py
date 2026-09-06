#!/usr/bin/env python3
import os
import re
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR / "redirects.db")))
SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "1") != "0"

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is required")
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD is required")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=16 * 1024,
)

# Cloudflare/Nginx may forward the original scheme/host.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
RESERVED = {
    "login",
    "logout",
    "dashboard",
    "create",
    "edit",
    "delete",
    "static",
    "favicon.ico",
}

BASE_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>{{ title }} — Redirect Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0b0d10;--panel:#13171c;--border:#242a31;--text:#f2f4f7;--muted:#9aa4af;--accent:#66d9ef;--danger:#ff6b6b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1100px;margin:0 auto;padding:28px 18px 48px}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:24px}
.brand{font-weight:800;font-size:20px}.nav{display:flex;gap:14px;align-items:center}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:22px;box-shadow:0 12px 30px rgba(0,0,0,.15)}
h1{margin:0 0 8px;font-size:30px}.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:18px}
.stat{padding:18px;background:var(--panel);border:1px solid var(--border);border-radius:14px}.stat b{display:block;font-size:28px;margin-top:5px}
form{display:grid;gap:12px}label{font-size:13px;color:var(--muted)}
input{width:100%;padding:12px 13px;background:#0d1014;border:1px solid var(--border);color:var(--text);border-radius:10px;outline:none}
input:focus{border-color:#46515e}
button,.button{border:0;border-radius:10px;padding:11px 15px;background:#e8edf2;color:#101317;font-weight:700;cursor:pointer;display:inline-block}
button.danger,.button.danger{background:var(--danger);color:#1b0606}.button.secondary{background:#232a32;color:var(--text)}
.actions{display:flex;gap:8px;flex-wrap:wrap}.table-wrap{overflow-x:auto}
.table{width:100%;border-collapse:collapse;margin-top:12px}.table th,.table td{padding:13px 10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
.table th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.flash{padding:11px 13px;border-radius:10px;background:#18271f;border:1px solid #284d38;margin-bottom:14px}
.error{background:#2c191b;border-color:#61343a}.login{max-width:420px;margin:12vh auto}
.small{font-size:12px}.truncate{max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
@media(max-width:800px){.grid{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}.truncate{max-width:240px}}
</style>
</head>
<body>
<div class="wrap">
<div class="top">
  <div class="brand">Redirect Dashboard</div>
  {% if logged_in %}
  <div class="nav">
    <a href="{{ url_for('dashboard') }}">Dashboard</a>
    <a href="{{ url_for('logout') }}">Logout</a>
  </div>
  {% endif %}
</div>
{% with messages=get_flashed_messages(with_categories=true) %}
  {% for category, message in messages %}
    <div class="flash {% if category=='error' %}error{% endif %}">{{ message }}</div>
  {% endfor %}
{% endwith %}
{{ body|safe }}
</div>
</body>
</html>
"""

LOGIN_BODY = """
<div class="login panel">
  <h1>Admin Login</h1>
  <p class="muted">Sign in to manage your redirects.</p>
  <form method="post" action="{{ url_for('login') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf }}">
    <div>
      <label>Username</label>
      <input name="username" autocomplete="username" required>
    </div>
    <div>
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" required>
    </div>
    <button type="submit">Login</button>
  </form>
</div>
"""

DASHBOARD_BODY = """
<div class="panel" style="margin-bottom:18px">
  <h1>Redirects</h1>
  <p class="muted">Create links like <code>https://example.com/telegram</code> that redirect to another URL.</p>
  <form method="post" action="{{ url_for('create_redirect') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf }}">
    <div><label>Slug</label><input name="slug" placeholder="telegram" maxlength="64" required></div>
    <div><label>Destination URL</label><input name="destination" placeholder="https://t.me/example" required></div>
    <div><button type="submit">Create redirect</button></div>
  </form>
</div>

<div class="grid">
  <div class="stat"><span class="muted">Links</span><b>{{ stats.links }}</b></div>
  <div class="stat"><span class="muted">Total clicks</span><b>{{ stats.clicks }}</b></div>
  <div class="stat"><span class="muted">Account</span><b>Admin</b></div>
</div>

<div class="panel">
  <div class="table-wrap">
  <table class="table">
    <thead><tr><th>Path</th><th>Destination</th><th>Clicks</th><th>Actions</th></tr></thead>
    <tbody>
    {% for row in links %}
      <tr>
        <td><a href="/{{ row['slug'] }}" target="_blank" rel="noopener">/{{ row['slug'] }}</a></td>
        <td class="truncate" title="{{ row['destination'] }}">{{ row['destination'] }}</td>
        <td>{{ row['clicks'] }}</td>
        <td>
          <div class="actions">
            <a class="button secondary" href="{{ url_for('edit_redirect', redirect_id=row['id']) }}">Edit</a>
            <form method="post" action="{{ url_for('delete_redirect', redirect_id=row['id']) }}" onsubmit="return confirm('Delete this redirect?');" style="display:inline">
              <input type="hidden" name="csrf_token" value="{{ csrf }}">
              <button class="danger" type="submit">Delete</button>
            </form>
          </div>
        </td>
      </tr>
    {% else %}
      <tr><td colspan="4" class="muted">No redirects yet.</td></tr>
    {% endfor %}
    </tbody>
  </table>
  </div>
</div>
"""

EDIT_BODY = """
<div class="panel" style="max-width:760px">
  <h1>Edit /{{ row['slug'] }}</h1>
  <form method="post" action="{{ url_for('edit_redirect', redirect_id=row['id']) }}">
    <input type="hidden" name="csrf_token" value="{{ csrf }}">
    <div><label>Slug</label><input name="slug" value="{{ row['slug'] }}" maxlength="64" required></div>
    <div><label>Destination URL</label><input name="destination" value="{{ row['destination'] }}" required></div>
    <div class="actions">
      <button type="submit">Save changes</button>
      <a class="button secondary" href="{{ url_for('dashboard') }}">Cancel</a>
    </div>
  </form>
</div>
"""


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS redirects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            destination TEXT NOT NULL,
            clicks INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    row = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (ADMIN_USERNAME,),
    ).fetchone()

    if not row:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD)),
        )
        conn.commit()

    conn.close()


def is_logged_in():
    return bool(session.get("user_id"))


def require_login():
    if not is_logged_in():
        return redirect(url_for("login", next=request.path))
    return None


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def check_csrf():
    expected = session.get("csrf_token")
    supplied = request.form.get("csrf_token", "")
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        abort(400, description="Invalid CSRF token")


def valid_destination(value: str) -> bool:
    try:
        p = urlparse(value)
        return p.scheme in {"http", "https"} and bool(p.netloc) and " " not in value
    except Exception:
        return False


def valid_slug(slug: str) -> bool:
    return bool(SLUG_RE.fullmatch(slug)) and slug not in RESERVED


def render_page(title, body, **context):
    # Important: render the inner template first so {{ csrf }} and other
    # variables are expanded before it is inserted into BASE_HTML.
    rendered_body = render_template_string(
        body,
        csrf=csrf_token(),
        **context,
    )
    return render_template_string(
        BASE_HTML,
        title=title,
        body=rendered_body,
        logged_in=is_logged_in(),
    )


@app.after_request
def no_cache_dynamic_pages(response):
    # Never cache login/admin pages. This also prevents stale CSRF forms.
    if request.path == "/login" or request.path == "/dashboard" or request.path.startswith(("/create", "/edit", "/delete")):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    if is_logged_in():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)

            next_url = request.args.get("next", "")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_page("Login", LOGIN_BODY)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def home():
    return redirect(url_for("dashboard")) if is_logged_in() else redirect(url_for("login"))


@app.get("/dashboard")
def dashboard():
    auth = require_login()
    if auth:
        return auth

    conn = get_db()
    links = conn.execute("SELECT * FROM redirects ORDER BY id DESC").fetchall()
    stats_row = conn.execute(
        "SELECT COUNT(*) AS links, COALESCE(SUM(clicks), 0) AS clicks FROM redirects"
    ).fetchone()
    conn.close()

    return render_page("Dashboard", DASHBOARD_BODY, links=links, stats=stats_row)


@app.post("/create")
def create_redirect():
    auth = require_login()
    if auth:
        return auth

    check_csrf()
    slug = request.form.get("slug", "").strip().lower().strip("/")
    destination = request.form.get("destination", "").strip()

    if not valid_slug(slug):
        flash(
            "Slug must be 1–64 characters using lowercase letters, numbers, _ or -; reserved paths are not allowed.",
            "error",
        )
        return redirect(url_for("dashboard"))

    if not valid_destination(destination):
        flash("Destination must be a valid http:// or https:// URL.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO redirects (slug, destination) VALUES (?, ?)",
            (slug, destination),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        flash("That slug already exists.", "error")
        conn.close()
        return redirect(url_for("dashboard"))

    conn.close()
    flash(f"Created /{slug}.")
    return redirect(url_for("dashboard"))


@app.route("/edit/<int:redirect_id>", methods=["GET", "POST"])
def edit_redirect(redirect_id):
    auth = require_login()
    if auth:
        return auth

    if request.method == "POST":
        check_csrf()
        slug = request.form.get("slug", "").strip().lower().strip("/")
        destination = request.form.get("destination", "").strip()

        if not valid_slug(slug) or not valid_destination(destination):
            flash("Invalid slug or destination URL.", "error")
            return redirect(url_for("edit_redirect", redirect_id=redirect_id))

        conn = get_db()
        try:
            cursor = conn.execute(
                "UPDATE redirects SET slug = ?, destination = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (slug, destination, redirect_id),
            )
            if cursor.rowcount == 0:
                conn.close()
                abort(404)
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("That slug already exists.", "error")
            return redirect(url_for("edit_redirect", redirect_id=redirect_id))

        conn.close()
        flash("Redirect updated.")
        return redirect(url_for("dashboard"))

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM redirects WHERE id = ?",
        (redirect_id,),
    ).fetchone()
    conn.close()

    if not row:
        abort(404)

    return render_page("Edit", EDIT_BODY, row=row)


@app.post("/delete/<int:redirect_id>")
def delete_redirect(redirect_id):
    auth = require_login()
    if auth:
        return auth

    check_csrf()
    conn = get_db()
    conn.execute("DELETE FROM redirects WHERE id = ?", (redirect_id,))
    conn.commit()
    conn.close()

    flash("Redirect deleted.")
    return redirect(url_for("dashboard"))


@app.get("/<slug>")
def do_redirect(slug):
    slug = slug.strip().lower()
    if slug in RESERVED:
        abort(404)

    conn = get_db()
    row = conn.execute(
        "SELECT id, destination FROM redirects WHERE slug = ?",
        (slug,),
    ).fetchone()

    if not row:
        conn.close()
        abort(404)

    conn.execute(
        "UPDATE redirects SET clicks = clicks + 1, updated_at = updated_at WHERE id = ?",
        (row["id"],),
    )
    conn.commit()
    conn.close()

    return redirect(row["destination"], code=302)


@app.errorhandler(400)
def bad_request(error):
    return str(error.description or "Bad request"), 400


@app.errorhandler(404)
def not_found(_):
    return "Not found", 404


init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
