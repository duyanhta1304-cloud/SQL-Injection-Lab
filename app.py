"""Apex Gear Store: an intentionally vulnerable, toggleable SQLi teaching lab."""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from flask import Flask, flash, redirect, render_template, request, url_for

import database
import honeypot
from security import ALLOWED_SORT_COLUMNS, ASTSecurityGuard, SecurityViolation, execute_secure


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("APEX_SECRET_KEY", "apex-demo-only-change-me")

# Process-local by design: this switch supports a single-user classroom demo.
DEFENCE_ACTIVE = False

TEMPLATE_BY_VIEW = {
    "home": "home.html",
    "search": "search.html",
    "login": "login.html",
}

PRODUCT_IMAGES = {
    "SteelSeries Apex Pro TKL Gen 3": "products/keyboard.png",
    "Keychron Q1 Max": "products/nebula-keyboard.png",
    "LG UltraGear 27GR83Q-B": "products/monitor.png",
    "Dell UltraSharp U3223QE": "products/studioview-monitor.png",
    "Samsung 990 PRO 2TB": "products/ssd.png",
    "WD_BLACK SN850X 1TB": "products/pulse-ssd.png",
    "Logitech G PRO X SUPERLIGHT 2": "products/vector-mouse.png",
    "Logitech MX Master 3S": "products/mouse.png",
}


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",", 1)[0].strip() or request.remote_addr or "unknown"


def _default_debug() -> dict[str, str]:
    return {
        "sql": "",
        "ast": "Not inspected on this request.",
        "honeypot": "No canary interaction detected.",
    }


def _verdict_text(verdict: dict[str, Any]) -> str:
    tokens = ", ".join(verdict["detected_tokens"]) or "none"
    label = "MALICIOUS" if verdict["is_malicious"] else "CLEAN"
    return f"{label} · risk={verdict['risk_score']}/100 · tokens={tokens}"


def _render(view: str, *, status: int = 200, **context):
    payload = {
        "title": context.pop("title", "Store"),
        "view": view,
        "defence_active": DEFENCE_ACTIVE,
        "products": [],
        "results": [],
        "query_text": "",
        "sort": "name",
        "username": "",
        "product_images": PRODUCT_IMAGES,
        "alert": None,
        "debug": _default_debug(),
        "debug_open": False,
    }
    payload.update(context)
    return render_template(TEMPLATE_BY_VIEW[view], **payload), status


@app.get("/")
def home():
    sql = "SELECT id, name, category, price, description, stock FROM products ORDER BY name"
    with database.get_db_connection() as connection:
        products = connection.execute(sql).fetchall()
    debug = _default_debug()
    debug["sql"] = sql
    return _render("home", products=products, debug=debug, title="Performance hardware")


@app.get("/search")
def search():
    query_text = request.args.get("q", "")
    requested_sort = request.args.get("sort", "name")
    sort_column = ALLOWED_SORT_COLUMNS.get(requested_sort, "name")
    debug = _default_debug()
    verdict = ASTSecurityGuard.inspect_input(query_text)
    debug["ast"] = _verdict_text(verdict) if DEFENCE_ACTIVE else "BYPASSED while baseline mode is active."

    if honeypot.check_canary_table_access(query_text, _client_ip()):
        debug["honeypot"] = "CRITICAL: decoy table reference logged to security_alerts.log."

    if DEFENCE_ACTIVE and honeypot.inspect_honeypots(request):
        debug["honeypot"] = "BLOCKED: hidden admin_debug_token canary was populated."
        return _render(
            "search",
            status=403,
            query_text=query_text,
            sort=requested_sort,
            debug=debug,
            debug_open=True,
            alert={
                "kind": "error",
                "message": "Request blocked: hidden canary field tampering was detected and logged.",
            },
            title="Security alert",
        )

    try:
        with database.get_db_connection() as connection:
            cursor = connection.cursor()
            if DEFENCE_ACTIVE:
                sql = (
                    "SELECT id, name, category, price, description FROM products "
                    "WHERE name LIKE ? OR category LIKE ? "
                    f"ORDER BY {sort_column}"
                )
                params = (f"%{query_text}%", f"%{query_text}%")
                debug["sql"] = f"{sql} | params=({params[0]!r}, {params[1]!r})"
                inspection = execute_secure(cursor, sql, params)
                debug["ast"] = _verdict_text(inspection)
            else:
                sql = (
                    "SELECT id, name, category, price, description FROM products "
                    f"WHERE name LIKE '%{query_text}%' OR category LIKE '%{query_text}%' "
                    f"ORDER BY {sort_column}"
                )
                debug["sql"] = sql
                cursor.execute(sql)
            results = cursor.fetchall()
    except SecurityViolation as exc:
        debug["ast"] = _verdict_text(exc.inspection)
        honeypot.log_security_event(_client_ip(), "ast_search_block", query_text)
        return _render(
            "search",
            status=403,
            query_text=query_text,
            sort=requested_sort,
            debug=debug,
            debug_open=True,
            alert={"kind": "error", "message": "SQL injection attempt blocked before database execution."},
            title="Security alert",
        )
    except sqlite3.Error as exc:
        return _render(
            "search",
            status=400,
            query_text=query_text,
            sort=requested_sort,
            debug=debug,
            debug_open=True,
            alert={"kind": "error", "message": f"SQLite rejected the constructed demonstration query: {exc}"},
            title="Query error",
        )

    return _render(
        "search",
        results=results,
        query_text=query_text,
        sort=requested_sort,
        debug=debug,
        debug_open=True,
        title="Search results",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return _render("login", title="Sign in")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    debug = _default_debug()
    combined_verdict = ASTSecurityGuard.inspect_input(f"{username} {password}")
    debug["ast"] = _verdict_text(combined_verdict) if DEFENCE_ACTIVE else "BYPASSED while baseline mode is active."

    if honeypot.check_canary_table_access(f"{username} {password}", _client_ip()):
        debug["honeypot"] = "CRITICAL: decoy table reference logged to security_alerts.log."

    if DEFENCE_ACTIVE and honeypot.inspect_honeypots(request):
        debug["honeypot"] = "BLOCKED: hidden admin_debug_token canary was populated."
        return _render(
            "login",
            status=403,
            username=username,
            debug=debug,
            debug_open=True,
            alert={"kind": "error", "message": "Authentication blocked: honeypot field tampering was detected."},
            title="Security alert",
        )

    try:
        with database.get_db_connection() as connection:
            cursor = connection.cursor()
            if DEFENCE_ACTIVE:
                sql = "SELECT id, username, email, role FROM users WHERE username = ? AND password = ?"
                debug["sql"] = f"{sql} | params=({username!r}, '[REDACTED]')"
                inspection = execute_secure(cursor, sql, (username, password))
                debug["ast"] = _verdict_text(inspection)
            else:
                sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                debug["sql"] = sql
                cursor.execute(sql)
            user = cursor.fetchone()
    except SecurityViolation as exc:
        debug["ast"] = _verdict_text(exc.inspection)
        honeypot.log_security_event(_client_ip(), "ast_login_block", username)
        return _render(
            "login",
            status=403,
            username=username,
            debug=debug,
            debug_open=True,
            alert={"kind": "error", "message": "Authentication bypass attempt blocked before database execution."},
            title="Security alert",
        )
    except sqlite3.Error as exc:
        return _render(
            "login",
            status=400,
            username=username,
            debug=debug,
            debug_open=True,
            alert={"kind": "error", "message": f"SQLite rejected the constructed demonstration query: {exc}"},
            title="Login query error",
        )

    if user:
        return _render(
            "login",
            username=username,
            debug=debug,
            debug_open=True,
            alert={"kind": "success", "message": f"Signed in as {user['username']} ({user['role']})."},
            title="Signed in",
        )

    return _render(
        "login",
        status=401,
        username=username,
        debug=debug,
        debug_open=True,
        alert={"kind": "error", "message": "Invalid username or password."},
        title="Sign in failed",
    )


@app.post("/toggle-defence")
def toggle_defence():
    global DEFENCE_ACTIVE
    DEFENCE_ACTIVE = not DEFENCE_ACTIVE
    label = "enabled" if DEFENCE_ACTIVE else "disabled"
    flash(f"Layered SQL injection defence {label}.", "success" if DEFENCE_ACTIVE else "info")
    destination = request.referrer if request.referrer and request.referrer.startswith(request.host_url) else url_for("home")
    return redirect(destination)


if __name__ == "__main__":
    database.init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
