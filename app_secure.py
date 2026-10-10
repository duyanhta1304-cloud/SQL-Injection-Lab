"""Defended version of the storefront; compare its routes with app.py."""

from __future__ import annotations

import os
import sqlite3

from flask import Flask, render_template, request

import database
import honeypot
from security import ALLOWED_SORT_COLUMNS, ASTSecurityGuard, SecurityViolation, execute_secure


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("APEX_SECRET_KEY", "apex-demo-only-change-me")

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


def _render(template: str, *, status: int = 200, **context):
    context.setdefault("product_images", PRODUCT_IMAGES)
    context.setdefault("honeypot_template", "_honeypot_field.html")
    return render_template(template, **context), status


def _block_suspicious(value: str, vector: str) -> bool:
    """Inspect input and record any attempt to access the decoy table."""
    client_ip = request.remote_addr or "unknown"
    canary_hit = honeypot.check_canary_table_access(value, client_ip)
    verdict = ASTSecurityGuard.inspect_input(value)
    if verdict["is_malicious"]:
        honeypot.log_security_event(client_ip, vector, value)
    return canary_hit or verdict["is_malicious"]


@app.get("/")
def home():
    with database.get_db_connection() as connection:
        products = connection.execute(
            "SELECT id, name, category, price, description, stock FROM products ORDER BY name"
        ).fetchall()
    return _render("home.html", title="Performance hardware", products=products)


@app.get("/search")
def search():
    query_text = request.args.get("q", "")
    requested_sort = request.args.get("sort", "name")
    sort_column = ALLOWED_SORT_COLUMNS.get(requested_sort, "name")

    if honeypot.inspect_honeypots(request) or _block_suspicious(query_text, "search_input_block"):
        return _render(
            "search.html", status=403, title="Search error", query_text=query_text,
            sort=requested_sort, results=[],
            alert={"kind": "error", "message": "The search could not be completed."},
        )

    # FIX: placeholders keep the search text in the data portion of the query.
    sql = (
        "SELECT id, name, category, price, description FROM products "
        "WHERE name LIKE ? OR category LIKE ? "
        f"ORDER BY {sort_column}"
    )
    params = (f"%{query_text}%", f"%{query_text}%")
    try:
        with database.get_db_connection() as connection:
            cursor = connection.cursor()
            execute_secure(cursor, sql, params)
            results = cursor.fetchall()
    except SecurityViolation:
        honeypot.log_security_event(request.remote_addr or "unknown", "search_query_block", query_text)
        return _render(
            "search.html", status=403, title="Search error", query_text=query_text,
            sort=requested_sort, results=[],
            alert={"kind": "error", "message": "The search could not be completed."},
        )
    except sqlite3.Error:
        return _render(
            "search.html", status=400, title="Search error", query_text=query_text,
            sort=requested_sort, results=[],
            alert={"kind": "error", "message": "The search could not be completed."},
        )

    return _render(
        "search.html", title="Search results", query_text=query_text,
        sort=requested_sort, results=results,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return _render("login.html", title="Sign in", username="")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if honeypot.inspect_honeypots(request) or _block_suspicious(
        f"{username} {password}", "login_input_block"
    ):
        return _render(
            "login.html", status=403, title="Sign in", username=username,
            alert={"kind": "error", "message": "Sign in could not be completed."},
        )

    # FIX: credentials are bound as values and cannot change the WHERE clause.
    sql = "SELECT id, username, email, role FROM users WHERE username = ? AND password = ?"
    try:
        with database.get_db_connection() as connection:
            cursor = connection.cursor()
            execute_secure(cursor, sql, (username, password))
            user = cursor.fetchone()
    except SecurityViolation:
        honeypot.log_security_event(request.remote_addr or "unknown", "login_query_block", username)
        return _render(
            "login.html", status=403, title="Sign in", username=username,
            alert={"kind": "error", "message": "Sign in could not be completed."},
        )
    except sqlite3.Error:
        return _render(
            "login.html", status=400, title="Sign in", username=username,
            alert={"kind": "error", "message": "Sign in could not be completed."},
        )

    if user:
        return _render(
            "login.html", title="Signed in", username=username,
            alert={"kind": "success", "message": f"Signed in as {user['username']} ({user['role']})."},
        )

    return _render(
        "login.html", status=401, title="Sign in", username=username,
        alert={"kind": "error", "message": "Invalid username or password."},
    )


if __name__ == "__main__":
    database.init_db()
    honeypot.install_canary_table()
    app.run(host="127.0.0.1", port=5000, debug=False)
