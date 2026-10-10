"""Intentionally vulnerable storefront for the local SQL injection demonstration."""

from __future__ import annotations

import os
import sqlite3

from flask import Flask, render_template, request

import database


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

SORT_COLUMNS = {"name": "name", "price": "price", "category": "category"}


def _render(template: str, *, status: int = 200, **context):
    context.setdefault("product_images", PRODUCT_IMAGES)
    return render_template(template, **context), status


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
    sort_column = SORT_COLUMNS.get(requested_sort, "name")

    # VULNERABILITY: untrusted search text becomes SQL syntax through interpolation.
    sql = (
        "SELECT id, name, category, price, description FROM products "
        f"WHERE name LIKE '%{query_text}%' OR category LIKE '%{query_text}%' "
        f"ORDER BY {sort_column}"
    )
    try:
        with database.get_db_connection() as connection:
            results = connection.execute(sql).fetchall()
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

    # VULNERABILITY: both credentials are interpolated into the SQL statement.
    sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        with database.get_db_connection() as connection:
            user = connection.execute(sql).fetchone()
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
    app.run(host="127.0.0.1", port=5000, debug=False)
