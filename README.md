# Apex Gear Store SQL Injection Lab

Two separate entry points show the same storefront before and after the SQL injection fix. The pages have no security switch or debug console. The vulnerable version is intentionally unsafe and is for a local classroom demonstration only.

## Run either version

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. Stop the server before starting the defended version:

```powershell
python app_secure.py
```

Both entry points rebuild the same local `apex_store.db` with fictional records on startup. Run one at a time. Both bind to localhost only.

## Files to compare

| File | Role |
| --- | --- |
| `app.py` | Vulnerable search and login routes; untrusted text is inserted into SQL strings. |
| `app_secure.py` | Complete defended version of those routes. |
| `security.py` | SQL token inspection, `SecurityViolation`, and parameterized execution helper. |
| `honeypot.py` | Optional decoy table, hidden field inspection, and local alert logging. |
| `database.py` | Shared fictional users and products. |
| `templates/`, `static/` | Shared storefront UI; `_honeypot_field.html` is included only by the defended app. |

See [DEFENCE_GUIDE.md](DEFENCE_GUIDE.md) for the exact code changes, example requests, and suggested report structure.

The primary SQL injection fix is parameter binding. The token inspection and honeypots provide additional detection and logging, but their heuristic results can have false positives and should not be presented as a substitute for parameterized queries. The sign-in page demonstrates query behavior; it does not create a real authenticated session.
