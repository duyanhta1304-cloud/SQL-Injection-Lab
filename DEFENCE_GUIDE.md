# Adding the defence to the vulnerable store

Use `app.py` as the **before** version and `app_secure.py` as the **after** version. They have the same visible store pages. Start only one at a time because both rebuild `apex_store.db` and use port 5000.

## Attacks to run against `app.py`

Start the vulnerable version with `python app.py` and open <http://127.0.0.1:5000>. Enter the payloads below into the site's own forms. They target only the fictional data seeded by `database.py`.

### Attack A: return every product from a search

1. Search for `zzzz` first. It should return no products.
2. Replace the search text with this exact input and press **Search**:

   ```text
   zzzz%' OR 1=1 --
   ```

3. The result now includes all eight products, including **Keychron Q1 Max**.

The input closes the `LIKE` string, adds an always-true `OR 1=1`, then uses `--` to comment out the remaining generated SQL. The query effectively becomes:

```sql
SELECT id, name, category, price, description FROM products
WHERE name LIKE '%zzzz%' OR 1=1 --%' OR category LIKE ...
```

### Attack B: sign in with a wrong password

1. Open **Sign in** (or go to <http://127.0.0.1:5000/login>).
2. Enter this as the **Username**:

   ```text
   admin' --
   ```

3. Enter `wrong-password` as the **Password** and submit.
4. The vulnerable page responds **Signed in as admin (admin)** despite the incorrect password.

The injected quote ends the username value. The comment removes the password condition, leaving the equivalent of `WHERE username = 'admin'`. This demo page displays a sign-in result; it does not establish a real login session.

### Attack C: show fictional user records through search

1. Put this input into the product search box and press **Search**:

   ```text
   zzzz%' UNION ALL SELECT id, username, email, role, credit_card FROM users --
   ```

2. The results table displays user rows instead of products. For example, the admin row contains `admin@apexgear.local`. Its fictional card fragment appears under **Description / value**.

The original product query returns five columns. The injected `UNION ALL SELECT` supplies five columns from `users`, so SQLite combines the two result sets. The `zzzz` prefix avoids matching products, making the injected rows easy to see. These addresses and card fragments are demonstration data.

After recording the results, stop `app.py` and start `python app_secure.py`. Repeat the three inputs. The defended routes return HTTP 403 for them, while normal search and valid fictional credentials still work.

## 1. Search: bind the text as data

In `app.py`, the search term is interpolated twice into the SQL string:

```python
sql = (
    "SELECT id, name, category, price, description FROM products "
    f"WHERE name LIKE '%{query_text}%' OR category LIKE '%{query_text}%' "
    f"ORDER BY {sort_column}"
)
results = connection.execute(sql).fetchall()
```

Replace that query and execution with the pattern from `app_secure.py`:

```python
sql = (
    "SELECT id, name, category, price, description FROM products "
    "WHERE name LIKE ? OR category LIKE ? "
    f"ORDER BY {sort_column}"
)
params = (f"%{query_text}%", f"%{query_text}%")
cursor = connection.cursor()
execute_secure(cursor, sql, params)
results = cursor.fetchall()
```

The `?` markers keep `query_text` out of the SQL syntax. `ORDER BY` cannot use a value placeholder for a column name, so both versions map the requested sort key through an explicit allowlist. In the defended version that allowlist is `ALLOWED_SORT_COLUMNS` in `security.py`.

## 2. Login: bind both credentials

The vulnerable route builds this SQL:

```python
sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
user = connection.execute(sql).fetchone()
```

The defended route executes this instead:

```python
sql = "SELECT id, username, email, role FROM users WHERE username = ? AND password = ?"
cursor = connection.cursor()
execute_secure(cursor, sql, (username, password))
user = cursor.fetchone()
```

The username and password are database values even when they contain quotes, SQL keywords, or comment syntax. Selecting only the columns needed by the response also avoids fetching the card fragment.

## 3. Add the separate detection layer

`app_secure.py` imports `ASTSecurityGuard`, `SecurityViolation`, and `execute_secure` from `security.py`. Before running each query, it calls `_block_suspicious` to inspect the raw input and log suspicious values. It also catches `SecurityViolation` raised by `execute_secure`. The guard uses `sqlparse` tokens and heuristics; despite its class name, it is not a full SQL abstract syntax tree parser. Its verdict is a secondary signal. Binding parameters is what prevents a submitted value from rewriting the SQL statement.

## 4. Add the separate honeypots

`app_secure.py` imports `honeypot.py`. At startup it calls `honeypot.install_canary_table()` after `database.init_db()`. The decoy table is absent from the baseline after it starts. The defended routes call `honeypot.inspect_honeypots(request)` and `honeypot.check_canary_table_access(...)`, with alerts written to `security_alerts.log`. Only the defended app includes `templates/_honeypot_field.html` in its forms. These are tripwires and telemetry, not the main SQL injection fix.

## Demonstration for the report

Show a normal request beside one of the attack results above. Then show the vulnerable query and its parameterized replacement from sections 1 and 2. Explain the extra detection in sections 3 and 4. Keep screenshots and tests limited to your local copy of the application.

For a complete application beyond this SQL injection demonstration, passwords need proper hashing and sign-in needs real session management. The current users and credentials are fictional seed data.
