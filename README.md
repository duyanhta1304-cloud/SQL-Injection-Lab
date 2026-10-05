# SQL Injection Lab

An intentionally vulnerable Flask storefront for demonstrating SQL injection attacks and layered defences in a controlled classroom environment.

> [!WARNING]
> This application deliberately contains exploitable SQL queries. Run it only on localhost or inside an isolated lab environment. Do not deploy it to a public server.

## Features

- Toggle between an intentionally vulnerable baseline and defended mode.
- Demonstrate authentication bypass and UNION-based SQL injection.
- Compare string-built SQL with parameterized statements.
- Inspect suspicious input with a token/AST-based security guard.
- Detect decoy table access and hidden-field honeypot activity.
- Review the executed query and defence verdict in the on-page security console.

## Run locally

1. Clone the repository and enter its directory.
2. Create a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install the dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

4. Start the application:

   ```powershell
   python app.py
   ```

5. Open `http://127.0.0.1:5000`.

The SQLite database is recreated with demonstration data whenever the application starts. Database files and security logs are intentionally excluded from Git.

## Project structure

```text
app.py                 Flask routes and mode switching
database.py            SQLite schema and repeatable seed data
security.py            Input inspection and safe query execution
honeypot.py             Canary and security event logging
templates/             Jinja page templates
static/styles.css       Shared responsive styling
static/products/        Product images
```

## Safe use

All usernames, passwords, email addresses, card fragments, and canary tokens in this repository are fictional demonstration data. Keep testing limited to this application and systems you are authorized to assess.
