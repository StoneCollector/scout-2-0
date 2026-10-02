# El Banco — Test Target

A lightweight, zero-dependency banking application used for testing and verifying the Scout Web Scanner.

## Quick Start

Run the server on `http://127.0.0.1:5000`:

```cmd
run.bat
```

Or run directly with Python:

```cmd
python app.py
```

## Available Endpoints

- `/` — Main dashboard linking to all endpoints.
- `/login` — Account sign-in form (unencrypted password transmission over plain HTTP).
- `/search?q=query` — Transaction search reflecting query parameter without output encoding (OWASP ASVS V5.3).
- `/transfer?account=ACC100` — Wire transfer form disclosing raw SQL syntax errors on single quote inputs (OWASP ASVS V5.2).
- `/admin` — Unauthenticated administrative portal.
- `/.env` — Exposed environment configuration file containing dummy database credentials and keys.
- `/robots.txt` — Disclosing internal administrative paths.

## Testing with Scout

1. Start the target: `dummy_bank\run.bat` (running on `http://127.0.0.1:5000`).
2. Open Scout at `http://127.0.0.1:8000`.
3. Navigate to **Web Scanner**, enter `http://127.0.0.1:5000`, and click **Scan**.
