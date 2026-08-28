# Local Dashboard

SentinelLint includes a browser UI over the existing analyzer. It is a **local application**, not a cloud service.

## Start

Windows:

```text
start_dashboard.bat
```

Or:

```powershell
python web_server.py
```

Open:

```text
http://127.0.0.1:8000
```

## What the dashboard supports

- Python/C++ file upload
- ZIP project upload
- code paste
- project/folder selection where the browser supports it
- severity/language/category filters
- source context
- CWE, confidence and remediation details
- source-to-sink evidence paths
- existing fix + re-scan workflow

## Privacy model

- Server binds to `127.0.0.1`.
- Core analysis requires no internet connection.
- Submitted source is not executed.
- Uploaded data is kept in a temporary local workspace for the running process.
- The dashboard itself makes no third-party HTTP requests.

## Troubleshooting

### `web_server.py` not found

Open PowerShell **inside the folder containing `web_server.py`** and run:

```powershell
python web_server.py
```

### Port already in use

Choose another local port:

```powershell
$env:SENTINELLINT_PORT=8001
python web_server.py
```

Then open `http://127.0.0.1:8001`.

### Dashboard opens but shows no scan

Keep the server terminal running and refresh the page. Check the terminal for the request/error message.
