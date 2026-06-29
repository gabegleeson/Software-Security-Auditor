# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the App

```powershell
# Activate virtual environment
.venv\Scripts\activate

# Development server (hot-reload, debug toolbar)
$env:FLASK_DEBUG="1"; python app.py

# Production server (waitress, no reloader) — same as how it runs on IIS
python app.py
```

The app runs at `http://127.0.0.1:5000`. Credentials are created on first run via the `/setup` page and stored securely in the database.

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `APP_SECRET_KEY` | `change-this-secret-key` | Flask session secret |
| `NVD_API_KEY` | _(empty)_ | NVD CVE API key |

## Hard Rules

**Do not modify the database schema.** Do not add, remove, or rename tables or columns in `init_db()`. The production database cannot be migrated, so any schema change will break it. New data must fit into existing columns — use the `data` JSON blob on the relevant table.

## Architecture

This is a single-file Flask application (`app.py`, ~6500 lines) with no blueprints. Everything lives in one module: constants, data model helpers, database access, and all route handlers.

### Database

SQLite at `.venv/data/software_auditor.db`. Tables are created by `init_db()` and auto-migrated at startup. The schema uses a JSON blob pattern — most tables store a `data TEXT` column containing a JSON dict; only key lookup fields (name, id, vendor_name) are real columns.

Main tables:
- `software` — one row per software product (the "item" record)
- `software_assessments` — one row per security assessment submission linked to a software item
- `assessments` — legacy table for older records
- `vendors` — vendor profile records
- `vendor_assessments` — vendor-level security assessments
- `vendor_entities` — normalised vendor names for cross-referencing
- `data_storage_countries` / `data_storage_country_groups` / `vendor_data_storage_countries` — data hosting location tracking
- `categories` — software categories
- `country_risk_comments` — per-country risk notes
- `settings` — key/value app settings

### In-Memory Runtime State

At startup (`refresh_runtime_state()`, called once after `init_db()`), all records are loaded into module-level globals:

- `SOFTWARE_ITEMS` — list of software product records
- `SOFTWARE_ASSESSMENT_RECORDS` — list of submitted assessment records
- `SOFTWARE_RECORDS` — combined list (`SOFTWARE_ITEMS + SOFTWARE_ASSESSMENT_RECORDS`)
- `VENDOR_RECORDS` — list of vendor profile records
- `VENDOR_ASSESSMENT_RECORDS` — list of vendor assessment records
- `CATEGORIES`, `APP_SETTINGS`, `NEXT_*_ID` counters

All mutations go through `persist_*()` functions which write back to SQLite, then update the globals directly — there is no re-load from DB per request.

### Data Model

Records are plain Python dicts. `blank_assessment()` provides the canonical zero-value dict for both software items and assessments (they share `ASSESSMENT_FIELDS`). `enrich_assessment()` adds computed fields (`deployment_stage`, `review_date`, `assessment_date`) on load and after mutations.

The distinction between a *software item* (`is_assessment=False`) and a *submitted assessment* (`is_assessment=True, submission_status="submitted"`) is tracked via the `is_assessment` flag. A software item is the persistent product record; assessments are point-in-time snapshots.

### Vendor Linkage

Vendor data is denormalised across software records and vendor records. `get_vendor_backed_value(record, field)` resolves a field by checking the software record first, then falling back to the matching vendor record. `sync_vendor_entity_tables()` keeps the `vendor_entities` table consistent with the runtime vendor catalog built from `VENDOR_RECORDS` and `SOFTWARE_ITEMS`.

### Alert System

`compute_software_alert_keys(record, vendor_record, vendor_map, home_country, item)` returns a set of alert key strings (defined in `PDF_ALERT_LABELS`) for a given software item. Alert risk levels and signatory routing are configurable via the Settings page and stored in the `settings` table. `highest_risk_from_alerts()` ranks alert sets to a single risk level (High > Moderate > Low).

### PDF Generation

`build_assessment_pdf()` uses ReportLab to generate assessment PDFs. A school crest logo is loaded from a hardcoded absolute path (`PDF_LOGO_PATH`, `app.py:47`) — this will fail if run outside the original machine. The `pypdf` library is used to merge additional vendor T&C/privacy policy PDFs uploaded by users.

### File Uploads

PDF uploads (vendor T&Cs, privacy policies, EULAs) are stored in the `uploads/` directory at the project root. Filenames are UUIDs; original filenames are kept in the corresponding record's `data` JSON.

### Templates

All templates extend `templates/base.html`. Jinja2 with a custom `linkify` filter (converts URLs in text to `<a>` tags, defined at `app.py:32`). No frontend build step — plain HTML/CSS/JS in templates, no separate static directory.
