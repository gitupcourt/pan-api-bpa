# pan-api-bpa

Drive the hosted SCM Posture (BPA) API against a PAN-OS config or tech
support file, then present the results through
[open-pan-bpa](https://github.com/gitupcourt/open-pan-bpa)'s renderer — so
API-based and offline assessments produce identical HTML/CSV output.

**Not an official Palo Alto Networks product.** Results are advisory.

## How it fits together

```
config / TSF ──> Posture API ──> API report JSON
                                      │  convert (this tool)
                                      ▼
                       open-pan-bpa report schema JSON
                                      │  bpa render
                                      ▼
                            HTML + CSV (shared layer)
```

Presentation lives **only** in open-pan-bpa. This tool fetches and converts.
Any report-output improvement over there applies here automatically.

## Setup

```
pip install requests
```

Plus the `bpa` binary on PATH (or `--bpa-bin`). Credentials are env-only:

```
$env:PANW_CLIENT_ID     = "..."   # SCM service account
$env:PANW_CLIENT_SECRET = "..."
$env:PANW_TSG_ID        = "..."
```

## Usage

```
# Full run from a tech support file
python pan_api_bpa.py --tsf device_ts.tgz --out reports/

# Offline: convert + render an API report JSON you already have
python pan_api_bpa.py --report bpa_xxxx.json --hostname fw01 --out reports/
```

## Conversion semantics

- Verdict vocabulary matches the offline engine: `pass / fail / note / n/a`.
  Allow-scoped checks on non-allow rules become `n/a`; failed checks on
  disabled rules and predefined read-only objects downgrade to `note`
  (disable with `--no-corrections`).
- Check identity: API check IDs are mapped to open-pan-bpa slugs through the
  catalog's `pan_bpa_ids` cross-references (`bpa catalog`, fetched at
  runtime — nothing vendored). Unmapped checks pass through as
  `pan-api-<id>` with their API titles, so nothing is dropped.
- **Check IDs are registry-specific.** Never cross-reference by ID between
  runs; the slug is the identity.

## API behavior baked in (do not "fix")

- Upload is **raw XML with a `Content-Encoding: gzip` header**; genuinely
  gzipped bytes fail the backend's parse. `--gzip-upload` exists as an
  escape hatch only.
- Content-Type tries `plain/text` (documented, sic) then `text/plain`.
- `result.report_url` is often empty on success; the report lands under
  `result.custom_check_url`. Every URL in `result` is tried.

## Data handling

Configs and tech support files are sensitive. Nothing in this repo may ever
include one, nor an API report generated from one — outputs default to the
working directory and are gitignored defensively. `--delete-after-processing`
asks the API to drop the uploaded config server-side.
