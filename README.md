# pan-api-bpa

Drive **Palo Alto Networks' official Best Practice Assessment (BPA) API**
against a PAN-OS config or tech support file, then present the results
through [open-pan-bpa](https://github.com/gitupcourt/open-pan-bpa)'s
renderer — so API-based and offline assessments produce identical HTML/CSV
output. The assessment itself is performed by Palo Alto Networks' hosted
engine; this script automates the submission and parses its report.

**This tool is not itself an official Palo Alto Networks product** (it is an
independent client of their documented public API). Results are advisory.

## The official API

- **Posture Management / BPA API** (the default and go-forward path this
  tool drives):
  [pan.dev — Posture introduction](https://pan.dev/scm/api/config/posture-management/introduction-posture/).
  Workflow: request an upload URL, PUT the PAN-OS configuration, poll for
  completion, download the report JSON.
- **AIOps for NGFW BPA API** (the previous generation, same authentication
  model): [pan.dev — AIOps NGFW BPA](https://pan.dev/aiops-ngfw-bpa/api/).
  Kept for reference; tenants migrated to native SCM typically cannot use it
  (error 1210 — no AIOps instance to bind).
- The API's optional `delete_after_processing` flag (exposed here as
  `--delete-after-processing`) instructs the service to delete the uploaded
  configuration once the report is generated.

## How it fits together

```
config / TSF ──> Posture API ──> API report JSON
                                      │  convert (this tool)
                                      ▼
                       open-pan-bpa report schema JSON
                                      │  render (this tool)
                                      ▼
              HTML + CSV — byte-identical to open-pan-bpa's
```

**Standalone by design — no binary required.** Everything happens in one
readable Python file. This is the "trust but verify" path: if you'd rather
not run a compiled binary, you can audit every line of what touches your
config. The HTML is rendered through a byte-identical vendored copy of
open-pan-bpa's report template, and the output is verified byte-for-byte
against the binary's renderer (see [VENDORED.md](VENDORED.md)) — same
report, either tool, provably.

**Prefer one binary instead?** open-pan-bpa v0.5.0+ ships the same hosted-API
flow built in as `bpa api-scan` (a separate, explicitly-online subcommand;
`bpa scan` stays fully offline). Pick whichever trust posture fits:

| | Engine | Runs as |
|---|---|---|
| `bpa scan` | open-pan-bpa, offline | binary |
| `bpa api-scan` | Palo Alto Networks' hosted engine | binary |
| `pan_api_bpa.py` (this tool) | Palo Alto Networks' hosted engine | auditable Python |

## Setup

```
pip install requests
```

That's the only dependency (and only for live API runs — `--report` mode,
converting an existing API report JSON, is stdlib-only and fully offline).

**Authentication** uses the common SASE service-account model, documented by
Palo Alto Networks:

1. [Get started](https://pan.dev/sase/docs/getstarted/) — obtain your
   Tenant Service Group (TSG) ID.
2. [Create a service account](https://pan.dev/sase/docs/service-accounts/)
   for that TSG (needs an SCM role — Essentials or Pro) — this yields the
   Client ID and Client Secret.
3. The script exchanges those for an
   [OAuth2 access token](https://pan.dev/sase/api/auth/post-auth-v-1-oauth-2-access-token/)
   with scope `tsg_id:{TSG}` automatically.

Credentials are env-only (never flags, so secrets stay out of shell history):

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

## Where the best practices come from

Nothing here is invented:

- **The verdicts are Palo Alto Networks' own.** This tool submits the config
  to PAN's hosted posture (BPA) engine and reports what *their* engine
  returned — check names, messages, and pass/fail results all originate from
  the vendor's assessment of your configuration.
- **Documentation citations ride along.** Checks mapped to the open-pan-bpa
  catalog carry that catalog's `references` — links to the specific pages on
  [docs.paloaltonetworks.com](https://docs.paloaltonetworks.com)
  (Best Practices portal and admin guides) — rendered as `[doc N]` links in
  the HTML and a `references` column in the CSV. open-pan-bpa enforces in CI
  that every cataloged check cites its documentation.
- Unmapped checks pass through with Palo Alto Networks' own check text
  verbatim, so the vendor's wording is the source even without a citation.
- The verdict corrections (scope filtering, disabled-rule and
  predefined-object downgrades) reclassify — they never delete a vendor
  finding, and `--no-corrections` disables them entirely.

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
