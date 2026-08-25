#!/usr/bin/env python3
"""
pan_api_bpa.py — run a PAN-OS config through the hosted SCM Posture (BPA) API
and present the results through open-pan-bpa's renderer.

This tool is the API-driven sibling of open-pan-bpa (offline engine). It owns
exactly two jobs:

  1. FETCH   — drive the SCM Posture API (upload config, poll, download the
               report JSON), carrying every workaround the API needs in
               practice (see NOTES below).
  2. CONVERT — map the API report JSON into the open-pan-bpa report schema,
               applying the same verdict vocabulary the offline engine uses
               natively (pass / fail / note / n/a).

Presentation (HTML/CSV) is deliberately NOT implemented here: the converted
report is handed to `bpa render`, so both tools share one presentation layer
and output improvements never need porting.

The assessment engine is Palo Alto Networks' own; this is a client of their
documented public API:
  Posture / BPA API : https://pan.dev/scm/api/config/posture-management/introduction-posture/
  Auth (SASE model) : https://pan.dev/sase/docs/service-accounts/
  Legacy AIOps BPA  : https://pan.dev/aiops-ngfw-bpa/api/

This tool is not itself an official Palo Alto Networks product. Results are
advisory.

Prereqs:
  - pip install requests
  - the `bpa` binary (open-pan-bpa >= 0.4) on PATH, or --bpa-bin
  - SCM service account with an SCM role on the TSG

Credentials are read from environment variables ONLY (never flags, so secrets
stay out of shell history):
  PANW_CLIENT_ID, PANW_CLIENT_SECRET, PANW_TSG_ID

Examples:
  # Full run from a tech support file:
  python pan_api_bpa.py --tsf device_ts.tgz --out reports/

  # Convert + render an API report JSON you already have (no network):
  python pan_api_bpa.py --report bpa_xxxx.json --hostname fw01 --out reports/

NOTES — hard-won API behavior this script bakes in (do not "fix" these):
  - Upload is RAW XML with a `Content-Encoding: gzip` header. The backend
    reads the object raw; properly-gzipped bytes fail its XML parse. This
    matches pan.dev's own curl example (which works only because it is wrong).
  - Content-Type tries "plain/text" (documented, sic) then "text/plain";
    the presigned URL signs the header value.
  - On COMPLETED, `result.report_url` is often empty; the report actually
    lands in `result.custom_check_url`. Every http(s) URL in `result` is
    downloaded.
  - Check IDs are registry-specific. Mapping to open-pan-bpa slugs uses the
    catalog's pan_bpa_ids cross-references and falls back to synthetic
    pan-api-<id> slugs; never treat IDs as stable across runs.
"""

import argparse
import datetime
import gzip
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
POSTURE_BASE = "https://api.strata.paloaltonetworks.com"

TOOL = "pan-api-bpa"
TOOL_VERSION = "0.1.0"

# ------------------------------------------------------------------ fetch ---


def die(msg, resp=None):
    if resp is not None:
        msg += f"\n  HTTP {resp.status_code}: {resp.text[:2000]}"
    sys.exit(f"ERROR: {msg}")


def get_token(client_id, client_secret, tsg_id):
    import requests
    print(f"[1/4] Authenticating (TSG {tsg_id})...")
    r = requests.post(
        AUTH_URL,
        auth=(client_id, client_secret),
        data={"grant_type": "client_credentials", "scope": f"tsg_id:{tsg_id}"},
        timeout=30,
    )
    if r.status_code != 200:
        die("Authentication failed. Check PANW_CLIENT_ID/SECRET/TSG_ID.", r)
    tok = r.json().get("access_token")
    if not tok:
        die(f"No access_token in auth response: {r.text[:500]}")
    return tok


def extract_from_tsf(tsf_path, workdir):
    """Extract the effective config from a tech support file. Prefers the
    hidden .merged-running-config.xml (Panorama-pushed policy included)."""
    print(f"      Extracting config from: {os.path.basename(tsf_path)}")
    config_path = None
    with tarfile.open(tsf_path, "r:*") as tar:
        cands = [m for m in tar.getmembers() if m.isfile()
                 and m.name.endswith("running-config.xml")]
        cands.sort(key=lambda m: (
            not m.name.endswith(".merged-running-config.xml"),
            "saved-configs" not in m.name,
            len(m.name)))
        if cands:
            chosen = cands[0]
            src = tar.extractfile(chosen)
            config_path = os.path.join(workdir, "running-config.xml")
            with open(config_path, "wb") as out:
                out.write(src.read())
            kind = "merged (Panorama-managed)" if chosen.name.endswith(
                ".merged-running-config.xml") else "local"
            print(f"      Using {kind} config: {chosen.name}")
    if not config_path:
        die(f"No running-config.xml found in {tsf_path}")
    return config_path


def config_hostname(config_path):
    try:
        for _, elem in ET.iterparse(config_path):
            if elem.tag == "hostname":
                return (elem.text or "").strip()
    except (ET.ParseError, OSError):
        pass
    return ""


def posture_fetch(token, config_path, out_json, args):
    """Upload the config, poll to completion, download the report JSON."""
    import requests
    print("[2/4] Initiating config upload (Posture API)...")
    r = requests.post(
        f"{POSTURE_BASE}/posture/checks/v1/reports/config-file-upload",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        json={"delete_after_processing": args.delete_after_processing},
        timeout=60,
    )
    if r.status_code == 429:
        die("Rate limited: maximum of 5 active jobs reached; retry later.", r)
    if r.status_code != 201:
        die("Upload initiation failed. Verify the service account has an "
            "SCM role (Essentials or Pro) on this TSG.", r)
    data = r.json()
    task_id, upload_url = data.get("task_id"), data.get("upload_url")
    if not task_id or not upload_url:
        die(f"Unexpected response: {json.dumps(data)[:1000]}")

    with open(config_path, "rb") as f:
        raw = f.read()
    payload = raw if args.raw_upload else gzip.compress(raw)
    mode = "RAW config + gzip header" if args.raw_upload else "gzipped config"
    print(f"[3/4] Uploading {mode} ({len(raw) / 1048576:.1f} MB raw)...")
    r = None
    for i, ctype in enumerate(["plain/text", "text/plain"]):
        r = requests.put(upload_url, data=payload,
                         headers={"Content-Type": ctype,
                                  "Content-Encoding": "gzip"},
                         timeout=600)
        if r.status_code in (200, 201):
            break
        if "SignatureDoesNotMatch" in r.text and i == 0:
            print("      Signature mismatch; retrying with 'text/plain'...")
            continue
        break
    if r is None or r.status_code not in (200, 201):
        die("Config upload to signed URL failed.", r)

    print(f"[4/4] Polling (timeout {args.timeout}s)...")
    deadline = time.time() + args.timeout
    last = None
    while time.time() < deadline:
        r = requests.get(
            f"{POSTURE_BASE}/posture/checks/v1/reports/{task_id}/bpa-result",
            headers={"Authorization": f"Bearer {token}"}, timeout=30)
        if r.status_code == 200:
            body = r.json()
            status, msg = body.get("status"), body.get("message", "")
            tag = f"{status}" + (f" — {msg}" if msg else "")
            if tag != last:
                print(f"      {tag}")
                last = tag
            if status == "COMPLETED":
                result = body.get("result") or {}
                urls = {k: v for k, v in result.items()
                        if isinstance(v, str) and v.startswith("http")}
                if not urls:
                    die(f"COMPLETED but no URLs in result: "
                        f"{json.dumps(body)[:1500]}")
                # report_url is often empty; the report lands under other keys.
                for key in ("report_url", "custom_check_url", *urls):
                    url = urls.get(key) if key in urls else None
                    if not url:
                        continue
                    rep = requests.get(url, timeout=300)
                    if rep.status_code == 200:
                        with open(out_json, "wb") as f:
                            f.write(rep.content)
                        print(f"      {key} -> {out_json} "
                              f"({len(rep.content) / 1024:.0f} KB)")
                        return out_json
                die("All artifact downloads failed (signed URLs expire in "
                    "~30 min; rerun the script).")
            if status == "FAILED":
                hint = ("" if args.raw_upload else
                        "\n  Retry without --gzip-upload: the backend reads "
                        "the object raw and fails on actually-gzipped bytes.")
                die(f"Processing failed. {msg or ''}"
                    f"\n  {json.dumps(body)[:1500]}{hint}")
        elif r.status_code != 404:
            print(f"      (transient HTTP {r.status_code}, retrying)")
        time.sleep(args.interval)
    die(f"Timed out after {args.timeout}s waiting for task {task_id}.")


# ---------------------------------------------------------------- convert ---

# Rule-scoped checks that only apply to allow rules (current-registry IDs plus
# name fragments so the filter survives renumbering).
ALLOW_ONLY_CHECK_IDS = {5, 208, 351, 353, 354}
ALLOW_ONLY_NAME_FRAGMENTS = (
    "with an allow action", "with the allow action", "action set to allow",
    "with an action of allow", "and the action is allow",
)

# Predefined read-only objects per feature (substring match on feature name).
PREDEFINED_OBJECTS = {
    "antivirus": {"default", "strict"},
    "anti_spyware": {"default", "strict"},
    "vulnerability": {"default", "strict"},
    "file_blocking": {"basic file blocking", "strict file blocking"},
    "wildfire": {"default"},
    "decryption": {"default"},
    "ike": {"default", "Suite-B-GCM-128", "Suite-B-GCM-256"},
    "ipsec": {"default", "Suite-B-GCM-128", "Suite-B-GCM-256"},
}

SEVERITY_BY_CHECK_TYPE = {
    "critical": "critical", "warning": "warning", "note": "informational",
    "informational": "informational",
}


def norm_title(s):
    s = (s or "").lower()
    for ch in "\"'‘’“”.,:;!?()[]":
        s = s.replace(ch, "")
    return " ".join(s.split())


def is_allow_only(check_id, check_name):
    if check_id in ALLOW_ONLY_CHECK_IDS:
        return True
    n = norm_title(check_name)
    if "not allow" in n:
        return False
    return any(f in n for f in ALLOW_ONLY_NAME_FRAGMENTS)


def load_catalog(bpa_bin):
    """Ask the bpa binary for its check catalog; build an id->check map."""
    try:
        out = subprocess.run([bpa_bin, "catalog"], capture_output=True,
                             text=True, check=True, encoding="utf-8")
    except FileNotFoundError:
        die(f"'{bpa_bin}' not found — install open-pan-bpa or pass --bpa-bin")
    except subprocess.CalledProcessError as e:
        die(f"'{bpa_bin} catalog' failed: {e.stderr[:500]}")
    cat = json.loads(out.stdout)
    by_id = {}
    for pack in cat.get("packs") or []:
        for chk in pack.get("checks") or []:
            for pid in chk.get("pan_bpa_ids") or []:
                by_id.setdefault(pid, chk)
    return {"schema_version": cat.get("schema_version"),
            "tool_version": cat.get("tool_version"), "by_id": by_id}


def convert(api, catalog, hostname, input_path, corrections=True):
    """Map an API report JSON into the open-pan-bpa report schema."""
    findings = []
    by_id = catalog["by_id"]
    mapped = unmapped = 0

    bp = api.get("best_practices") or {}
    for section, feats in bp.items():
        if not isinstance(feats, dict):
            continue
        for feature, wrappers in feats.items():
            if not isinstance(wrappers, list):
                continue
            for w in wrappers:
                if not isinstance(w, dict):
                    continue
                cfg = w.get("configuration") or {}
                obj = {
                    "section": section,
                    "feature": feature,
                    "name": cfg.get("name") or "",
                    "location": cfg.get("location") or "",
                }
                uuid = cfg.get("rule_uuid") or cfg.get("uuid") or ""
                if uuid:
                    obj["uuid"] = uuid
                for origin in ("warnings", "notes"):
                    for chk in w.get(origin) or []:
                        if not isinstance(chk, dict):
                            continue
                        f = convert_check(chk, origin, obj, cfg, feature,
                                          by_id, corrections)
                        if f is None:
                            continue
                        if f.pop("_mapped"):
                            mapped += 1
                        else:
                            unmapped += 1
                        findings.append(f)

    summary = {"checks": len({f["slug"] for f in findings}),
               "objects_evaluated": len({(f["object"]["section"],
                                          f["object"]["feature"],
                                          f["object"]["name"],
                                          f["object"]["location"])
                                         for f in findings}),
               "pass": 0, "fail": 0, "notes": 0, "not_applicable": 0,
               "fail_by_severity": {}}
    for f in findings:
        v = f["verdict"]
        if v == "pass":
            summary["pass"] += 1
        elif v == "fail":
            summary["fail"] += 1
            sev = f["severity"]
            summary["fail_by_severity"][sev] = \
                summary["fail_by_severity"].get(sev, 0) + 1
        elif v == "note":
            summary["notes"] += 1
        else:
            summary["not_applicable"] += 1

    print(f"      Converted {len(findings)} findings "
          f"({mapped} slug-mapped, {unmapped} pan-api-* passthrough)")
    registry = (api.get("information") or {}).get("last_updated_time") or ""
    return {
        "schema_version": catalog["schema_version"],
        "tool": TOOL,
        "tool_version": f"{TOOL_VERSION} (api registry {registry or 'unknown'};"
                        f" render {catalog['tool_version']})",
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
                        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": hostname or "api-device",
        "vsys": [],
        "input_path": os.path.basename(input_path),
        "input_kind": "api",
        "summary": summary,
        "findings": findings,
    }


def convert_check(chk, origin, obj, cfg, feature, by_id, corrections):
    cid = chk.get("check_id")
    name = chk.get("check_name") or ""
    passed = bool(chk.get("check_passed"))

    # Base verdict: the API's own notes bucket is advisory.
    verdict = "pass" if passed else ("note" if origin == "notes" else "fail")
    note_reason = ""

    if corrections and not passed:
        # Allow-only checks are out of scope on non-allow rules (matches the
        # offline engine's native n/a semantics).
        action = cfg.get("action")
        if is_allow_only(cid, name) and action and action != "allow":
            verdict = "n/a"
        elif str(cfg.get("disabled")).lower() in ("yes", "true"):
            verdict = "note"
            note_reason = "disabled rule — remediate or delete"
        else:
            for key, names in PREDEFINED_OBJECTS.items():
                if key in feature and (obj["name"] in names
                                       or obj["location"] == "predefined"):
                    verdict = "note"
                    note_reason = ("predefined read-only — remediate via "
                                   "clone-and-attach")
                    break

    mapped = by_id.get(cid) if cid is not None else None
    f = {"_mapped": mapped is not None}
    if mapped:
        f["slug"] = mapped["slug"]
        f["title"] = mapped["title"]
        f["severity"] = mapped["severity"]
        if mapped.get("references"):
            f["references"] = mapped["references"]
    else:
        f["slug"] = f"pan-api-{cid if cid is not None else norm_title(name)[:40].replace(' ', '-')}"
        f["title"] = name or f"API check {cid}"
        f["severity"] = SEVERITY_BY_CHECK_TYPE.get(
            (chk.get("check_type") or "").lower(), "informational")
    f["verdict"] = verdict
    if verdict != "pass":
        msg = chk.get("check_message") or ""
        if note_reason:
            msg = f"{msg} [{note_reason}]" if msg else note_reason
        if msg:
            f["message"] = msg
        ff = chk.get("failed_fields")
        if isinstance(ff, dict) and ff:
            f["failed_fields"] = ff
    f["object"] = obj
    return f


# -------------------------------------------------------------------- cli ---


def render(bpa_bin, report_json, out_dir, formats):
    cmd = [bpa_bin, "render", report_json, "--out", out_dir,
           "--format", formats]
    r = subprocess.run(cmd, text=True, encoding="utf-8")
    if r.returncode != 0:
        die(f"'{bpa_bin} render' failed (exit {r.returncode})")


def main():
    ap = argparse.ArgumentParser(
        description="Hosted posture (BPA) API driver with open-pan-bpa "
                    "presentation. Not an official Palo Alto Networks product.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--tsf", help="tech support file (.tgz/.tar.gz)")
    src.add_argument("--config", help="bare running-config XML")
    src.add_argument("--report", help="existing API report JSON "
                                      "(offline: convert + render only)")
    ap.add_argument("--out", default=".", help="output directory")
    ap.add_argument("--format", default="html,csv",
                    help="render formats: html,csv,json (default html,csv)")
    ap.add_argument("--hostname", default="",
                    help="hostname for the report (auto-detected from config)")
    ap.add_argument("--bpa-bin", default="bpa",
                    help="path to the open-pan-bpa binary")
    ap.add_argument("--keep-api-json", action="store_true",
                    help="keep the raw API report JSON next to the outputs")
    ap.add_argument("--no-corrections", action="store_true",
                    help="skip scope/disabled/predefined verdict corrections")
    ap.add_argument("--gzip-upload", dest="raw_upload", action="store_false",
                    help="actually gzip the upload body (the backend usually "
                         "rejects this; raw upload is the working default)")
    ap.add_argument("--delete-after-processing", action="store_true",
                    help="ask the API to delete the config server-side")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--interval", type=int, default=10)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    catalog = load_catalog(args.bpa_bin)

    with tempfile.TemporaryDirectory() as workdir:
        hostname = args.hostname
        if args.report:
            api_json_path = args.report
        else:
            config_path = args.config
            if args.tsf:
                config_path = extract_from_tsf(args.tsf, workdir)
            hostname = hostname or config_hostname(config_path)
            cid = os.environ.get("PANW_CLIENT_ID")
            secret = os.environ.get("PANW_CLIENT_SECRET")
            tsg = os.environ.get("PANW_TSG_ID")
            if not (cid and secret and tsg):
                die("Set PANW_CLIENT_ID, PANW_CLIENT_SECRET, PANW_TSG_ID "
                    "(credentials are env-only by design).")
            token = get_token(cid, secret, tsg)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            dest = args.out if args.keep_api_json else workdir
            api_json_path = os.path.join(
                dest, f"api-bpa_{hostname or 'device'}_{stamp}.json")
            posture_fetch(token, config_path, api_json_path, args)

        with open(api_json_path, encoding="utf-8") as f:
            api = json.load(f)
        if hostname == "":
            hostname = re.sub(r"\.json$", "", os.path.basename(api_json_path))

        rep = convert(api, catalog, hostname, api_json_path,
                      corrections=not args.no_corrections)
        converted = os.path.join(
            args.out, f"bpa-{re.sub(r'[^A-Za-z0-9._-]', '-', rep['hostname'])}.json")
        with open(converted, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=2)
        print(f"      wrote {converted}")

        formats = ",".join(x for x in args.format.split(",")
                           if x.strip() and x.strip() != "json")
        if formats:
            render(args.bpa_bin, converted, args.out, formats)


if __name__ == "__main__":
    main()
