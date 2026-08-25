# Vendored artifacts

This tool renders reports itself (no binary dependency). Two files are
vendored from [open-pan-bpa](https://github.com/gitupcourt/open-pan-bpa) so
the output stays identical between the two tools:

| File | What it is | Vendored from |
|---|---|---|
| `template.html` | The HTML report template (byte-identical copy of `internal/report/template.html`) | open-pan-bpa v0.4.0 |
| `catalog.json` | The check catalog (`bpa catalog` output: slugs, titles, severities, sections, documentation references, `pan_bpa_ids`) | open-pan-bpa v0.4.0 |

**Verify, don't trust:** `template.html` should hash identically to the file
in the open-pan-bpa source tree at the pinned version above. `catalog.json`
is reproducible with `bpa catalog` from that version's binary.

**Refreshing** (whenever open-pan-bpa's report or packs change):

```
copy <open-pan-bpa>/internal/report/template.html template.html
bpa catalog > catalog.json
```

Then update the pinned version in this file and smoke-test with
`--report <any API report JSON>`. If the template gains directives this
script's renderer doesn't substitute, rendering fails loudly with a
re-vendor message rather than emitting a broken page.

**Byte-parity contract:** the Python renderer reproduces Go
`html/template`'s output exactly (verified by SHA-256 against `bpa render`
on the same report JSON), including its stripping of `//` comments from the
interactive script block. Two constraints keep that true — the template's
JS must never put `//` inside a string literal, and template edits upstream
should re-run the parity comparison here.
