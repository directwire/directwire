# IETF Internet-Draft — draft-directwire-agent-transport

The Directwire protocol, formatted as an IETF Internet-Draft. This is the
standards-facing artifact derived from the living protocol spec
[`../SPEC.md`](../SPEC.md) (SPEC.md is the source of truth for protocol
content; the draft is a frozen, dated snapshot).

## Files

| file | purpose |
|---|---|
| `draft-directwire-agent-transport-00.xml` | **Canonical source.** RFC 7991 v3 (`xml2rfc`) vocabulary — the format the IETF toolchain (datatracker, `xml2rfc`, `idnits`) consumes natively. |
| `draft-directwire-agent-transport-00.txt` | Generated plain-text draft (build artifact, committed). |
| `draft-directwire-agent-transport-00.html` | Generated HTML rendering (build artifact, committed). |
| `build.sh` | Reproducible build: creates a local `.venv`, installs `xml2rfc` (pure Python), builds `.txt`/`.html`, optionally runs `idnits`. |

## Build

Requires only a working Python (no ruby, no system packages):

```bash
./build.sh          # on Windows: bash ietf/build.sh (Git Bash / WSL)
```

The `.venv` is gitignored. `xml2rfc` is pinned by the build script on install;
reproduce the exact environment with:

```bash
python -m venv .venv && .venv/Scripts/pip install xml2rfc
```

## Edit / version bump

1. Edit `draft-directwire-agent-transport-00.xml`.
2. `./build.sh` to regenerate the `.txt`/`.html`.
3. On any substantive change, bump the draft name
   (`draft-directwire-agent-transport-01`, …) in the `<rfc docName=…>` and the
   `<seriesInfo value=…>`, and update the `<date>`.
4. Push; the CI job `.github/workflows/ietf-draft.yml` rebuilds and runs
   `idnits` preflight checks on every PR.

## Submission (datatracker.datatracker.ietf.org)

1. Log in, "New submission" → upload the `.xml` (or `.txt`).
2. Contact info: the author block is the org "Directwire" with a placeholder
   `.example` address — replace with a real editorial contact before the first
   real submission.
3. Expect an email "submission received" with the assigned datatracker URL and
   an idnits report; fix any nits it flags and resubmit as `-01`.
