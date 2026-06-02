# Usage

## Install

```bash
# from source
git clone https://github.com/shrivastava67/Mitiscan.git
cd Mitiscan
pip install -e .

# or pipx (recommended for end users once published)
pipx install mitiscan
```

## First run

```bash
mitiscan                     # GUI
mitiscan --check-deps        # audit external tools
mitiscan --bootstrap         # install missing tools (apt → pip → go → git)
```

## Headless scan

Written authorization is required. The `--authorized` flag asserts it; a
receipt is dropped into the run directory.

```bash
mitiscan --headless example.com \
         --authorized \
         --profile BALANCED
```

Profiles:

| Profile      | Concurrency       | Stealth                      |
|--------------|-------------------|------------------------------|
| `STEALTH`    | sequential        | longer jitter, fewer probes  |
| `BALANCED`   | parallel per stage| default                      |
| `AGGRESSIVE` | parallel + faster | noisy, max throughput        |

## Resume an interrupted scan

```bash
mitiscan --resume <run_id>
```

`<run_id>` is the directory under `mitiscan_outputs/`.

## Allowing private ranges

By default RFC-1918 is denied. For lab work:

```bash
mitiscan --headless 10.0.0.5 --authorized --allow-private
```

## Outputs

Per-run directory:

```
mitiscan_outputs/<run_id>/
  report.html              # primary
  report.md
  report.json
  report.pdf               # if weasyprint OK
  mitiscan.jsonl           # structured log
  audit.jsonl              # security events
  authorization.txt        # receipt
  checkpoint.json          # per-module resume state
```

## Container

```bash
docker run --rm -v "$PWD/out:/app/mitiscan_outputs" \
  ghcr.io/shrivastava67/mitiscan:latest \
  --headless example.com --authorized --profile BALANCED
```

## Verifying a release

```bash
gh attestation verify mitiscan-0.1.0-py3-none-any.whl \
  --repo shrivastava67/Mitiscan
```
