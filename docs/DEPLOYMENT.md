# Deployment

## Single host

`pipx install mitiscan` or pull the container image. That's it.

## CI pipeline (recommended)

Run Mitiscan from a scheduled GitHub Actions job against staging. Example:

```yaml
name: Nightly scan
on:
  schedule:
    - cron: "0 2 * * *"
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@v4
      - run: pipx install mitiscan
      - run: |
          mitiscan --headless ${{ vars.SCAN_TARGET }} \
            --authorized --profile BALANCED
      - uses: actions/upload-artifact@v4
        with: { name: report, path: mitiscan_outputs/ }
```

## Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata: { name: mitiscan-nightly }
spec:
  template:
    spec:
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: mitiscan
          image: ghcr.io/shrivastava67/mitiscan:latest
          args: ["--headless", "$(TARGET)", "--authorized", "--profile", "BALANCED"]
          env:
            - { name: TARGET, value: "staging.example.com" }
          resources:
            requests: { cpu: "500m", memory: "512Mi" }
            limits:   { cpu: "2",    memory: "2Gi"  }
          volumeMounts:
            - { name: out, mountPath: /app/mitiscan_outputs }
      volumes:
        - { name: out, emptyDir: {} }
```

## Air-gapped

Pre-build the container with all `--bootstrap` tools baked in:

```bash
docker build --target runtime --build-arg BOOTSTRAP=1 -t mitiscan:airgap .
```

Ship the SBOM (`sbom.cdx.json`) alongside.

## Operations

- Forward `mitiscan.jsonl` to your SIEM. Records are RFC-3339 timestamped.
- Alert on `audit.jsonl` events with `event=crash` or `event=scope.denied`.
- Rotate run dirs older than your retention window.
