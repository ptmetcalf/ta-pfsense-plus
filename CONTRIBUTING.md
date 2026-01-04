# Contributing

Thanks for helping improve TA-pfsense Plus.

## AppInspect

Run AppInspect against the packaged archive, not the repo root.

```bash
python3 -m venv .venv-appinspect
source .venv-appinspect/bin/activate
pip install --upgrade pip
pip install splunk-appinspect
pip install splunk-packaging-toolkit

mkdir -p dist

tar \
  --exclude="ta-pfsense-plus/.git" \
  --exclude="ta-pfsense-plus/.github" \
  --exclude="ta-pfsense-plus/.gitignore" \
  --exclude="ta-pfsense-plus/.release-please-config.json" \
  --exclude="ta-pfsense-plus/.release-please-manifest.json" \
  --exclude="ta-pfsense-plus/.claude" \
  --exclude="ta-pfsense-plus/.DS_Store" \
  --exclude="ta-pfsense-plus/.venv-appinspect" \
  --exclude="ta-pfsense-plus/dist" \
  --exclude="ta-pfsense-plus/tools" \
  -czf dist/ta-pfsense-plus.tgz -C .. ta-pfsense-plus

splunk-appinspect inspect dist/ta-pfsense-plus.tgz --data-format json \
  --output-file dist/appinspect.json

slim validate dist/ta-pfsense-plus.tgz
```

## Packaging

The GitHub Actions release workflow builds a `.tgz` with the same excludes.
If you create archives locally, keep the same exclude list so AppInspect passes.
