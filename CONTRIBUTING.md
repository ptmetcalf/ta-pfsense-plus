# Contributing

Thanks for helping improve TA-pfsense Plus.

## AppInspect

Run AppInspect against the packaged archive, not the repo root.

```bash
tar \
  --exclude="ta-pfsense-plus/.git" \
  --exclude="ta-pfsense-plus/.github" \
  --exclude="ta-pfsense-plus/.gitignore" \
  --exclude="ta-pfsense-plus/.claude" \
  --exclude="ta-pfsense-plus/.DS_Store" \
  --exclude="ta-pfsense-plus/tools" \
  -czf TA-pfsense-plus.tgz -C .. ta-pfsense-plus

splunk-appinspect inspect TA-pfsense-plus.tgz --data-format json \
  --output-file appinspect.json
```

## Packaging

The GitHub Actions release workflow builds a `.tgz` with the same excludes.
If you create archives locally, keep the same exclude list so AppInspect passes.
