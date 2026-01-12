# Changelog

## Unreleased

### Features

* migrate enrichment lookups to KV store and add enrichment macros
* add Python lookup generation tooling with CIDR normalization
* update transforms/props to support KV lookups and new collections

### Bug Fixes

* remove legacy lookup table config and CSVs in favor of KV-backed enrichment
* drop invalid TIME_DELIMITER settings in props.conf
* update docs for enrichment lookup storage and overrides

## [1.1.0](https://github.com/ptmetcalf/ta-pfsense-plus/compare/v1.0.1...v1.1.0) (2026-01-12)


### Miscellaneous Chores

* release-as 1.1.0 ([8c54fb2](https://github.com/ptmetcalf/ta-pfsense-plus/commit/8c54fb2a2cf8e4b567bd5c0cf19d990326bd7c9a))

## [1.0.1](https://github.com/ptmetcalf/ta-pfsense-plus/compare/v1.0.0...v1.0.1) (2026-01-04)


### Bug Fixes

* update file permissions for lookup scripts ([606a411](https://github.com/ptmetcalf/ta-pfsense-plus/commit/606a411628af2448325715a4b8a1f77f14d7e081))
* update README for CSVs and add initial lookup CSV files ([b00c788](https://github.com/ptmetcalf/ta-pfsense-plus/commit/b00c788c7f1a4d306efae9e22ffa2457887abdad))

## [1.0.0](https://github.com/ptmetcalf/ta-pfsense-plus/compare/v1.0.0...v1.0.0) (2026-01-04)


### Features

* initial release ([9b04e19](https://github.com/ptmetcalf/ta-pfsense-plus/commit/9b04e1988256b72a1ef62202b86b546db4e7884d))
* update app configuration to include check_for_updates setting ([f5fb543](https://github.com/ptmetcalf/ta-pfsense-plus/commit/f5fb5432aa9e4f38e13d65a3ad4fb91959440ba0))
* update release asset upload method to use GitHub CLI ([5b0f2ea](https://github.com/ptmetcalf/ta-pfsense-plus/commit/5b0f2ea659ff10dbb01d4e62f2b44365ce81d76f))
* update release workflow to trigger on workflow_run and remove tag push event ([317d80f](https://github.com/ptmetcalf/ta-pfsense-plus/commit/317d80fd8498dc1f732d775333825e0e419d37f9))
