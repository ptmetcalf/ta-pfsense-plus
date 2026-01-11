# Changelog

## Unreleased

### Features

* add enrichment macros for dashboard use (`pfsense_enrich_dns`, `pfsense_enrich_ip_tags`)
* normalize interface CIDRs in enrichment lookup generation

### Bug Fixes

* remove port alias enrichment lookup and CSV
* drop legacy lookup_table_files.conf and rely on transforms-based lookups
* remove invalid TIME_DELIMITER settings in props.conf
* align docs with app-local CSV overrides

## [1.2.0](https://github.com/ptmetcalf/ta-pfsense-plus/compare/v1.1.0...v1.2.0) (2026-01-04)


### Features

* update version patterns in release configuration for better matching ([b977912](https://github.com/ptmetcalf/ta-pfsense-plus/commit/b977912929517b5d0d61d6ddaad6128ee5920045))

## [1.1.0](https://github.com/ptmetcalf/ta-pfsense-plus/compare/v1.0.0...v1.1.0) (2026-01-04)


### Features

* enhance time parsing for iplog and dnsbl entries in props.conf ([249a03e](https://github.com/ptmetcalf/ta-pfsense-plus/commit/249a03e62ae3f2020aa8e115d962ebfc08ea03fa))
* streamline environment variable usage in release workflow ([9002748](https://github.com/ptmetcalf/ta-pfsense-plus/commit/90027481f53446b781ee0369c3ec79ddc02c04f3))

## [1.0.3](https://github.com/ptmetcalf/ta-pfsense-plus/compare/v1.0.2...v1.0.3) (2026-01-06)


### Bug Fixes

* enhance README with companion app recommendation for lookup CSVs and clarify enrichment process ([c0573b5](https://github.com/ptmetcalf/ta-pfsense-plus/commit/c0573b5503d2a04306566b4a189ffb5f5fad4a8b))
* sync app.conf version in release ([9d3526d](https://github.com/ptmetcalf/ta-pfsense-plus/commit/9d3526d0e43842a65f021e1da9cff52ffde2301f))
* update file permissions for lookup scripts ([606a411](https://github.com/ptmetcalf/ta-pfsense-plus/commit/606a411628af2448325715a4b8a1f77f14d7e081))
* update README for CSVs and add initial lookup CSV files ([b00c788](https://github.com/ptmetcalf/ta-pfsense-plus/commit/b00c788c7f1a4d306efae9e22ffa2457887abdad))
* update README to clarify enrichment lookup paths and simplify instructions ([cadc85d](https://github.com/ptmetcalf/ta-pfsense-plus/commit/cadc85de445e65281ef64e13ca7aa641c40e2cc7))
* update README to clarify local override for CSVs and remove unused lookup files ([8507c69](https://github.com/ptmetcalf/ta-pfsense-plus/commit/8507c692636ed2b134e8c9d09f61344311278c61))
* update README to clarify system lookups path for upgrade-safe CSV enrichment ([e8f0cb4](https://github.com/ptmetcalf/ta-pfsense-plus/commit/e8f0cb49be6893988158e82ce8235bc38d1033a6))
* update README to recommend system/local lookups for upgrade-safe CSV enrichment ([8a9ae20](https://github.com/ptmetcalf/ta-pfsense-plus/commit/8a9ae207ee93c6a0fe88ab69a59fc8258d1b5793))
* update README to specify local override path for CSV enrichment and add default lookup table configuration ([b5f6a07](https://github.com/ptmetcalf/ta-pfsense-plus/commit/b5f6a07c4fe03dcfbf438f34fa0b79dc0e07111e))

## [1.0.2](https://github.com/ptmetcalf/ta-pfsense-plus/compare/v1.0.1...v1.0.2) (2026-01-04)


### Bug Fixes

* update app.conf version to 1.0.1 and sync with release process ([b104d6d](https://github.com/ptmetcalf/ta-pfsense-plus/commit/b104d6d07387484fe72027323ee19749c2e03960))

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
