# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and follows [Semantic Versioning](https://semver.org/).

## [0.2.1] - 2026-08-04

### Fixed 🐛

- Replace force_reconfigure's one-shot startup guess with a health watchdog
- Address Copilot review on the BIRD health watchdog

## [0.2.0] - 2026-08-04

### Added ✨

- Source router's BGP AS from a RouterConfig CRD, not an env var
- Source roadwarriors' device Obfuscation from a CRD, not 9 env vars

### Changed 🔧

- Extract slipmesh-core into a separate git-dependency repo

### Fixed 🐛

- Use int64, not int32, for genuinely u32 CRD fields
- Scope mesh/roadwarriors' Secret RBAC rule to their own name
- Assert against passing "create" to named_rule_for
- Reject AS 0 in RouterConfig's bgp_as schema

### Release

- V0.2.0

## [0.1.1] - 2026-08-03

### Fixed 🐛

- Log the full error chain, not just its outermost context
- Serialize netlink requests to avoid EBUSY under concurrency
- Address Copilot review feedback on the chain-rendering helpers

### Release

- V0.1.1

## [0.1.0] - 2026-08-03

### Added ✨

- Initial implementation of slipmesh operators

### CI/CD ⚙️

- Add secret and dependency-advisory scanning

### Documentation 📚

- Record the O(n^2) collapse() trade-off as deliberate

### Fixed 🐛

- Address Copilot review findings
- Replace rustsec/audit-check action with a plain cargo audit run
- Pin alpine to 3.24, not 3.21 - bird2 doesn't exist before 3.22

### Miscellaneous 🧹

- Empty repository root
- Upgrade netlink-packet-route to 0.31.0 (#2)

### Release

- V0.1.0
