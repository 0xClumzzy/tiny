# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2024-11-20

### Added
- Live LDAP enumeration via `ldapsearch` (`--dc-ip`, `--domain`, `--bind-dn`, etc.)
- Enumeration flags: `--users`, `--groups`, `--computers`, `--spns`, `--unconstrained`, `--asrep`, `--constrained`, `--rbcd`, `--da`
- Attack playbook export (`--playbook`)
- Environment posture collection (password policy, lockout, LAPS)
- Install script (`install.sh`) with pipx/pip/dev/remote modes
- Professional repository files: LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY
- GitHub Actions CI workflow

### Changed
- Fixed UAC bit parsing: unconstrained delegation (0x80000), AS-REP (0x400000), protocol transition (0x1000000)
- Improved nested group resolution for Domain Admins enumeration
- Enhanced scoring accuracy for delegation and credential signals

### Fixed
- Computer object inference from `sAMAccountName$` when `objectClass` missing
- Domain guessing from DN for non-standard partitions

## [1.1.0] - 2024-10-15

### Added
- Tier-based output files (`-o/--out`)
- JSON report (`--json`)
- Markdown report (`--md`)
- Full attribute export (`--full`)
- Quiet mode (`--quiet`)
- Brief mode (`--brief`)

### Changed
- Refactored scoring engine for maintainability
- Improved terminal report readability

## [1.0.0] - 2024-09-01

### Added
- Initial release
- LDIF parsing and merging
- Crown-jewel pyramid scoring (4 tiers)
- Quick wins detection
- Category-based file splitting
- Nested group membership resolution
- `memberOf` fallback when groups missing
- Domain detection from DN

---

## Release Notes Template

### [Unreleased]

#### Added
- 

#### Changed
- 

#### Deprecated
- 

#### Removed
- 

#### Fixed
- 

#### Security
-