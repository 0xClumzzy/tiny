# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :x:                |
| 1.0.x   | :x:                |

Only the latest minor release receives security updates. Please upgrade.

## Reporting a Vulnerability

**Do not file public issues for security vulnerabilities.**

Email: **clumzzysec@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix

We aim to:
- Acknowledge within 48 hours
- Provide initial assessment within 5 business days
- Release fix within 30 days for confirmed vulnerabilities

## Security Considerations

### Input Handling

- `tiny` parses LDIF files; malformed input may cause parsing errors but not code execution
- No deserialization of untrusted data (no pickle, yaml, eval)
- Live enumeration uses `ldapsearch` subprocess; arguments are validated

### Data Sensitivity

- `tiny` processes potentially sensitive AD data (password hashes, descriptions, delegation configs)
- Output files contain this data; secure them appropriately
- Use `--quiet` to suppress terminal output when piping sensitive data

### Network Operations

- Live enumeration (`--dc-ip`) connects to Domain Controllers via `ldapsearch`
- Credentials passed via `--bind-pass` or prompt; not logged
- No built-in encryption; relies on LDAPS/StartTLS via `ldapsearch` flags

### Dependencies

- Zero runtime dependencies (standard library only)
- Dev dependencies pinned in `pyproject.toml`
- Supply chain: built from source, published from CI

## Disclosure Timeline

1. Report received → acknowledgment (48h)
2. Triage → validation (5 business days)
3. Fix development → testing
4. Coordinated disclosure → patch release
5. Public advisory (after users have time to upgrade)

## Hall of Fame

We recognize responsible disclosure. Contributors will be credited in release notes unless they request anonymity.
