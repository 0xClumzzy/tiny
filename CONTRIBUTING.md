# Contributing to tiny-ldap

Thank you for your interest in contributing! This document outlines the process for contributing to tiny-ldap.

## Code of Conduct

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check existing [issues](https://github.com/USER/tiny-ldap/issues) first
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, tiny version)
   - Sample LDIF (sanitized) if relevant

### Suggesting Features

1. Check existing issues and discussions
2. Open a feature request with:
   - Clear use case
   - Proposed solution
   - Any relevant AD/LDAP context

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make changes with:
   - Clear, focused commits
   - Tests for new functionality
   - Updated documentation
4. Run quality checks locally (see below)
5. Submit PR with description linking to issue

## Development Setup

```bash
# Clone and install in development mode
git clone https://github.com/USER/tiny-ldap.git
cd tiny-ldap
./install.sh --dev

# Install pre-commit hooks
pre-commit install
```

## Quality Checks

Run before committing:

```bash
# Format and lint
ruff check --fix .
ruff format .

# Type check
mypy src/tiny

# Run tests
pytest -v

# Full pre-commit run
pre-commit run --all-files
```

## Testing

```bash
# All tests
pytest -v

# With coverage
pytest --cov=src/tiny --cov-report=term-missing

# Specific test file
pytest tests/test_score.py -v
```

## Code Style

- **Formatter**: Ruff (100 char line length, double quotes)
- **Linter**: Ruff with pycodestyle, pyflakes, isort, pyupgrade, bugbear
- **Types**: mypy strict mode
- **Commits**: Conventional Commits format (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`)

## Adding Scoring Rules

Scoring logic lives in `src/tiny/score.py`. When adding rules:

1. Add score constant with clear name
2. Document the AD attribute and rationale in docstring
3. Add test case in `tests/test_score.py`
4. Update CHANGELOG.md

## Documentation

- Update README.md for user-facing changes
- Update docstrings for API changes
- Add examples for new flags/features

## Release Process

Maintainers only:

1. Update version in `pyproject.toml` and `src/tiny/__init__.py`
2. Update CHANGELOG.md
3. Create git tag: `git tag v1.2.0`
4. Push tag: `git push origin v1.2.0`
5. GitHub Actions builds and publishes to PyPI

## Security

For security issues, see [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.

## Questions?

Open a [Discussion](https://github.com/USER/tiny-ldap/discussions) or email the maintainers.