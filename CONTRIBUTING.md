# Contributing to WebShield

Thanks for helping improve WebShield.

## Development

- Keep behavior covered by `unittest` tests.
- Run `python -m unittest discover -s tests -v`.
- Run `python -m compileall -q src/webshield`.
- Do not add remote activation, arbitrary command execution, arbitrary profile paths or web-triggered privileged actions.

## Pull requests

Explain the security impact, tests, documentation changes and any new assumptions. Claims in documentation must be supported by the implementation.

## Security issues

Do not report vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md).
