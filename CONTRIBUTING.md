# Contributing

## Contribution rules

- Use respectful communication and follow the Code of Conduct.
- Keep the scanner local; do not add network calls to the core scan path.
- Treat Terraform plan analysis as a primary feature. New deployment-context behavior needs tests and documentation.
- Do not add automatic suppression from weak evidence.
- Add tests for new behavior.
- Sign off commits using DCO:

```bash
git commit -s
```

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
make test
make coverage
```

## Pull request checklist

- [ ] Tests added or updated.
- [ ] `make compile` passes.
- [ ] `make test` passes.
- [ ] `make coverage` passes.
- [ ] Documentation updated.
- [ ] Security/privacy impact considered.
