# Release Process

1. Update `CHANGELOG.md`.
2. Confirm `pyproject.toml` version.
3. Run quality gates:

```bash
make compile
make test
make coverage
make sample
```

4. Review generated sample outputs.
5. Tag release:

```bash
git tag -s v1.0.0 -m "Reachability Advisor v1.0.0"
git push origin v1.0.0
```

6. Publish release notes with:

- security-relevant changes;
- output format changes;
- new source rules;
- known limitations.
