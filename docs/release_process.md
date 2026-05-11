# Release Process

1. Update `CHANGELOG.md`.
2. Confirm `pyproject.toml` version.
3. Run quality gates:

```bash
make compile
make lint
make type-check
make test
make coverage
make sample
make fixtures
make release-check
make package
```

4. Review generated sample and release-validation outputs.
5. Confirm public package metadata:

- `pyproject.toml` and `reachability_advisor.__version__` match.
- classifier is `Development Status :: 5 - Production/Stable`.
- no alpha/beta package status remains.
- source distribution and wheel build as `reachability_advisor-<version>`.
- built wheel installs and `reachability-advisor version` runs.

6. Tag release:

```bash
git tag -s v1.0.0 -m "Reachability Advisor v1.0.0"
git push origin v1.0.0
```

7. Publish release notes with:

- security-relevant changes;
- output format changes;
- new source rules;
- known limitations.
