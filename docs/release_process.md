# Release Process

Releases are created from Git tags matching `v*`.

## Steps

1. Run the local gates:

   ```bash
   make compile
   make lint
   make type-check
   make test
   make coverage
   make sample
   make demo
   make fixtures
   make release-check
   make package
   ```

2. Review `CHANGELOG.md` and add or update the release entry.
3. Tag the release:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

4. The release workflow builds sdist/wheel artifacts, generates SHA256 checksums, and attaches them to a GitHub release.

The workflow does not publish to PyPI.
