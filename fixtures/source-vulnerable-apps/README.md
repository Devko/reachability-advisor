# Source Reachability Fixtures

These fixtures test package-family source evidence without depending on a network connection.

`coverage-expectations.json` has two sections:

- `samples` points to small checked-in vulnerable sample apps. Tests run the maintained Semgrep-family patterns over these files and require 100% expected-family coverage.
- `pinned_public_cases` records public vulnerable repositories and exact commits used as external scale references. These are not cloned during unit tests. They are pinned so a maintainer can reproduce coverage checks without relying on a moving branch.

The built-in analyzer remains fallback evidence. Production release gates should use generated Semgrep, CodeQL, or govulncheck evidence and require `critical_query_family_coverage` of `1.0`.
