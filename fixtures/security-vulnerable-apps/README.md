# Security Evidence Fixtures

These fixtures test SAST/DAST profile coverage without running a scanner or calling a live target.

`coverage-expectations.json` points to small vulnerable sample apps and normalized scanner evidence. Unit tests require each maintained security profile to cover the expected CWE examples. `public_reference_cases` records larger public targets that maintainers can pin in a separate validation run.
