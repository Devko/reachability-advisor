PYTHON ?= python
PYTHONPATH ?= src
COVERAGE_FAIL_UNDER ?= 93

.PHONY: test coverage compile sample hcl-sample fixtures release-check package clean

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest discover -s tests -v

coverage:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m coverage run --source=src/reachability_advisor -m unittest discover -s tests
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m coverage report -m --fail-under=$(COVERAGE_FAIL_UNDER)

compile:
	$(PYTHON) -m compileall -q src tests

hcl-sample:
	mkdir -p outputs
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor hcl-audit --path samples/terraform-source --out outputs/hcl-audit-sample.json --markdown-out outputs/hcl-audit-sample.md
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor scan --sbom samples/sboms/audit-api.cdx.json --vulns samples/vulnerabilities.json --terraform-source samples/terraform-source --artifact-alias audit-api=gcr.io/acme/audit-api:1.0.0 --terraform-coverage-out outputs/terraform-source-coverage.json --mapping-out outputs/hcl-mapping.json --out outputs/hcl-findings.json --no-table

fixtures:
	mkdir -p outputs/fixtures
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor fixtures validate --json-out outputs/fixtures-validate.json
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor fixtures run --out outputs/fixtures-report.json --output-dir outputs/fixtures

release-check:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) scripts/validate_release.py

package:
	$(PYTHON) -m build

sample:
	mkdir -p outputs
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor scan \
		--sbom samples/sboms/payments-api.cdx.json \
		--sbom samples/sboms/notifier.cdx.json \
		--sbom samples/sboms/orders-api.cdx.json \
		--sbom samples/sboms/audit-api.cdx.json \
		--vulns samples/vulnerabilities.json \
		--terraform-plan samples/tfplan-multicloud.json \
		--terraform-coverage-out outputs/terraform-coverage.json \
		--source-root payments-api=samples/source/payments-api \
		--source-root notifier=samples/source/notifier \
		--source-root orders-api=samples/source/orders-api \
		--source-root audit-api=samples/source/audit-api \
		--out outputs/findings.json \
		--sarif-out outputs/findings.sarif \
		--diagnostics-out outputs/diagnostics.json \
		--markdown-out outputs/pr-summary.md \
		--annotations-out outputs/annotations.txt

clean:
	rm -rf .coverage htmlcov build dist *.egg-info outputs/*.json outputs/*.sarif outputs/*.md outputs/*.txt
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
