PYTHON ?= python
PYTHONPATH ?= src
COVERAGE_FAIL_UNDER ?= 93
MYPY_TARGETS ?= src

.PHONY: test coverage compile lint type-check quality sample demo hcl-sample fixtures external-complex release-check package clean

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) scripts/run_tests.py

coverage:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) scripts/run_coverage.py

compile:
	$(PYTHON) -m compileall -q -x fixture_data src scripts tests

lint:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m ruff check src tests scripts

type-check:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m mypy $(MYPY_TARGETS)

quality: compile test coverage lint type-check release-check package

hcl-sample:
	mkdir -p outputs
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor hcl-audit --path samples/terraform-source --out outputs/hcl-audit-sample.json --markdown-out outputs/hcl-audit-sample.md
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor scan --sbom samples/sboms/audit-api.cdx.json --vuln-in samples/vulnerabilities.json --terraform-source samples/terraform-source --artifact-alias audit-api=gcr.io/acme/audit-api:1.0.0 --terraform-coverage-out outputs/terraform-source-coverage.json --mapping-out outputs/hcl-mapping.json --out outputs/hcl-findings.json --no-table

fixtures:
	mkdir -p outputs/fixtures
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor fixtures validate --json-out outputs/fixtures-validate.json
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor fixtures run --out outputs/fixtures-report.json --output-dir outputs/fixtures

external-complex:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) scripts/run_complex_app_validation.py --no-clone --strict

release-check:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) scripts/validate_release.py

package:
	$(PYTHON) -m build --no-isolation

sample:
	mkdir -p outputs
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor scan \
		--sbom samples/sboms/payments-api.cdx.json \
		--sbom samples/sboms/notifier.cdx.json \
		--sbom samples/sboms/orders-api.cdx.json \
		--sbom samples/sboms/audit-api.cdx.json \
		--sbom samples/sboms/inventory-api.cdx.json \
		--sbom samples/sboms/batch-worker.cdx.json \
		--sbom samples/sboms/reports-api.cdx.json \
		--vuln-in samples/vulnerabilities.json \
		--terraform-plan samples/tfplan-multicloud.json \
		--terraform-coverage-out outputs/terraform-coverage.json \
		--source-root payments-api=samples/source/payments-api \
		--source-root notifier=samples/source/notifier \
		--source-root orders-api=samples/source/orders-api \
		--source-root audit-api=samples/source/audit-api \
		--source-root inventory-api=samples/source/inventory-api \
		--source-root batch-worker=samples/source/batch-worker \
		--source-root reports-api=samples/source/reports-api \
		--out outputs/findings.json \
		--baseline-out outputs/reachability-baseline.json \
		--sarif-out outputs/findings.sarif \
		--diagnostics-out outputs/diagnostics.json \
		--markdown-out outputs/pr-summary.md \
		--html-out outputs/reachability-graph.html \
		--annotations-out outputs/annotations.txt

demo:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m reachability_advisor demo

clean:
	rm -rf .coverage htmlcov build dist *.egg-info outputs/*.json outputs/*.sarif outputs/*.md outputs/*.html outputs/*.txt
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
