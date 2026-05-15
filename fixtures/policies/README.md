# Provider Policy Fixtures

These fixtures exercise the structured policy evaluator without requiring a cloud account.

`provider-policy-examples.json` contains sanitized examples based on common production policy shapes:

- AWS cross-account role trust with organization and external-id conditions;
- AWS trust principal mismatch;
- AWS scoped identity-policy access, permissions boundary, service control policy, resource-policy explicit deny, and cross-account resource-policy allow;
- Azure Key Vault reader role assignment;
- Azure role assignment principal mismatch;
- Azure deny assignment overriding a role assignment;
- GCP Secret Manager conditional IAM binding and cross-project scoped binding;
- GCP principal access boundary and GKE Workload Identity cases;
- Kubernetes service account RBAC for a named secret;
- Kubernetes service account impersonation as privilege-escalation evidence.

The fixture test asserts principal, action, resource, and condition matching, plus the blocker emitted for explicit deny, implicit deny, scoped access, boundary/SCP/PAB constraints, workload identity, and conditional access.
