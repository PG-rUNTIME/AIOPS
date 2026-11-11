# ADR-0012: Approval-gated remediation with four-eyes and an append-only audit log

- Status: accepted · Date: 2026-11-11

## Decision
- Per (tenant, failure type) policy: `recommend_only` (default — execution impossible) or `one_click`.
- Flow: operator proposes an **allow-listed** playbook → a *different* user with role `approver`
  approves → operator executes. Executing anything not `approved` returns 409 and the denial is
  audit-logged in its own transaction.
- Executors: `DryRunExecutor` (dev), `AnsibleRunnerExecutor` (`ansible_runner.run`).
- Auto-remediation (stage 3 in the architecture doc) is out of scope until a failure type has a
  proven record.
