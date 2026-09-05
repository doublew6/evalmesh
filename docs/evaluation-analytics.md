# Evaluation analytics and release gates

EvalMesh derives analytics only from immutable `PublicRun` records. Raw target output,
private case content, expected values, paths, and credentials never enter the summary
or comparison layer.

## Sampling metrics

For each case with `k` configured repetitions:

- `pass_at_1` is whether attempt 1 passed.
- `success_at_k` is whether at least one of the `k` attempts passed.
- `stable_pass_at_k` is whether every attempt passed.
- `attempt_pass_rate` is the fraction of all attempts that passed.

Suite values are the corresponding fraction across cases. Latency and allowlisted
target metrics publish count, minimum, maximum, mean, P50, and P95. Percentiles use
the deterministic nearest-rank definition.

Every `Runner.run()` call mints one opaque `batch_id`. A summary rejects mixed batches,
duplicate run IDs, and non-contiguous attempts. The public `variant` identifies the
evaluated model, prompt, tools, knowledge snapshot, or application using opaque slugs.
It does not change `suite_digest`.

The loader now separates the case/grader digest from `variant.execution_id` so
explicit Codex model changes remain comparable. The digest calculation changed;
capture new baselines for this loader version. See the
[fingerprint migration notes](experiments.md#fingerprint-migration).

## Capture a summary

Choose a non-console reporter when stdout must contain only JSON:

```bash
evalmesh run evalmesh.toml --reporter jsonl --summary-format json > candidate.json
```

The JSON contract is `evalmesh.summary.v1`; print its schema with:

```bash
evalmesh schema summary
```

## Compare variants

Both summaries must have the same subject and suite ID:

```bash
evalmesh compare baseline.json candidate.json
evalmesh compare baseline.json candidate.json --format json
```

The JSON comparison contract is `evalmesh.comparison.v1`; its schema is available as
`evalmesh schema comparison`. JSON gate output uses `evalmesh.gate-result.v1` and
`evalmesh schema gate-result`.

A regression means a case was stable across all baseline attempts but is not stable
across all candidate attempts. An improvement is the reverse. Added and removed cases
are reported separately. When the suite digest changed, shared cases are marked
incomparable instead of presenting a dataset change as a model regression or
improvement. Release gates reject suite changes by default.

## Release policy

Policies are strict versioned TOML files:

```toml
schema_version = 1

[gate]
minimum_attempt_pass_rate = 0.95
minimum_pass_at_1 = 0.95
minimum_success_at_k = 0.99
minimum_stable_pass_at_k = 0.90
maximum_critical_failures = 0
maximum_regressions = 0
maximum_removed_cases = 0
maximum_p95_latency_delta = 0.10
allow_suite_change = false

[gate.metric_mean_deltas]
total_cost = 0.05

[[slices]]
kind = "dimension"
name = "task_type"
value = "calculation"
minimum_pass_at_1 = 0.98
minimum_stable_pass_at_k = 0.95
```

Apply the policy in CI:

```bash
evalmesh gate candidate.json --baseline baseline.json --policy gate.toml
```

Exit code `0` means the gate passed, `1` means a policy violation, and `2` means the
summary, policy, comparison, or reporting configuration was invalid. Violation output
uses fixed content-free reason codes.
