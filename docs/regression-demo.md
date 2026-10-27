# Catch a regression before shipping an agent change

This runnable example compares a passing baseline with an intentionally broken
candidate. It uses a synthetic echo task to demonstrate how EvalMesh detects a
contract regression. No model, API key, network request, or Opik instance is used.

## Install from source

Requires Python 3.11+ on a POSIX host (for example, macOS or Linux):

```bash
git clone https://github.com/doublew6/evalmesh.git
cd evalmesh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Installation may access package indexes; the core has no runtime dependencies.

## Baseline: preserve both inputs

The two [cases](../examples/regression/cases.jsonl) contain `hello` and `你好`.
The baseline echoes each message unchanged. Each case runs twice and must pass
both the process-exit grader and exact JSON-output grader.

```bash
evalmesh validate examples/regression/baseline.toml
evalmesh run examples/regression/baseline.toml
```

Expected: four `PASS` lines, exit status `0`, and:

```text
summary: attempts=4 pass_rate=1.000 reporting=ok
```

## Candidate: a successful process can still be wrong

The candidate deliberately strips non-ASCII characters. It exits successfully and
still echoes `hello`, but corrupts `你好`. The fixtures and graders stay unchanged.

```bash
evalmesh validate examples/regression/candidate.toml
evalmesh run examples/regression/candidate.toml
```

Expected: two `PASS` lines for `hello`, two `FAIL` lines for `unicode`, exit status
`1`, and:

```text
summary: attempts=4 pass_rate=0.500 reporting=ok
```

Exit `1` is the intended evaluation failure, not a setup error. Exit `2` means a
configuration or reporting error. A shell or CI job with fail-on-error behavior
will stop on the candidate command; handle that expected status explicitly when
running this demonstration as part of a larger script.

## What this establishes

The CLI can expose a known regression against declared expected values. It does
not automatically understand arbitrary task quality or prove that one model is
better than another. Expected values are withheld from the target; inputs and
target outputs stay within the evaluation boundary. Local JSONL records under
`.evalmesh/` contain projected metadata by default, not the messages themselves.

For a real workflow, replace the synthetic target and cases with an authorized
command or HTTP adapter, choose graders that reflect the task, and retain the
same cases when comparing versions. Start with non-sensitive fixtures.

- [Manifest and grader reference](reference.md)
- [Command, HTTP, and skill integration recipes](integrations.md)
- [Privacy model and execution limitations](privacy.md)

The harness is not a security sandbox. Use an appropriate isolated account,
container, or VM for an untrusted target. Remote reporting requires separate,
explicit configuration.
