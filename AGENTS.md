# EvalMesh contributor instructions

EvalMesh is an independent, backend-neutral evaluation harness. Do not copy data or
machine-specific configuration from any operator project into this repository.

- Keep the core package dependency-free on Python 3.11+.
- Raw case inputs, expected values, target output, environment values, and absolute
  paths may exist only inside the execution/privacy boundary.
- Reporters accept `PublicRun` only. Never add a raw result overload.
- Use argv arrays with `shell=False`; do not read `.env` files or inherit the complete
  parent environment.
- Add only synthetic fixtures. Use opaque identifiers in examples and tests.
- Opik is an optional reporter, not a domain dependency. An explicit endpoint is
  mandatory and remote endpoints are opt-in.
- Run `python -m unittest discover -s tests -v` and `evalmesh doctor .` before release.
