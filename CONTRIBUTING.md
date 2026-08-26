# Contributing

1. Use synthetic cases and opaque IDs. Never commit real prompts, traces, paths,
   endpoints, or credentials.
2. Preserve the `RawExecutionResult -> PrivacyGateway -> PublicRun -> Reporter` data
   flow. Reporters must never accept raw execution objects.
3. Add tests for every manifest field, adapter, grader, and redaction rule.
4. Run:

   ```bash
   python -m unittest discover -s tests -v
   python -m evalmesh doctor .
   ```

5. Explain changes to the public schema and privacy behavior in the pull request.

Release builds must preserve `setup.cfg`: its `sdist` ownership settings prevent the
builder's account name and UID from entering tar headers. Inspect both archive member
metadata and extracted contents before upload. Never publish directly from a private
working tree containing ignored files.
