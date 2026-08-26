# Security policy

Do not open a public issue containing a credential, diary entry, prompt, trace,
machine path, hostname, or private endpoint. Report a suspected vulnerability through
the repository's private security-advisory channel.

EvalMesh does not claim to sandbox evaluated code. Its security boundary is data
minimization before persistence or reporting. Operators remain responsible for OS
isolation, network policy, credential scope, Opik access control, retention, and
backups.

If a secret reaches Git history or a remote reporter, rotate it immediately. Removing
the current file or trace does not remove clones, caches, queues, or backups.
