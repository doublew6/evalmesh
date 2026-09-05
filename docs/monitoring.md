# Private agent inventory monitoring

EvalMesh can monitor the availability of local agent projects, Skills, Codex
scheduled tasks, services, launchd jobs, and containers without publishing their
machine-specific configuration.

## Boundary and topology

Store each real inventory outside the source checkout, use mode `0600`, and choose
opaque `host_id` and asset `id` values. Do not
put personal names, hostnames, repository names, task prompts, or customer labels in
IDs or tags.

Run the inventory on the machine that owns the assets:

```bash
evalmesh monitor /secure/config/evalmesh/node-a.private.json
```

The command validates the private JSON, creates a mode-`0700` temporary private
snapshot plus a standard v1 suite containing only opaque cases, binds the snapshot
digest to every private case, invokes fixed probes through the normal command
adapter, and deletes both afterward. The worker rejects a snapshot changed after
compilation. `Runner` then applies the existing
`RawExecutionResult -> PrivacyGateway -> PublicRun -> JSONL-first -> remote reporter`
flow. Every asset publishes only a generic kind, `health=0|1`, deterministic scores,
opaque IDs/tags, and configured timing metadata. Keep the inventory filename and
directory names independent from those public IDs; EvalMesh rejects target-operation
values that overlap public identifiers.

For multiple computers, run one local inventory per host and point both commands at
the same private Opik project. EvalMesh intentionally does not execute remote SSH
commands. If Opik is on another private host, use authenticated HTTPS and
`--allow-remote-opik`; non-loopback plaintext HTTP remains rejected.

## Inventory

The top-level object is strict:

```json
{
  "schema_version": 1,
  "host_id": "node-a",
  "assets": [
    {
      "id": "service-a",
      "kind": "http",
      "url": "http://127.0.0.1:8765/healthz",
      "expected_status": 200,
      "tags": ["service"]
    }
  ]
}
```

`evalmesh schema inventory` prints the portable JSON Schema. Runtime validation is
stricter: unknown fields and duplicate IDs fail closed, inventory and bounded probe
files cannot be symlinks or hardlinks, and error messages omit private values.

Supported asset kinds are:

| Kind | Check | Restrictions |
| --- | --- | --- |
| `path` | existence, type, optional modification age | relative to inventory or absolute |
| `git` | valid HEAD, optional exact revision/tracked cleanliness | output and remote discarded |
| `skill` | bounded regular `SKILL.md` with name/description frontmatter | body never emitted |
| `automation` | bounded Codex TOML definition or one SQLite automation status row; optional activity-file age | prompt/schedule/activity content never emitted; activity is not proof of success |
| `http` | GET and exact status | loopback HTTP or HTTPS; no credentials, query, redirects, proxy, or response body |
| `tcp` | connection succeeds | loopback only |
| `launchd` | exact user job is loaded or absent; optional exact last exit code | fixed `launchctl print` argv; bounded output is parsed then discarded |
| `docker` | exact container running state; optional explicit local `host` | fixed `docker inspect` argv; host accepts only an absolute Unix socket or loopback TCP endpoint |

The automation SQLite form queries only the status of one exact ID:

```json
{
  "id": "task-a",
  "kind": "automation",
  "database_path": "/private/path/codex.db",
  "automation_id": "private-id",
  "expected_status": "ACTIVE"
}
```

Never publish a real inventory as an example. The tracked
`examples/inventory/inventory.example.json` is synthetic.

## Reporting and scheduling

Local-only monitoring uses the defaults:

```bash
evalmesh monitor /secure/config/evalmesh/node-a.private.json
```

For a local Opik instance:

```bash
export EVALMESH_OPIK_URL=http://127.0.0.1:5173/api
export EVALMESH_OPIK_PROJECT=evalmesh-agent-monitoring
evalmesh monitor /secure/config/evalmesh/node-a.private.json --reporter console,jsonl,opik
```

To create one Opik project per monitored agent, give every private inventory asset
exactly one public routing tag such as `project:agent-a`, then opt in to tag-based
routing:

```bash
evalmesh monitor /secure/config/evalmesh/node-a.private.json \
  --reporter console,jsonl,opik \
  --opik-project-from-tag project:
```

The suffix after the prefix becomes the Opik project name. It must be a public
identifier slug. Routing fails before any probe runs if an asset has no matching tag,
has more than one, or names an invalid project. Paths, commands, automation content,
and environment values remain inside the private inventory boundary.

Use launchd, another host scheduler, or a Codex scheduled task to invoke that fixed
command. Keep reporter routing and credentials in the scheduler environment rather
than the inventory. An external Fleet heartbeat should also watch the EvalMesh
monitor process, because a stopped monitor cannot report its own failure.
