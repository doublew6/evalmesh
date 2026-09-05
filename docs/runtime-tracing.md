# Private runtime tracing

EvalMesh can send real Agent execution traces to a private Opik deployment while
keeping prompts and outputs out of the source repository. Runtime tracing is a
separate data plane from health monitoring and evaluation score reporting:

```text
Agent hook -> runtime envelope -> bounded redaction -> private JSONL -> Opik trace/spans
```

The Agent process supplies content at runtime through the Python API or the CLI's
standard input. Never place a real prompt, response, tool result, credential, or
machine path in a tracked config, fixture, test, command argument, or environment
variable.

## Private policy

Create one mode-`0600` JSON policy per Agent outside every Git worktree. The output
path must also be absolute and outside every Git worktree.

```json
{
  "schema_version": 1,
  "endpoint": "http://127.0.0.1:5173/api",
  "workspace": "default",
  "project_name": "agent-a",
  "output_path": "/secure/runtime/agent-a.execution.jsonl",
  "capture_prompt": true,
  "capture_output": true,
  "capture_tool_io": true,
  "redact_values": []
}
```

Loopback Opik is the default trust boundary. A non-loopback endpoint requires both
authenticated TLS and `"allow_remote": true`. A credential, when required, belongs
only in this private policy. The loader rejects symlinks, hardlinks, group/world
permissions, unknown fields, and policies inside Git worktrees.

Prompt and final response content are visible in Opik as the root Trace `Input` and
`Output`. Tool and model details appear as child spans. Keys associated with secrets,
environment values, homes, working directories, or paths are always removed;
configured secret values and absolute host paths are redacted recursively. All
content is bounded before persistence or delivery.

## Framework-neutral Python hook

Use one root context around the Agent run. Shared model and tool dispatchers can use
context-local helpers, so every call is attached to the correct run without threading
the tracer object through application code. The context is safe for sibling asyncio
tasks:

```python
from evalmesh import RuntimeTracer, llm_span, tool_span

with RuntimeTracer(policy_path, name="agent.run", prompt=runtime_prompt) as trace:
    with tool_span("lookup", input=runtime_tool_input) as span:
        result = call_tool(runtime_tool_input)
        span.set_output(result)
    with llm_span(
        "compose",
        input=runtime_model_input,
        model="model-a",
        provider="provider-a",
    ) as span:
        answer, usage = call_model(runtime_model_input)
        span.set_output(answer)
        span.set_usage(usage)
    trace.set_output(runtime_answer)
```

`tool_span()` and `llm_span()` deliberately fail when there is no active
`RuntimeTracer`. This makes a missing task-entry hook visible during integration tests
instead of silently dropping tool activity. `span.set_usage()` attaches numeric usage
and cost fields. Usage accepts non-negative integer `input_tokens`,
`cached_input_tokens`, `output_tokens`, `reasoning_output_tokens`, and `total_tokens`
values up to one billion; other fields fail closed. Use only opaque `model`,
`provider`, metadata, and tag identifiers.

For every Agent project, instrument exactly two boundaries:

1. The real task entry creates one `RuntimeTracer`, supplies the runtime prompt, and
   calls `trace.set_output()` with the final response.
2. The shared tool/model dispatcher wraps every invocation in `tool_span()` or
   `llm_span()`, records the returned value, and lets exceptions close the span with
   `metadata.status = "error"`.

A production smoke run is observable only when its Opik root Trace has non-empty
`Input` and `Output`, at least one LLM span for a model-backed Agent, and tool spans
whenever tools were invoked. Health-monitoring traces do not satisfy this contract.

## Language-neutral ingestion

Existing applications can instead serialize one
`evalmesh.runtime-trace.v1` envelope and pipe it to:

```text
evalmesh trace ingest /secure/runtime/agent-a.private.json
```

The envelope is read only from stdin. The command prints only storage/reporting
status, never content or a private path. Parent spans must precede their children.
Each span is one of `general`, `tool`, `llm`, or `guardrail`.

Frameworks with native OpenTelemetry or an Opik integration should use their native
hooks to produce the same hierarchy. Codex supports opt-in OTLP export without code
changes. Keep prompt capture enabled only when its exporter is routed to the same
approved private Opik boundary; do not put a prompt in Codex configuration.

## Shared OTLP gateway

Native OpenTelemetry producers can share one loopback-only JSON gateway. Give it a
separate mode-`0600` config outside Git:

```json
{
  "schema_version": 1,
  "listen_host": "127.0.0.1",
  "listen_port": 14318,
  "endpoint": "http://127.0.0.1:5173/api",
  "workspace": "default",
  "projects": ["agent-a", "agent-b"],
  "output_directory": "/secure/runtime/otel",
  "redact_values": []
}
```

Start it under the host service manager with:

```text
evalmesh trace gateway /secure/runtime/gateway.private.json
```

Each producer posts OTLP/HTTP JSON to `/v1/traces/PROJECT`. Codex may additionally
send its JSON log exporter to `/v1/logs/PROJECT`; that route keeps only unredacted
`codex.user_prompt` records and converts them to GenAI input spans because Opik does
not accept the OTLP logs signal. The project must be in the private allowlist. The
gateway preserves approved prompt attributes, recursively removes
secret/environment/path attributes and configured values, syncs one private JSONL
record, then forwards to Opik with the selected project header. It rejects protobuf,
non-loopback binding, unknown routes, oversized payloads, and an occupied port.

## Delivery guarantees

The projected record is transactionally appended and synced to its private JSONL
store before the isolated Opik SDK worker starts. If local persistence fails, Opik is
not called. Each SDK delivery uses an explicit endpoint/project, a fresh private
runtime directory, no ambient proxy or Opik configuration, disabled SDK telemetry,
redirect refusal, and explicit flush/drop checks.

This layer cannot infer tool calls hidden inside an opaque executable. A black-box
launcher can observe process duration and final output only. Tool-level visibility
requires native telemetry, a framework callback, or one hook at the Agent's shared
tool dispatcher.

## Startup-only Python instrumentation

Python Agents using LangChain/LangGraph or the OpenAI/Anthropic SDKs can share one
private startup hook instead of adding decorators throughout application code. Install
the matching OpenInference instrumentor packages in the Agent's own virtual environment,
then place a private `sitecustomize.py` outside every repository:

```python
from evalmesh.auto_instrumentation import install_from_environment

install_from_environment()
```

The service manager supplies only `EVALMESH_AUTO_INSTRUMENT=1`, an opaque
`EVALMESH_OTEL_PROJECT`, a loopback `EVALMESH_OTEL_ENDPOINT`, and the private bootstrap
directory on `PYTHONPATH`. The bootstrap creates a standard OpenTelemetry provider,
enables each installed OpenInference instrumentor, and exports OTLP/HTTP JSON through
the shared local-first gateway. Prompt, response, and tool values originate inside the
running Agent and are never configuration values. If instrumentation is missing or
fails, the Agent continues without telemetry.

This startup hook is intentionally optional: EvalMesh's core installation remains
dependency-free. Install instrumentors into the same environment as the Agent so their
versions are resolved against that Agent's framework packages, and validate one real
request before enabling the next service.
