# dendrite-mcp

An intentional stub for Dendrite's future **inbound** MCP server: exposing some of Dendrite's own capabilities (triggering a package/vulnerability check, reading current trust/policy state, and eventually proposing actions) to external MCP-connected agents.

## Why this is a separate crate from `dendrite-magi`

`dendrite-magi` also speaks MCP, but only as a **client** — connecting *out* to an external agent to serve as one MAGI seat's full vote replacement (see `crates/dendrite-magi/README.md`). That's a narrow, outbound dependency: the agent it talks to only ever produces a vote inside the existing quorum, and if that connection is misconfigured or malicious, the fail-closed abstain behaviour already bounds the damage to "this seat's vote doesn't count."

This crate is the opposite shape: an **inbound**, additive privileged surface. Any tool this server ever exposes is a new way for something outside Dendrite to act on it — which is a fundamentally different risk than "the AI I chose to hook up to my Host seat gives bad votes." Per the confirmed design (see `docs/ROADMAP.md`'s MCP scope note), an eventual `dendrite-mcp` tool call must go through Dendrite's ordinary proposal → MAGI → policy → Guard → transaction pipeline like any other caller, never bypass it by living inside `dendrite-magi` or `dendrited` itself. Keeping the two MCP roles in separate crates keeps that asymmetry visible in the code, not just in a doc comment.

## Why this is a stub, not a real implementation yet

An inbound MCP server is additive attack surface on top of the existing HTTP API, whose own auth story is still an open gap (see `docs/ROADMAP.md`). Building out real tools here before that gap closes would mean shipping a second, parallel way to reach Dendrite's privileged pipeline with even less auth in front of it than the API already has. So today this binary does the minimum that's still genuinely real (not a placeholder that merely prints a message and exits): it completes the actual MCP initialize handshake over stdio and reports zero tools, zero resources, zero prompts.

```bash
$ echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke-test","version":"0.0.0"}}}' | cargo run -p dendrite-mcp
```

returns a real `InitializeResult` naming `dendrite-mcp` with an `instructions` field pointing back at this README — connectable today, useful tomorrow.

## What comes next

Once the HTTP API auth gap is closed, this crate is where the first real tools would go — each one a thin wrapper that submits an ordinary action proposal into the same pipeline everything else uses, not a new privileged code path. No systemd unit or `.deb` packaging exists for this crate yet, on purpose: it doesn't need to run continuously, or at all, until there's a tool worth exposing.

## Testing

```bash
cargo check -p dendrite-mcp --all-targets
cargo clippy -p dendrite-mcp --all-targets -- -D warnings
```
