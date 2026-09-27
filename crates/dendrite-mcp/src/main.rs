//! `dendrite-mcp`: intentional stub for Dendrite's future **inbound** MCP
//! server — exposing Dendrite's own capabilities (triggering package checks,
//! reading current trust/policy state, and so on) to external MCP-connected
//! agents.
//!
//! See `crates/dendrite-mcp/README.md` for why this is a separate crate
//! from `dendrite-magi` (which only ever acts as an MCP *client*) and why
//! it deliberately exposes zero tools today.

use rmcp::ServiceExt;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{Implementation, InitializeResult, ServerCapabilities};
use rmcp::transport::stdio;

/// A handler with every method left at its `ServerHandler` default — which
/// means "understands the MCP handshake, advertises no capabilities, and
/// has no tools, resources or prompts to serve." That's the whole stub:
/// something a client can genuinely connect to and get a real (empty)
/// capability list from, rather than a binary that merely prints a message
/// and exits.
#[derive(Debug, Clone, Copy, Default)]
struct StubServer;

impl ServerHandler for StubServer {
    fn get_info(&self) -> InitializeResult {
        // `Implementation::from_build_env()`'s `env!()` calls resolve at
        // *rmcp's own* compile time, not this crate's — left at its
        // default it reports itself as "rmcp"/rmcp's version, which would
        // be a confusing thing for a connecting client to see. Naming it
        // explicitly from this crate's own Cargo metadata fixes that.
        InitializeResult::new(ServerCapabilities::default())
            .with_server_info(Implementation::new(
                "dendrite-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "dendrite-mcp is a stub: it speaks MCP but exposes no tools yet. See \
                 crates/dendrite-mcp/README.md and docs/ROADMAP.md for the intended scope (an \
                 inbound, additive privileged surface that will go through Dendrite's ordinary \
                 proposal -> MAGI -> policy -> Guard -> transaction pipeline like any other \
                 caller, once the HTTP API auth gap it depends on is closed).",
            )
    }
}

#[tokio::main]
async fn main() {
    eprintln!(
        "dendrite-mcp: stub MCP server starting on stdio (no tools exposed yet — see \
         crates/dendrite-mcp/README.md)"
    );

    let service = match StubServer.serve(stdio()).await {
        Ok(service) => service,
        Err(error) => {
            eprintln!("dendrite-mcp: failed to start serving: {error}");
            std::process::exit(1);
        }
    };

    if let Err(error) = service.waiting().await {
        eprintln!("dendrite-mcp: error while serving: {error}");
        std::process::exit(1);
    }
}
