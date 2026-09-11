//! Core Dendrite daemon orchestration.

mod actions;
mod core;
mod guard;
mod http;
mod incidents;
mod runtime;
mod telemetry;

pub use actions::{ActionService, ActionStoreError};
pub use core::{DaemonCore, DaemonError, IngestionOutcome};
pub use guard::{GuardService, GuardStoreError};
pub use incidents::{IncidentService, IncidentStoreError};
pub use runtime::{DaemonRuntime, RuntimeConfig, RuntimeError};
pub use telemetry::TelemetryManager;
