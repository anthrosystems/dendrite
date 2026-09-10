//! Core Dendrite daemon orchestration.

mod core;
mod incidents;

pub use core::{DaemonCore, DaemonError, IngestionOutcome};
pub use incidents::{IncidentService, ProposalService};
