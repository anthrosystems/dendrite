use dendrite_protocol::{
    ActionProposal, GuardDecision, GuardRequest, GuardResponse, GuardStatusDto,
    IntegrityFindingDto, TrustState,
};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug)]
pub enum GuardStoreError {
    /// The socket couldn't be reached at all (not running, wrong path,
    /// timed out). Carries the raw I/O error text for logs.
    Unreachable(String),
    /// `dendrite-guard` answered, but with an error or a response shape
    /// that didn't match the request.
    Protocol(String),
}

impl std::fmt::Display for GuardStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(error) => write!(formatter, "dendrite-guard is unreachable: {error}"),
            Self::Protocol(message) => {
                write!(formatter, "dendrite-guard protocol error: {message}")
            }
        }
    }
}

/// Talks to the separate `dendrite-guard` process over a Unix socket. This
/// is a real OS-process boundary, not an in-process call, for the same
/// reason MAGI became one (see `crates/dendrite-guard/README.md` and
/// `docs/architecture.md`'s process-separation notes): Guard's whole job is
/// deciding whether `dendrited` still has authority to act, so that
/// decision needs to live somewhere a compromise of `dendrited` itself
/// can't reach directly.
pub trait GuardEvaluator: Send {
    fn trust_state(&self) -> TrustState;
    fn evaluate_authority(&self, proposal: &ActionProposal) -> GuardDecision;
    fn status(&self) -> Result<GuardStatusDto, GuardStoreError>;
    fn findings(&self) -> Result<Vec<IntegrityFindingDto>, GuardStoreError>;
    #[cfg(debug_assertions)]
    fn debug_set_state(&self, state: &str) -> Result<(), GuardStoreError>;
    #[cfg(debug_assertions)]
    fn debug_record_finding(
        &self,
        target: &str,
        severity: &str,
        description: &str,
    ) -> Result<(), GuardStoreError>;
}

/// Default `dendrite-guard` socket path for local dev — packaged installs
/// override this via `DENDRITE_GUARD_SOCKET`
/// (`/run/dendrite/dendrite-guard.sock`, set in `packaging/dendrited.service`).
pub const DEFAULT_GUARD_SOCKET_PATH: &str = "/tmp/dendrite-guard.sock";

/// Short — like the MAGI call, this sits on the request-handling path, and
/// an unreachable `dendrite-guard` must not hang the whole daemon waiting
/// for it.
const GUARD_CALL_TIMEOUT: Duration = Duration::from_secs(2);

pub struct GuardIpcClient {
    socket_path: PathBuf,
}

impl GuardIpcClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    fn call(&self, request: &GuardRequest) -> Result<GuardResponse, String> {
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|error| format!("{error}"))?;
        stream
            .set_read_timeout(Some(GUARD_CALL_TIMEOUT))
            .map_err(|error| format!("{error}"))?;
        stream
            .set_write_timeout(Some(GUARD_CALL_TIMEOUT))
            .map_err(|error| format!("{error}"))?;

        let mut line = serde_json::to_string(request).map_err(|error| format!("{error}"))?;
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .map_err(|error| format!("{error}"))?;

        let mut response_line = String::new();
        BufReader::new(stream)
            .read_line(&mut response_line)
            .map_err(|error| format!("{error}"))?;
        serde_json::from_str(response_line.trim()).map_err(|error| format!("{error}"))
    }
}

impl GuardEvaluator for GuardIpcClient {
    /// Fails closed to `Compromised` — the strongest trust state Guard has
    /// — rather than `Trusted` or hanging: an unreachable `dendrite-guard`
    /// must never read as "everything's fine". This intentionally differs
    /// from MAGI's abstain-on-unreachable choice: MAGI is a three-way vote
    /// where silence from one seat shouldn't drown out the other two, but
    /// Guard has exactly one voice on trust, so there's no quorum for
    /// "unreachable" to defer to — collapsing straight to the same denial a
    /// real detected compromise produces is the only fail-closed answer
    /// available. See `docs/architecture.md`'s Guard process-separation note.
    fn trust_state(&self) -> TrustState {
        match self.call(&GuardRequest::TrustState) {
            Ok(GuardResponse::TrustState { trust_state }) => trust_state,
            Ok(GuardResponse::Error { message }) => {
                eprintln!(
                    "dendrite-guard returned an error for trust_state ({message}); treating trust state as compromised"
                );
                TrustState::Compromised
            }
            Ok(_) => {
                eprintln!(
                    "dendrite-guard sent an unexpected response to trust_state; treating trust state as compromised"
                );
                TrustState::Compromised
            }
            Err(error) => {
                eprintln!(
                    "dendrite-guard is unreachable ({error}); treating trust state as compromised"
                );
                TrustState::Compromised
            }
        }
    }

    fn evaluate_authority(&self, proposal: &ActionProposal) -> GuardDecision {
        match self.call(&GuardRequest::EvaluateAuthority {
            proposal: proposal.clone(),
        }) {
            Ok(GuardResponse::Authority { decision }) => decision,
            Ok(GuardResponse::Error { message }) => {
                eprintln!(
                    "dendrite-guard returned an error for evaluate_authority ({message}); denying"
                );
                GuardDecision::Deny
            }
            Ok(_) => {
                eprintln!(
                    "dendrite-guard sent an unexpected response to evaluate_authority; denying"
                );
                GuardDecision::Deny
            }
            Err(error) => {
                eprintln!("dendrite-guard is unreachable ({error}); denying");
                GuardDecision::Deny
            }
        }
    }

    /// Unlike `trust_state`/`evaluate_authority`, this stays fallible rather
    /// than fabricating a status: it's read by `antiserum_attestation` (see
    /// `core.rs`), which signs and can export what it's given, so a made-up
    /// "unreachable"-flavoured status could end up misrepresenting host
    /// integrity in a signed package. Better to fail the request than sign
    /// a guess.
    fn status(&self) -> Result<GuardStatusDto, GuardStoreError> {
        match self.call(&GuardRequest::Status) {
            Ok(GuardResponse::Info { guard_status }) => Ok(guard_status),
            Ok(GuardResponse::Error { message }) => Err(GuardStoreError::Protocol(message)),
            Ok(_) => Err(GuardStoreError::Protocol(
                "unexpected response to status".into(),
            )),
            Err(error) => Err(GuardStoreError::Unreachable(error)),
        }
    }

    /// Same reasoning as `status`: this feeds signed Antiserum attestations,
    /// so an unreachable `dendrite-guard` must fail the request rather than
    /// return a fabricated empty/placeholder findings list.
    fn findings(&self) -> Result<Vec<IntegrityFindingDto>, GuardStoreError> {
        match self.call(&GuardRequest::Findings) {
            Ok(GuardResponse::Findings { findings }) => Ok(findings),
            Ok(GuardResponse::Error { message }) => Err(GuardStoreError::Protocol(message)),
            Ok(_) => Err(GuardStoreError::Protocol(
                "unexpected response to findings".into(),
            )),
            Err(error) => Err(GuardStoreError::Unreachable(error)),
        }
    }

    #[cfg(debug_assertions)]
    fn debug_set_state(&self, state: &str) -> Result<(), GuardStoreError> {
        match self.call(&GuardRequest::DebugSetState {
            state: state.to_owned(),
        }) {
            Ok(GuardResponse::Ack) => Ok(()),
            Ok(GuardResponse::Error { message }) => Err(GuardStoreError::Protocol(message)),
            Ok(_) => Err(GuardStoreError::Protocol(
                "unexpected response to debug_set_state".into(),
            )),
            Err(error) => Err(GuardStoreError::Unreachable(error)),
        }
    }

    #[cfg(debug_assertions)]
    fn debug_record_finding(
        &self,
        target: &str,
        severity: &str,
        description: &str,
    ) -> Result<(), GuardStoreError> {
        match self.call(&GuardRequest::DebugRecordFinding {
            target: target.to_owned(),
            severity: severity.to_owned(),
            description: description.to_owned(),
        }) {
            Ok(GuardResponse::Ack) => Ok(()),
            Ok(GuardResponse::Error { message }) => Err(GuardStoreError::Protocol(message)),
            Ok(_) => Err(GuardStoreError::Protocol(
                "unexpected response to debug_record_finding".into(),
            )),
            Err(error) => Err(GuardStoreError::Unreachable(error)),
        }
    }
}

pub struct GuardService {
    guard: Box<dyn GuardEvaluator>,
}

impl GuardService {
    pub fn new() -> Self {
        Self {
            guard: Box::new(GuardIpcClient::new(PathBuf::from(
                DEFAULT_GUARD_SOCKET_PATH,
            ))),
        }
    }

    /// Overrides the default `dendrite-guard` socket path (see
    /// `DEFAULT_GUARD_SOCKET_PATH`) — used by `DaemonRuntime::open` to wire
    /// in the configured `DENDRITE_GUARD_SOCKET` path, and by tests to
    /// inject a fake evaluator instead of talking to a real socket.
    pub fn set_guard_evaluator(&mut self, guard: Box<dyn GuardEvaluator>) {
        self.guard = guard;
    }

    pub fn trust_state(&self) -> TrustState {
        self.guard.trust_state()
    }

    pub fn evaluate_authority(&self, proposal: &ActionProposal) -> GuardDecision {
        self.guard.evaluate_authority(proposal)
    }

    pub fn status(&self) -> Result<GuardStatusDto, GuardStoreError> {
        self.guard.status()
    }

    pub fn findings(&self) -> Result<Vec<IntegrityFindingDto>, GuardStoreError> {
        self.guard.findings()
    }

    /// `now` is accepted for call-site compatibility (the CLI's `debug
    /// guard-state` path threads a real timestamp all the way down) but
    /// unused here: the timestamp `dendrite-guard` records is now its own
    /// wall clock at request-handling time, since the write itself happens
    /// server-side over the socket rather than against a local connection.
    #[cfg(debug_assertions)]
    pub fn debug_set_state(&mut self, state: &str, _now: u64) -> Result<(), GuardStoreError> {
        self.guard.debug_set_state(state)
    }

    /// See `debug_set_state` on why `now` is unused.
    #[cfg(debug_assertions)]
    pub fn debug_record_finding(
        &mut self,
        target: &str,
        severity: &str,
        description: &str,
        _now: u64,
    ) -> Result<(), GuardStoreError> {
        self.guard
            .debug_record_finding(target, severity, description)
    }
}

impl Default for GuardService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dendrite_protocol::{ActionProposalId, ActionType, IncidentId, ObjectId};
    use std::sync::Mutex;

    fn proposal() -> ActionProposal {
        ActionProposal {
            id: ActionProposalId("act_test".into()),
            incident_id: IncidentId("inc_test".into()),
            action: ActionType::Observe,
            target: ObjectId("target".into()),
        }
    }

    /// A fake `GuardEvaluator` that never talks to a real socket — used so
    /// `GuardService`'s own tests (and `dendrited`'s, via
    /// `set_guard_evaluator`) don't need `dendrite-guard` running. Mirrors
    /// `actions.rs`'s `TestRuleMagiEvaluator`.
    struct FixedGuardEvaluator {
        trust_state: Mutex<TrustState>,
    }

    impl FixedGuardEvaluator {
        fn new(trust_state: TrustState) -> Self {
            Self {
                trust_state: Mutex::new(trust_state),
            }
        }
    }

    impl GuardEvaluator for FixedGuardEvaluator {
        fn trust_state(&self) -> TrustState {
            *self.trust_state.lock().unwrap()
        }

        fn evaluate_authority(&self, _proposal: &ActionProposal) -> GuardDecision {
            match *self.trust_state.lock().unwrap() {
                TrustState::Trusted => GuardDecision::Allow,
                _ => GuardDecision::Deny,
            }
        }

        fn status(&self) -> Result<GuardStatusDto, GuardStoreError> {
            Ok(GuardStatusDto {
                trust_state: self.trust_state().as_str().into(),
                authority: "available".into(),
                findings_count: 0,
            })
        }

        fn findings(&self) -> Result<Vec<IntegrityFindingDto>, GuardStoreError> {
            Ok(Vec::new())
        }

        #[cfg(debug_assertions)]
        fn debug_set_state(&self, state: &str) -> Result<(), GuardStoreError> {
            use std::str::FromStr;
            let state = TrustState::from_str(state)
                .map_err(|_| GuardStoreError::Protocol(format!("invalid trust state: {state}")))?;
            *self.trust_state.lock().unwrap() = state;
            Ok(())
        }

        #[cfg(debug_assertions)]
        fn debug_record_finding(
            &self,
            _target: &str,
            _severity: &str,
            _description: &str,
        ) -> Result<(), GuardStoreError> {
            Ok(())
        }
    }

    #[test]
    fn trusted_guard_allows_authority() {
        let mut service = GuardService::new();
        service.set_guard_evaluator(Box::new(FixedGuardEvaluator::new(TrustState::Trusted)));
        assert_eq!(
            service.evaluate_authority(&proposal()),
            GuardDecision::Allow
        );
    }

    #[test]
    fn compromised_guard_removes_authority() {
        let mut service = GuardService::new();
        service.set_guard_evaluator(Box::new(FixedGuardEvaluator::new(TrustState::Compromised)));
        assert_eq!(service.evaluate_authority(&proposal()), GuardDecision::Deny);
        assert_eq!(service.trust_state(), TrustState::Compromised);
    }

    #[test]
    fn guard_ipc_client_denies_and_reports_compromised_when_dendrite_guard_is_unreachable() {
        let client = GuardIpcClient::new(PathBuf::from(
            "/tmp/dendrite-guard-test-definitely-not-listening.sock",
        ));
        assert_eq!(client.evaluate_authority(&proposal()), GuardDecision::Deny);
        assert_eq!(client.trust_state(), TrustState::Compromised);
    }
}
