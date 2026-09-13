use crate::{InstanceKeyRecord, SelfStore, SelfStoreError};
use dendrite_protocol::{IntegrityFindingDto, TrustState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const ANTISERUM_FORMAT: &str = "dendrite-antiserum";
pub const ANTISERUM_SCHEMA_VERSION: u64 = 1;
pub const ANTISERUM_DEFAULT_STREAM: &str = "default";
pub const ANTISERUM_ENVELOPE_SIGNATURE_CONTEXT: &str = "antiserum-envelope-v1";
pub const ANTISERUM_MERKLE_ALGORITHM: &str = "sha256-merkle-v1";
pub const ANTISERUM_ATTESTATION_PATH: &str = "attestation.json";
pub const ANTISERUM_MAX_ATTESTATION_AGE_SECONDS: i64 = 30;

const LEAF_DOMAIN: &[u8] = b"DENDRITE-ANTISERUM-LEAF-V1\0";
const NODE_DOMAIN: &[u8] = b"DENDRITE-ANTISERUM-NODE-V1\0";

#[derive(Debug)]
pub enum AntiserumError {
    SelfStore(SelfStoreError),
    Json(serde_json::Error),
    Time(String),
    InvalidBundle(String),
}

impl From<SelfStoreError> for AntiserumError {
    fn from(error: SelfStoreError) -> Self {
        Self::SelfStore(error)
    }
}

impl From<serde_json::Error> for AntiserumError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiserumAttestation {
    pub instance_id: String,
    pub key_id: String,
    pub state: String,
    pub export_safety: String,
    pub observed_at: String,
    pub guard_version: String,
    pub policy_revision: u64,
    pub integrity: AntiserumIntegrity,
    pub active_findings: u64,
}

impl AntiserumAttestation {
    pub fn from_guard(
        instance_id: &str,
        key_id: &str,
        trust_state: TrustState,
        findings: &[IntegrityFindingDto],
        observed_at: u64,
    ) -> Result<Self, AntiserumError> {
        let (state, export_safety) = match trust_state {
            TrustState::Trusted => ("trusted", "normal"),
            TrustState::Degraded | TrustState::Recovering => ("degraded", "restricted"),
            TrustState::Suspected | TrustState::Quarantined | TrustState::Compromised => {
                ("untrusted", "blocked")
            }
        };

        let mut integrity = AntiserumIntegrity {
            protected_objects: "healthy".into(),
            dendrite_binary: "healthy".into(),
            configuration: "healthy".into(),
            host_identity_key: "healthy".into(),
        };
        for finding in findings {
            let status = integrity_status_for_severity(&finding.severity);
            match finding.target.as_str() {
                "protected_objects" => {
                    merge_integrity_status(&mut integrity.protected_objects, status)
                }
                "dendrite_binary" => merge_integrity_status(&mut integrity.dendrite_binary, status),
                "configuration" => merge_integrity_status(&mut integrity.configuration, status),
                "host_identity_key" => {
                    merge_integrity_status(&mut integrity.host_identity_key, status)
                }
                _ => {}
            }
        }

        Ok(Self {
            instance_id: instance_id.into(),
            key_id: key_id.into(),
            state: state.into(),
            export_safety: export_safety.into(),
            observed_at: format_unix_timestamp(observed_at)?,
            guard_version: env!("CARGO_PKG_VERSION").into(),
            // Guard does not yet persist a separately versioned policy document. Zero is the
            // explicit v1 value for "no persisted policy revision" and must not be inferred as
            // authority by an importer.
            policy_revision: 0,
            integrity,
            active_findings: findings.len() as u64,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiserumIntegrity {
    pub protected_objects: String,
    pub dendrite_binary: String,
    pub configuration: String,
    pub host_identity_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiserumEnvelope {
    pub format: String,
    pub schema_version: u64,
    pub antiserum_id: String,
    pub sequence: u64,
    pub issuer: AntiserumIssuer,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub attestation: AntiserumAttestationRef,
    pub payloads: Vec<AntiserumPayloadDeclaration>,
    pub content_root: AntiserumContentRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiserumIssuer {
    pub source_type: String,
    pub instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    pub key_id: String,
    pub public_key: String,
    pub key_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiserumAttestationRef {
    pub path: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiserumPayloadDeclaration {
    pub class: String,
    pub path: String,
    pub status: AntiserumPayloadStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AntiserumPayloadStatus {
    Populated,
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiserumContentRoot {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiserumPayload {
    pub class: String,
    pub path: String,
    pub bytes: Vec<u8>,
}

impl AntiserumPayload {
    pub fn new(class: impl Into<String>, path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            class: class.into(),
            path: path.into(),
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAntiserumPackage {
    pub envelope: AntiserumEnvelope,
    pub envelope_signature: String,
    pub attestation: AntiserumAttestation,
    pub payloads: Vec<AntiserumPayload>,
}

impl SignedAntiserumPackage {
    pub fn logical_files(&self) -> Result<BTreeMap<String, Vec<u8>>, AntiserumError> {
        let mut files = BTreeMap::new();
        files.insert(
            "envelope.json".into(),
            canonical_json_bytes(&self.envelope)?,
        );
        files.insert(
            "envelope.sig".into(),
            format!("{}\n", self.envelope_signature).into_bytes(),
        );
        files.insert(
            ANTISERUM_ATTESTATION_PATH.into(),
            canonical_json_bytes(&self.attestation)?,
        );
        for payload in &self.payloads {
            if files
                .insert(payload.path.clone(), payload.bytes.clone())
                .is_some()
            {
                return Err(AntiserumError::InvalidBundle(format!(
                    "duplicate logical package path {}",
                    payload.path
                )));
            }
        }
        Ok(files)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiserumVerificationKey {
    pub instance_id: String,
    pub key_id: String,
    pub public_key: String,
    pub fingerprint: String,
}

impl From<&InstanceKeyRecord> for AntiserumVerificationKey {
    fn from(key: &InstanceKeyRecord) -> Self {
        Self {
            instance_id: key.instance_id.clone(),
            key_id: key.key_id.clone(),
            public_key: key.public_key.clone(),
            fingerprint: key.fingerprint.clone(),
        }
    }
}

pub fn build_signed_package(
    self_store: &mut SelfStore,
    signing_key: &InstanceKeyRecord,
    attestation: AntiserumAttestation,
    payloads: Vec<AntiserumPayload>,
    created_at: u64,
    expires_at: Option<u64>,
    stream: &str,
) -> Result<SignedAntiserumPackage, AntiserumError> {
    validate_payloads(&payloads)?;
    validate_attestation_shape(&attestation)?;
    if attestation.instance_id != signing_key.instance_id
        || attestation.key_id != signing_key.key_id
    {
        return Err(AntiserumError::InvalidBundle(
            "attestation identity does not match signing key".into(),
        ));
    }

    let attestation_bytes = canonical_json_bytes(&attestation)?;
    let attestation_digest = sha256_label(&attestation_bytes);
    let mut content_files = Vec::with_capacity(payloads.len() + 1);
    content_files.push((ANTISERUM_ATTESTATION_PATH.to_string(), attestation_bytes));
    content_files.extend(
        payloads
            .iter()
            .map(|payload| (payload.path.clone(), payload.bytes.clone())),
    );
    let content_root = merkle_root(&content_files)?;
    let sequence = self_store.next_antiserum_sequence(stream)?;

    let envelope = AntiserumEnvelope {
        format: ANTISERUM_FORMAT.into(),
        schema_version: ANTISERUM_SCHEMA_VERSION,
        antiserum_id: uuid::Uuid::new_v4().to_string(),
        sequence,
        issuer: AntiserumIssuer {
            source_type: "dendrite-instance".into(),
            instance_id: signing_key.instance_id.clone(),
            fqdn: None,
            key_id: signing_key.key_id.clone(),
            public_key: signing_key.public_key.clone(),
            key_fingerprint: signing_key.fingerprint.clone(),
        },
        created_at: format_unix_timestamp(created_at)?,
        expires_at: expires_at.map(format_unix_timestamp).transpose()?,
        attestation: AntiserumAttestationRef {
            path: ANTISERUM_ATTESTATION_PATH.into(),
            digest: attestation_digest,
        },
        payloads: payloads
            .iter()
            .map(|payload| {
                Ok(AntiserumPayloadDeclaration {
                    class: payload.class.clone(),
                    path: payload.path.clone(),
                    status: payload_status(payload)?,
                })
            })
            .collect::<Result<Vec<_>, AntiserumError>>()?,
        content_root: AntiserumContentRoot {
            algorithm: ANTISERUM_MERKLE_ALGORITHM.into(),
            value: content_root,
        },
    };

    validate_attestation_freshness(&envelope, &attestation)?;
    validate_lifetime(&envelope, created_at)?;
    let envelope_bytes = canonical_json_bytes(&envelope)?;
    let envelope_signature = self_store.sign_instance_bound(
        &signing_key.key_id,
        ANTISERUM_ENVELOPE_SIGNATURE_CONTEXT,
        &envelope_bytes,
    )?;

    Ok(SignedAntiserumPackage {
        envelope,
        envelope_signature,
        attestation,
        payloads,
    })
}

pub fn verify_signed_package(
    bundle: &SignedAntiserumPackage,
    exporter_key: &AntiserumVerificationKey,
    now: u64,
) -> Result<(), AntiserumError> {
    validate_envelope_shape(&bundle.envelope)?;
    validate_attestation_shape(&bundle.attestation)?;
    validate_payloads(&bundle.payloads)?;

    let issuer = &bundle.envelope.issuer;
    if issuer.instance_id != exporter_key.instance_id
        || issuer.key_id != exporter_key.key_id
        || issuer.public_key != exporter_key.public_key
        || issuer.key_fingerprint != exporter_key.fingerprint
    {
        return Err(AntiserumError::InvalidBundle(
            "envelope issuer does not match the authenticated immediate exporter key".into(),
        ));
    }
    if bundle.attestation.instance_id != issuer.instance_id
        || bundle.attestation.key_id != issuer.key_id
    {
        return Err(AntiserumError::InvalidBundle(
            "attestation identity does not match envelope issuer".into(),
        ));
    }

    let declarations: Vec<_> = bundle
        .payloads
        .iter()
        .map(|payload| {
            Ok(AntiserumPayloadDeclaration {
                class: payload.class.clone(),
                path: payload.path.clone(),
                status: payload_status(payload)?,
            })
        })
        .collect::<Result<Vec<_>, AntiserumError>>()?;
    if declarations != bundle.envelope.payloads {
        return Err(AntiserumError::InvalidBundle(
            "payload declarations do not exactly match package payloads".into(),
        ));
    }

    let attestation_bytes = canonical_json_bytes(&bundle.attestation)?;
    if bundle.envelope.attestation.path != ANTISERUM_ATTESTATION_PATH
        || bundle.envelope.attestation.digest != sha256_label(&attestation_bytes)
    {
        return Err(AntiserumError::InvalidBundle(
            "attestation digest does not match attestation.json".into(),
        ));
    }

    let mut content_files = Vec::with_capacity(bundle.payloads.len() + 1);
    content_files.push((ANTISERUM_ATTESTATION_PATH.to_string(), attestation_bytes));
    content_files.extend(
        bundle
            .payloads
            .iter()
            .map(|payload| (payload.path.clone(), payload.bytes.clone())),
    );
    let root = merkle_root(&content_files)?;
    if bundle.envelope.content_root.algorithm != ANTISERUM_MERKLE_ALGORITHM
        || bundle.envelope.content_root.value != root
    {
        return Err(AntiserumError::InvalidBundle(
            "content Merkle root does not match package contents".into(),
        ));
    }

    validate_attestation_freshness(&bundle.envelope, &bundle.attestation)?;
    validate_lifetime(&bundle.envelope, now)?;

    let envelope_bytes = canonical_json_bytes(&bundle.envelope)?;
    SelfStore::verify_instance_bound(
        &exporter_key.instance_id,
        &exporter_key.key_id,
        &exporter_key.public_key,
        &exporter_key.fingerprint,
        ANTISERUM_ENVELOPE_SIGNATURE_CONTEXT,
        &envelope_bytes,
        &bundle.envelope_signature,
    )?;
    Ok(())
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, AntiserumError> {
    let value = serde_json::to_value(value)?;
    let mut output = Vec::new();
    write_canonical_json(&value, &mut output)?;
    Ok(output)
}

pub fn merkle_root(files: &[(String, Vec<u8>)]) -> Result<String, AntiserumError> {
    if files.is_empty() {
        return Err(AntiserumError::InvalidBundle(
            "cannot compute Antiserum content root for an empty file set".into(),
        ));
    }
    let mut sorted = files.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    for pair in sorted.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(AntiserumError::InvalidBundle(format!(
                "duplicate content path {}",
                pair[0].0
            )));
        }
    }

    let mut level: Vec<[u8; 32]> = sorted
        .iter()
        .map(|(path, bytes)| {
            let content_digest = Sha256::digest(bytes);
            let mut hasher = Sha256::new();
            hasher.update(LEAF_DOMAIN);
            hasher.update(path.as_bytes());
            hasher.update([0]);
            hasher.update(content_digest);
            hasher.finalize().into()
        })
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            let mut hasher = Sha256::new();
            hasher.update(NODE_DOMAIN);
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().into());
        }
        level = next;
    }

    Ok(format!("sha256:{}", hex::encode(level[0])))
}

const STANDARD_PAYLOADS: [(&str, &str); 9] = [
    (
        "vulnerability",
        "payloads/vulnerabilities/vulnerabilities.json",
    ),
    ("indicator-hash", "payloads/indicators/hashes.json"),
    ("indicator-domain", "payloads/indicators/domains.json"),
    ("indicator-ip", "payloads/indicators/ips.json"),
    ("indicator-url", "payloads/indicators/urls.json"),
    ("behaviour", "payloads/behaviours/behaviours.json"),
    ("graph-fragment", "payloads/graph/graph-fragment.json"),
    ("attack-chain", "payloads/graph/attack-chains.json"),
    ("provenance", "provenance/sources.json"),
];

fn validate_payloads(payloads: &[AntiserumPayload]) -> Result<(), AntiserumError> {
    if payloads.len() != STANDARD_PAYLOADS.len() {
        return Err(AntiserumError::InvalidBundle(format!(
            "Antiserum v1 package must contain exactly {} standard payload files",
            STANDARD_PAYLOADS.len()
        )));
    }

    let mut classes = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for payload in payloads {
        let expected = expected_payload_path(&payload.class).ok_or_else(|| {
            AntiserumError::InvalidBundle(format!(
                "unknown Antiserum payload class {}",
                payload.class
            ))
        })?;
        if payload.path != expected {
            return Err(AntiserumError::InvalidBundle(format!(
                "payload class {} must use canonical path {expected}",
                payload.class
            )));
        }
        if !classes.insert(payload.class.as_str()) {
            return Err(AntiserumError::InvalidBundle(format!(
                "duplicate payload class {}",
                payload.class
            )));
        }
        if !paths.insert(payload.path.as_str()) {
            return Err(AntiserumError::InvalidBundle(format!(
                "duplicate payload path {}",
                payload.path
            )));
        }

        let _ = payload_status(payload)?;
    }

    for (class, path) in STANDARD_PAYLOADS {
        if !classes.contains(class) || !paths.contains(path) {
            return Err(AntiserumError::InvalidBundle(format!(
                "missing mandatory Antiserum v1 payload {class} at {path}"
            )));
        }
    }
    Ok(())
}

fn expected_payload_path(class: &str) -> Option<&'static str> {
    STANDARD_PAYLOADS
        .iter()
        .find_map(|(candidate, path)| (*candidate == class).then_some(*path))
}

fn payload_status(payload: &AntiserumPayload) -> Result<AntiserumPayloadStatus, AntiserumError> {
    let document: Value = serde_json::from_slice(&payload.bytes).map_err(|error| {
        AntiserumError::InvalidBundle(format!(
            "payload {} is not valid JSON: {error}",
            payload.class
        ))
    })?;
    let object = document.as_object().ok_or_else(|| {
        AntiserumError::InvalidBundle(format!("payload {} must be a JSON object", payload.class))
    })?;
    if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(AntiserumError::InvalidBundle(format!(
            "payload {} must declare schema_version 1",
            payload.class
        )));
    }

    let empty = match payload.class.as_str() {
        "vulnerability" => json_array_is_empty(object, "vulnerabilities", &payload.class)?,
        "indicator-hash" | "indicator-domain" | "indicator-ip" | "indicator-url" => {
            json_array_is_empty(object, "indicators", &payload.class)?
        }
        "behaviour" => json_array_is_empty(object, "behaviours", &payload.class)?,
        "graph-fragment" => {
            json_array_is_empty(object, "nodes", &payload.class)?
                && json_array_is_empty(object, "relationships", &payload.class)?
        }
        "attack-chain" => json_array_is_empty(object, "attack_chains", &payload.class)?,
        "provenance" => json_array_is_empty(object, "sources", &payload.class)?,
        _ => {
            return Err(AntiserumError::InvalidBundle(format!(
                "unknown Antiserum payload class {}",
                payload.class
            )));
        }
    };

    Ok(if empty {
        AntiserumPayloadStatus::Empty
    } else {
        AntiserumPayloadStatus::Populated
    })
}

fn json_array_is_empty(
    object: &serde_json::Map<String, Value>,
    field: &str,
    class: &str,
) -> Result<bool, AntiserumError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::is_empty)
        .ok_or_else(|| {
            AntiserumError::InvalidBundle(format!(
                "payload {class} must contain array field {field}"
            ))
        })
}

fn validate_envelope_shape(envelope: &AntiserumEnvelope) -> Result<(), AntiserumError> {
    if envelope.format != ANTISERUM_FORMAT
        || envelope.schema_version != ANTISERUM_SCHEMA_VERSION
        || envelope.sequence == 0
        || envelope.antiserum_id.is_empty()
    {
        return Err(AntiserumError::InvalidBundle(
            "unsupported or malformed Antiserum envelope".into(),
        ));
    }
    if !matches!(
        envelope.issuer.source_type.as_str(),
        "anthrosystems" | "dendrite-instance" | "organisation"
    ) {
        return Err(AntiserumError::InvalidBundle(
            "unsupported Antiserum issuer source_type".into(),
        ));
    }
    if uuid::Uuid::parse_str(&envelope.issuer.instance_id).is_err()
        || envelope.issuer.key_id.is_empty()
        || envelope.issuer.public_key.is_empty()
        || envelope.issuer.key_fingerprint.is_empty()
    {
        return Err(AntiserumError::InvalidBundle(
            "malformed Antiserum issuer identity".into(),
        ));
    }
    if envelope.payloads.len() != STANDARD_PAYLOADS.len() {
        return Err(AntiserumError::InvalidBundle(format!(
            "Antiserum v1 envelope must describe exactly {} payload files",
            STANDARD_PAYLOADS.len()
        )));
    }
    if envelope.attestation.path != ANTISERUM_ATTESTATION_PATH
        || envelope.content_root.algorithm != ANTISERUM_MERKLE_ALGORITHM
    {
        return Err(AntiserumError::InvalidBundle(
            "unsupported Antiserum attestation or content-root declaration".into(),
        ));
    }
    Ok(())
}

fn validate_attestation_shape(attestation: &AntiserumAttestation) -> Result<(), AntiserumError> {
    if uuid::Uuid::parse_str(&attestation.instance_id).is_err() || attestation.key_id.is_empty() {
        return Err(AntiserumError::InvalidBundle(
            "malformed attestation identity".into(),
        ));
    }
    if !matches!(
        attestation.state.as_str(),
        "trusted" | "degraded" | "untrusted" | "unknown"
    ) {
        return Err(AntiserumError::InvalidBundle(
            "unsupported attestation state".into(),
        ));
    }
    if !matches!(
        attestation.export_safety.as_str(),
        "normal" | "restricted" | "blocked"
    ) {
        return Err(AntiserumError::InvalidBundle(
            "unsupported attestation export_safety".into(),
        ));
    }
    for status in [
        attestation.integrity.protected_objects.as_str(),
        attestation.integrity.dendrite_binary.as_str(),
        attestation.integrity.configuration.as_str(),
        attestation.integrity.host_identity_key.as_str(),
    ] {
        if !matches!(status, "healthy" | "degraded" | "failed" | "unknown") {
            return Err(AntiserumError::InvalidBundle(
                "unsupported attestation integrity state".into(),
            ));
        }
    }
    if attestation.guard_version.is_empty() {
        return Err(AntiserumError::InvalidBundle(
            "attestation guard_version must not be empty".into(),
        ));
    }
    parse_timestamp(&attestation.observed_at)?;
    Ok(())
}

fn validate_attestation_freshness(
    envelope: &AntiserumEnvelope,
    attestation: &AntiserumAttestation,
) -> Result<(), AntiserumError> {
    let created = parse_timestamp(&envelope.created_at)?;
    let observed = parse_timestamp(&attestation.observed_at)?;
    let age = created - observed;
    if age.is_negative() || age.whole_seconds() > ANTISERUM_MAX_ATTESTATION_AGE_SECONDS {
        return Err(AntiserumError::InvalidBundle(format!(
            "attestation must be observed no more than {ANTISERUM_MAX_ATTESTATION_AGE_SECONDS} seconds before export"
        )));
    }
    Ok(())
}

fn validate_lifetime(envelope: &AntiserumEnvelope, now: u64) -> Result<(), AntiserumError> {
    let created = parse_timestamp(&envelope.created_at)?;
    let now = OffsetDateTime::from_unix_timestamp(now as i64)
        .map_err(|error| AntiserumError::Time(error.to_string()))?;
    if created > now + time::Duration::seconds(300) {
        return Err(AntiserumError::InvalidBundle(
            "envelope creation time is implausibly far in the future".into(),
        ));
    }
    if let Some(expires_at) = envelope.expires_at.as_deref() {
        let expires = parse_timestamp(expires_at)?;
        if expires < created {
            return Err(AntiserumError::InvalidBundle(
                "envelope expiration precedes creation".into(),
            ));
        }
        if now > expires {
            return Err(AntiserumError::InvalidBundle(
                "Antiserum package has expired".into(),
            ));
        }
    }
    Ok(())
}

fn format_unix_timestamp(timestamp: u64) -> Result<String, AntiserumError> {
    OffsetDateTime::from_unix_timestamp(timestamp as i64)
        .map_err(|error| AntiserumError::Time(error.to_string()))?
        .format(&Rfc3339)
        .map_err(|error| AntiserumError::Time(error.to_string()))
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, AntiserumError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|error| AntiserumError::Time(error.to_string()))
}

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn integrity_status_for_severity(severity: &str) -> &'static str {
    match severity {
        "warning" => "degraded",
        "high" | "critical" => "failed",
        _ => "healthy",
    }
}

fn merge_integrity_status(current: &mut String, candidate: &str) {
    fn rank(value: &str) -> u8 {
        match value {
            "failed" => 3,
            "degraded" => 2,
            "unknown" => 1,
            _ => 0,
        }
    }
    if rank(candidate) > rank(current) {
        *current = candidate.into();
    }
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), AntiserumError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => {
            if *value {
                output.extend_from_slice(b"true");
            } else {
                output.extend_from_slice(b"false");
            }
        }
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(serde_json::to_string(value)?.as_bytes()),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                output.push(b':');
                write_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub fn package_to_danti_bytes(package: &SignedAntiserumPackage) -> Result<Vec<u8>, AntiserumError> {
    let files = package.logical_files()?;
    let mut output = Vec::new();
    for (path, bytes) in files {
        write_tar_entry(&mut output, &path, &bytes)?;
    }
    output.extend_from_slice(&[0u8; 1024]);
    Ok(output)
}

pub fn package_from_danti_bytes(bytes: &[u8]) -> Result<SignedAntiserumPackage, AntiserumError> {
    let files = read_tar_files(bytes)?;
    let required = required_logical_paths();
    if files.len() != required.len() {
        return Err(AntiserumError::InvalidBundle(format!(
            "Antiserum package contains {} logical files; expected {}",
            files.len(),
            required.len()
        )));
    }
    for path in files.keys() {
        if !required.contains(path.as_str()) {
            return Err(AntiserumError::InvalidBundle(format!(
                "unknown Antiserum package path {path}"
            )));
        }
    }
    for path in &required {
        if !files.contains_key(*path) {
            return Err(AntiserumError::InvalidBundle(format!(
                "missing Antiserum package path {path}"
            )));
        }
    }

    let envelope: AntiserumEnvelope = serde_json::from_slice(
        files
            .get("envelope.json")
            .expect("required envelope path checked"),
    )?;
    let attestation: AntiserumAttestation = serde_json::from_slice(
        files
            .get(ANTISERUM_ATTESTATION_PATH)
            .expect("required attestation path checked"),
    )?;
    let envelope_signature = String::from_utf8(
        files
            .get("envelope.sig")
            .expect("required signature path checked")
            .clone(),
    )
    .map_err(|_| AntiserumError::InvalidBundle("envelope.sig is not UTF-8".into()))?
    .trim()
    .to_owned();

    let payloads = STANDARD_PAYLOADS
        .iter()
        .map(|(class, path)| {
            Ok(AntiserumPayload::new(
                *class,
                *path,
                files
                    .get(*path)
                    .expect("required payload path checked")
                    .clone(),
            ))
        })
        .collect::<Result<Vec<_>, AntiserumError>>()?;

    Ok(SignedAntiserumPackage {
        envelope,
        envelope_signature,
        attestation,
        payloads,
    })
}

pub fn verification_key_from_package(package: &SignedAntiserumPackage) -> AntiserumVerificationKey {
    AntiserumVerificationKey {
        instance_id: package.envelope.issuer.instance_id.clone(),
        key_id: package.envelope.issuer.key_id.clone(),
        public_key: package.envelope.issuer.public_key.clone(),
        fingerprint: package.envelope.issuer.key_fingerprint.clone(),
    }
}

fn required_logical_paths() -> BTreeSet<&'static str> {
    let mut paths = BTreeSet::from(["envelope.json", "envelope.sig", ANTISERUM_ATTESTATION_PATH]);
    for (_, path) in STANDARD_PAYLOADS {
        paths.insert(path);
    }
    paths
}

fn write_tar_entry(output: &mut Vec<u8>, path: &str, bytes: &[u8]) -> Result<(), AntiserumError> {
    if path.is_empty()
        || path.len() > 100
        || path.starts_with('/')
        || path.contains("..")
        || path.contains('\\')
    {
        return Err(AntiserumError::InvalidBundle(format!(
            "invalid Antiserum package path {path}"
        )));
    }
    let mut header = [0u8; 512];
    header[..path.len()].copy_from_slice(path.as_bytes());
    write_tar_octal(&mut header[100..108], 0o600)?;
    write_tar_octal(&mut header[108..116], 0)?;
    write_tar_octal(&mut header[116..124], 0)?;
    write_tar_octal(&mut header[124..136], bytes.len() as u64)?;
    write_tar_octal(&mut header[136..148], 0)?;
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    write_tar_checksum(&mut header[148..156], checksum)?;
    output.extend_from_slice(&header);
    output.extend_from_slice(bytes);
    let padding = (512 - (bytes.len() % 512)) % 512;
    output.resize(output.len() + padding, 0);
    Ok(())
}

fn write_tar_octal(field: &mut [u8], value: u64) -> Result<(), AntiserumError> {
    let width = field.len();
    let encoded = format!("{:0width$o}", value, width = width - 1);
    if encoded.len() > width - 1 {
        return Err(AntiserumError::InvalidBundle(
            "Antiserum package field exceeds tar limit".into(),
        ));
    }
    field.fill(0);
    field[..encoded.len()].copy_from_slice(encoded.as_bytes());
    Ok(())
}

fn write_tar_checksum(field: &mut [u8], value: u64) -> Result<(), AntiserumError> {
    if field.len() != 8 {
        return Err(AntiserumError::InvalidBundle(
            "invalid tar checksum field".into(),
        ));
    }
    let encoded = format!("{:06o}", value);
    if encoded.len() != 6 {
        return Err(AntiserumError::InvalidBundle(
            "tar checksum overflow".into(),
        ));
    }
    field[..6].copy_from_slice(encoded.as_bytes());
    field[6] = 0;
    field[7] = b' ';
    Ok(())
}

fn read_tar_files(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, AntiserumError> {
    let mut cursor = Cursor::new(bytes);
    let mut files = BTreeMap::new();
    loop {
        let mut header = [0u8; 512];
        if cursor.read_exact(&mut header).is_err() {
            return Err(AntiserumError::InvalidBundle(
                "truncated Antiserum package".into(),
            ));
        }
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        if &header[257..263] != b"ustar\0" || header[156] != b'0' {
            return Err(AntiserumError::InvalidBundle(
                "unsupported Antiserum package entry".into(),
            ));
        }
        let path_end = header[..100]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(100);
        let path = std::str::from_utf8(&header[..path_end])
            .map_err(|_| AntiserumError::InvalidBundle("package path is not UTF-8".into()))?
            .to_owned();
        if path.is_empty() || path.starts_with('/') || path.contains("..") || path.contains('\\') {
            return Err(AntiserumError::InvalidBundle(format!(
                "invalid Antiserum package path {path}"
            )));
        }
        let stored_checksum = parse_tar_octal(&header[148..156])?;
        let mut checksum_header = header;
        checksum_header[148..156].fill(b' ');
        let actual_checksum: u64 = checksum_header.iter().map(|byte| u64::from(*byte)).sum();
        if stored_checksum != actual_checksum {
            return Err(AntiserumError::InvalidBundle(format!(
                "tar checksum mismatch for {path}"
            )));
        }
        let size = parse_tar_octal(&header[124..136])? as usize;
        if size > 64 * 1024 * 1024 {
            return Err(AntiserumError::InvalidBundle(
                "Antiserum package entry is too large".into(),
            ));
        }
        let mut content = vec![0u8; size];
        cursor.read_exact(&mut content).map_err(|_| {
            AntiserumError::InvalidBundle(format!("truncated package entry {path}"))
        })?;
        let padding = (512 - (size % 512)) % 512;
        if padding > 0 {
            let mut discard = vec![0u8; padding];
            cursor
                .read_exact(&mut discard)
                .map_err(|_| AntiserumError::InvalidBundle("truncated package padding".into()))?;
        }
        if files.insert(path.clone(), content).is_some() {
            return Err(AntiserumError::InvalidBundle(format!(
                "duplicate package path {path}"
            )));
        }
    }
    Ok(files)
}

fn parse_tar_octal(field: &[u8]) -> Result<u64, AntiserumError> {
    let text = std::str::from_utf8(field)
        .map_err(|_| AntiserumError::InvalidBundle("invalid tar numeric field".into()))?
        .trim_matches(|character| character == '\0' || character == ' ');
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8)
        .map_err(|_| AntiserumError::InvalidBundle("invalid tar numeric value".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SelfStore;
    use std::fs;

    fn store(name: &str) -> (SelfStore, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "dendrite-antiserum-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("self.sqlite3");
        let mut store = SelfStore::open(path.to_str().unwrap()).unwrap();
        store.ensure_active_signing_key().unwrap();
        (store, root)
    }

    fn standard_payloads(label: &str) -> Vec<AntiserumPayload> {
        let json = |class: &str, path: &str, value: Value| {
            AntiserumPayload::new(class, path, serde_json::to_vec(&value).unwrap())
        };
        vec![
            json(
                "vulnerability",
                "payloads/vulnerabilities/vulnerabilities.json",
                serde_json::json!({"schema_version": 1, "vulnerabilities": []}),
            ),
            json(
                "indicator-hash",
                "payloads/indicators/hashes.json",
                serde_json::json!({"schema_version": 1, "indicators": []}),
            ),
            json(
                "indicator-domain",
                "payloads/indicators/domains.json",
                serde_json::json!({"schema_version": 1, "indicators": []}),
            ),
            json(
                "indicator-ip",
                "payloads/indicators/ips.json",
                serde_json::json!({"schema_version": 1, "indicators": []}),
            ),
            json(
                "indicator-url",
                "payloads/indicators/urls.json",
                serde_json::json!({"schema_version": 1, "indicators": []}),
            ),
            json(
                "behaviour",
                "payloads/behaviours/behaviours.json",
                serde_json::json!({"schema_version": 1, "behaviours": []}),
            ),
            json(
                "graph-fragment",
                "payloads/graph/graph-fragment.json",
                serde_json::json!({"schema_version": 1, "nodes": [], "relationships": []}),
            ),
            json(
                "attack-chain",
                "payloads/graph/attack-chains.json",
                serde_json::json!({"schema_version": 1, "attack_chains": []}),
            ),
            json(
                "provenance",
                "provenance/sources.json",
                serde_json::json!({
                    "schema_version": 1,
                    "sources": [{"id": format!("src-{label}")}]
                }),
            ),
        ]
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = serde_json::json!({"z": 1, "a": {"y": 2, "b": 3}});
        assert_eq!(
            String::from_utf8(canonical_json_bytes(&value).unwrap()).unwrap(),
            r#"{"a":{"b":3,"y":2},"z":1}"#
        );
    }

    #[test]
    fn signed_package_verifies_and_detects_payload_tampering() {
        let (mut store, root) = store("signed");
        let key = store.active_key().unwrap().unwrap();
        let attestation = AntiserumAttestation::from_guard(
            &key.instance_id,
            &key.key_id,
            TrustState::Trusted,
            &[],
            1_800_000_000,
        )
        .unwrap();
        let package = build_signed_package(
            &mut store,
            &key,
            attestation,
            standard_payloads("a"),
            1_800_000_000,
            None,
            ANTISERUM_DEFAULT_STREAM,
        )
        .unwrap();
        let verifier = AntiserumVerificationKey::from(&key);
        verify_signed_package(&package, &verifier, 1_800_000_100).unwrap();

        let danti = package_to_danti_bytes(&package).unwrap();
        let reparsed = package_from_danti_bytes(&danti).unwrap();
        assert_eq!(reparsed, package);
        verify_signed_package(&reparsed, &verifier, 1_800_000_100).unwrap();

        let mut tampered = package.clone();
        tampered.payloads[0].bytes.push(b'!');
        assert!(verify_signed_package(&tampered, &verifier, 1_800_000_100).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn envelope_marks_empty_and_populated_payloads() {
        let (mut store, root) = store("status");
        let key = store.active_key().unwrap().unwrap();
        let attestation = AntiserumAttestation::from_guard(
            &key.instance_id,
            &key.key_id,
            TrustState::Trusted,
            &[],
            1_800_000_000,
        )
        .unwrap();
        let bundle = build_signed_package(
            &mut store,
            &key,
            attestation,
            standard_payloads("status"),
            1_800_000_000,
            None,
            ANTISERUM_DEFAULT_STREAM,
        )
        .unwrap();

        for declaration in &bundle.envelope.payloads {
            let expected = if declaration.class == "provenance" {
                AntiserumPayloadStatus::Populated
            } else {
                AntiserumPayloadStatus::Empty
            };
            assert_eq!(declaration.status, expected, "{}", declaration.class);
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn signature_is_bound_to_instance_identity() {
        let (store, root) = store("binding");
        let key = store.active_key().unwrap().unwrap();
        let signature = store
            .sign_instance_bound(&key.key_id, "test-context", b"payload")
            .unwrap();
        SelfStore::verify_instance_bound(
            &key.instance_id,
            &key.key_id,
            &key.public_key,
            &key.fingerprint,
            "test-context",
            b"payload",
            &signature,
        )
        .unwrap();
        assert!(
            SelfStore::verify_instance_bound(
                "00000000-0000-0000-0000-000000000000",
                &key.key_id,
                &key.public_key,
                &key.fingerprint,
                "test-context",
                b"payload",
                &signature,
            )
            .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn merkle_root_is_order_independent_but_path_sensitive() {
        let one = vec![("a".into(), b"A".to_vec()), ("b".into(), b"B".to_vec())];
        let two = vec![("b".into(), b"B".to_vec()), ("a".into(), b"A".to_vec())];
        assert_eq!(merkle_root(&one).unwrap(), merkle_root(&two).unwrap());

        let changed = vec![("c".into(), b"A".to_vec()), ("b".into(), b"B".to_vec())];
        assert_ne!(merkle_root(&one).unwrap(), merkle_root(&changed).unwrap());
    }
}
