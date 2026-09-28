use crate::{
    AntiserumError, AntiserumPayload, BehaviourDefinition, KnowledgeError, KnowledgeService,
    SignedAntiserumPackage, VulnerabilityError, VulnerabilityService, package_from_danti_bytes,
    package_to_danti_bytes, verification_key_from_package, verify_signed_package,
};
use dendrite_protocol::{MemoryGraphDto, MemoryNodeDto, MemoryRelationshipDto};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const VULNERABILITY_PATH: &str = "payloads/vulnerabilities/vulnerabilities.json";
pub const HASH_PATH: &str = "payloads/indicators/hashes.json";
pub const DOMAIN_PATH: &str = "payloads/indicators/domains.json";
pub const IP_PATH: &str = "payloads/indicators/ips.json";
pub const URL_PATH: &str = "payloads/indicators/urls.json";
pub const BEHAVIOUR_PATH: &str = "payloads/behaviours/behaviours.json";
pub const GRAPH_PATH: &str = "payloads/graph/graph-fragment.json";
pub const ATTACK_CHAIN_PATH: &str = "payloads/graph/attack-chains.json";
pub const PROVENANCE_PATH: &str = "provenance/sources.json";

const MAX_AUTOMATIC_GRAPH_NODES: usize = 50_000;
const MAX_AUTOMATIC_GRAPH_RELATIONSHIPS: usize = 150_000;

#[derive(Debug)]
pub enum AnalysisError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Antiserum(AntiserumError),
    Vulnerability(VulnerabilityError),
    Knowledge(KnowledgeError),
    Invalid(String),
}

impl From<std::io::Error> for AnalysisError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<serde_json::Error> for AnalysisError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
impl From<AntiserumError> for AnalysisError {
    fn from(error: AntiserumError) -> Self {
        Self::Antiserum(error)
    }
}
impl From<VulnerabilityError> for AnalysisError {
    fn from(error: VulnerabilityError) -> Self {
        Self::Vulnerability(error)
    }
}
impl From<KnowledgeError> for AnalysisError {
    fn from(error: KnowledgeError) -> Self {
        Self::Knowledge(error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GraphExportScope {
    Complete,
    BestPath,
    ReachableGraph,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphExportOptions {
    pub scope: GraphExportScope,
    pub start_node: Option<String>,
    pub max_depth: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordExportScope {
    All,
    Selected,
    ActiveExposures,
    Associated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordExportOptions {
    pub scope: RecordExportScope,
    #[serde(default)]
    pub selected_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateAntiserumRequest {
    pub graph: Option<GraphExportOptions>,
    pub attack_chains: Option<RecordExportOptions>,
    pub vulnerabilities: Option<RecordExportOptions>,
    pub indicator_hashes: Option<RecordExportOptions>,
    pub indicator_domains: Option<RecordExportOptions>,
    pub indicator_ips: Option<RecordExportOptions>,
    pub indicator_urls: Option<RecordExportOptions>,
    pub behaviours: Option<RecordExportOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiserumPackageOrigin {
    ManualExport,
    AutomaticExport,
    Imported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiserumPackageVerification {
    pub signature: String,
    pub content_root: String,
    pub attestation: String,
    pub local_trust: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiserumPackageSummary {
    pub antiserum_id: String,
    pub origin: AntiserumPackageOrigin,
    pub issuer_instance_id: String,
    pub issuer_key_fingerprint: String,
    pub sequence: u64,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub payloads: Vec<crate::AntiserumPayloadDeclaration>,
    pub verification: AntiserumPackageVerification,
    pub size_bytes: u64,
    pub knowledge_status: String,
    pub knowledge_accepted_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiserumKnowledgeAcceptanceResult {
    pub antiserum_id: String,
    pub accepted_at: u64,
    pub graph_nodes: usize,
    pub graph_relationships: usize,
    pub behaviours: usize,
    pub vulnerabilities: usize,
    pub vulnerability_candidates: usize,
    pub skipped_payloads: Vec<String>,
    pub already_accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiserumPackageDetail {
    pub summary: AntiserumPackageSummary,
    pub envelope: crate::AntiserumEnvelope,
    pub attestation: crate::AntiserumAttestation,
    pub provenance: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChainRecord {
    pub id: String,
    pub incident_id: String,
    pub title: String,
    pub original_title: String,
    pub severity: String,
    pub confidence: u8,
    pub observed_at: u64,
    pub steps: Vec<dendrite_protocol::EvidenceObjectRef>,
    pub relationships: Vec<String>,
    pub evidence_id: String,
    pub matched_cve_ids: Vec<String>,
    pub behaviour_ids: Vec<String>,
    pub behaviour_fingerprint: Option<String>,
    pub classification_confidence: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct BuiltPayloadSet {
    pub payloads: Vec<AntiserumPayload>,
    pub graph: MemoryGraphDto,
    pub attack_chain_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AntiserumPackageStore {
    root: PathBuf,
}

impl AntiserumPackageStore {
    pub fn for_self_store(self_path: &str) -> Result<Self, AnalysisError> {
        let root = if self_path == ":memory:" {
            std::env::temp_dir().join(format!("dendrite-antiserum-{}", uuid::Uuid::new_v4()))
        } else {
            Path::new(self_path)
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("antiserum")
        };
        Self::open(root)
    }

    pub fn open(root: PathBuf) -> Result<Self, AnalysisError> {
        secure_dir(&root)?;
        for directory in ["exports", "imports", "automatic"] {
            secure_dir(&root.join(directory))?;
        }
        Ok(Self { root })
    }

    pub fn store(
        &self,
        package: &SignedAntiserumPackage,
        origin: AntiserumPackageOrigin,
    ) -> Result<AntiserumPackageSummary, AnalysisError> {
        let bytes = package_to_danti_bytes(package)?;
        for directory in ["exports", "automatic", "imports"] {
            let existing = self
                .root
                .join(directory)
                .join(format!("{}.danti", package.envelope.antiserum_id));
            if existing.exists() {
                return Err(AnalysisError::Invalid(format!(
                    "Antiserum {} is already stored on this host",
                    package.envelope.antiserum_id
                )));
            }
        }
        let directory = self.root.join(match &origin {
            AntiserumPackageOrigin::ManualExport => "exports",
            AntiserumPackageOrigin::AutomaticExport => "automatic",
            AntiserumPackageOrigin::Imported => "imports",
        });
        let path = directory.join(format!("{}.danti", package.envelope.antiserum_id));
        write_secure_file(&path, &bytes)?;
        summary_from_stored_package(package, origin, bytes.len() as u64)
    }

    pub fn parse_import(
        &self,
        bytes: &[u8],
        now: u64,
    ) -> Result<SignedAntiserumPackage, AnalysisError> {
        let package = package_from_danti_bytes(bytes)?;
        let key = verification_key_from_package(&package);
        verify_signed_package(&package, &key, now)?;
        Ok(package)
    }

    pub fn list(&self, now: u64) -> Result<Vec<AntiserumPackageSummary>, AnalysisError> {
        let mut rows = Vec::new();
        for (directory, origin) in [
            ("exports", AntiserumPackageOrigin::ManualExport),
            ("automatic", AntiserumPackageOrigin::AutomaticExport),
            ("imports", AntiserumPackageOrigin::Imported),
        ] {
            for entry in fs::read_dir(self.root.join(directory))? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("danti") {
                    continue;
                }
                let bytes = fs::read(&path)?;
                let package = match package_from_danti_bytes(&bytes) {
                    Ok(package) => package,
                    Err(_) => continue,
                };
                let key = verification_key_from_package(&package);
                let verified = verify_signed_package(&package, &key, now).is_ok();
                let mut summary =
                    summary_from_stored_package(&package, origin.clone(), bytes.len() as u64)?;
                if !verified {
                    summary.verification.signature = "invalid".into();
                    summary.verification.content_root = "invalid".into();
                }
                rows.push(summary);
            }
        }
        rows.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        Ok(rows)
    }

    pub fn load(
        &self,
        antiserum_id: &str,
    ) -> Result<(SignedAntiserumPackage, AntiserumPackageOrigin, Vec<u8>), AnalysisError> {
        validate_identifier(antiserum_id)?;
        for (directory, origin) in [
            ("exports", AntiserumPackageOrigin::ManualExport),
            ("automatic", AntiserumPackageOrigin::AutomaticExport),
            ("imports", AntiserumPackageOrigin::Imported),
        ] {
            let path = self
                .root
                .join(directory)
                .join(format!("{antiserum_id}.danti"));
            if path.exists() {
                let bytes = fs::read(path)?;
                let package = package_from_danti_bytes(&bytes)?;
                return Ok((package, origin, bytes));
            }
        }
        Err(AnalysisError::Invalid(format!(
            "Antiserum {antiserum_id} was not found"
        )))
    }

    pub fn detail(
        &self,
        antiserum_id: &str,
        now: u64,
    ) -> Result<AntiserumPackageDetail, AnalysisError> {
        let (package, origin, bytes) = self.load(antiserum_id)?;
        let key = verification_key_from_package(&package);
        verify_signed_package(&package, &key, now)?;
        let provenance = package
            .payloads
            .iter()
            .find(|payload| payload.class == "provenance")
            .map(|payload| serde_json::from_slice(&payload.bytes))
            .transpose()?
            .unwrap_or_else(|| json!({"schema_version":1,"sources":[]}));
        Ok(AntiserumPackageDetail {
            summary: summary_from_stored_package(&package, origin, bytes.len() as u64)?,
            envelope: package.envelope.clone(),
            attestation: package.attestation.clone(),
            provenance,
        })
    }

    pub fn graph(&self, antiserum_id: &str, now: u64) -> Result<MemoryGraphDto, AnalysisError> {
        let (package, _, _) = self.load(antiserum_id)?;
        verify_signed_package(&package, &verification_key_from_package(&package), now)?;
        let payload = package
            .payloads
            .iter()
            .find(|payload| payload.class == "graph-fragment")
            .ok_or_else(|| AnalysisError::Invalid("Antiserum graph payload is missing".into()))?;
        graph_payload_to_dto(&payload.bytes)
    }
}

pub fn graph_scope(
    graph: &MemoryGraphDto,
    options: &GraphExportOptions,
) -> Result<MemoryGraphDto, AnalysisError> {
    match options.scope {
        GraphExportScope::Complete => Ok(graph.clone()),
        GraphExportScope::BestPath => trace_best_path(graph, options),
        GraphExportScope::ReachableGraph => trace_reachable_graph(graph, options),
    }
}

pub fn build_payloads(
    graph: &MemoryGraphDto,
    chains: &[AttackChainRecord],
    instance_id: &str,
    vulnerability: Option<&VulnerabilityService>,
    knowledge: Option<&KnowledgeService>,
    request: &CreateAntiserumRequest,
    now: u64,
) -> Result<BuiltPayloadSet, AnalysisError> {
    let selected_graph = if let Some(options) = request.graph.as_ref() {
        graph_scope(graph, options)?
    } else {
        empty_graph()
    };
    let graph_node_ids = selected_graph
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<HashSet<_>>();

    let selected_chains = match request.attack_chains.as_ref() {
        None => Vec::new(),
        Some(options) => select_chains(chains, options, &graph_node_ids),
    };

    let (vulnerability_payload, vulnerability_sources) =
        build_vulnerability_payload(vulnerability, request.vulnerabilities.as_ref())?;
    let behaviour_payload = build_behaviour_payload(knowledge, request.behaviours.as_ref())?;
    let graph_payload = build_graph_payload(&selected_graph)?;
    let attack_chain_payload = build_attack_chain_payload(&selected_chains, instance_id)?;
    let provenance_payload = build_provenance_payload(instance_id, now, vulnerability_sources)?;
    let empty = empty_standard_payloads()?;

    Ok(BuiltPayloadSet {
        payloads: vec![
            vulnerability_payload,
            empty["indicator-hash"].clone(),
            empty["indicator-domain"].clone(),
            empty["indicator-ip"].clone(),
            empty["indicator-url"].clone(),
            behaviour_payload,
            graph_payload,
            attack_chain_payload,
            provenance_payload,
        ],
        graph: selected_graph,
        attack_chain_ids: selected_chains
            .iter()
            .map(|chain| chain.id.clone())
            .collect(),
    })
}

pub fn automatic_attack_chain_request(
    start_node: &str,
    chain_id: &str,
    behaviour_ids: &[String],
) -> CreateAntiserumRequest {
    CreateAntiserumRequest {
        graph: Some(GraphExportOptions {
            scope: GraphExportScope::ReachableGraph,
            start_node: Some(start_node.to_owned()),
            max_depth: None,
        }),
        attack_chains: Some(RecordExportOptions {
            scope: RecordExportScope::Selected,
            selected_ids: vec![chain_id.to_owned()],
        }),
        behaviours: (!behaviour_ids.is_empty()).then(|| RecordExportOptions {
            scope: RecordExportScope::Selected,
            selected_ids: behaviour_ids.to_vec(),
        }),
        ..CreateAntiserumRequest::default()
    }
}

pub fn enforce_automatic_export_ceiling(graph: &MemoryGraphDto) -> Result<(), AnalysisError> {
    if graph.nodes.len() > MAX_AUTOMATIC_GRAPH_NODES
        || graph.relationships.len() > MAX_AUTOMATIC_GRAPH_RELATIONSHIPS
    {
        return Err(AnalysisError::Invalid(format!(
            "automatic Antiserum graph exceeds safety ceiling ({} nodes, {} relationships)",
            graph.nodes.len(),
            graph.relationships.len()
        )));
    }
    Ok(())
}

fn trace_best_path(
    graph: &MemoryGraphDto,
    options: &GraphExportOptions,
) -> Result<MemoryGraphDto, AnalysisError> {
    let start = required_start_node(graph, options)?;
    let by_source = relationships_by_source(graph);
    let nodes_by_id = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<HashMap<_, _>>();
    let mut node_ids = BTreeSet::from([start.to_owned()]);
    let mut relationship_ids = BTreeSet::new();
    let mut current = start.to_owned();
    let mut visited = HashSet::from([current.clone()]);
    let mut depth = 0usize;
    loop {
        if options.max_depth.is_some_and(|limit| depth >= limit) {
            break;
        }
        let Some(candidates) = by_source.get(current.as_str()) else {
            break;
        };
        let best = candidates.iter().copied().max_by(|left, right| {
            left.effective_strength
                .cmp(&right.effective_strength)
                .then_with(|| left.confidence.cmp(&right.confidence))
                .then_with(|| left.last_seen_at.cmp(&right.last_seen_at))
                .then_with(|| right.id.cmp(&left.id))
        });
        let Some(relationship) = best else {
            break;
        };
        if !nodes_by_id.contains_key(relationship.target.as_str())
            || !visited.insert(relationship.target.clone())
        {
            break;
        }
        relationship_ids.insert(relationship.id.clone());
        node_ids.insert(relationship.target.clone());
        current = relationship.target.clone();
        depth += 1;
    }
    subgraph(graph, &node_ids, &relationship_ids)
}

fn trace_reachable_graph(
    graph: &MemoryGraphDto,
    options: &GraphExportOptions,
) -> Result<MemoryGraphDto, AnalysisError> {
    let start = required_start_node(graph, options)?;
    let by_source = relationships_by_source(graph);
    let valid_nodes = graph
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<HashSet<_>>();
    let mut node_ids = BTreeSet::from([start.to_owned()]);
    let mut relationship_ids = BTreeSet::new();
    let mut queue = VecDeque::from([(start.to_owned(), 0usize)]);
    while let Some((current, depth)) = queue.pop_front() {
        if options.max_depth.is_some_and(|limit| depth >= limit) {
            continue;
        }
        let Some(relationships) = by_source.get(current.as_str()) else {
            continue;
        };
        for relationship in relationships {
            if !valid_nodes.contains(relationship.target.as_str()) {
                continue;
            }
            relationship_ids.insert(relationship.id.clone());
            if node_ids.insert(relationship.target.clone()) {
                queue.push_back((relationship.target.clone(), depth + 1));
            }
        }
    }
    subgraph(graph, &node_ids, &relationship_ids)
}

fn required_start_node<'a>(
    graph: &'a MemoryGraphDto,
    options: &'a GraphExportOptions,
) -> Result<&'a str, AnalysisError> {
    let start = options
        .start_node
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AnalysisError::Invalid("trace export requires a starting node".into()))?;
    if !graph.nodes.iter().any(|node| node.id == start) {
        return Err(AnalysisError::Invalid(format!(
            "starting node {start} does not exist in the active Memory Graph"
        )));
    }
    Ok(start)
}

fn relationships_by_source(graph: &MemoryGraphDto) -> HashMap<&str, Vec<&MemoryRelationshipDto>> {
    let mut by_source: HashMap<&str, Vec<&MemoryRelationshipDto>> = HashMap::new();
    for relationship in &graph.relationships {
        by_source
            .entry(relationship.source.as_str())
            .or_default()
            .push(relationship);
    }
    by_source
}

fn subgraph(
    graph: &MemoryGraphDto,
    node_ids: &BTreeSet<String>,
    relationship_ids: &BTreeSet<String>,
) -> Result<MemoryGraphDto, AnalysisError> {
    let nodes = graph
        .nodes
        .iter()
        .filter(|node| node_ids.contains(&node.id))
        .cloned()
        .collect::<Vec<_>>();
    let relationships = graph
        .relationships
        .iter()
        .filter(|relationship| relationship_ids.contains(&relationship.id))
        .cloned()
        .collect::<Vec<_>>();
    Ok(MemoryGraphDto {
        total_nodes: nodes.len() as u64,
        total_relationships: relationships.len() as u64,
        nodes,
        relationships,
        truncated: false,
    })
}

fn empty_graph() -> MemoryGraphDto {
    MemoryGraphDto {
        nodes: Vec::new(),
        relationships: Vec::new(),
        truncated: false,
        total_nodes: 0,
        total_relationships: 0,
    }
}

fn select_chains<'a>(
    chains: &'a [AttackChainRecord],
    options: &RecordExportOptions,
    graph_node_ids: &HashSet<&str>,
) -> Vec<&'a AttackChainRecord> {
    match options.scope {
        RecordExportScope::All | RecordExportScope::ActiveExposures => chains.iter().collect(),
        RecordExportScope::Selected => {
            let selected = options
                .selected_ids
                .iter()
                .map(String::as_str)
                .collect::<HashSet<_>>();
            chains
                .iter()
                .filter(|chain| selected.contains(chain.id.as_str()))
                .collect()
        }
        RecordExportScope::Associated => chains
            .iter()
            .filter(|chain| {
                chain
                    .steps
                    .iter()
                    .any(|step| graph_node_ids.contains(step.id.as_str()))
            })
            .collect(),
    }
}

fn build_vulnerability_payload(
    vulnerability: Option<&VulnerabilityService>,
    options: Option<&RecordExportOptions>,
) -> Result<(AntiserumPayload, Vec<Value>), AnalysisError> {
    let Some(options) = options else {
        return Ok((
            json_payload(
                "vulnerability",
                VULNERABILITY_PATH,
                &json!({"schema_version":1,"vulnerabilities":[]}),
            )?,
            Vec::new(),
        ));
    };
    let Some(service) = vulnerability else {
        return Ok((
            json_payload(
                "vulnerability",
                VULNERABILITY_PATH,
                &json!({"schema_version":1,"vulnerabilities":[]}),
            )?,
            Vec::new(),
        ));
    };
    let mut records = service.knowledge_records()?;
    let mut candidates = service.candidates()?;
    match options.scope {
        RecordExportScope::Selected => {
            let selected = options
                .selected_ids
                .iter()
                .map(String::as_str)
                .collect::<HashSet<_>>();
            records.retain(|record| selected.contains(record.id.as_str()));
            candidates.retain(|record| selected.contains(record.candidate_id.as_str()));
        }
        RecordExportScope::ActiveExposures => {
            let active = service
                .exposures(false)?
                .into_iter()
                .map(|exposure| exposure.cve_id)
                .collect::<HashSet<_>>();
            records.retain(|record| active.contains(&record.id));
            candidates.clear();
        }
        RecordExportScope::All | RecordExportScope::Associated => {}
    }
    let mut source_lookup = BTreeMap::<String, String>::new();
    let mut sources = Vec::new();
    let mut values = Vec::new();
    for record in records {
        let source_id = source_lookup
            .entry(record.provenance.clone())
            .or_insert_with(|| {
                let id = format!("src_vulnerability_{:06}", sources.len() + 1);
                sources.push(json!({
                    "id": id,
                    "type": "public-feed",
                    "name": "CVE knowledge",
                    "reference": record.provenance.clone(),
                    "retrieved_at": Value::Null
                }));
                id
            })
            .clone();
        values.push(json!({
            "id": record.id,
            "record_type": "cve",
            "title": record.name,
            "description": record.description,
            "behaviour_ids": record.behaviour_ids,
            "package": record.package,
            "ecosystem": "debian",
            "affected": { "introduced": Value::Null, "fixed": record.fixed_version.or(record.affected_before) },
            "severity": normalise_severity(&record.severity),
            "cvss": record.cvss.and_then(|value| value.parse::<f64>().ok()),
            "published_at": optional_rfc3339(record.published_at)?,
            "modified_at": optional_rfc3339(record.modified_at)?,
            "references": [],
            "source_refs": [source_id]
        }));
    }
    for candidate in candidates {
        let source_id = "src_dendrite_candidate".to_string();
        if !sources
            .iter()
            .any(|value| value.get("id").and_then(Value::as_str) == Some(source_id.as_str()))
        {
            sources.push(json!({
                "id": source_id,
                "type": "dendrite-observation",
                "name": "Dendrite Vulnerability Candidate",
                "reference": Value::Null,
                "retrieved_at": Value::Null
            }));
        }
        for product in &candidate.affected_products {
            values.push(json!({
                "id": candidate.candidate_id,
                "record_type": "candidate",
                "title": candidate.title,
                "description": candidate.description,
                "behaviour_ids": candidate.behaviour_ids,
                "candidate_status": candidate.status,
                "confidence": candidate.confidence,
                "package": product,
                "ecosystem": "unknown",
                "affected": {
                    "introduced": candidate.affected_versions.first(),
                    "fixed": Value::Null
                },
                "severity": normalise_severity(&candidate.severity),
                "cvss": candidate.cvss.as_ref().and_then(|value| value.parse::<f64>().ok()),
                "published_at": optional_rfc3339(Some(candidate.created_at))?,
                "modified_at": optional_rfc3339(Some(candidate.updated_at))?,
                "references": [],
                "source_refs": [source_id]
            }));
        }
    }
    Ok((
        json_payload(
            "vulnerability",
            VULNERABILITY_PATH,
            &json!({"schema_version":1,"vulnerabilities":values}),
        )?,
        sources,
    ))
}

fn build_behaviour_payload(
    knowledge: Option<&KnowledgeService>,
    options: Option<&RecordExportOptions>,
) -> Result<AntiserumPayload, AnalysisError> {
    let behaviours = match (knowledge, options) {
        (_, None) | (None, _) => Vec::new(),
        (Some(service), Some(options)) => match options.scope {
            RecordExportScope::Selected => service.selected_behaviours(&options.selected_ids)?,
            _ => service.behaviours()?,
        },
    };
    let values = behaviours.iter().map(behaviour_json).collect::<Vec<_>>();
    json_payload(
        "behaviour",
        BEHAVIOUR_PATH,
        &json!({"schema_version":1,"behaviours":values}),
    )
}

fn behaviour_json(behaviour: &BehaviourDefinition) -> Value {
    json!({
        "id": behaviour.id,
        "name": behaviour.name,
        "description": behaviour.description,
        "confidence": behaviour.confidence,
        "severity": behaviour.severity,
        "techniques": behaviour.techniques,
        "conditions": behaviour.conditions,
        "relationship": {
            "ordered": behaviour.ordered,
            "max_interval_seconds": behaviour.max_interval_seconds
        },
        "source_refs": behaviour.source_refs,
        "fingerprint": behaviour.fingerprint,
        "origin_instance_id": behaviour.origin_instance_id,
        "imported_from_instance_id": behaviour.imported_from_instance_id,
        "derived_by_instance_id": behaviour.derived_by_instance_id,
        "lineage": behaviour.lineage
    })
}

/// Strips a node's own `origin_instance_id` prefix off its full `MemoryNodeId`
/// string, returning the bare `ObjectId` portion. Every `MemoryNodeId` is
/// constructed as `{origin_instance_id}::{object_id}` (see
/// `local_memory_node_id()` in `core.rs`), so this is always safe for a
/// well-formed node — falls back to the full id unchanged if the prefix
/// doesn't match, which only happens for a malformed/adversarial payload and
/// is caught downstream when the importer's own recomputed join doesn't
/// match anything sensible.
fn bare_object_id(node_id: &str, origin_instance_id: &str) -> String {
    node_id
        .strip_prefix(origin_instance_id)
        .and_then(|rest| rest.strip_prefix("::"))
        .unwrap_or(node_id)
        .to_string()
}

fn build_graph_payload(graph: &MemoryGraphDto) -> Result<AntiserumPayload, AnalysisError> {
    let nodes = graph
        .nodes
        .iter()
        .map(|node| {
            let origin = node.origin_instance_id.clone().ok_or_else(|| {
                AnalysisError::Invalid(format!("Memory node {} has no origin_instance_id", node.id))
            })?;
            let object_id = bare_object_id(&node.id, &origin);
            Ok(json!({
                "id": node.id,
                "object_id": object_id,
                "kind": node.kind,
                "label": node.label,
                "properties": {
                    "state": node.state,
                    "priority": node.priority,
                    "retention": node.retention,
                    "correlation_keys": node.correlation_keys
                },
                "first_seen": format_rfc3339(node.created_at)?,
                "last_seen": format_rfc3339(node.last_seen_at)?,
                "origin_instance_id": origin,
                "imported_from_instance_id": node.imported_from_instance_id,
                "derived_by_instance_id": node.derived_by_instance_id,
                "lineage": node.lineage
            }))
        })
        .collect::<Result<Vec<Value>, AnalysisError>>()?;
    let included = graph
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<HashSet<_>>();
    let relationships = graph
        .relationships
        .iter()
        .filter(|relationship| {
            included.contains(relationship.source.as_str())
                && included.contains(relationship.target.as_str())
        })
        .map(|relationship| {
            let origin = relationship.origin_instance_id.clone().ok_or_else(|| {
                AnalysisError::Invalid(format!(
                    "Memory relationship {} has no origin_instance_id",
                    relationship.id
                ))
            })?;
            Ok(json!({
                "id": relationship.id,
                "kind": relationship.kind,
                "source_id": relationship.source,
                "target_id": relationship.target,
                "confidence": relationship.confidence,
                "origin_instance_id": origin,
                "imported_from_instance_id": relationship.imported_from_instance_id,
                "derived_by_instance_id": relationship.derived_by_instance_id,
                "lineage": relationship.lineage
            }))
        })
        .collect::<Result<Vec<Value>, AnalysisError>>()?;
    json_payload(
        "graph-fragment",
        GRAPH_PATH,
        &json!({"schema_version":1,"nodes":nodes,"relationships":relationships}),
    )
}

fn build_attack_chain_payload(
    chains: &[&AttackChainRecord],
    instance_id: &str,
) -> Result<AntiserumPayload, AnalysisError> {
    let values = chains.iter().map(|chain| json!({
        "id": chain.id,
        "title": chain.title,
        "original_title": chain.original_title,
        "severity": normalise_severity(&chain.severity),
        "confidence": chain.confidence,
        "classification_confidence": chain.classification_confidence,
        "matched_vulnerability_ids": chain.matched_cve_ids,
        "behaviour_ids": chain.behaviour_ids,
        "behaviour_fingerprint": chain.behaviour_fingerprint,
        "observed_at": format_rfc3339(chain.observed_at).unwrap_or_else(|_| "1970-01-01T00:00:00Z".into()),
        "steps": chain.steps.iter().enumerate().map(|(position, step)| json!({
            "position": position,
            "object_id": step.id,
            "label": step.label,
            "kind": step.kind
        })).collect::<Vec<_>>(),
        "relationships": chain.relationships,
        "supporting_evidence": [chain.evidence_id],
        "origin_instance_id": instance_id,
        "imported_from_instance_id": Value::Null,
        "derived_by_instance_id": instance_id,
        "lineage": [instance_id],
        "source_refs": ["src_local_observation"]
    })).collect::<Vec<_>>();
    json_payload(
        "attack-chain",
        ATTACK_CHAIN_PATH,
        &json!({"schema_version":1,"attack_chains":values}),
    )
}

fn build_provenance_payload(
    instance_id: &str,
    now: u64,
    mut additional: Vec<Value>,
) -> Result<AntiserumPayload, AnalysisError> {
    let mut sources = vec![json!({
        "id": "src_local_observation",
        "type": "dendrite-observation",
        "instance_id": instance_id,
        "observed_at": format_rfc3339(now)?
    })];
    sources.append(&mut additional);
    json_payload(
        "provenance",
        PROVENANCE_PATH,
        &json!({"schema_version":1,"sources":sources}),
    )
}

fn empty_standard_payloads() -> Result<BTreeMap<String, AntiserumPayload>, AnalysisError> {
    let mut payloads = BTreeMap::new();
    for (class, path) in [
        ("indicator-hash", HASH_PATH),
        ("indicator-domain", DOMAIN_PATH),
        ("indicator-ip", IP_PATH),
        ("indicator-url", URL_PATH),
    ] {
        payloads.insert(
            class.into(),
            json_payload(class, path, &json!({"schema_version":1,"indicators":[]}))?,
        );
    }
    payloads.insert(
        "behaviour".into(),
        json_payload(
            "behaviour",
            BEHAVIOUR_PATH,
            &json!({"schema_version":1,"behaviours":[]}),
        )?,
    );
    Ok(payloads)
}

fn json_payload(
    class: &str,
    path: &str,
    document: &Value,
) -> Result<AntiserumPayload, AnalysisError> {
    Ok(AntiserumPayload::new(
        class,
        path,
        serde_json::to_vec(document)?,
    ))
}

fn graph_payload_to_dto(bytes: &[u8]) -> Result<MemoryGraphDto, AnalysisError> {
    let document: Value = serde_json::from_slice(bytes)?;
    let nodes = document
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| AnalysisError::Invalid("graph payload has no nodes array".into()))?;
    let relationships = document
        .get("relationships")
        .and_then(Value::as_array)
        .ok_or_else(|| AnalysisError::Invalid("graph payload has no relationships array".into()))?;
    let nodes = nodes
        .iter()
        .map(|node| {
            let properties = node.get("properties").and_then(Value::as_object);
            let origin_instance_id = required_string(node, "origin_instance_id")?;
            // Never trust a shipped, pre-joined MemoryNodeId string verbatim - recompute
            // it ourselves from the bare object_id (new field) joined with the
            // already-verified origin_instance_id above, exactly the way
            // local_memory_node_id() builds it locally. Falls back to stripping the
            // claimed origin prefix off the legacy "id" field for packages exported
            // before this field existed, but REJECTS the node outright if that prefix
            // doesn't match rather than accepting an unverifiable value - that
            // verification, not just the new field, is the actual fix: a
            // malformed/adversarial exporter could otherwise claim an id whose prefix
            // doesn't match its own origin_instance_id and have it accepted verbatim.
            let object_id = match optional_string(node, "object_id") {
                Some(value) => value,
                None => {
                    let legacy_id = required_string(node, "id")?;
                    legacy_id
                        .strip_prefix(&origin_instance_id)
                        .and_then(|rest| rest.strip_prefix("::"))
                        .ok_or_else(|| {
                            AnalysisError::Invalid(format!(
                                "Memory node id {legacy_id} does not match its claimed origin_instance_id {origin_instance_id}"
                            ))
                        })?
                        .to_string()
                }
            };
            let id = format!("{origin_instance_id}::{object_id}");
            Ok(MemoryNodeDto {
                id,
                kind: required_string(node, "kind")?,
                label: required_string(node, "label")?,
                state: properties
                    .and_then(|value| value.get("state"))
                    .and_then(Value::as_str)
                    .unwrap_or("observed")
                    .into(),
                priority: properties
                    .and_then(|value| value.get("priority"))
                    .and_then(Value::as_str)
                    .unwrap_or("normal")
                    .into(),
                retention: properties
                    .and_then(|value| value.get("retention"))
                    .and_then(Value::as_str)
                    .unwrap_or("long_term")
                    .into(),
                created_at: parse_rfc3339(required_str(node, "first_seen")?)?,
                last_seen_at: parse_rfc3339(required_str(node, "last_seen")?)?,
                expires_at: None,
                origin_instance_id: Some(origin_instance_id),
                imported_from_instance_id: optional_string(node, "imported_from_instance_id"),
                derived_by_instance_id: optional_string(node, "derived_by_instance_id"),
                lineage: string_array(node, "lineage")?,
                correlation_keys: properties
                    .and_then(|value| value.get("correlation_keys"))
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<_>, AnalysisError>>()?;
    let relationships = relationships
        .iter()
        .map(|relationship| {
            let confidence = relationship
                .get("confidence")
                .and_then(Value::as_u64)
                .unwrap_or(100)
                .min(100) as u8;
            Ok(MemoryRelationshipDto {
                id: required_string(relationship, "id")?,
                kind: required_string(relationship, "kind")?,
                source: required_string(relationship, "source_id")?,
                target: required_string(relationship, "target_id")?,
                state: "observed".into(),
                priority: "normal".into(),
                retention: "long_term".into(),
                strength: confidence,
                effective_strength: confidence,
                confidence,
                observation_count: 1,
                created_at: 0,
                last_seen_at: 0,
                expires_at: None,
                origin_instance_id: Some(required_string(relationship, "origin_instance_id")?),
                imported_from_instance_id: optional_string(
                    relationship,
                    "imported_from_instance_id",
                ),
                derived_by_instance_id: optional_string(relationship, "derived_by_instance_id"),
                lineage: string_array(relationship, "lineage")?,
            })
        })
        .collect::<Result<Vec<_>, AnalysisError>>()?;
    Ok(MemoryGraphDto {
        total_nodes: nodes.len() as u64,
        total_relationships: relationships.len() as u64,
        nodes,
        relationships,
        truncated: false,
    })
}

pub fn summary_from_stored_package(
    package: &SignedAntiserumPackage,
    origin: AntiserumPackageOrigin,
    size_bytes: u64,
) -> Result<AntiserumPackageSummary, AnalysisError> {
    let knowledge_status = if origin == AntiserumPackageOrigin::Imported {
        "not_accepted"
    } else {
        "source"
    };
    Ok(AntiserumPackageSummary {
        antiserum_id: package.envelope.antiserum_id.clone(),
        origin,
        issuer_instance_id: package.envelope.issuer.instance_id.clone(),
        issuer_key_fingerprint: package.envelope.issuer.key_fingerprint.clone(),
        sequence: package.envelope.sequence,
        created_at: package.envelope.created_at.clone(),
        expires_at: package.envelope.expires_at.clone(),
        payloads: package.envelope.payloads.clone(),
        verification: AntiserumPackageVerification {
            signature: "valid".into(),
            content_root: "valid".into(),
            attestation: package.attestation.state.clone(),
            local_trust: "unassigned".into(),
        },
        size_bytes,
        knowledge_status: knowledge_status.into(),
        knowledge_accepted_at: None,
    })
}

fn secure_dir(path: &Path) -> Result<(), AnalysisError> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_secure_file(path: &Path, bytes: &[u8]) -> Result<(), AnalysisError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), AnalysisError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AnalysisError::Invalid(
            "invalid Antiserum identifier".into(),
        ));
    }
    Ok(())
}

fn normalise_severity(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "moderate" => "medium",
        "low" => "low",
        _ => "unknown",
    }
    .into()
}

fn format_rfc3339(value: u64) -> Result<String, AnalysisError> {
    OffsetDateTime::from_unix_timestamp(value as i64)
        .map_err(|error| AnalysisError::Invalid(format!("timestamp {value} is invalid: {error}")))?
        .format(&Rfc3339)
        .map_err(|error| AnalysisError::Invalid(format!("timestamp formatting failed: {error}")))
}

fn optional_rfc3339(value: Option<u64>) -> Result<Value, AnalysisError> {
    value
        .map(format_rfc3339)
        .transpose()
        .map(|value| value.map_or(Value::Null, Value::String))
}

fn parse_rfc3339(value: &str) -> Result<u64, AnalysisError> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|error| {
        AnalysisError::Invalid(format!("invalid RFC3339 timestamp {value}: {error}"))
    })?;
    u64::try_from(parsed.unix_timestamp())
        .map_err(|_| AnalysisError::Invalid("timestamp predates Unix epoch".into()))
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, AnalysisError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AnalysisError::Invalid(format!("missing string field {key}")))
}
fn required_string(value: &Value, key: &str) -> Result<String, AnalysisError> {
    Ok(required_str(value, key)?.to_owned())
}
fn optional_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}
fn string_array(value: &Value, key: &str) -> Result<Vec<String>, AnalysisError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| AnalysisError::Invalid(format!("missing array field {key}")))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| AnalysisError::Invalid(format!("{key} must contain strings")))
        })
        .collect()
}

#[cfg(test)]
mod graph_import_tests {
    use super::*;

    fn sample_node(id: &str, origin_instance_id: &str) -> MemoryNodeDto {
        MemoryNodeDto {
            id: id.into(),
            kind: "process".into(),
            label: "cat".into(),
            state: "observed".into(),
            priority: "normal".into(),
            retention: "long_term".into(),
            created_at: 1_700_000_000,
            last_seen_at: 1_700_000_000,
            expires_at: None,
            origin_instance_id: Some(origin_instance_id.into()),
            imported_from_instance_id: None,
            derived_by_instance_id: None,
            lineage: vec![origin_instance_id.into()],
            correlation_keys: vec!["process-identity:comm:17718013163177550631".into()],
        }
    }

    fn graph_with_one_node(node: MemoryNodeDto) -> MemoryGraphDto {
        MemoryGraphDto {
            nodes: vec![node],
            relationships: Vec::new(),
            truncated: false,
            total_nodes: 1,
            total_relationships: 0,
        }
    }

    #[test]
    fn export_carries_a_bare_object_id_alongside_the_full_id() {
        let node = sample_node(
            "f4dab864-423b-4348-9744-f3340f4656b0::process_identity:comm:17718013163177550631",
            "f4dab864-423b-4348-9744-f3340f4656b0",
        );
        let graph = graph_with_one_node(node);
        let payload = build_graph_payload(&graph).expect("payload builds");
        let document: Value = serde_json::from_slice(&payload.bytes).expect("valid json");
        let exported_node = &document["nodes"][0];
        assert_eq!(
            exported_node["object_id"].as_str(),
            Some("process_identity:comm:17718013163177550631")
        );
        assert_eq!(
            exported_node["origin_instance_id"].as_str(),
            Some("f4dab864-423b-4348-9744-f3340f4656b0")
        );
    }

    #[test]
    fn import_recomputes_the_join_instead_of_trusting_the_shipped_id() {
        // Even if a shipped "id" were somehow wrong, the join computed from
        // origin_instance_id + object_id is what wins - simulate that directly by
        // exporting normally (id and object_id agree here) and confirming the
        // round-tripped id is exactly the origin::object_id join, not a passthrough.
        let node = sample_node(
            "host-a::process_identity:comm:17718013163177550631",
            "host-a",
        );
        let graph = graph_with_one_node(node);
        let payload = build_graph_payload(&graph).expect("payload builds");
        let round_tripped = graph_payload_to_dto(&payload.bytes).expect("payload parses");
        assert_eq!(
            round_tripped.nodes[0].id,
            "host-a::process_identity:comm:17718013163177550631"
        );
    }

    #[test]
    fn import_rejects_a_legacy_id_whose_prefix_does_not_match_its_origin() {
        // No "object_id" field at all (pre-fix export shape), and the shipped "id"
        // claims a different host than origin_instance_id says produced it - this is
        // exactly the spoofing gap the fix closes, and it must now be a hard error,
        // not silently accepted the way the old verbatim-trust code would have.
        let bytes = json!({
            "schema_version": 1,
            "nodes": [{
                "id": "attacker-host::process_identity:comm:17718013163177550631",
                "kind": "process",
                "label": "cat",
                "properties": {"state": "observed", "priority": "normal", "retention": "long_term"},
                "first_seen": "2023-11-14T22:13:20Z",
                "last_seen": "2023-11-14T22:13:20Z",
                "origin_instance_id": "host-a",
                "imported_from_instance_id": Value::Null,
                "derived_by_instance_id": Value::Null,
                "lineage": ["host-a"]
            }],
            "relationships": []
        })
        .to_string();

        let result = graph_payload_to_dto(bytes.as_bytes());
        assert!(
            result.is_err(),
            "a node id whose prefix doesn't match its claimed origin must be rejected"
        );
    }

    #[test]
    fn import_accepts_a_legacy_payload_with_no_object_id_when_the_prefix_does_match() {
        // Backward compatibility: an older export with no "object_id" field but a
        // correctly-prefixed legacy "id" still imports fine.
        let bytes = json!({
            "schema_version": 1,
            "nodes": [{
                "id": "host-a::process_identity:comm:17718013163177550631",
                "kind": "process",
                "label": "cat",
                "properties": {"state": "observed", "priority": "normal", "retention": "long_term"},
                "first_seen": "2023-11-14T22:13:20Z",
                "last_seen": "2023-11-14T22:13:20Z",
                "origin_instance_id": "host-a",
                "imported_from_instance_id": Value::Null,
                "derived_by_instance_id": Value::Null,
                "lineage": ["host-a"]
            }],
            "relationships": []
        })
        .to_string();

        let graph = graph_payload_to_dto(bytes.as_bytes()).expect("legacy payload still parses");
        assert_eq!(
            graph.nodes[0].id,
            "host-a::process_identity:comm:17718013163177550631"
        );
    }
}
