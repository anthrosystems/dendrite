use dendrited::{
    AntiserumPayload, AntiserumVerificationKey, DaemonCore, package_from_danti_bytes,
    package_to_danti_bytes, verify_signed_package,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const VULNERABILITY_PATH: &str = "payloads/vulnerabilities/vulnerabilities.json";
const HASH_PATH: &str = "payloads/indicators/hashes.json";
const DOMAIN_PATH: &str = "payloads/indicators/domains.json";
const IP_PATH: &str = "payloads/indicators/ips.json";
const URL_PATH: &str = "payloads/indicators/urls.json";
const BEHAVIOUR_PATH: &str = "payloads/behaviours/behaviours.json";
const GRAPH_PATH: &str = "payloads/graph/graph-fragment.json";
const ATTACK_CHAIN_PATH: &str = "payloads/graph/attack-chains.json";
const PROVENANCE_PATH: &str = "provenance/sources.json";

fn main() {
    if let Err(error) = run() {
        eprintln!("Antiserum live-data smoke test FAILED: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let self_db = env::var("DENDRITE_SELF_DB").unwrap_or_else(|_| "data/self.sqlite3".into());
    let stm_db = env::var("DENDRITE_STM_DB").unwrap_or_else(|_| "data/stm.sqlite3".into());
    let ltm_db = env::var("DENDRITE_LTM_DB").unwrap_or_else(|_| "data/ltm.sqlite3".into());
    let incidents_db =
        env::var("DENDRITE_INCIDENT_DB").unwrap_or_else(|_| "data/incidents.sqlite3".into());
    let guard_db = env::var("DENDRITE_GUARD_DB").unwrap_or_else(|_| "data/guard.sqlite3".into());
    let output_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data/antiserum-smoke"));
    let now = unix_now()?;

    let mut core =
        DaemonCore::open_with_tiered_stores(&self_db, &stm_db, &ltm_db, &incidents_db, &guard_db)
            .map_err(debug_error)?;
    let instance_id = core.instance_id().to_owned();
    let signing_key = core.signing_key_status();

    let (vulnerability_payload, vulnerability_sources, vulnerability_count) =
        build_vulnerability_payload(&incidents_db)?;
    let (graph_payload, graph_node_count, graph_relationship_count) = build_graph_payload(&core)?;
    let (attack_chain_payload, attack_chain_count) =
        build_attack_chain_payload(&core, &instance_id)?;

    let local_source_id = "src_local_observation".to_string();
    let provenance_payload =
        build_provenance_payload(&instance_id, now, &local_source_id, vulnerability_sources)?;

    // The live format always carries every canonical v1 payload file.
    // Empty knowledge remains a schema-valid empty document and is explicitly
    // marked "empty" by the signed envelope.
    let empty_standard_payloads = empty_standard_payloads()?;
    let payloads = vec![
        vulnerability_payload,
        empty_standard_payloads["indicator-hash"].clone(),
        empty_standard_payloads["indicator-domain"].clone(),
        empty_standard_payloads["indicator-ip"].clone(),
        empty_standard_payloads["indicator-url"].clone(),
        empty_standard_payloads["behaviour"].clone(),
        graph_payload,
        attack_chain_payload,
        provenance_payload,
    ];

    let package = core
        .build_antiserum_package(payloads, now, None)
        .map_err(debug_error)?;

    let verifier = AntiserumVerificationKey {
        instance_id: instance_id.clone(),
        key_id: signing_key.key_id.clone(),
        public_key: signing_key.public_key.clone(),
        fingerprint: signing_key.fingerprint.clone(),
    };
    verify_signed_package(&package, &verifier, now).map_err(debug_error)?;

    let expected_status = [
        ("vulnerability", VULNERABILITY_PATH, vulnerability_count > 0),
        ("indicator-hash", HASH_PATH, false),
        ("indicator-domain", DOMAIN_PATH, false),
        ("indicator-ip", IP_PATH, false),
        ("indicator-url", URL_PATH, false),
        ("behaviour", BEHAVIOUR_PATH, false),
        (
            "graph-fragment",
            GRAPH_PATH,
            graph_node_count > 0 || graph_relationship_count > 0,
        ),
        ("attack-chain", ATTACK_CHAIN_PATH, attack_chain_count > 0),
        ("provenance", PROVENANCE_PATH, true),
    ];
    if package.envelope.payloads.len() != expected_status.len() {
        return Err(format!(
            "expected {} payload declarations, got {}",
            expected_status.len(),
            package.envelope.payloads.len()
        ));
    }
    for (class, path, populated) in expected_status {
        let declaration = package
            .envelope
            .payloads
            .iter()
            .find(|payload| payload.class == class && payload.path == path)
            .ok_or_else(|| format!("missing payload declaration for {class}"))?;
        let expected = if populated { "populated" } else { "empty" };
        let actual = match declaration.status {
            dendrited::AntiserumPayloadStatus::Populated => "populated",
            dendrited::AntiserumPayloadStatus::Empty => "empty",
        };
        if actual != expected {
            return Err(format!(
                "payload status mismatch for {class}: expected {expected}, got {actual}"
            ));
        }
    }

    write_logical_bundle(&output_dir, &package.logical_files().map_err(debug_error)?)?;
    let danti_bytes = package_to_danti_bytes(&package).map_err(debug_error)?;
    let danti_path = output_dir.with_extension("danti");
    fs::write(&danti_path, &danti_bytes).map_err(debug_error)?;
    let reparsed = package_from_danti_bytes(&danti_bytes).map_err(debug_error)?;
    verify_signed_package(&reparsed, &verifier, now).map_err(debug_error)?;

    // Replay protection is exercised against an isolated receiver so the smoke
    // package itself remains importable through the real Analysis UI afterwards.
    let mut replay_receiver =
        DaemonCore::open_with_stores(":memory:", ":memory:", ":memory:", ":memory:")
            .map_err(debug_error)?;
    replay_receiver
        .verify_and_record_antiserum_sequence(&package, &verifier, now)
        .map_err(debug_error)?;
    let replay_rejected = replay_receiver
        .verify_and_record_antiserum_sequence(&package, &verifier, now)
        .is_err();
    if !replay_rejected {
        return Err("replay acceptance unexpectedly succeeded".into());
    }

    for index in 0..package.payloads.len() {
        let mut tampered = package.clone();
        tampered.payloads[index].bytes.push(b' ');
        if verify_signed_package(&tampered, &verifier, now).is_ok() {
            return Err(format!(
                "payload tampering unexpectedly verified for {}",
                package.payloads[index].class
            ));
        }
    }

    let mut envelope_tampered = package.clone();
    envelope_tampered
        .envelope
        .antiserum_id
        .push_str("-tampered");
    if verify_signed_package(&envelope_tampered, &verifier, now).is_ok() {
        return Err("envelope tampering unexpectedly verified".into());
    }

    println!("Antiserum live-data smoke test PASSED");
    println!("instance id: {instance_id}");
    println!("signing key: {}", signing_key.key_id);
    println!("key fingerprint: {}", signing_key.fingerprint);
    println!("antiserum id: {}", package.envelope.antiserum_id);
    println!("sequence: {}", package.envelope.sequence);
    println!("content root: {}", package.envelope.content_root.value);
    println!("logical output: {}", output_dir.display());
    println!("danti package: {}", danti_path.display());
    println!("live vulnerability records: {vulnerability_count}");
    println!("live graph nodes: {graph_node_count}");
    println!("live graph relationships: {graph_relationship_count}");
    println!("live evidence-backed attack chains: {attack_chain_count}");
    println!("authenticated payload files: {}", package.payloads.len());
    for payload in &package.payloads {
        let status = package
            .envelope
            .payloads
            .iter()
            .find(|entry| entry.class == payload.class)
            .map(|entry| match entry.status {
                dendrited::AntiserumPayloadStatus::Populated => "populated",
                dendrited::AntiserumPayloadStatus::Empty => "empty",
            })
            .unwrap_or("unknown");
        println!("  {} [{}] -> {}", payload.class, status, payload.path);
    }
    println!("canonical payload files written: 9");
    println!("signature verification: PASS");
    println!("danti encode/parse verification: PASS");
    println!("first sequence acceptance: PASS");
    println!("replay rejection: PASS");
    println!("all payload tamper rejection: PASS");
    println!("envelope tamper rejection: PASS");
    Ok(())
}

fn build_vulnerability_payload(
    incidents_db: &str,
) -> Result<(AntiserumPayload, Vec<Value>, usize), String> {
    let connection = Connection::open(incidents_db).map_err(debug_error)?;
    let mut statement = connection
        .prepare(
            "SELECT cve_id, package, affected_before, fixed_version, severity, cvss,
                    published_at, modified_at, source, provenance, imported_at
             FROM cve_knowledge
             ORDER BY cve_id, package",
        )
        .map_err(debug_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<u64>>(6)?,
                row.get::<_, Option<u64>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, u64>(10)?,
            ))
        })
        .map_err(debug_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(debug_error)?;

    let mut source_ids = BTreeMap::<(String, String, u64), String>::new();
    let mut sources = Vec::new();
    let mut vulnerabilities = Vec::with_capacity(rows.len());

    for (
        cve_id,
        package,
        affected_before,
        fixed_version,
        severity,
        cvss,
        published_at,
        modified_at,
        source,
        provenance,
        imported_at,
    ) in rows
    {
        let source_key = (source.clone(), provenance.clone(), imported_at);
        let source_id = if let Some(existing) = source_ids.get(&source_key) {
            existing.clone()
        } else {
            let id = format!("src_vulnerability_{:06}", source_ids.len() + 1);
            sources.push(json!({
                "id": id,
                "type": "public-feed",
                "name": source,
                "reference": provenance,
                "retrieved_at": format_rfc3339(imported_at)?
            }));
            source_ids.insert(source_key, id.clone());
            id
        };

        let cvss = cvss.and_then(|value| value.parse::<f64>().ok());
        // Dendrite's current CVE store has `affected_before`/`fixed_version`. In the Antiserum v1
        // model both represent the upper boundary of the affected range; prefer the explicit fixed
        // version when present and otherwise carry the affected-before boundary as `fixed`.
        let fixed = fixed_version.or(affected_before);
        vulnerabilities.push(json!({
            "id": cve_id,
            "package": package,
            "ecosystem": "debian",
            "affected": {
                "introduced": Value::Null,
                "fixed": fixed
            },
            "severity": normalise_severity(&severity),
            "cvss": cvss,
            "published_at": optional_rfc3339(published_at)?,
            "modified_at": optional_rfc3339(modified_at)?,
            "references": [],
            "source_refs": [source_id]
        }));
    }

    let document = json!({
        "schema_version": 1,
        "vulnerabilities": vulnerabilities
    });
    let count = document["vulnerabilities"].as_array().map_or(0, Vec::len);
    Ok((
        json_payload("vulnerability", VULNERABILITY_PATH, &document)?,
        sources,
        count,
    ))
}

fn build_graph_payload(core: &DaemonCore) -> Result<(AntiserumPayload, usize, usize), String> {
    let graph = core.memory_graph(0).map_err(debug_error)?;
    if graph.truncated {
        return Err(
            "live Memory Graph unexpectedly truncated during Antiserum smoke export".into(),
        );
    }

    let mut nodes = Vec::with_capacity(graph.nodes.len());
    for node in graph.nodes {
        let origin = node
            .origin_instance_id
            .ok_or_else(|| format!("Memory node {} has no origin_instance_id", node.id))?;
        if node.lineage.is_empty() {
            return Err(format!(
                "Memory node {} has empty provenance lineage",
                node.id
            ));
        }
        nodes.push(json!({
            "id": node.id,
            "kind": node.kind,
            "label": node.label,
            "properties": {},
            "first_seen": format_rfc3339(node.created_at)?,
            "last_seen": format_rfc3339(node.last_seen_at)?,
            "origin_instance_id": origin,
            "imported_from_instance_id": node.imported_from_instance_id,
            "derived_by_instance_id": node.derived_by_instance_id,
            "lineage": node.lineage
        }));
    }

    let node_ids = nodes
        .iter()
        .filter_map(|node| node["id"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let mut relationships = Vec::new();
    for relationship in graph.relationships {
        // Export only self-contained graph relationships. A relationship pointing to a node not in
        // this snapshot would make the portable graph fragment internally incomplete.
        if !node_ids.contains(&relationship.source) || !node_ids.contains(&relationship.target) {
            continue;
        }
        let origin = relationship.origin_instance_id.ok_or_else(|| {
            format!(
                "Memory relationship {} has no origin_instance_id",
                relationship.id
            )
        })?;
        if relationship.lineage.is_empty() {
            return Err(format!(
                "Memory relationship {} has empty provenance lineage",
                relationship.id
            ));
        }
        relationships.push(json!({
            "id": relationship.id,
            "kind": relationship.kind,
            "source_id": relationship.source,
            "target_id": relationship.target,
            "confidence": relationship.confidence,
            "origin_instance_id": origin,
            "imported_from_instance_id": relationship.imported_from_instance_id,
            "derived_by_instance_id": relationship.derived_by_instance_id,
            "lineage": relationship.lineage
        }));
    }

    let node_count = nodes.len();
    let relationship_count = relationships.len();
    let document = json!({
        "schema_version": 1,
        "nodes": nodes,
        "relationships": relationships
    });
    Ok((
        json_payload("graph-fragment", GRAPH_PATH, &document)?,
        node_count,
        relationship_count,
    ))
}

fn build_attack_chain_payload(
    core: &DaemonCore,
    instance_id: &str,
) -> Result<(AntiserumPayload, usize), String> {
    let graph = core.memory_graph(0).map_err(debug_error)?;
    let relationship_ids = graph
        .relationships
        .iter()
        .map(|relationship| {
            (
                (relationship.source.clone(), relationship.target.clone()),
                relationship.id.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut chains = Vec::new();
    for incident in core.list_incidents().map_err(debug_error)? {
        let Some(detail) = core.incident_detail(&incident.id).map_err(debug_error)? else {
            continue;
        };
        for evidence in detail.evidence {
            if evidence.source != "memory_graph" || evidence.objects.len() < 2 {
                continue;
            }
            let steps = evidence
                .objects
                .iter()
                .enumerate()
                .map(|(position, object)| {
                    json!({
                        "position": position,
                        "object_id": object.id,
                        "label": object.label,
                        "kind": object.kind
                    })
                })
                .collect::<Vec<_>>();

            let relationships = evidence
                .objects
                .windows(2)
                .filter_map(|pair| {
                    relationship_ids
                        .get(&(pair[0].id.clone(), pair[1].id.clone()))
                        .cloned()
                })
                .collect::<Vec<_>>();

            chains.push(json!({
                "id": format!("chain:{}:{}", incident.id, evidence.id),
                "title": incident.summary.clone(),
                "severity": normalise_severity(&incident.severity),
                "confidence": evidence.confidence,
                "observed_at": format_rfc3339(evidence.observed_at)?,
                "steps": steps,
                "relationships": relationships,
                "supporting_evidence": [evidence.id],
                "origin_instance_id": instance_id,
                "imported_from_instance_id": Value::Null,
                "derived_by_instance_id": instance_id,
                "lineage": [instance_id],
                "source_refs": ["src_local_observation"]
            }));
        }
    }

    let count = chains.len();
    let document = json!({
        "schema_version": 1,
        "attack_chains": chains
    });
    Ok((
        json_payload("attack-chain", ATTACK_CHAIN_PATH, &document)?,
        count,
    ))
}

fn build_provenance_payload(
    instance_id: &str,
    now: u64,
    local_source_id: &str,
    mut vulnerability_sources: Vec<Value>,
) -> Result<AntiserumPayload, String> {
    let mut sources = vec![json!({
        "id": local_source_id,
        "type": "dendrite-observation",
        "instance_id": instance_id,
        "observed_at": format_rfc3339(now)?
    })];
    sources.append(&mut vulnerability_sources);
    let document = json!({
        "schema_version": 1,
        "sources": sources
    });
    json_payload("provenance", PROVENANCE_PATH, &document)
}

fn json_payload(class: &str, path: &str, value: &Value) -> Result<AntiserumPayload, String> {
    let bytes = serde_json::to_vec(value).map_err(debug_error)?;
    Ok(AntiserumPayload::new(class, path, bytes))
}

fn empty_standard_payloads() -> Result<BTreeMap<String, AntiserumPayload>, String> {
    let mut payloads = BTreeMap::new();
    let empty_indicators = json!({"schema_version": 1, "indicators": []});
    let empty_behaviours = json!({"schema_version": 1, "behaviours": []});

    for (class, path) in [
        ("indicator-hash", HASH_PATH),
        ("indicator-domain", DOMAIN_PATH),
        ("indicator-ip", IP_PATH),
        ("indicator-url", URL_PATH),
    ] {
        payloads.insert(
            class.to_string(),
            json_payload(class, path, &empty_indicators)?,
        );
    }
    payloads.insert(
        "behaviour".to_string(),
        json_payload("behaviour", BEHAVIOUR_PATH, &empty_behaviours)?,
    );
    Ok(payloads)
}

fn write_logical_bundle(root: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    if root.exists() {
        fs::remove_dir_all(root).map_err(debug_error)?;
    }

    for (relative, bytes) in files {
        let destination = root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(debug_error)?;
        }
        fs::write(&destination, bytes).map_err(debug_error)?;
    }
    Ok(())
}

fn normalise_severity(value: &str) -> &'static str {
    match value.to_ascii_lowercase().as_str() {
        "informational" | "info" => "informational",
        "low" => "low",
        "medium" | "moderate" => "medium",
        "high" => "high",
        "critical" => "critical",
        _ => "unknown",
    }
}

fn optional_rfc3339(timestamp: Option<u64>) -> Result<Value, String> {
    match timestamp {
        Some(timestamp) => Ok(Value::String(format_rfc3339(timestamp)?)),
        None => Ok(Value::Null),
    }
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(debug_error)
}

fn format_rfc3339(timestamp: u64) -> Result<String, String> {
    OffsetDateTime::from_unix_timestamp(timestamp as i64)
        .map_err(debug_error)?
        .format(&Rfc3339)
        .map_err(debug_error)
}

fn debug_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}
