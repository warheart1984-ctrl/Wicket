//! The witness log: a chain Nova does not write. Each entry is signed with the witness key.
//!
//! `through` cutoffs on a trusted key are not applied here. `verify` refuses a key file that
//! uses one, so a retirement does not look enforced when it is not.

use infinity_kernel::{hash_value, Signer, TrustedKeys};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
};

pub const EXECUTION_VERSION: &str = "infinity.witness.execution.v1";
pub const DIVERGENCE_VERSION: &str = "infinity.witness.divergence.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessEntry {
    pub version: String,
    pub receipt_id: String,
    pub previous_receipt_hash: Option<String>,
    pub allow_receipt_id: Option<String>,
    pub call_digest: Option<String>,
    pub attempt: u64,
    pub status: Option<String>,
    pub divergence: Option<String>,
    pub issued_at: String,
    /// Verified caller id. Covered by the entry hash when present, and omitted when it is not,
    /// so entries written before this field keep their ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WitnessInput {
    version: String,
    #[serde(default)]
    allow_receipt_id: Option<String>,
    #[serde(default)]
    call_digest: Option<String>,
    attempt: u64,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    divergence: Option<String>,
    issued_at: String,
    #[serde(default)]
    caller_id: Option<String>,
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn is_receipt_id(value: &str) -> bool {
    value.strip_prefix("receipt:sha3-256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn material(entry: &WitnessEntry) -> Value {
    let mut value = json!({
        "version": entry.version,
        "previous_receipt_hash": entry.previous_receipt_hash,
        "allow_receipt_id": entry.allow_receipt_id,
        "call_digest": entry.call_digest,
        "attempt": entry.attempt,
        "status": entry.status,
        "divergence": entry.divergence,
        "issued_at": entry.issued_at,
    });
    if let Some(caller_id) = &entry.caller_id {
        value["caller_id"] = json!(caller_id);
    }
    value
}

fn check_shape(entry: &WitnessEntry) -> Result<(), String> {
    if entry.attempt != 1 {
        return Err(
            "retries are not accepted; attempt must be 1 (a failed call does not get another)"
                .into(),
        );
    }
    if let Some(digest) = &entry.call_digest {
        if !is_sha256(digest) {
            return Err("call_digest must look like sha256:<64 lowercase hex>".into());
        }
    }
    if let Some(allow) = &entry.allow_receipt_id {
        if !is_receipt_id(allow) {
            return Err("allow_receipt_id must be a receipt id".into());
        }
    }
    if let Some(caller_id) = &entry.caller_id {
        if caller_id.is_empty() {
            return Err("caller_id must be non-empty when present".into());
        }
    }
    match entry.version.as_str() {
        EXECUTION_VERSION => {
            if !matches!(
                entry.status.as_deref(),
                Some("started") | Some("completed") | Some("failed")
            ) {
                return Err("execution status must be started, completed, or failed".into());
            }
            if entry.divergence.is_some() {
                return Err("an execution entry has no divergence".into());
            }
            if entry.allow_receipt_id.is_none() || entry.call_digest.is_none() {
                return Err("an execution entry needs allow_receipt_id and call_digest".into());
            }
            Ok(())
        }
        DIVERGENCE_VERSION => {
            if entry.status.is_some() {
                return Err("a divergence entry has no status".into());
            }
            if !matches!(
                entry.divergence.as_deref(),
                Some("mismatch")
                    | Some("unauthorized")
                    | Some("reused")
                    | Some("late")
                    | Some("IDENTITY_UNVERIFIED")
                    | Some("AUTHORITY_DENIED")
            ) {
                return Err(
                    "divergence must be mismatch, unauthorized, reused, late, IDENTITY_UNVERIFIED, or AUTHORITY_DENIED"
                        .into(),
                );
            }
            Ok(())
        }
        other => Err(format!("unknown witness entry version {other:?}")),
    }
}

/// One allow, one execution. A `started` entry consumes it. Divergence does not.
fn check_consumption(existing: &[WitnessEntry], incoming: &WitnessEntry) -> Result<(), String> {
    if incoming.version != EXECUTION_VERSION {
        return Ok(());
    }
    let allow = incoming.allow_receipt_id.as_deref().unwrap_or("");
    let prior: Vec<&WitnessEntry> = existing
        .iter()
        .filter(|entry| {
            entry.version == EXECUTION_VERSION && entry.allow_receipt_id.as_deref() == Some(allow)
        })
        .collect();
    match incoming.status.as_deref() {
        Some("started") if !prior.is_empty() => Err("allow already consumed".into()),
        Some("completed") | Some("failed") => {
            let started = prior
                .iter()
                .any(|entry| entry.status.as_deref() == Some("started"));
            let terminal = prior
                .iter()
                .any(|entry| matches!(entry.status.as_deref(), Some("completed") | Some("failed")));
            if started && !terminal {
                Ok(())
            } else {
                Err("completed or failed needs an open started entry for that allow".into())
            }
        }
        Some("started") => Ok(()),
        _ => Err("execution status must be started, completed, or failed".into()),
    }
}

fn read_entries(text: &str) -> Result<Vec<WitnessEntry>, String> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<WitnessEntry>(line).map_err(|e| e.to_string()))
        .collect()
}

fn expected_id(entry: &WitnessEntry) -> Result<String, String> {
    Ok(format!(
        "witness:{}",
        hash_value(&material(entry)).map_err(|e| e.to_string())?
    ))
}

fn chain_ok(entries: &[WitnessEntry]) -> Result<(), String> {
    let mut previous: Option<&str> = None;
    for (index, entry) in entries.iter().enumerate() {
        let position = index + 1;
        check_shape(entry)?;
        if entry.previous_receipt_hash.as_deref() != previous {
            return Err(format!(
                "entry {position} does not name the witness entry before it"
            ));
        }
        let id = expected_id(entry)?;
        if entry.receipt_id != id {
            return Err(format!(
                "entry {position} receipt_id does not match its contents"
            ));
        }
        check_consumption(&entries[..index], entry)?;
        previous = Some(entry.receipt_id.as_str());
    }
    Ok(())
}

fn signatures_ok(entries: &[WitnessEntry], keys: &TrustedKeys) -> Result<(), String> {
    if keys.has_cutoff() {
        return Err(
            "witness-verify does not honor `through` cutoffs; refusing a key file that uses them"
                .into(),
        );
    }
    for (index, entry) in entries.iter().enumerate() {
        let position = index + 1;
        let (Some(key_id), Some(signature)) = (entry.key_id.as_deref(), entry.signature.as_deref())
        else {
            return Err(format!("entry {position} is not signed"));
        };
        if !keys.contains(key_id) {
            return Err(format!(
                "entry {position} is signed by a key that is not trusted"
            ));
        }
        if !keys.verify_entry(key_id, &entry.receipt_id, signature) {
            return Err(format!(
                "entry {position} has a signature that does not verify"
            ));
        }
    }
    Ok(())
}

pub fn verify(path: &str, keys: &TrustedKeys) -> Result<usize, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.to_string()),
    };
    let entries = read_entries(&text)?;
    chain_ok(&entries)?;
    signatures_ok(&entries, keys)?;
    Ok(entries.len())
}

pub fn append(path: &str, signer: &Signer, input_json: &str) -> Result<WitnessEntry, String> {
    let input: WitnessInput = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.lock().map_err(|e| e.to_string())?;
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|e| e.to_string())?;
    let mut entries = read_entries(&text)?;
    let own = TrustedKeys::from_signer(signer);
    chain_ok(&entries)?;
    for (index, entry) in entries.iter().enumerate() {
        if entry.key_id.as_deref() != Some(signer.key_id())
            || !entry.signature.as_deref().is_some_and(|signature| {
                own.verify_entry(signer.key_id(), &entry.receipt_id, signature)
            })
        {
            return Err(format!(
                "refusing to append: entry {} is not signed by this witness key",
                index + 1
            ));
        }
    }
    let mut entry = WitnessEntry {
        version: input.version,
        receipt_id: String::new(),
        previous_receipt_hash: entries.last().map(|last| last.receipt_id.clone()),
        allow_receipt_id: input.allow_receipt_id,
        call_digest: input.call_digest,
        attempt: input.attempt,
        status: input.status,
        divergence: input.divergence,
        issued_at: input.issued_at,
        caller_id: input.caller_id,
        key_id: None,
        signature: None,
    };
    check_shape(&entry)?;
    check_consumption(&entries, &entry)?;
    entry.receipt_id = expected_id(&entry)?;
    entry.key_id = Some(signer.key_id().to_string());
    entry.signature = Some(signer.sign_entry(&entry.receipt_id));
    entries.push(entry.clone());
    chain_ok(&entries)?;
    signatures_ok(&entries, &own)?;
    let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
    writeln!(file, "{line}").map_err(|e| e.to_string())?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const ALLOW: &str =
        "receipt:sha3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn signer() -> Signer {
        Signer::from_seed([7; 32])
    }

    fn execution(status: &str) -> String {
        serde_json::json!({
            "version": EXECUTION_VERSION,
            "allow_receipt_id": ALLOW,
            "call_digest": DIGEST,
            "attempt": 1,
            "status": status,
            "divergence": null,
            "issued_at": "2026-10-07T00:00:00Z",
        })
        .to_string()
    }

    #[test]
    fn one_allow_is_consumed_by_started_and_a_second_start_is_refused() {
        let dir = std::env::temp_dir().join(format!("witness-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let log = dir.join("w.jsonl");
        let _ = fs::remove_file(&log);
        let path = log.to_str().unwrap();
        let key = signer();
        let started = append(path, &key, &execution("started")).unwrap();
        assert!(started.receipt_id.starts_with("witness:sha3-256:"));
        assert!(started.signature.is_some());
        let again = append(path, &key, &execution("started")).unwrap_err();
        assert!(again.contains("allow already consumed"), "{again}");
        append(path, &key, &execution("completed")).unwrap();
        let keys = TrustedKeys::from_signer(&key);
        assert_eq!(verify(path, &keys).unwrap(), 2);
        let _ = fs::remove_file(&log);
    }

    #[test]
    fn a_divergence_does_not_consume_the_allow() {
        let dir = std::env::temp_dir().join(format!("witness-div-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let log = dir.join("w.jsonl");
        let _ = fs::remove_file(&log);
        let path = log.to_str().unwrap();
        let key = signer();
        let divergence = serde_json::json!({
            "version": DIVERGENCE_VERSION,
            "allow_receipt_id": ALLOW,
            "call_digest": DIGEST,
            "attempt": 1,
            "status": null,
            "divergence": "mismatch",
            "issued_at": "2026-10-07T00:00:00Z",
        })
        .to_string();
        append(path, &key, &divergence).unwrap();
        append(path, &key, &execution("started")).unwrap();
        let _ = fs::remove_file(&log);
    }

    #[test]
    fn an_edited_witness_entry_fails_verification() {
        let dir = std::env::temp_dir().join(format!("witness-edit-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let log = dir.join("w.jsonl");
        let _ = fs::remove_file(&log);
        let path = log.to_str().unwrap();
        let key = signer();
        append(path, &key, &execution("started")).unwrap();
        let text = fs::read_to_string(path)
            .unwrap()
            .replace("started", "failed");
        fs::write(path, text).unwrap();
        let keys = TrustedKeys::from_signer(&key);
        assert!(verify(path, &keys).is_err());
        let _ = fs::remove_file(path);
    }
}
