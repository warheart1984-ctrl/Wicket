use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const PROPOSAL_VERSION: &str = "infinity.proposal.v1";
pub const POLICY_VERSION: &str = "infinity.policy.v1";
pub const DECISION_VERSION: &str = "infinity.decision.v1";
pub const RECEIPT_VERSION: &str = "infinity.receipt.v2";
/// Still verified, no longer issued: v1 receipts did not hash `issued_at`.
pub const RECEIPT_VERSION_V1: &str = "infinity.receipt.v1";
pub const OUTCOME_VERSION: &str = "infinity.outcome.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub kind: String,
    pub id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub version: String,
    pub proposal_id: String,
    pub actor: Actor,
    pub action: String,
    pub target: String,
    pub effect: String,
    pub risk: String,
    pub requires_human_approval: bool,
    pub policy_version: String,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub approval_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: String,
    pub policy_id: String,
    #[serde(default)]
    pub denied_effects: Vec<String>,
    #[serde(default)]
    pub effects_requiring_approval: Vec<String>,
    #[serde(default)]
    pub risks_requiring_approval: Vec<String>,
}
#[derive(Debug, Clone, Default)]
pub struct ApprovalSet {
    ids: BTreeSet<String>,
}
impl ApprovalSet {
    pub fn from_ids(ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            ids: ids.into_iter().collect(),
        }
    }
    pub fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Approval {
    pub required: bool,
    pub approval_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub version: String,
    pub proposal_id: String,
    pub verdict: String,
    pub reason_codes: Vec<String>,
    pub policy_hash: String,
    pub proposal_hash: String,
    pub approval: Approval,
    pub invariants_checked: Vec<String>,
    pub decision_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub version: String,
    pub receipt_id: String,
    pub previous_receipt_hash: Option<String>,
    pub proposal_hash: String,
    pub policy_hash: String,
    pub decision_hash: String,
    pub verdict: String,
    pub reason_codes: Vec<String>,
    pub issued_at: String,
    /// Set when the receipt was signed. Not part of the hash: the signature is over the hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}
/// What happened after an `allow`: written to the same chain, so "the model was called" has a
/// record that points at the decision which permitted it. Only hashes are stored, never content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub version: String,
    pub receipt_id: String,
    pub previous_receipt_hash: Option<String>,
    pub decision_receipt_id: String,
    pub status: String,
    pub request_sha256: Option<String>,
    pub response_sha256: Option<String>,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}
/// One line of a receipt log: a decision receipt or an outcome.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum LogEntry {
    Decision(Receipt),
    Outcome(Outcome),
}
impl<'de> Deserialize<'de> for LogEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let is_outcome = value
            .get("version")
            .and_then(Value::as_str)
            .is_some_and(|v| v.starts_with("infinity.outcome."));
        if is_outcome {
            serde_json::from_value(value)
                .map(LogEntry::Outcome)
                .map_err(serde::de::Error::custom)
        } else {
            serde_json::from_value(value)
                .map(LogEntry::Decision)
                .map_err(serde::de::Error::custom)
        }
    }
}
impl From<Receipt> for LogEntry {
    fn from(receipt: Receipt) -> Self {
        LogEntry::Decision(receipt)
    }
}
impl From<Outcome> for LogEntry {
    fn from(outcome: Outcome) -> Self {
        LogEntry::Outcome(outcome)
    }
}
impl LogEntry {
    pub fn receipt_id(&self) -> &str {
        match self {
            LogEntry::Decision(r) => &r.receipt_id,
            LogEntry::Outcome(o) => &o.receipt_id,
        }
    }
    pub fn key_id(&self) -> Option<&str> {
        match self {
            LogEntry::Decision(r) => r.key_id.as_deref(),
            LogEntry::Outcome(o) => o.key_id.as_deref(),
        }
    }
    pub fn signature(&self) -> Option<&str> {
        match self {
            LogEntry::Decision(r) => r.signature.as_deref(),
            LogEntry::Outcome(o) => o.signature.as_deref(),
        }
    }
    pub fn is_signed(&self) -> bool {
        self.signature().is_some()
    }
    /// Sign this entry in place. Call after the entry's id is final: the signature is over the id.
    pub fn sign(&mut self, signer: &Signer) {
        let signature = signer.sign_entry(self.receipt_id());
        let key_id = Some(signer.key_id().to_string());
        match self {
            LogEntry::Decision(r) => {
                r.key_id = key_id;
                r.signature = Some(signature);
            }
            LogEntry::Outcome(o) => {
                o.key_id = key_id;
                o.signature = Some(signature);
            }
        }
    }
    pub fn previous_receipt_hash(&self) -> Option<&str> {
        match self {
            LogEntry::Decision(r) => r.previous_receipt_hash.as_deref(),
            LogEntry::Outcome(o) => o.previous_receipt_hash.as_deref(),
        }
    }
}
#[derive(Debug, Error)]
pub enum KernelError {
    #[error("invalid JSON value: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
}

pub fn canonical_json(value: &Value) -> Result<String, KernelError> {
    Ok(serde_json::to_string(value)?)
}
pub fn hash_value(value: &Value) -> Result<String, KernelError> {
    let mut hasher = Sha3_256::new();
    hasher.update(canonical_json(value)?.as_bytes());
    Ok(format!("sha3-256:{:x}", hasher.finalize()))
}
fn proposal_value(p: &Proposal) -> Value {
    serde_json::to_value(p).expect("serializable proposal")
}
fn policy_value(p: &Policy) -> Value {
    serde_json::to_value(p).expect("serializable policy")
}
fn decision_material(d: &Decision) -> Value {
    json!({
        "version": d.version, "proposal_id": d.proposal_id, "verdict": d.verdict,
        "reason_codes": d.reason_codes, "policy_hash": d.policy_hash, "proposal_hash": d.proposal_hash,
        "approval": d.approval, "invariants_checked": d.invariants_checked
    })
}
fn denied_decision(
    proposal: &Proposal,
    policy_hash: String,
    proposal_hash: String,
    code: &str,
) -> Result<Decision, KernelError> {
    build_decision(
        proposal,
        policy_hash,
        proposal_hash,
        "deny",
        vec![code.into()],
        Approval {
            required: false,
            approval_id: None,
        },
    )
}
fn build_decision(
    proposal: &Proposal,
    policy_hash: String,
    proposal_hash: String,
    verdict: &str,
    codes: Vec<String>,
    approval: Approval,
) -> Result<Decision, KernelError> {
    let mut decision = Decision {
        version: DECISION_VERSION.into(),
        proposal_id: proposal.proposal_id.clone(),
        verdict: verdict.into(),
        reason_codes: codes,
        policy_hash,
        proposal_hash,
        approval,
        invariants_checked: vec![
            "no_authority_self_mutation".into(),
            "kernel_is_sole_verdict_authority".into(),
        ],
        decision_hash: String::new(),
    };
    decision.decision_hash = hash_value(&decision_material(&decision))?;
    Ok(decision)
}
pub fn evaluate(
    proposal: Proposal,
    policy: Policy,
    approvals: ApprovalSet,
) -> Result<Decision, KernelError> {
    let proposal_hash = hash_value(&proposal_value(&proposal))?;
    let policy_hash = hash_value(&policy_value(&policy))?;
    if proposal.version != PROPOSAL_VERSION {
        return denied_decision(
            &proposal,
            policy_hash,
            proposal_hash,
            "UNKNOWN_PROPOSAL_VERSION",
        );
    }
    if policy.version != POLICY_VERSION {
        return denied_decision(
            &proposal,
            policy_hash,
            proposal_hash,
            "UNKNOWN_POLICY_VERSION",
        );
    }
    if proposal.policy_version != policy.policy_id {
        return denied_decision(&proposal, policy_hash, proposal_hash, "POLICY_MISMATCH");
    }
    if proposal.payload.get("verdict").is_some() {
        return denied_decision(
            &proposal,
            policy_hash,
            proposal_hash,
            "VERDICT_SELECTION_FORBIDDEN",
        );
    }
    if ![
        "read",
        "write",
        "deploy",
        "authority_change",
        "audit_delete",
    ]
    .contains(&proposal.effect.as_str())
    {
        return denied_decision(&proposal, policy_hash, proposal_hash, "UNKNOWN_EFFECT");
    }
    if !["low", "medium", "high", "critical"].contains(&proposal.risk.as_str()) {
        return denied_decision(&proposal, policy_hash, proposal_hash, "UNKNOWN_RISK");
    }
    if ["authority_change", "deploy", "audit_delete"].contains(&proposal.effect.as_str()) {
        return denied_decision(&proposal, policy_hash, proposal_hash, "FORBIDDEN_EFFECT");
    }
    if policy.denied_effects.contains(&proposal.effect) {
        return denied_decision(
            &proposal,
            policy_hash,
            proposal_hash,
            "POLICY_DENIED_EFFECT",
        );
    }
    let needs_approval = proposal.requires_human_approval
        || policy.effects_requiring_approval.contains(&proposal.effect)
        || policy.risks_requiring_approval.contains(&proposal.risk);
    if needs_approval {
        let valid = proposal
            .approval_id
            .as_deref()
            .filter(|id| approvals.contains(id));
        if let Some(id) = valid {
            return build_decision(
                &proposal,
                policy_hash,
                proposal_hash,
                "allow",
                vec!["ALLOWED".into()],
                Approval {
                    required: true,
                    approval_id: Some(id.into()),
                },
            );
        }
        return build_decision(
            &proposal,
            policy_hash,
            proposal_hash,
            "await_human_approval",
            vec!["APPROVAL_REQUIRED".into()],
            Approval {
                required: true,
                approval_id: None,
            },
        );
    }
    build_decision(
        &proposal,
        policy_hash,
        proposal_hash,
        "allow",
        vec!["SAFE_READ".into()],
        Approval {
            required: false,
            approval_id: None,
        },
    )
}
/// What a receipt's id is a hash of. v1 left out `issued_at`, so its time could be edited
/// unnoticed; v2 includes it. An unknown version has no material and never verifies.
fn receipt_material(r: &Receipt) -> Option<Value> {
    let mut material = json!({
        "version": r.version, "previous_receipt_hash": r.previous_receipt_hash, "proposal_hash": r.proposal_hash,
        "policy_hash": r.policy_hash, "decision_hash": r.decision_hash, "verdict": r.verdict, "reason_codes": r.reason_codes
    });
    match r.version.as_str() {
        RECEIPT_VERSION_V1 => Some(material),
        RECEIPT_VERSION => {
            material["issued_at"] = json!(r.issued_at);
            Some(material)
        }
        _ => None,
    }
}
fn outcome_material(o: &Outcome) -> Value {
    json!({
        "version": o.version, "previous_receipt_hash": o.previous_receipt_hash,
        "decision_receipt_id": o.decision_receipt_id, "status": o.status,
        "request_sha256": o.request_sha256, "response_sha256": o.response_sha256, "issued_at": o.issued_at
    })
}
pub fn issue_receipt(
    decision: &Decision,
    previous: Option<&LogEntry>,
    issued_at: String,
) -> Result<Receipt, KernelError> {
    let mut receipt = Receipt {
        version: RECEIPT_VERSION.into(),
        receipt_id: String::new(),
        previous_receipt_hash: previous.map(|p| p.receipt_id().to_string()),
        proposal_hash: decision.proposal_hash.clone(),
        policy_hash: decision.policy_hash.clone(),
        decision_hash: decision.decision_hash.clone(),
        verdict: decision.verdict.clone(),
        reason_codes: decision.reason_codes.clone(),
        issued_at,
        key_id: None,
        signature: None,
    };
    let material = receipt_material(&receipt).ok_or_else(|| {
        KernelError::Invalid("cannot issue a receipt of an unknown version".into())
    })?;
    receipt.receipt_id = format!("receipt:{}", hash_value(&material)?);
    Ok(receipt)
}
fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}
/// Record what happened after a decision. `status` is `completed` or `failed`; the hashes are
/// `sha256:<64 hex>` of the request and reply, supplied by the caller (the kernel never sees content).
pub fn issue_outcome(
    decision_receipt_id: &str,
    status: &str,
    request_sha256: Option<String>,
    response_sha256: Option<String>,
    previous: Option<&LogEntry>,
    issued_at: String,
) -> Result<Outcome, KernelError> {
    if !["completed", "failed"].contains(&status) {
        return Err(KernelError::Invalid(format!(
            "outcome status must be completed or failed, not {status:?}"
        )));
    }
    if !decision_receipt_id.starts_with("receipt:") {
        return Err(KernelError::Invalid(
            "decision_receipt_id must be a receipt id".into(),
        ));
    }
    for hash in request_sha256.iter().chain(response_sha256.iter()) {
        if !is_sha256(hash) {
            return Err(KernelError::Invalid(
                "hashes must look like sha256:<64 lowercase hex>".into(),
            ));
        }
    }
    let mut outcome = Outcome {
        version: OUTCOME_VERSION.into(),
        receipt_id: String::new(),
        previous_receipt_hash: previous.map(|p| p.receipt_id().to_string()),
        decision_receipt_id: decision_receipt_id.into(),
        status: status.into(),
        request_sha256,
        response_sha256,
        issued_at,
        key_id: None,
        signature: None,
    };
    outcome.receipt_id = format!("receipt:{}", hash_value(&outcome_material(&outcome))?);
    Ok(outcome)
}
pub fn verify_receipt(receipt: &Receipt) -> Result<bool, KernelError> {
    Ok(match receipt_material(receipt) {
        Some(material) => receipt.receipt_id == format!("receipt:{}", hash_value(&material)?),
        None => false,
    })
}
pub fn verify_outcome(outcome: &Outcome) -> Result<bool, KernelError> {
    Ok(outcome.version == OUTCOME_VERSION
        && outcome.receipt_id == format!("receipt:{}", hash_value(&outcome_material(outcome))?))
}
/// True if every entry's hash is right, each names the one before it, and every outcome points at
/// an earlier `allow` decision that has no other outcome.
pub fn verify_log(entries: &[LogEntry]) -> Result<bool, KernelError> {
    let mut allows: BTreeSet<&str> = BTreeSet::new();
    let mut answered: BTreeSet<&str> = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let hash_ok = match entry {
            LogEntry::Decision(r) => verify_receipt(r)?,
            LogEntry::Outcome(o) => verify_outcome(o)?,
        };
        let expected_previous = index.checked_sub(1).map(|i| entries[i].receipt_id());
        if !hash_ok || entry.previous_receipt_hash() != expected_previous {
            return Ok(false);
        }
        match entry {
            LogEntry::Decision(r) if r.verdict == "allow" => {
                allows.insert(&r.receipt_id);
            }
            LogEntry::Decision(_) => {}
            LogEntry::Outcome(o) => {
                if !allows.contains(o.decision_receipt_id.as_str())
                    || !answered.insert(&o.decision_receipt_id)
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSummary {
    pub decisions: usize,
    pub outcomes: usize,
    /// `allow` decisions with no outcome yet: still in flight, or the call never finished.
    pub allows_without_outcome: usize,
}
pub fn summarize(entries: &[LogEntry]) -> LogSummary {
    let answered: BTreeSet<&str> = entries
        .iter()
        .filter_map(|e| match e {
            LogEntry::Outcome(o) => Some(o.decision_receipt_id.as_str()),
            LogEntry::Decision(_) => None,
        })
        .collect();
    let decisions = entries
        .iter()
        .filter(|e| matches!(e, LogEntry::Decision(_)))
        .count();
    let allows_without_outcome = entries
        .iter()
        .filter(|e| matches!(e, LogEntry::Decision(r) if r.verdict == "allow" && !answered.contains(r.receipt_id.as_str())))
        .count();
    LogSummary {
        decisions,
        outcomes: entries.len() - decisions,
        allows_without_outcome,
    }
}

// ---- signatures ------------------------------------------------------------------------------
//
// Ed25519 signatures over entries and anchor records. They are *optional*: unsigned entries and
// old logs verify exactly as before. The signature covers the entry's id, and the id is a hash of
// every other field, so a valid signature vouches for all of them. A signature stops anyone who
// lacks the key from forging or altering entries. It does not stop rolling a log back to an
// earlier genuine state, and it does not help if the key is stolen with the log.

const ENTRY_DOMAIN: &str = "infinity-core/entry/v1";
const ANCHOR_DOMAIN: &str = "infinity-core/anchor/v1";
const PRIVATE_PREFIX: &str = "ed25519-private:";
const PUBLIC_PREFIX: &str = "ed25519-public:";
const SIGNATURE_PREFIX: &str = "ed25519:";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}
/// The id of a public key: `key:sha3-256:<hash of the 32 key bytes>`.
pub fn key_id_for(public_key: &[u8; 32]) -> String {
    format!("key:sha3-256:{:x}", Sha3_256::digest(public_key))
}
fn entry_message(key_id: &str, receipt_id: &str) -> Vec<u8> {
    format!("{ENTRY_DOMAIN}\n{key_id}\n{receipt_id}").into_bytes()
}
fn anchor_message(key_id: &str, count: u64, head_receipt_id: &str) -> Vec<u8> {
    format!("{ANCHOR_DOMAIN}\n{key_id}\n{count}\n{head_receipt_id}").into_bytes()
}

/// Holds a private key. Never prints or serializes it.
pub struct Signer {
    key: SigningKey,
    key_id: String,
}
impl Signer {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let key_id = key_id_for(&key.verifying_key().to_bytes());
        Signer { key, key_id }
    }
    /// Parse `ed25519-private:<64 hex>` (surrounding whitespace is ignored).
    pub fn from_text(text: &str) -> Result<Self, KernelError> {
        text.trim()
            .strip_prefix(PRIVATE_PREFIX)
            .and_then(from_hex::<32>)
            .map(Signer::from_seed)
            .ok_or_else(|| {
                KernelError::Invalid(format!("expected {PRIVATE_PREFIX}<64 hex digits>"))
            })
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    /// `ed25519-public:<64 hex>`, the form a trusted-keys file lists.
    pub fn public_key_text(&self) -> String {
        format!(
            "{PUBLIC_PREFIX}{}",
            to_hex(&self.key.verifying_key().to_bytes())
        )
    }
    pub fn private_key_text(&self) -> String {
        format!("{PRIVATE_PREFIX}{}", to_hex(&self.key.to_bytes()))
    }
    pub fn sign_entry(&self, receipt_id: &str) -> String {
        let sig = self.key.sign(&entry_message(&self.key_id, receipt_id));
        format!("{SIGNATURE_PREFIX}{}", to_hex(&sig.to_bytes()))
    }
    pub fn sign_anchor(&self, count: u64, head_receipt_id: &str) -> String {
        let sig = self
            .key
            .sign(&anchor_message(&self.key_id, count, head_receipt_id));
        format!("{SIGNATURE_PREFIX}{}", to_hex(&sig.to_bytes()))
    }
}

/// Public keys the verifier trusts. They must come from somewhere the log's writer cannot
/// change; a key found inside the log proves nothing.
///
/// A key may be limited to an earlier part of the log: `<key> through <receipt id>` trusts it only
/// for entries up to and including that receipt (and anchor records that cover no more than that).
/// That is how a key is retired or revoked. It is a position in the hash chain, not a time: the
/// time in an entry is written by whoever holds the key, so a stolen key could backdate.
#[derive(Default)]
pub struct TrustedKeys {
    keys: BTreeMap<String, VerifyingKey>,
    cutoffs: BTreeMap<String, String>,
}

fn is_receipt_id(text: &str) -> bool {
    text.strip_prefix("receipt:sha3-256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}
impl TrustedKeys {
    /// One key per line: `ed25519-public:<64 hex>`, optionally followed by
    /// `through receipt:sha3-256:<64 hex>`. Blank lines and `#` comments are ignored.
    pub fn from_text(text: &str) -> Result<Self, KernelError> {
        let mut keys = BTreeMap::new();
        let mut cutoffs = BTreeMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut words = line.split_whitespace();
            let key_text = words.next().unwrap_or("");
            let through = match (words.next(), words.next(), words.next()) {
                (None, _, _) => None,
                (Some("through"), Some(receipt), None) if is_receipt_id(receipt) => Some(receipt),
                _ => {
                    return Err(KernelError::Invalid(format!(
                        "trusted keys line {}: expected {PUBLIC_PREFIX}<64 hex digits>, optionally followed by `through receipt:sha3-256:<64 hex digits>`",
                        n + 1
                    )))
                }
            };
            let bytes = key_text
                .strip_prefix(PUBLIC_PREFIX)
                .and_then(from_hex::<32>)
                .ok_or_else(|| {
                    KernelError::Invalid(format!(
                        "trusted keys line {}: expected {PUBLIC_PREFIX}<64 hex digits>",
                        n + 1
                    ))
                })?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
                KernelError::Invalid(format!(
                    "trusted keys line {}: not a valid Ed25519 public key",
                    n + 1
                ))
            })?;
            let key_id = key_id_for(&bytes);
            if keys.insert(key_id.clone(), key).is_some() {
                return Err(KernelError::Invalid(format!(
                    "trusted keys line {}: this key is listed twice",
                    n + 1
                )));
            }
            if let Some(receipt) = through {
                cutoffs.insert(key_id, receipt.to_string());
            }
        }
        if keys.is_empty() {
            return Err(KernelError::Invalid(
                "the trusted keys file lists no keys".into(),
            ));
        }
        Ok(TrustedKeys { keys, cutoffs })
    }
    pub fn from_signer(signer: &Signer) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(signer.key_id.clone(), signer.key.verifying_key());
        TrustedKeys {
            keys,
            cutoffs: BTreeMap::new(),
        }
    }
    pub fn contains(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }
    /// The last receipt this key is trusted for, if it has been retired or revoked.
    pub fn cutoff(&self, key_id: &str) -> Option<&str> {
        self.cutoffs.get(key_id).map(String::as_str)
    }
    /// Is `key_id` trusted for something at 1-based position `position` of `entries`? An entry
    /// signed with a limited key must come at or before the receipt the limit names. If that receipt
    /// is not in this log at all, nothing signed by the key is accepted: this may be a different
    /// history, and the safe answer is no.
    pub fn allows_position(
        &self,
        key_id: &str,
        position: usize,
        entries: &[LogEntry],
    ) -> Result<(), String> {
        let Some(receipt) = self.cutoff(key_id) else {
            return Ok(());
        };
        match entries.iter().position(|e| e.receipt_id() == receipt) {
            None => Err(format!(
                "the key {key_id} is trusted only through {receipt}, which is not in this log"
            )),
            Some(index) if position > index + 1 => Err(format!(
                "the key {key_id} was retired or revoked after entry {}, but this is entry {position}",
                index + 1
            )),
            Some(_) => Ok(()),
        }
    }
    fn check(&self, key_id: &str, message: &[u8], signature: &str) -> bool {
        let (Some(key), Some(bytes)) = (
            self.keys.get(key_id),
            signature
                .strip_prefix(SIGNATURE_PREFIX)
                .and_then(from_hex::<64>),
        ) else {
            return false;
        };
        key.verify_strict(message, &Signature::from_bytes(&bytes))
            .is_ok()
    }
    pub fn verify_entry(&self, key_id: &str, receipt_id: &str, signature: &str) -> bool {
        self.check(key_id, &entry_message(key_id, receipt_id), signature)
    }
    pub fn verify_anchor(
        &self,
        key_id: &str,
        count: u64,
        head_receipt_id: &str,
        signature: &str,
    ) -> bool {
        self.check(
            key_id,
            &anchor_message(key_id, count, head_receipt_id),
            signature,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureReport {
    pub signed: usize,
    pub unsigned: usize,
}

/// Check the signatures in a log whose hashes `verify_log` has already accepted.
///
/// * every signature must verify against a trusted key (an unknown key is a failure);
/// * once an entry is signed, every later one must be too, so stripping signatures from the end
///   of a log is caught;
/// * with `require`, every entry must be signed. Without it, a log that was *never* signed passes,
///   which also means someone who strips *all* signatures cannot be told from a log that never
///   had any. Use `require` once signing is switched on.
pub fn verify_signatures(
    entries: &[LogEntry],
    keys: &TrustedKeys,
    require: bool,
) -> Result<SignatureReport, KernelError> {
    let mut signed = 0;
    for (index, entry) in entries.iter().enumerate() {
        let position = index + 1;
        match (entry.key_id(), entry.signature()) {
            (Some(key_id), Some(signature)) => {
                if !keys.contains(key_id) {
                    return Err(KernelError::Invalid(format!(
                        "entry {position} is signed by a key that is not trusted ({key_id})"
                    )));
                }
                if !keys.verify_entry(key_id, entry.receipt_id(), signature) {
                    return Err(KernelError::Invalid(format!(
                        "entry {position} has a signature that does not verify"
                    )));
                }
                keys.allows_position(key_id, position, entries)
                    .map_err(|why| KernelError::Invalid(format!("entry {position}: {why}")))?;
                signed += 1;
            }
            (None, None) => {
                if require {
                    return Err(KernelError::Invalid(format!(
                        "entry {position} is not signed"
                    )));
                }
                if signed > 0 {
                    return Err(KernelError::Invalid(format!(
                        "entry {position} is unsigned after signed entries: signatures were stripped, or signing was switched off"
                    )));
                }
            }
            _ => {
                return Err(KernelError::Invalid(format!(
                    "entry {position} has a key id without a signature, or the reverse"
                )));
            }
        }
    }
    Ok(SignatureReport {
        signed,
        unsigned: entries.len() - signed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(effect: &str) -> Proposal {
        Proposal {
            version: PROPOSAL_VERSION.into(),
            proposal_id: "p".into(),
            actor: Actor {
                kind: "agent".into(),
                id: "a".into(),
            },
            action: "a".into(),
            target: "t".into(),
            effect: effect.into(),
            risk: "low".into(),
            requires_human_approval: false,
            policy_version: "p1".into(),
            payload: json!({}),
            evidence_refs: vec![],
            approval_id: None,
        }
    }
    fn policy() -> Policy {
        Policy {
            version: POLICY_VERSION.into(),
            policy_id: "p1".into(),
            denied_effects: vec![],
            effects_requiring_approval: vec!["write".into()],
            risks_requiring_approval: vec![],
        }
    }
    #[test]
    fn allows_read() {
        assert_eq!(
            evaluate(p("read"), policy(), ApprovalSet::default())
                .unwrap()
                .verdict,
            "allow"
        );
    }
    #[test]
    fn awaits_unapproved_write() {
        assert_eq!(
            evaluate(p("write"), policy(), ApprovalSet::default())
                .unwrap()
                .verdict,
            "await_human_approval"
        );
    }
    #[test]
    fn denies_forbidden_effect() {
        assert_eq!(
            evaluate(p("deploy"), policy(), ApprovalSet::default())
                .unwrap()
                .verdict,
            "deny"
        );
    }
    #[test]
    fn rejects_payload_verdict() {
        let mut proposal = p("read");
        proposal.payload = json!({"verdict":"allow"});
        assert_eq!(
            evaluate(proposal, policy(), ApprovalSet::default())
                .unwrap()
                .reason_codes,
            vec!["VERDICT_SELECTION_FORBIDDEN"]
        );
    }
    #[test]
    fn chain_detects_tamper() {
        let d = evaluate(p("read"), policy(), ApprovalSet::default()).unwrap();
        let mut r = issue_receipt(&d, None, "x".into()).unwrap();
        assert!(verify_log(&[r.clone().into()]).unwrap());
        r.verdict = "deny".into();
        assert!(!verify_log(&[r.into()]).unwrap());
    }

    fn allow_receipt(previous: Option<&LogEntry>, at: &str) -> Receipt {
        let d = evaluate(p("read"), policy(), ApprovalSet::default()).unwrap();
        assert_eq!(d.verdict, "allow");
        issue_receipt(&d, previous, at.into()).unwrap()
    }
    const HASH_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn the_time_a_receipt_was_issued_is_covered_by_its_hash() {
        let mut r = allow_receipt(None, "2026-10-02T10:00:00Z");
        assert_eq!(r.version, RECEIPT_VERSION);
        assert!(verify_log(&[r.clone().into()]).unwrap());
        r.issued_at = "1999-01-01T00:00:00Z".into();
        assert!(
            !verify_log(&[r.into()]).unwrap(),
            "editing issued_at must be detected"
        );
    }

    #[test]
    fn old_v1_receipts_still_verify_but_their_time_is_not_covered() {
        // Build a v1 receipt the way the old code did: no issued_at in the hashed material.
        let mut r = allow_receipt(None, "t");
        r.version = RECEIPT_VERSION_V1.into();
        let material = json!({
            "version": r.version, "previous_receipt_hash": r.previous_receipt_hash, "proposal_hash": r.proposal_hash,
            "policy_hash": r.policy_hash, "decision_hash": r.decision_hash, "verdict": r.verdict, "reason_codes": r.reason_codes
        });
        r.receipt_id = format!("receipt:{}", hash_value(&material).unwrap());
        assert!(verify_log(&[r.clone().into()]).unwrap());
        r.issued_at = "edited".into();
        assert!(verify_log(&[r.into()]).unwrap(), "documented v1 limitation");
    }

    #[test]
    fn an_unknown_receipt_version_never_verifies() {
        let mut r = allow_receipt(None, "t");
        r.version = "infinity.receipt.v99".into();
        assert!(!verify_log(&[r.into()]).unwrap());
    }

    #[test]
    fn an_outcome_after_an_allow_verifies_and_is_part_of_the_chain() {
        let allow = allow_receipt(None, "t1");
        let first: LogEntry = allow.clone().into();
        let outcome = issue_outcome(
            &allow.receipt_id,
            "completed",
            Some(HASH_A.into()),
            Some(HASH_B.into()),
            Some(&first),
            "t2".into(),
        )
        .unwrap();
        let entries: Vec<LogEntry> = vec![first, outcome.into()];
        assert!(verify_log(&entries).unwrap());
        assert_eq!(
            summarize(&entries),
            LogSummary {
                decisions: 1,
                outcomes: 1,
                allows_without_outcome: 0
            }
        );
    }

    #[test]
    fn an_allow_without_an_outcome_is_reported_not_rejected() {
        let entries: Vec<LogEntry> = vec![allow_receipt(None, "t1").into()];
        assert!(verify_log(&entries).unwrap());
        assert_eq!(summarize(&entries).allows_without_outcome, 1);
    }

    #[test]
    fn every_field_of_an_outcome_is_covered_by_its_hash() {
        let allow = allow_receipt(None, "t1");
        let first: LogEntry = allow.clone().into();
        let good = issue_outcome(
            &allow.receipt_id,
            "completed",
            Some(HASH_A.into()),
            Some(HASH_B.into()),
            Some(&first),
            "t2".into(),
        )
        .unwrap();
        let edits: [fn(&mut Outcome); 5] = [
            |o| o.status = "failed".into(),
            |o| o.response_sha256 = Some(HASH_A.into()),
            |o| o.request_sha256 = None,
            |o| o.issued_at = "t9".into(),
            |o| o.decision_receipt_id = "receipt:other".into(),
        ];
        for edit in edits {
            let mut bad = good.clone();
            edit(&mut bad);
            assert!(!verify_log(&[first.clone(), bad.into()]).unwrap());
        }
    }

    #[test]
    fn an_outcome_must_answer_an_earlier_allow_and_only_once() {
        let allow = allow_receipt(None, "t1");
        let first: LogEntry = allow.clone().into();
        // points at nothing
        let orphan = issue_outcome(
            "receipt:sha3-256:nope",
            "completed",
            None,
            None,
            Some(&first),
            "t2".into(),
        )
        .unwrap();
        assert!(!verify_log(&[first.clone(), orphan.into()]).unwrap());
        // answered twice
        let one = issue_outcome(
            &allow.receipt_id,
            "completed",
            None,
            None,
            Some(&first),
            "t2".into(),
        )
        .unwrap();
        let one_entry: LogEntry = one.into();
        let two = issue_outcome(
            &allow.receipt_id,
            "failed",
            None,
            None,
            Some(&one_entry),
            "t3".into(),
        )
        .unwrap();
        assert!(!verify_log(&[first.clone(), one_entry, two.into()]).unwrap());
        // listed before the decision it claims to answer
        let early = issue_outcome(
            &allow.receipt_id,
            "completed",
            None,
            None,
            None,
            "t0".into(),
        )
        .unwrap();
        let early_entry: LogEntry = early.into();
        let late = allow_receipt(Some(&early_entry), "t1");
        assert!(!verify_log(&[early_entry, late.into()]).unwrap());
    }

    #[test]
    fn an_outcome_cannot_answer_a_deny_or_a_wait() {
        for (effect, verdict) in [
            ("authority_change", "deny"),
            ("write", "await_human_approval"),
        ] {
            let decision = evaluate(p(effect), policy(), ApprovalSet::default()).unwrap();
            assert_eq!(decision.verdict, verdict);
            let held: LogEntry = issue_receipt(&decision, None, "t1".into()).unwrap().into();
            let outcome = issue_outcome(
                held.receipt_id(),
                "completed",
                None,
                None,
                Some(&held),
                "t2".into(),
            )
            .unwrap();
            assert!(
                !verify_log(&[held, outcome.into()]).unwrap(),
                "a model call needs an allow ({verdict})"
            );
        }
    }

    #[test]
    fn malformed_outcomes_are_not_issued() {
        let id = "receipt:sha3-256:x";
        assert!(issue_outcome(id, "maybe", None, None, None, "t".into()).is_err());
        assert!(issue_outcome("not-a-receipt", "completed", None, None, None, "t".into()).is_err());
        assert!(issue_outcome(
            id,
            "completed",
            Some("sha256:XYZ".into()),
            None,
            None,
            "t".into()
        )
        .is_err());
        assert!(issue_outcome(
            id,
            "completed",
            Some(HASH_A.to_uppercase()),
            None,
            None,
            "t".into()
        )
        .is_err());
        assert!(
            issue_outcome(id, "completed", Some(HASH_A.into()), None, None, "t".into()).is_ok()
        );
    }

    #[test]
    fn log_entries_round_trip_through_json_as_the_right_kind() {
        let allow = allow_receipt(None, "t1");
        let first: LogEntry = allow.clone().into();
        let outcome: LogEntry = issue_outcome(
            &allow.receipt_id,
            "failed",
            None,
            None,
            Some(&first),
            "t2".into(),
        )
        .unwrap()
        .into();
        for entry in [first, outcome] {
            let text = serde_json::to_string(&entry).unwrap();
            let back: LogEntry = serde_json::from_str(&text).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), text);
            assert!(matches!(
                (&entry, &back),
                (LogEntry::Decision(_), LogEntry::Decision(_))
                    | (LogEntry::Outcome(_), LogEntry::Outcome(_))
            ));
        }
    }

    // ---- signatures -------------------------------------------------------------------------

    fn signer(n: u8) -> Signer {
        Signer::from_seed([n; 32])
    }
    fn trusting(signers: &[&Signer]) -> TrustedKeys {
        let text: String = signers.iter().map(|s| s.public_key_text() + "\n").collect();
        TrustedKeys::from_text(&text).unwrap()
    }
    /// allow, outcome, allow: three chained entries, none signed yet.
    fn chain() -> Vec<LogEntry> {
        let a = allow_receipt(None, "2026-10-02T10:00:00Z");
        let a_entry: LogEntry = a.clone().into();
        let o: LogEntry = issue_outcome(
            &a.receipt_id,
            "completed",
            None,
            None,
            Some(&a_entry),
            "2026-10-02T10:00:01Z".into(),
        )
        .unwrap()
        .into();
        let b = allow_receipt(Some(&o), "2026-10-02T10:00:02Z");
        vec![a_entry, o, b.into()]
    }
    fn signed_chain(by: &Signer) -> Vec<LogEntry> {
        let mut entries = chain();
        for e in entries.iter_mut() {
            e.sign(by);
        }
        entries
    }

    #[test]
    fn a_signed_log_verifies_against_the_trusted_key() {
        let key = signer(1);
        let entries = signed_chain(&key);
        assert!(
            verify_log(&entries).unwrap(),
            "signing must not disturb the hash chain"
        );
        let report = verify_signatures(&entries, &trusting(&[&key]), true).unwrap();
        assert_eq!(
            report,
            SignatureReport {
                signed: 3,
                unsigned: 0
            }
        );
    }

    #[test]
    fn signatures_are_deterministic_and_the_key_id_is_stable() {
        let (a, b) = (signer(1), signer(1));
        assert_eq!(a.key_id(), b.key_id());
        assert_eq!(a.sign_entry("receipt:x"), b.sign_entry("receipt:x"));
        assert_ne!(a.key_id(), signer(2).key_id());
        assert!(
            a.key_id().starts_with("key:sha3-256:")
                && a.key_id().len() == "key:sha3-256:".len() + 64
        );
    }

    #[test]
    fn the_wrong_key_does_not_verify() {
        let entries = signed_chain(&signer(1));
        let err = verify_signatures(&entries, &trusting(&[&signer(2)]), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not trusted"), "{err}");
    }

    #[test]
    fn a_key_id_swapped_for_another_trusted_key_fails() {
        let (one, two) = (signer(1), signer(2));
        let mut entries = signed_chain(&one);
        if let LogEntry::Decision(r) = &mut entries[0] {
            r.key_id = Some(two.key_id().to_string()); // claims to be signed by key two
        }
        let err = verify_signatures(&entries, &trusting(&[&one, &two]), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn a_forged_entry_needs_the_key_even_if_the_attacker_recomputes_every_hash() {
        let key = signer(1);
        let honest = signed_chain(&key);
        // The attacker rewrites entry 1 (allow -> deny), recomputes its id, and keeps the old signature.
        let LogEntry::Decision(original) = &honest[0] else {
            unreachable!()
        };
        let mut forged = original.clone();
        forged.verdict = "deny".into();
        forged.receipt_id = format!(
            "receipt:{}",
            hash_value(&receipt_material(&forged).unwrap()).unwrap()
        );
        let err = verify_signatures(&[forged.into()], &trusting(&[&key]), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn a_damaged_signature_fails() {
        let key = signer(1);
        let mut entries = signed_chain(&key);
        if let LogEntry::Outcome(o) = &mut entries[1] {
            o.signature = o.signature.as_deref().map(damaged);
        }
        assert!(verify_signatures(&entries, &trusting(&[&key]), true).is_err());
    }

    /// The same signature with its last hex digit changed.
    fn damaged(signature: &str) -> String {
        let (head, last) = signature.split_at(signature.len() - 1);
        format!("{head}{}", if last == "0" { "1" } else { "0" })
    }

    #[test]
    fn a_signature_made_for_one_purpose_cannot_be_reused_for_another() {
        let key = signer(1);
        // an anchor signature offered as an entry signature, and the reverse
        let anchor_sig = key.sign_anchor(3, "receipt:x");
        assert!(!trusting(&[&key]).verify_entry(key.key_id(), "receipt:x", &anchor_sig));
        let entry_sig = key.sign_entry("receipt:x");
        assert!(!trusting(&[&key]).verify_anchor(key.key_id(), 3, "receipt:x", &entry_sig));
        assert!(trusting(&[&key]).verify_anchor(
            key.key_id(),
            3,
            "receipt:x",
            &key.sign_anchor(3, "receipt:x")
        ));
        assert!(!trusting(&[&key]).verify_anchor(
            key.key_id(),
            4,
            "receipt:x",
            &key.sign_anchor(3, "receipt:x")
        ));
    }

    #[test]
    fn once_signing_starts_every_later_entry_must_be_signed() {
        let key = signer(1);
        let mut entries = signed_chain(&key);
        let LogEntry::Decision(last) = &mut entries[2] else {
            unreachable!()
        };
        last.key_id = None;
        last.signature = None; // someone strips the newest signature
        let trusted = trusting(&[&key]);
        let err = verify_signatures(&entries, &trusted, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsigned after signed"), "{err}");
    }

    #[test]
    fn signing_can_be_switched_on_part_way_through_a_log() {
        let key = signer(1);
        let mut entries = chain();
        entries[1].sign(&key);
        entries[2].sign(&key);
        let trusted = trusting(&[&key]);
        assert_eq!(
            verify_signatures(&entries, &trusted, false).unwrap(),
            SignatureReport {
                signed: 2,
                unsigned: 1
            }
        );
        assert!(
            verify_signatures(&entries, &trusted, true).is_err(),
            "require means all of them"
        );
    }

    #[test]
    fn a_log_that_was_never_signed_passes_only_when_signatures_are_not_required() {
        let entries = chain();
        let trusted = trusting(&[&signer(1)]);
        assert_eq!(
            verify_signatures(&entries, &trusted, false).unwrap(),
            SignatureReport {
                signed: 0,
                unsigned: 3
            }
        );
        assert!(verify_signatures(&entries, &trusted, true).is_err());
    }

    #[test]
    fn a_key_id_with_no_signature_is_rejected() {
        let key = signer(1);
        let mut entries = signed_chain(&key);
        if let LogEntry::Decision(r) = &mut entries[0] {
            r.signature = None;
        }
        assert!(verify_signatures(&entries, &trusting(&[&key]), false).is_err());
    }

    #[test]
    fn rolling_back_to_an_earlier_genuine_prefix_still_verifies_a_documented_limit() {
        // Signatures prove who wrote an entry, not that no newer entry existed. Detecting a
        // rollback needs an external copy of the newest anchor (the published one).
        let key = signer(1);
        let entries = signed_chain(&key);
        let rolled_back = &entries[..2];
        assert!(verify_log(rolled_back).unwrap());
        assert!(verify_signatures(rolled_back, &trusting(&[&key]), true).is_ok());
    }

    #[test]
    fn unsigned_entries_serialize_exactly_as_before() {
        let text = serde_json::to_string(&chain()[0]).unwrap();
        assert!(
            !text.contains("signature") && !text.contains("key_id"),
            "{text}"
        );
        let signed = serde_json::to_string(&signed_chain(&signer(1))[0]).unwrap();
        assert!(
            signed.contains("\"signature\":\"ed25519:")
                && signed.contains("\"key_id\":\"key:sha3-256:")
        );
        let back: LogEntry = serde_json::from_str(&signed).unwrap();
        assert!(back.is_signed());
    }

    #[test]
    fn key_files_must_have_the_right_shape() {
        let key = signer(7);
        let again = Signer::from_text(&format!("  {}\n", key.private_key_text())).unwrap();
        assert_eq!(again.key_id(), key.key_id());
        for bad in [
            "",
            "ed25519-private:abc",
            &format!("ed25519-public:{}", "0".repeat(64)),
            &"a".repeat(64),
            &format!("ed25519-private:{}", "G".repeat(64)),
        ] {
            assert!(Signer::from_text(bad).is_err(), "{bad:?}");
        }
        let text = format!(
            "# the operator's key\n\n{}  # primary\n",
            key.public_key_text()
        );
        assert!(TrustedKeys::from_text(&text)
            .unwrap()
            .contains(key.key_id()));
        assert!(TrustedKeys::from_text("# nothing here\n").is_err());
        assert!(
            TrustedKeys::from_text(&key.private_key_text()).is_err(),
            "a private key is not a trusted public key"
        );
        assert!(TrustedKeys::from_text("ed25519-public:xyz").is_err());
    }

    // ---- retiring and revoking keys -------------------------------------------------------------

    /// First two entries signed by `old`, the third by `new`: a planned hand-over.
    fn rotated_chain(old: &Signer, new: &Signer) -> Vec<LogEntry> {
        let mut entries = chain();
        entries[0].sign(old);
        entries[1].sign(old);
        entries[2].sign(new);
        entries
    }
    fn limited(old: &Signer, through: &str, new: &Signer) -> TrustedKeys {
        TrustedKeys::from_text(&format!(
            "{} through {through}\n{}\n",
            old.public_key_text(),
            new.public_key_text()
        ))
        .unwrap()
    }

    #[test]
    fn a_key_limited_to_an_entry_is_trusted_up_to_it_and_not_after() {
        let (old, new) = (signer(1), signer(2));
        let entries = rotated_chain(&old, &new);
        // retired exactly at the hand-over: everything verifies
        let keys = limited(&old, entries[1].receipt_id(), &new);
        assert_eq!(verify_signatures(&entries, &keys, true).unwrap().signed, 3);
        // retired one entry too early: the second entry is now after the limit
        let early = limited(&old, entries[0].receipt_id(), &new);
        let err = verify_signatures(&entries, &early, true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("entry 2") && err.contains("retired or revoked"),
            "{err}"
        );
        // the same key without a limit is trusted everywhere
        let unlimited = trusting(&[&old, &new]);
        assert!(verify_signatures(&entries, &unlimited, true).is_ok());
    }

    #[test]
    fn a_stolen_key_cannot_sign_new_entries_after_its_limit() {
        let (old, new) = (signer(1), signer(2));
        let mut entries = rotated_chain(&old, &new);
        let limit = entries[1].receipt_id().to_string();
        // the thief appends a genuinely signed entry with the old key
        let forged = allow_receipt(Some(entries.last().unwrap()), "2026-10-02T10:00:09Z");
        let mut forged: LogEntry = forged.into();
        forged.sign(&old);
        entries.push(forged);
        assert!(verify_log(&entries).unwrap());
        assert!(
            verify_signatures(&entries, &trusting(&[&old, &new]), true).is_ok(),
            "without a limit the forgery is accepted: that is the problem the limit solves"
        );
        let err = verify_signatures(&entries, &limited(&old, &limit, &new), true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("entry 4") && err.contains("retired or revoked"),
            "{err}"
        );
    }

    #[test]
    fn a_limit_that_names_a_receipt_not_in_the_log_trusts_nothing_it_signed() {
        let (old, new) = (signer(1), signer(2));
        let entries = rotated_chain(&old, &new);
        let elsewhere = format!("receipt:sha3-256:{}", "9".repeat(64));
        let err = verify_signatures(&entries, &limited(&old, &elsewhere, &new), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not in this log"), "{err}");
        // but a log the limited key never signed is unaffected
        let only_new = signed_chain(&new);
        assert!(verify_signatures(&only_new, &limited(&old, &elsewhere, &new), true).is_ok());
    }

    #[test]
    fn trusted_key_lines_with_limits_are_parsed_strictly() {
        let key = signer(1).public_key_text();
        let good = format!("receipt:sha3-256:{}", "a".repeat(64));
        let keys = TrustedKeys::from_text(&format!("{key} through {good}  # retired\n")).unwrap();
        assert_eq!(keys.cutoff(signer(1).key_id()), Some(good.as_str()));
        assert_eq!(
            TrustedKeys::from_text(&format!("{key}\n"))
                .unwrap()
                .cutoff(signer(1).key_id()),
            None
        );
        for bad in [
            format!("{key} through"),
            format!("{key} through receipt:sha3-256:short"),
            format!("{key} through {}", "a".repeat(64)),
            format!("{key} until {good}"),
            format!("{key} through {good} extra"),
            format!("{key} {good}"),
            format!("{key}\n{key}"),
            format!("{key} through {good}\n{key}"),
            format!("{key} through RECEIPT:sha3-256:{}", "a".repeat(64)),
        ] {
            assert!(TrustedKeys::from_text(&bad).is_err(), "{bad:?}");
        }
    }
}
