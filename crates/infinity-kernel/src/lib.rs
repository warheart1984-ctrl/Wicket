use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;
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
}
