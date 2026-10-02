use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;
use thiserror::Error;

pub const PROPOSAL_VERSION: &str = "infinity.proposal.v1";
pub const POLICY_VERSION: &str = "infinity.policy.v1";
pub const DECISION_VERSION: &str = "infinity.decision.v1";
pub const RECEIPT_VERSION: &str = "infinity.receipt.v1";

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
#[derive(Debug, Error)]
pub enum KernelError {
    #[error("invalid JSON value: {0}")]
    Json(#[from] serde_json::Error),
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
fn receipt_material(r: &Receipt) -> Value {
    json!({
        "version": r.version, "previous_receipt_hash": r.previous_receipt_hash, "proposal_hash": r.proposal_hash,
        "policy_hash": r.policy_hash, "decision_hash": r.decision_hash, "verdict": r.verdict, "reason_codes": r.reason_codes
    })
}
pub fn issue_receipt(
    decision: &Decision,
    previous: Option<&Receipt>,
    issued_at: String,
) -> Result<Receipt, KernelError> {
    let mut receipt = Receipt {
        version: RECEIPT_VERSION.into(),
        receipt_id: String::new(),
        previous_receipt_hash: previous.map(|p| p.receipt_id.clone()),
        proposal_hash: decision.proposal_hash.clone(),
        policy_hash: decision.policy_hash.clone(),
        decision_hash: decision.decision_hash.clone(),
        verdict: decision.verdict.clone(),
        reason_codes: decision.reason_codes.clone(),
        issued_at,
    };
    receipt.receipt_id = format!("receipt:{}", hash_value(&receipt_material(&receipt))?);
    Ok(receipt)
}
pub fn verify_receipt(receipt: &Receipt) -> Result<bool, KernelError> {
    Ok(receipt.receipt_id == format!("receipt:{}", hash_value(&receipt_material(receipt))?))
}
pub fn verify_log(receipts: &[Receipt]) -> Result<bool, KernelError> {
    for (index, receipt) in receipts.iter().enumerate() {
        if !verify_receipt(receipt)?
            || receipt.previous_receipt_hash
                != (index.checked_sub(1).map(|i| receipts[i].receipt_id.clone()))
        {
            return Ok(false);
        }
    }
    Ok(true)
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
        assert!(verify_log(&[r.clone()]).unwrap());
        r.verdict = "deny".into();
        assert!(!verify_log(&[r]).unwrap());
    }
}
