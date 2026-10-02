use clap::{Parser, Subcommand};
use infinity_kernel::{
    evaluate, issue_receipt, verify_log, ApprovalSet, Decision, Policy, Proposal, Receipt,
};
use std::{
    fs,
    io::{Read, Write},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "infinityctl",
    about = "ICK — Infinity Constitutional Kernel CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Evaluate {
        #[arg(long)]
        proposal: String,
        #[arg(long)]
        policy: String,
        #[arg(long = "approval")]
        approvals: Vec<String>,
        #[arg(long, default_value = "demo-provenance")]
        issued_at: String,
        /// Append the receipt to this chained JSONL log (created if missing).
        #[arg(long)]
        log: Option<String>,
        /// With --log: also record an anchor (log length and latest receipt id) in this file.
        /// Keep the anchor file where whoever can edit the log cannot also edit it.
        #[arg(long, requires = "log")]
        anchor: Option<String>,
    },
    Replay {
        #[arg(long)]
        fixture: String,
    },
    VerifyLog {
        #[arg(long)]
        log: String,
        /// Also check the log against this anchor file (detects deleted or rewritten tails).
        #[arg(long)]
        anchor: Option<String>,
    },
    Demo {
        #[arg(long, default_value = "demo/receipts.live.jsonl")]
        log: String,
    },
}
fn read<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    serde_json::from_str(&fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
const ANCHOR_VERSION: &str = "infinity.anchor.v1";

/// Check every anchor in `anchor_text` against `receipts`: the receipt at position `count`
/// must still be the one that was anchored. A shorter log means receipts were deleted.
fn check_anchors(receipts: &[Receipt], anchor_text: &str) -> Result<(), String> {
    for (n, line) in anchor_text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let a: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("anchor line {}: {e}", n + 1))?;
        let count = a["count"].as_u64().unwrap_or(0) as usize;
        let head = a["head_receipt_id"].as_str().unwrap_or("");
        if a["version"] != ANCHOR_VERSION || count == 0 || head.is_empty() {
            return Err(format!("anchor line {} is malformed", n + 1));
        }
        match receipts.get(count - 1) {
            None => {
                return Err(format!(
                "log has {} receipts but anchor expects at least {count}: receipts were deleted",
                receipts.len()
            ))
            }
            Some(r) if r.receipt_id != head => {
                return Err(format!(
                    "receipt {count} does not match its anchor: the log was rewritten"
                ))
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn read_receipts(text: &str) -> Result<Vec<Receipt>, String> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Receipt>(line).map_err(|e| e.to_string()))
        .collect()
}

fn read_optional(path: &str) -> Result<String, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.to_string()),
    }
}

/// Lock the log, check the existing chain (and anchors), then append a receipt linked to the
/// last one. With an anchor file, record the new log length and head receipt id there too.
fn append_chained(
    path: &str,
    anchor: Option<&str>,
    decision: &Decision,
    issued_at: String,
) -> Result<Receipt, String> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.lock().map_err(|e| e.to_string())?;
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|e| e.to_string())?;
    let receipts = read_receipts(&text)?;
    if !verify_log(&receipts).map_err(|e| e.to_string())? {
        return Err("refusing to append: existing log failed verification".into());
    }
    if let Some(anchor_path) = anchor {
        check_anchors(&receipts, &read_optional(anchor_path)?)
            .map_err(|e| format!("refusing to append: {e}"))?;
    }
    let receipt = issue_receipt(decision, receipts.last(), issued_at).map_err(|e| e.to_string())?;
    let line = serde_json::to_string(&receipt).map_err(|e| e.to_string())?;
    writeln!(file, "{line}").map_err(|e| e.to_string())?;
    if let Some(anchor_path) = anchor {
        let record = serde_json::json!({
            "version": ANCHOR_VERSION,
            "count": receipts.len() + 1,
            "head_receipt_id": receipt.receipt_id,
        });
        let mut out = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(anchor_path)
            .map_err(|e| e.to_string())?;
        writeln!(out, "{record}").map_err(|e| e.to_string())?;
    }
    Ok(receipt)
}
fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Evaluate {
            proposal,
            policy,
            approvals,
            issued_at,
            log,
            anchor,
        } => {
            let p: Result<Proposal, _> = read(&proposal);
            let pol: Result<Policy, _> = read(&policy);
            p.and_then(|p| pol.map(|pol| (p, pol)))
                .and_then(|(p, pol)| {
                    let d = evaluate(p, pol, ApprovalSet::from_ids(approvals))
                        .map_err(|e| e.to_string())?;
                    let r = match &log {
                        Some(path) => append_chained(path, anchor.as_deref(), &d, issued_at)?,
                        None => issue_receipt(&d, None, issued_at).map_err(|e| e.to_string())?,
                    };
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({"decision":d,"receipt":r})
                        )
                        .expect("JSON")
                    );
                    Ok(())
                })
        }
        Command::Replay { fixture } => {
            let value: serde_json::Value = read(&fixture)?;
            let p: Proposal =
                serde_json::from_value(value["proposal"].clone()).map_err(|e| e.to_string())?;
            let pol: Policy =
                serde_json::from_value(value["policy"].clone()).map_err(|e| e.to_string())?;
            let ids = value["approvals"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>();
            let decision =
                evaluate(p, pol, ApprovalSet::from_ids(ids)).map_err(|e| e.to_string())?;
            if let Some(expected) = value.get("expected") {
                for key in [
                    "verdict",
                    "reason_codes",
                    "proposal_hash",
                    "policy_hash",
                    "decision_hash",
                ] {
                    if expected.get(key).is_some()
                        && expected.get(key)
                            != serde_json::to_value(&decision)
                                .ok()
                                .as_ref()
                                .and_then(|v| v.get(key))
                    {
                        return Err(format!("fixture mismatch: {key}"));
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&decision).expect("JSON"));
            Ok(())
        }
        Command::VerifyLog { log, anchor } => {
            let lines = fs::read_to_string(log).map_err(|e| e.to_string())?;
            let receipts = read_receipts(&lines)?;
            if let Some(anchor_path) = anchor {
                let text = fs::read_to_string(anchor_path).map_err(|e| e.to_string())?;
                check_anchors(&receipts, &text)?;
            }
            if verify_log(&receipts).map_err(|e| e.to_string())? {
                println!("log verified: {} receipts", receipts.len());
                Ok(())
            } else {
                Err("possible rollback or receipt tampering".into())
            }
        }
        Command::Demo { log } => {
            let sequence = [
                "fixtures/allow-safe-read.v1.json",
                "fixtures/deny-g3-authority-change.v1.json",
                "fixtures/await-effectful-write.v1.json",
                "fixtures/allow-approved-write.v1.json",
            ];
            let mut previous: Option<Receipt> = None;
            let mut receipts = Vec::new();
            for (index, fixture) in sequence.iter().enumerate() {
                let value: serde_json::Value = read(fixture)?;
                let proposal: Proposal =
                    serde_json::from_value(value["proposal"].clone()).map_err(|e| e.to_string())?;
                let policy: Policy =
                    serde_json::from_value(value["policy"].clone()).map_err(|e| e.to_string())?;
                let approvals = value["approvals"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect::<Vec<_>>();
                let decision = evaluate(proposal, policy, ApprovalSet::from_ids(approvals))
                    .map_err(|e| e.to_string())?;
                let receipt = issue_receipt(
                    &decision,
                    previous.as_ref(),
                    format!("demo-sequence-{index}"),
                )
                .map_err(|e| e.to_string())?;
                println!(
                    "{} -> {} ({})",
                    fixture, decision.verdict, receipt.receipt_id
                );
                previous = Some(receipt.clone());
                receipts.push(receipt);
            }
            let jsonl = receipts
                .into_iter()
                .map(|r| serde_json::to_string(&r).expect("JSON"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            fs::write(log, jsonl).map_err(|e| e.to_string())?;
            Ok(())
        }
    }
}
fn main() -> ExitCode {
    let result = run(Cli::parse().command);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}
fn fail(message: String) -> ExitCode {
    eprintln!("infinityctl: {message}");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(id: &str) -> Decision {
        let p: Proposal = serde_json::from_value(serde_json::json!({
            "version": "infinity.proposal.v1", "proposal_id": id,
            "actor": {"kind": "agent", "id": "t"}, "action": "get_status", "target": "x",
            "effect": "read", "risk": "low", "requires_human_approval": false,
            "policy_version": "p", "payload": {}, "evidence_refs": []
        }))
        .unwrap();
        let pol: Policy = serde_json::from_value(serde_json::json!({
            "version": "infinity.policy.v1", "policy_id": "p"
        }))
        .unwrap();
        evaluate(p, pol, ApprovalSet::from_ids(Vec::new())).unwrap()
    }

    fn temp_log(name: &str) -> String {
        let path = std::env::temp_dir().join(format!("ick-{name}-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn appended_receipts_form_a_verifiable_chain() {
        let log = temp_log("chain");
        let a = append_chained(&log, None, &decision("a"), "t".into()).unwrap();
        let b = append_chained(&log, None, &decision("b"), "t".into()).unwrap();
        assert_eq!(a.previous_receipt_hash, None);
        assert_eq!(b.previous_receipt_hash, Some(a.receipt_id));
        let text = fs::read_to_string(&log).unwrap();
        let receipts: Vec<Receipt> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert!(verify_log(&receipts).unwrap());
        let _ = fs::remove_file(log);
    }

    #[test]
    fn refuses_to_append_to_a_tampered_log() {
        let log = temp_log("tamper");
        append_chained(&log, None, &decision("a"), "t".into()).unwrap();
        append_chained(&log, None, &decision("b"), "t".into()).unwrap();
        let text = fs::read_to_string(&log).unwrap();
        let first = text
            .lines()
            .next()
            .unwrap()
            .replace("\"allow\"", "\"deny\"");
        let second = text.lines().nth(1).unwrap();
        fs::write(&log, format!("{first}\n{second}\n")).unwrap();
        assert!(append_chained(&log, None, &decision("c"), "t".into()).is_err());
        let _ = fs::remove_file(log);
    }

    #[test]
    fn anchor_detects_deleted_tail_and_blocks_appending() {
        let (log, anchor) = (temp_log("anchor"), temp_log("anchor-file"));
        for id in ["a", "b", "c"] {
            append_chained(&log, Some(&anchor), &decision(id), "t".into()).unwrap();
        }
        let text = fs::read_to_string(&log).unwrap();
        let anchors = fs::read_to_string(&anchor).unwrap();
        assert!(check_anchors(&read_receipts(&text).unwrap(), &anchors).is_ok());
        // Delete the last receipt: the chain alone still verifies, the anchor does not.
        let cut = text.lines().take(2).collect::<Vec<_>>().join("\n") + "\n";
        fs::write(&log, &cut).unwrap();
        assert!(verify_log(&read_receipts(&cut).unwrap()).unwrap());
        let err = check_anchors(&read_receipts(&cut).unwrap(), &anchors).unwrap_err();
        assert!(err.contains("deleted"), "{err}");
        // And the runtime refuses to continue from the shortened log.
        assert!(append_chained(&log, Some(&anchor), &decision("d"), "t".into()).is_err());
        let _ = fs::remove_file(log);
        let _ = fs::remove_file(anchor);
    }

    #[test]
    fn anchor_detects_a_rewritten_log() {
        let (log, anchor) = (temp_log("rewrite"), temp_log("rewrite-anchor"));
        append_chained(&log, Some(&anchor), &decision("a"), "t".into()).unwrap();
        append_chained(&log, Some(&anchor), &decision("b"), "t".into()).unwrap();
        // Replace the whole log with a different, internally valid chain.
        let other = temp_log("other");
        append_chained(&other, None, &decision("x"), "t".into()).unwrap();
        append_chained(&other, None, &decision("y"), "t".into()).unwrap();
        let forged = fs::read_to_string(&other).unwrap();
        let anchors = fs::read_to_string(&anchor).unwrap();
        let err = check_anchors(&read_receipts(&forged).unwrap(), &anchors).unwrap_err();
        assert!(err.contains("rewritten"), "{err}");
        for f in [log, anchor, other] {
            let _ = fs::remove_file(f);
        }
    }
}
