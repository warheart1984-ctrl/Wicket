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
    },
    Replay {
        #[arg(long)]
        fixture: String,
    },
    VerifyLog {
        #[arg(long)]
        log: String,
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
/// Lock the log, check the existing chain, then append a receipt linked to the last one.
fn append_chained(path: &str, decision: &Decision, issued_at: String) -> Result<Receipt, String> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.lock().map_err(|e| e.to_string())?;
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|e| e.to_string())?;
    let receipts = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Receipt>(line).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if !verify_log(&receipts).map_err(|e| e.to_string())? {
        return Err("refusing to append: existing log failed verification".into());
    }
    let receipt = issue_receipt(decision, receipts.last(), issued_at).map_err(|e| e.to_string())?;
    let line = serde_json::to_string(&receipt).map_err(|e| e.to_string())?;
    writeln!(file, "{line}").map_err(|e| e.to_string())?;
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
        } => {
            let p: Result<Proposal, _> = read(&proposal);
            let pol: Result<Policy, _> = read(&policy);
            p.and_then(|p| pol.map(|pol| (p, pol)))
                .and_then(|(p, pol)| {
                    let d = evaluate(p, pol, ApprovalSet::from_ids(approvals))
                        .map_err(|e| e.to_string())?;
                    let r = match &log {
                        Some(path) => append_chained(path, &d, issued_at)?,
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
        Command::VerifyLog { log } => {
            let lines = fs::read_to_string(log).map_err(|e| e.to_string())?;
            let receipts = lines
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str::<Receipt>(line).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?;
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
        let a = append_chained(&log, &decision("a"), "t".into()).unwrap();
        let b = append_chained(&log, &decision("b"), "t".into()).unwrap();
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
        append_chained(&log, &decision("a"), "t".into()).unwrap();
        append_chained(&log, &decision("b"), "t".into()).unwrap();
        let text = fs::read_to_string(&log).unwrap();
        let first = text
            .lines()
            .next()
            .unwrap()
            .replace("\"allow\"", "\"deny\"");
        let second = text.lines().nth(1).unwrap();
        fs::write(&log, format!("{first}\n{second}\n")).unwrap();
        assert!(append_chained(&log, &decision("c"), "t".into()).is_err());
        let _ = fs::remove_file(log);
    }
}
