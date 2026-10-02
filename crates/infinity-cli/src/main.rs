use clap::{Parser, Subcommand};
use infinity_kernel::{
    evaluate, issue_receipt, verify_log, ApprovalSet, Policy, Proposal, Receipt,
};
use std::{fs, process::ExitCode};

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
fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Evaluate {
            proposal,
            policy,
            approvals,
            issued_at,
        } => {
            let p: Result<Proposal, _> = read(&proposal);
            let pol: Result<Policy, _> = read(&policy);
            p.and_then(|p| pol.map(|pol| (p, pol)))
                .and_then(|(p, pol)| {
                    let d = evaluate(p, pol, ApprovalSet::from_ids(approvals))
                        .map_err(|e| e.to_string())?;
                    let r = issue_receipt(&d, None, issued_at).map_err(|e| e.to_string())?;
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
