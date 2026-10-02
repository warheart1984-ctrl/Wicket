use clap::{Parser, Subcommand};
use infinity_kernel::{
    evaluate, issue_outcome, issue_receipt, summarize, verify_log, ApprovalSet, Decision, LogEntry,
    Policy, Proposal,
};
use std::{
    fs,
    io::{Read, Write},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
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
        /// Time to record in the receipt (RFC 3339). Default: the current UTC time.
        #[arg(long)]
        issued_at: Option<String>,
        /// Append the receipt to this chained JSONL log (created if missing).
        #[arg(long)]
        log: Option<String>,
        /// With --log: also record an anchor (log length and latest receipt id) in this file.
        /// Keep the anchor file where whoever can edit the log cannot also edit it.
        #[arg(long, requires = "log")]
        anchor: Option<String>,
    },
    /// Record what happened after an `allow`, in the same chained log.
    RecordOutcome {
        #[arg(long)]
        log: String,
        #[arg(long)]
        anchor: Option<String>,
        /// Receipt id of the `allow` decision this outcome belongs to.
        #[arg(long)]
        decision_receipt: String,
        #[arg(long, value_parser = ["completed", "failed"])]
        status: String,
        /// sha256:<64 hex> of the request. Never the request itself.
        #[arg(long)]
        request_sha256: Option<String>,
        /// sha256:<64 hex> of the reply. Never the reply itself.
        #[arg(long)]
        response_sha256: Option<String>,
        #[arg(long)]
        issued_at: Option<String>,
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
fn check_anchors(receipts: &[LogEntry], anchor_text: &str) -> Result<(), String> {
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
            Some(r) if r.receipt_id() != head => {
                return Err(format!(
                    "receipt {count} does not match its anchor: the log was rewritten"
                ))
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Seconds since 1970 as `YYYY-MM-DDTHH:MM:SSZ` (UTC), without a date library.
fn rfc3339_from_unix(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (hour, minute, second) = (rem / 3600, rem % 3600 / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// The time to put in a receipt: the caller's, or else the clock. A clock set before 1970 is an
/// error, not a silent 1970 timestamp.
fn issued_at_or_now(given: Option<String>) -> Result<String, String> {
    if let Some(at) = given {
        return Ok(at);
    }
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the system clock is before 1970; pass --issued-at".to_string())?
        .as_secs();
    Ok(rfc3339_from_unix(secs as i64))
}

fn read_entries(text: &str) -> Result<Vec<LogEntry>, String> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<LogEntry>(line).map_err(|e| e.to_string()))
        .collect()
}

fn read_optional(path: &str) -> Result<String, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.to_string()),
    }
}

/// Lock the log, check the existing chain (and anchors), then append one entry linked to the last
/// one. `make` builds the entry from the previous one. The whole log is verified again with the new
/// entry in place, so an outcome that answers nothing, or a second outcome for one decision, is
/// refused here and never reaches the file. With an anchor file, the new log length and head
/// receipt id are recorded there too.
fn append_entry(
    path: &str,
    anchor: Option<&str>,
    make: impl FnOnce(Option<&LogEntry>) -> Result<LogEntry, String>,
) -> Result<LogEntry, String> {
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
    if !verify_log(&entries).map_err(|e| e.to_string())? {
        return Err("refusing to append: existing log failed verification".into());
    }
    if let Some(anchor_path) = anchor {
        check_anchors(&entries, &read_optional(anchor_path)?)
            .map_err(|e| format!("refusing to append: {e}"))?;
    }
    let entry = make(entries.last())?;
    entries.push(entry.clone());
    if !verify_log(&entries).map_err(|e| e.to_string())? {
        return Err(
            "refusing to append: an outcome must answer an earlier `allow` that has no outcome yet"
                .into(),
        );
    }
    let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
    writeln!(file, "{line}").map_err(|e| e.to_string())?;
    if let Some(anchor_path) = anchor {
        let record = serde_json::json!({
            "version": ANCHOR_VERSION,
            "count": entries.len(),
            "head_receipt_id": entry.receipt_id(),
        });
        let mut out = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(anchor_path)
            .map_err(|e| e.to_string())?;
        writeln!(out, "{record}").map_err(|e| e.to_string())?;
    }
    Ok(entry)
}

fn append_chained(
    path: &str,
    anchor: Option<&str>,
    decision: &Decision,
    issued_at: String,
) -> Result<LogEntry, String> {
    append_entry(path, anchor, |previous| {
        issue_receipt(decision, previous, issued_at)
            .map(LogEntry::Decision)
            .map_err(|e| e.to_string())
    })
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
            let issued_at = issued_at_or_now(issued_at)?;
            let p: Result<Proposal, _> = read(&proposal);
            let pol: Result<Policy, _> = read(&policy);
            p.and_then(|p| pol.map(|pol| (p, pol)))
                .and_then(|(p, pol)| {
                    let d = evaluate(p, pol, ApprovalSet::from_ids(approvals))
                        .map_err(|e| e.to_string())?;
                    let r = match &log {
                        Some(path) => append_chained(path, anchor.as_deref(), &d, issued_at)?,
                        None => issue_receipt(&d, None, issued_at)
                            .map(LogEntry::Decision)
                            .map_err(|e| e.to_string())?,
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
        Command::RecordOutcome {
            log,
            anchor,
            decision_receipt,
            status,
            request_sha256,
            response_sha256,
            issued_at,
        } => {
            let issued_at = issued_at_or_now(issued_at)?;
            let entry = append_entry(&log, anchor.as_deref(), |previous| {
                issue_outcome(
                    &decision_receipt,
                    &status,
                    request_sha256,
                    response_sha256,
                    previous,
                    issued_at,
                )
                .map(LogEntry::Outcome)
                .map_err(|e| e.to_string())
            })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "outcome": entry }))
                    .expect("JSON")
            );
            Ok(())
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
            let receipts = read_entries(&lines)?;
            if let Some(anchor_path) = anchor {
                let text = fs::read_to_string(anchor_path).map_err(|e| e.to_string())?;
                check_anchors(&receipts, &text)?;
            }
            if verify_log(&receipts).map_err(|e| e.to_string())? {
                let summary = summarize(&receipts);
                println!(
                    "log verified: {} receipts ({} decisions, {} outcomes, {} allowed without an outcome)",
                    receipts.len(),
                    summary.decisions,
                    summary.outcomes,
                    summary.allows_without_outcome
                );
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
            let mut previous: Option<LogEntry> = None;
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
                let entry = LogEntry::Decision(receipt);
                previous = Some(entry.clone());
                receipts.push(entry);
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
        assert_eq!(a.previous_receipt_hash(), None);
        assert_eq!(b.previous_receipt_hash(), Some(a.receipt_id()));
        let text = fs::read_to_string(&log).unwrap();
        let receipts: Vec<LogEntry> = text
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
        assert!(check_anchors(&read_entries(&text).unwrap(), &anchors).is_ok());
        // Delete the last receipt: the chain alone still verifies, the anchor does not.
        let cut = text.lines().take(2).collect::<Vec<_>>().join("\n") + "\n";
        fs::write(&log, &cut).unwrap();
        assert!(verify_log(&read_entries(&cut).unwrap()).unwrap());
        let err = check_anchors(&read_entries(&cut).unwrap(), &anchors).unwrap_err();
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
        let err = check_anchors(&read_entries(&forged).unwrap(), &anchors).unwrap_err();
        assert!(err.contains("rewritten"), "{err}");
        for f in [log, anchor, other] {
            let _ = fs::remove_file(f);
        }
    }

    #[test]
    fn unix_time_is_formatted_as_utc_rfc3339() {
        // Expected strings were produced by Python's datetime, not by this code.
        for (secs, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:01Z"),
            (86399, "1970-01-01T23:59:59Z"),
            (86400, "1970-01-02T00:00:00Z"),
            (951782400, "2000-02-29T00:00:00Z"),
            (1709164800, "2024-02-29T00:00:00Z"),
            (1790941376, "2026-10-02T11:42:56Z"),
            (4102444800, "2100-01-01T00:00:00Z"),
            (253402300799, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(rfc3339_from_unix(secs), expected, "{secs}");
        }
    }

    #[test]
    fn a_given_time_is_kept_and_the_default_is_the_clock() {
        assert_eq!(
            issued_at_or_now(Some("whenever".into())).unwrap(),
            "whenever"
        );
        let now = issued_at_or_now(None).unwrap();
        assert_eq!(now.len(), 20, "{now}");
        assert!(
            now.starts_with("20") && now.ends_with('Z') && &now[10..11] == "T",
            "{now}"
        );
    }

    fn sha(c: char) -> Option<String> {
        Some(format!("sha256:{}", c.to_string().repeat(64)))
    }

    fn outcome_for(
        log: &str,
        anchor: Option<&str>,
        decision_receipt: &str,
    ) -> Result<LogEntry, String> {
        append_entry(log, anchor, |previous| {
            issue_outcome(
                decision_receipt,
                "completed",
                sha('a'),
                sha('b'),
                previous,
                "t".into(),
            )
            .map(LogEntry::Outcome)
            .map_err(|e| e.to_string())
        })
    }

    #[test]
    fn an_outcome_is_appended_to_the_same_chain_and_anchored() {
        let (log, anchor) = (temp_log("out"), temp_log("out-anchor"));
        let allow = append_chained(&log, Some(&anchor), &decision("a"), "t".into()).unwrap();
        let outcome = outcome_for(&log, Some(&anchor), allow.receipt_id()).unwrap();
        assert_eq!(outcome.previous_receipt_hash(), Some(allow.receipt_id()));
        let entries = read_entries(&fs::read_to_string(&log).unwrap()).unwrap();
        assert!(verify_log(&entries).unwrap());
        assert_eq!(entries.len(), 2);
        // the anchor counts outcomes too, so deleting an outcome from the end is caught
        let anchors = fs::read_to_string(&anchor).unwrap();
        assert!(check_anchors(&entries, &anchors).is_ok());
        let err = check_anchors(&entries[..1], &anchors).unwrap_err();
        assert!(err.contains("deleted"), "{err}");
        for f in [log, anchor] {
            let _ = fs::remove_file(f);
        }
    }

    #[test]
    fn an_outcome_that_answers_nothing_is_never_written() {
        let log = temp_log("bad-out");
        let allow = append_chained(&log, None, &decision("a"), "t".into()).unwrap();
        let before = fs::read_to_string(&log).unwrap();
        assert!(outcome_for(&log, None, "receipt:sha3-256:nope").is_err());
        outcome_for(&log, None, allow.receipt_id()).unwrap();
        let once = fs::read_to_string(&log).unwrap();
        assert!(
            outcome_for(&log, None, allow.receipt_id()).is_err(),
            "one outcome per decision"
        );
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            once,
            "a refused outcome leaves the log alone"
        );
        assert_ne!(before, once);
        let _ = fs::remove_file(log);
    }

    #[test]
    fn an_outcome_cannot_be_recorded_for_a_denied_request() {
        let log = temp_log("deny-out");
        let denied = {
            let mut p = decision("a");
            p.verdict = "deny".into();
            p
        };
        let held = append_chained(&log, None, &denied, "t".into()).unwrap();
        assert!(outcome_for(&log, None, held.receipt_id()).is_err());
        let _ = fs::remove_file(log);
    }

    #[test]
    fn a_log_with_an_edited_timestamp_is_refused_for_appending() {
        let log = temp_log("time");
        append_chained(&log, None, &decision("a"), "2026-10-01T10:00:00Z".into()).unwrap();
        let text = fs::read_to_string(&log)
            .unwrap()
            .replace("2026-10-01T10:00:00Z", "1999-01-01T00:00:00Z");
        fs::write(&log, text).unwrap();
        assert!(append_chained(&log, None, &decision("b"), "t".into()).is_err());
        let _ = fs::remove_file(log);
    }
}
