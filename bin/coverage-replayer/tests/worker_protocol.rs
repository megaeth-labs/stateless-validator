//! The worker subprocess speaks its protocol on stdout and nothing else does:
//! drives the real binary as the dispatcher would and reads its answer.

use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};

#[test]
fn a_worker_answers_on_stdout_with_one_frame_per_request() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test_data/mainnet/genesis.json");
    // The worker resolves its tools at startup; this request fails before
    // either would run, so placeholders are enough.
    let tool = dir.path().join("llvm-tool");
    std::fs::write(&tool, b"").unwrap();
    let mut worker = Command::new(env!("CARGO_BIN_EXE_coverage-replayer"))
        .arg("internal-worker")
        .args(["--genesis-file", genesis])
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--llvm-profdata")
        .arg(&tool)
        .arg("--llvm-cov")
        .arg(&tool)
        .arg("--source-dir")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the worker");

    // A block whose spool entry does not exist: the worker must answer it,
    // as a failed block, rather than die.
    let request = format!(r#"{{"block":7,"spool":"{}"}}"#, dir.path().join("7.bin").display());
    let mut stdin = worker.stdin.take().unwrap();
    writeln!(stdin, "{request}").unwrap();
    drop(stdin);

    let lines: Vec<String> =
        BufReader::new(worker.stdout.take().unwrap()).lines().map(Result::unwrap).collect();
    assert!(worker.wait().unwrap().success());
    assert_eq!(lines.len(), 1, "exactly one frame and nothing else on stdout: {lines:?}");
    let frame: serde_json::Value = serde_json::from_str(&lines[0]).expect("a JSON frame");
    assert_eq!(frame["block"], 7);
    assert!(frame["error"].as_str().is_some_and(|e| !e.is_empty()), "{frame}");
}
