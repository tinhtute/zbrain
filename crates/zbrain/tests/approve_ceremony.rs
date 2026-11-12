//! `claim approve` must not be reachable from a non-interactive caller.
//!
//! The owner ceremony is the only approval path: the binary refuses without an
//! interactive terminal, and the draft stays a draft.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn temp_home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zbrain-approve-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn zbrain(home: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zbrain"));
    command
        .env("ZBRAIN_HOME", home)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn zbrain");
    if let Some(body) = stdin {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(body.as_bytes())
            .unwrap();
    }
    child.wait_with_output().expect("wait for zbrain")
}

#[test]
fn claim_approve_refuses_without_tty() {
    let home = temp_home("no-tty");
    assert!(zbrain(&home, &["setup"], None).status.success());
    assert!(zbrain(&home, &["workspace", "create", "ws"], None)
        .status
        .success());

    let draft = zbrain(
        &home,
        &[
            "claim",
            "draft",
            "--tier",
            "projects",
            "--title",
            "Agent fact",
            "--basis",
            "owner",
        ],
        Some("agent wrote this\n"),
    );
    assert!(draft.status.success());
    let draft: serde_json::Value = serde_json::from_slice(&draft.stdout).unwrap();
    let id = draft["id"].as_str().unwrap().to_string();
    let claim_path = home
        .join("workspaces/ws/wiki")
        .join(draft["path"].as_str().unwrap());

    let approve = zbrain(&home, &["claim", "approve", &id], None);
    let stderr = String::from_utf8_lossy(&approve.stderr);
    assert!(
        !approve.status.success(),
        "claim approve must refuse without a TTY; stdout = {}",
        String::from_utf8_lossy(&approve.stdout)
    );
    assert!(
        stderr.contains("interactive terminal (TTY)"),
        "stderr = {stderr}"
    );
    let contents = std::fs::read_to_string(&claim_path).unwrap();
    assert!(
        contents.contains("status: draft"),
        "claim was mutated: {contents}"
    );
}
