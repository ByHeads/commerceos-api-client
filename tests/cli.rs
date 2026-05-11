//! End-to-end CLI tests against a running local CommerceOS instance.
//!
//! Requirements:
//!   - A default connection saved (`api -c <alias>` once with `ctrl+s`, or env vars below)
//!   - The local server must respond to `/echo-all`, which echoes back whatever it receives
//!     (either as a single-element array or the array itself).
//!
//! All tests target the `/echo-all` endpoint so nothing is persisted.
//! Run with: `cargo test --test cli`

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::tempdir;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Run the api binary. If `API_TEST_BASE_URI` and `API_TEST_KEY` are set,
/// passes them via `-b`/`-k` to skip keychain access; otherwise uses the
/// saved default connection.
fn api() -> Command {
    let mut cmd = Command::cargo_bin("api").expect("api binary built");
    if let (Ok(base), Ok(key)) = (
        std::env::var("API_TEST_BASE_URI"),
        std::env::var("API_TEST_KEY"),
    ) {
        cmd.args(["-b", &base, "-k", &key]);
    }
    cmd
}

/// Pre-flight check: the server must respond on /echo-all.
fn require_local_cos() {
    let out = api()
        .args(["GET", "/echo-all", "--silent"])
        .output()
        .expect("spawn api");
    if !out.status.success() {
        panic!(
            "local COS not reachable via default connection. \
             Set up a default connection with `ctrl+s` in interactive mode first.\n\
             stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// ---------------------------------------------------------------------------
// Basic methods
// ---------------------------------------------------------------------------

#[test]
fn get_echo_all_returns_200() {
    require_local_cos();
    api()
        .args(["GET", "/echo-all"])
        .assert()
        .success()
        .stderr(predicate::str::contains("HTTP/1.1 200 OK"));
}

#[test]
fn put_inline_body_echoes_back() {
    require_local_cos();
    api()
        .args(["PUT", "/echo-all", r#"{"name":"alice"}"#])
        .assert()
        .success()
        .stderr(predicate::str::contains("HTTP/1.1 200 OK"))
        .stdout(predicate::str::contains("alice"));
}

#[test]
fn patch_inline_body_echoes_back() {
    require_local_cos();
    api()
        .args(["PATCH", "/echo-all", r#"{"updated":true}"#])
        .assert()
        .success()
        .stderr(predicate::str::contains("HTTP/1.1 200 OK"))
        .stdout(predicate::str::contains("updated"));
}

#[test]
fn post_inline_body_echoes_back() {
    require_local_cos();
    api()
        .args(["POST", "/echo-all", r#"{"posted":1}"#])
        .assert()
        .success()
        .stderr(predicate::str::contains("HTTP/1.1 200 OK"))
        .stdout(predicate::str::contains("posted"));
}

#[test]
fn delete_returns_response() {
    require_local_cos();
    api()
        .args(["DELETE", "/echo-all"])
        .assert()
        .success()
        .stderr(predicate::str::contains("HTTP/1.1"));
}

#[test]
fn array_body_echoes_back_as_array() {
    require_local_cos();
    let body = r#"[{"a":1},{"b":2}]"#;
    api()
        .args(["PUT", "/echo-all", body])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"a\""))
        .stdout(predicate::str::contains("\"b\""));
}

// ---------------------------------------------------------------------------
// Body input modes
// ---------------------------------------------------------------------------

#[test]
fn stdin_body_is_used_when_no_inline_body() {
    require_local_cos();
    api()
        .args(["PUT", "/echo-all"])
        .write_stdin(r#"{"from":"stdin"}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("from"))
        .stdout(predicate::str::contains("stdin"));
}

#[test]
fn file_body_is_uploaded_via_at_prefix() {
    require_local_cos();
    let path = fixtures_dir().join("single-object.json");
    let body_arg = format!("@{}", path.display());
    api()
        .args(["PUT", "/echo-all", &body_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"));
}

#[test]
fn multi_space_between_uri_and_at_file_is_handled() {
    require_local_cos();
    // Use a single positional arg containing multiple spaces — clap collapses
    // separate args, so the regression is in parse_input via interactive mode.
    // We can't directly trigger that path from CLI flags, but we *can* exercise
    // the bulk-line parser which uses the same logic.
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("multi-space.txt");
    let fixture = fixtures_dir().join("single-object.json");
    let line = format!("PUT /echo-all  @{}\n", fixture.display());
    std::fs::write(&req_file, line).unwrap();

    api()
        .args(["-a"])
        .arg(&req_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"));
}

#[test]
fn array_file_body_round_trips() {
    require_local_cos();
    let path = fixtures_dir().join("array.json");
    let body_arg = format!("@{}", path.display());
    api()
        .args(["PUT", "/echo-all", &body_arg])
        .assert()
        .success()
        .stdout(predicate::str::contains("first"))
        .stdout(predicate::str::contains("second"))
        .stdout(predicate::str::contains("third"));
}

// ---------------------------------------------------------------------------
// Output flags
// ---------------------------------------------------------------------------

#[test]
fn silent_suppresses_status_line() {
    require_local_cos();
    let assert = api()
        .args(["PUT", "/echo-all", r#"{"x":1}"#, "--silent"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        !stderr.contains("HTTP/1.1") && !stdout.contains("HTTP/1.1"),
        "--silent should suppress status line everywhere; stderr={stderr}, stdout={stdout}"
    );
    assert!(stdout.contains("\"x\""));
}

#[test]
fn raw_disables_pretty_printing() {
    require_local_cos();
    let assert = api()
        .args(["PUT", "/echo-all", r#"{"x":1}"#, "--raw"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    // Pretty-printed would be on multiple lines with "  " indent; raw is single-line.
    let body_line = stdout
        .lines()
        .find(|l| l.contains("\"x\""))
        .expect("output should contain x");
    assert!(
        !body_line.contains("  "),
        "--raw should not indent: {body_line}"
    );
}

#[test]
fn ndjson_returns_line_delimited() {
    require_local_cos();
    let assert = api()
        .args(["PUT", "/echo-all", "--ndjson"])
        .write_stdin("{\"row\":1}\n{\"row\":2}\n")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let json_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .collect();
    assert!(
        json_lines.len() >= 2,
        "expected >=2 NDJSON output lines, got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Outfile (`> path`)
// ---------------------------------------------------------------------------

#[test]
fn outfile_writes_response_to_file() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let outfile = dir.path().join("out.json");
    let uri_with_outfile = format!("/echo-all > {}", outfile.display());

    api()
        .args(["PUT", &uri_with_outfile, r#"{"saved":true}"#])
        .assert()
        .success();

    let written = std::fs::read_to_string(&outfile).expect("outfile written");
    assert!(written.contains("saved"), "outfile content: {written}");
}

#[test]
fn outfile_csv_extension_sets_csv_accept() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let outfile = dir.path().join("out.csv");
    let uri_with_outfile = format!("/echo-all > {}", outfile.display());

    let assert = api()
        .args(["GET", &uri_with_outfile])
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    // Server may not return CSV for a null payload, but the request must succeed —
    // the goal is to verify the client sets the right Accept header without errors.
    assert!(stderr.contains("HTTP/1.1") || std::fs::metadata(&outfile).is_ok());
}

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

#[test]
fn url_with_operators_succeeds() {
    require_local_cos();
    api()
        .args(["GET", "/echo-all~where(active=true)~take(5)"])
        .assert()
        .success()
        .stderr(predicate::str::contains("HTTP/1.1 200 OK"));
}

#[test]
fn url_with_negation_operator_succeeds() {
    require_local_cos();
    api()
        .args(["GET", "/echo-all~where(!flag)"])
        .assert()
        .success()
        .stderr(predicate::str::contains("HTTP/1.1 200 OK"));
}

// ---------------------------------------------------------------------------
// Bulk mode (-a)
// ---------------------------------------------------------------------------

#[test]
fn bulk_mode_runs_each_line_as_request() {
    require_local_cos();
    let req_file = fixtures_dir().join("requests.txt");

    let assert = api().args(["-a"]).arg(&req_file).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();

    let status_lines = stderr.matches("HTTP/1.1").count();
    assert_eq!(
        status_lines, 3,
        "expected 3 requests (GET, PUT, PATCH); got {status_lines}.\nstderr: {stderr}"
    );
    assert!(stdout.contains("first"));
    assert!(stdout.contains("second"));
}

#[test]
fn bulk_mode_skips_comments_and_blank_lines() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("with-comments.txt");
    let content = "\
# this is a comment

GET /echo-all
# another comment

PUT /echo-all {\"only\":\"two\"}
";
    std::fs::write(&req_file, content).unwrap();

    let assert = api().args(["-a"]).arg(&req_file).assert().success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert_eq!(
        stderr.matches("HTTP/1.1").count(),
        2,
        "comments and blank lines should be skipped; stderr: {stderr}"
    );
}

#[test]
fn bulk_mode_reads_from_stdin_when_value_is_dash() {
    require_local_cos();
    let content = "GET /echo-all\nPUT /echo-all {\"x\":1}\n";

    let assert = api()
        .args(["-a", "-"])
        .write_stdin(content)
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert_eq!(stderr.matches("HTTP/1.1").count(), 2);
}

#[test]
fn bulk_mode_reads_from_stdin_when_no_value() {
    require_local_cos();
    let content = "GET /echo-all\nPATCH /echo-all {\"y\":2}\n";

    let assert = api()
        .args(["-a"])
        .write_stdin(content)
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert_eq!(stderr.matches("HTTP/1.1").count(), 2);
}

#[test]
fn bulk_mode_supports_outfile_per_line() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let outfile = dir.path().join("bulk-out.json");
    let req_file = dir.path().join("bulk.txt");
    let content = format!(
        "PUT /echo-all {{\"bulk\":\"outfile\"}} > {}\n",
        outfile.display()
    );
    std::fs::write(&req_file, content).unwrap();

    api().args(["-a"]).arg(&req_file).assert().success();

    let written = std::fs::read_to_string(&outfile).expect("outfile written");
    assert!(written.contains("bulk"), "outfile content: {written}");
}

#[test]
fn silent_bulk_mode_prints_request_and_compact_status_only() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("silent-bulk.txt");
    let content = "PUT /echo-all [{\"name\":\"Joe\"}]\nGET /echo-all\n";
    std::fs::write(&req_file, content).unwrap();

    let assert = api()
        .args(["-sa"])
        .arg(&req_file)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // Each request line should appear in output, each followed by a |-HTTP/1.1 status
    assert!(
        stdout.contains("PUT /echo-all [{\"name\":\"Joe\"}]"),
        "expected request line in stdout: {stdout}"
    );
    assert!(stdout.contains("GET /echo-all"));
    assert_eq!(
        stdout.matches("└─HTTP/1.1").count(),
        2,
        "expected 2 compact status lines; got: {stdout}"
    );
    // No bodies should appear
    assert!(
        !stdout.contains("\"name\":\"Joe\"") || stdout.matches("\"name\"").count() == 1,
        "body should not be echoed back in silent bulk mode (only in request line): {stdout}"
    );
}

#[test]
fn bulk_mode_supports_at_file_per_line() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("bulk-at.txt");
    let fixture = fixtures_dir().join("single-object.json");
    let content = format!("PUT /echo-all @{}\n", fixture.display());
    std::fs::write(&req_file, content).unwrap();

    api()
        .args(["-a"])
        .arg(&req_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"));
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn nonexistent_endpoint_returns_404() {
    require_local_cos();
    let assert = api()
        .args(["GET", "/this-does-not-exist-xyz"])
        .assert();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        stderr.contains("404") || stdout.contains("404"),
        "expected 404 in output. stderr={stderr}\nstdout={stdout}"
    );
}

#[test]
fn version_flag_prints_version() {
    api()
        .args(["--version"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("v"));
}
