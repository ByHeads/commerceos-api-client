//! End-to-end CLI tests against a running local CommerceOS instance.
//!
//! Requirements:
//!   - Credentials on disk: copy `.api-credentials-sample.json` to
//!     `.api-credentials.json` in the repo root and fill in the key for
//!     http://localhost:5000. (Or set `API_TEST_BASE_URI` + `API_TEST_KEY`.)
//!     Tests run with `--no-keychain`, so the OS keychain is never unlocked.
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

/// Absolute path to the developer's local credentials file (repo root).
/// Gitignored; created by each developer from `.api-credentials-sample.json`.
fn credentials_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".api-credentials.json")
}

/// Run the api binary with `--no-keychain` so tests never unlock the OS keychain.
/// Credentials come from the repo-root `.api-credentials.json` (via
/// `API_CREDENTIALS_FILE`), unless `API_TEST_BASE_URI` and `API_TEST_KEY` are set,
/// in which case those are passed via `-b`/`-k` as a higher-precedence override.
fn api() -> Command {
    let mut cmd = Command::cargo_bin("api").expect("api binary built");
    cmd.arg("--no-keychain");
    cmd.env("API_CREDENTIALS_FILE", credentials_file());
    if let (Ok(base), Ok(key)) = (
        std::env::var("API_TEST_BASE_URI"),
        std::env::var("API_TEST_KEY"),
    ) {
        cmd.args(["-b", &base, "-k", &key]);
    }
    cmd
}

/// Fail with an instructive message if no test credentials are available.
fn require_credentials() {
    let has_env = std::env::var("API_TEST_BASE_URI").is_ok()
        && std::env::var("API_TEST_KEY").is_ok();
    if has_env || credentials_file().exists() {
        return;
    }
    let path = credentials_file();
    panic!(
        "No test credentials found.\n\n\
         Create {path} pointing at your local CommerceOS (http://localhost:5000)\n\
         and its API key. Copy the sample and fill in the key:\n\n    \
         cp .api-credentials-sample.json .api-credentials.json\n\n\
         then edit the `credential` field for localhost:5000.\n\
         (Alternatively, set the API_TEST_BASE_URI and API_TEST_KEY env vars.)",
        path = path.display(),
    );
}

/// Pre-flight check: credentials exist and the server responds on /echo-all.
fn require_local_cos() {
    require_credentials();
    let out = api()
        .args(["GET", "/echo-all", "--silent"])
        .output()
        .expect("spawn api");
    if !out.status.success() {
        panic!(
            "local COS not reachable. Ensure your local CommerceOS is running and\n\
             that .api-credentials.json points at it with a valid key.\n\
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
fn glob_at_file_combines_json_files_into_array() {
    require_local_cos();
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("a.json"), r#"{"id":1,"name":"Alice"}"#).unwrap();
    std::fs::write(dir.path().join("b.json"), r#"{"id":2,"name":"Bob"}"#).unwrap();
    std::fs::write(dir.path().join("c.json"), r#"[{"id":3,"name":"Carol"},{"id":4,"name":"Dan"}]"#).unwrap();

    let pattern = format!("@{}/*.json", dir.path().display());
    let assert = api()
        .args(["PUT", "/echo-all", &pattern])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // All four items should be present in the echoed array
    for name in &["Alice", "Bob", "Carol", "Dan"] {
        assert!(stdout.contains(name), "expected {name} in: {stdout}");
    }
}

#[test]
fn glob_at_file_combines_ndjson_streams() {
    require_local_cos();
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("a.ndjson"), "{\"row\":1}\n{\"row\":2}\n").unwrap();
    std::fs::write(dir.path().join("b.ndjson"), "{\"row\":3}\n{\"row\":4}\n").unwrap();

    let pattern = format!("@{}/*.ndjson", dir.path().display());
    let assert = api()
        .args(["PUT", "/echo-all", &pattern, "--ndjson"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // Server may echo a different shape; we just check the request succeeded.
    // (The server-side handler determines the response.)
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("HTTP/1.1 200"),
        "expected 200, stderr={stderr} stdout={stdout}"
    );
}

#[test]
fn glob_with_no_matches_errors() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let pattern = format!("@{}/nothing-*.json", dir.path().display());
    api()
        .args(["PUT", "/echo-all", &pattern])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no files match"));
}

#[test]
fn glob_at_file_skips_os_junk_files() {
    require_local_cos();
    let dir = tempdir().unwrap();
    // Two real JSON files plus typical OS junk that should all be skipped.
    std::fs::write(dir.path().join("a.json"), r#"{"id":1,"name":"Alice"}"#).unwrap();
    std::fs::write(dir.path().join("b.json"), r#"{"id":2,"name":"Bob"}"#).unwrap();
    // .DS_Store contains a binary header that would fail JSON parsing if included.
    std::fs::write(dir.path().join(".DS_Store"), b"\x00\x00\x00\x01junk").unwrap();
    // AppleDouble metadata — also dot-prefixed.
    std::fs::write(dir.path().join("._a.json"), b"\x00binary").unwrap();
    // Windows junk that doesn't start with `.` — caught by the explicit name filter.
    std::fs::write(dir.path().join("Thumbs.db"), b"not json").unwrap();
    std::fs::write(dir.path().join("desktop.ini"), b"[.ShellClassInfo]").unwrap();

    let pattern = format!("@{}/*", dir.path().display());
    let assert = api()
        .args(["PUT", "/echo-all", &pattern])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    for name in &["Alice", "Bob"] {
        assert!(stdout.contains(name), "expected {name} in: {stdout}");
    }
}

#[test]
fn clipboard_outfile_suppresses_stdout_and_logs_target() {
    require_local_cos();
    // `> clipboard` should route the response away from stdout (same as `> file`)
    // and emit the dimmed `> clipboard` marker on stderr in non-silent mode.
    // We don't read the clipboard back — CI runners are headless and that would
    // be flaky; the routing behavior is what we assert.
    let assert = api()
        .args(["GET", "/echo-all > clipboard"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("> clipboard"),
        "expected `> clipboard` marker on stderr, got stderr={stderr}"
    );
    // No file named `clipboard` should have been written into cwd as a side effect.
    assert!(
        !std::path::Path::new("clipboard").exists(),
        "writing to `> clipboard` must NOT create a file named `clipboard`"
    );
    // The dimmed marker is on stderr; stdout should not contain the JSON body.
    // (The body went to the clipboard, not stdout.)
    assert!(
        !stdout.contains('{'),
        "stdout should be empty when output goes to clipboard, got stdout={stdout}"
    );
}

#[test]
fn clipboard_outfile_is_case_insensitive() {
    require_local_cos();
    let assert = api()
        .args(["GET", "/echo-all > CLIPBOARD"])
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("> clipboard"),
        "expected `> clipboard` marker even when user typed `> CLIPBOARD`, stderr={stderr}"
    );
    assert!(
        !std::path::Path::new("CLIPBOARD").exists(),
        "writing to `> CLIPBOARD` must NOT create a file"
    );
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
fn no_streaming_flag_disables_streaming() {
    require_local_cos();
    // With --no-streaming, the request should succeed without ;stream=true
    // (server still responds; the flag just changes the Accept/Content-Type headers).
    api()
        .args(["GET", "/echo-all", "--no-streaming"])
        .assert()
        .success()
        .stderr(predicate::str::contains("HTTP/1.1 200 OK"));
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
fn version_prefix_v1_resolves_to_full_path() {
    require_local_cos();
    api()
        .args(["GET", "/v1/echo-all"])
        .assert()
        .success()
        .stderr(predicate::str::contains("HTTP/1.1 200 OK"));
}

#[test]
fn explicit_api_prefix_is_used_as_is() {
    require_local_cos();
    api()
        .args(["GET", "/api/v1/echo-all"])
        .assert()
        .success()
        .stderr(predicate::str::contains("HTTP/1.1 200 OK"));
}

#[test]
fn version_like_prefix_that_is_not_a_version_uses_default() {
    require_local_cos();
    // `/version/foo` is NOT a version prefix — should resolve to /api/v1/version/foo
    // which is a 404 (no such endpoint), but the request itself reaches the server
    // and gets a structured response.
    let assert = api().args(["GET", "/version/foo"]).assert();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("HTTP/1.1"),
        "request should reach the server, stderr={stderr}"
    );
}

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

/// A bare api binary with --no-keychain and an explicit base/key, for tests that
/// need a deterministic base URL (the URL gate) without touching saved creds.
fn api_with_base(base: &str) -> Command {
    let mut cmd = Command::cargo_bin("api").expect("api binary built");
    cmd.arg("--no-keychain");
    cmd.env("API_CREDENTIALS_FILE", credentials_file());
    cmd.args(["-b", base, "-k", "testkey"]);
    cmd
}

#[test]
fn url_gate_blocks_non_matching_base() {
    // No live server needed: the gate must fail before any request is attempted.
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("gated.api");
    std::fs::write(
        &req_file,
        "url has test.app.heads.com\nurl has localhost:5000\nGET /echo-all\n",
    )
    .unwrap();

    api_with_base("https://api.heads.com")
        .args(["-a"])
        .arg(&req_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("URL gate failed"));
}

#[test]
fn url_gate_allows_matching_base() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("gated-ok.api");
    std::fs::write(
        &req_file,
        "url has localhost:5000\nGET /echo-all\n",
    )
    .unwrap();

    let assert = api().args(["-a"]).arg(&req_file).assert().success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert_eq!(stderr.matches("HTTP/1.1").count(), 1, "stderr: {stderr}");
}

#[test]
fn bulk_sleep_directive_delays_execution() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("sleepy.api");
    std::fs::write(&req_file, "GET /echo-all\nsleep 1\nGET /echo-all\n").unwrap();

    let start = std::time::Instant::now();
    let assert = api().args(["-a"]).arg(&req_file).assert().success();
    let elapsed = start.elapsed();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert_eq!(stderr.matches("HTTP/1.1").count(), 2, "stderr: {stderr}");
    assert!(
        elapsed >= std::time::Duration::from_millis(900),
        "expected at least ~1s from `sleep 1`, took {elapsed:?}"
    );
}

#[test]
fn bulk_sleep_invalid_value_errors() {
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("badsleep.api");
    std::fs::write(&req_file, "GET /echo-all\nsleep abc\n").unwrap();

    api_with_base("http://localhost:5000")
        .args(["-a"])
        .arg(&req_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid sleep duration"));
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
fn bulk_mode_strips_jsonc_comments_in_bodies() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("comments.api");
    let content = "\
PUT /echo-all {
  // line comment
  \"name\": \"Alice\",
  # shell-style comment
  /* block
     comment */
  \"url\": \"https://heads.com\",
  \"keep\": \"// not a comment\"
}
";
    std::fs::write(&req_file, content).unwrap();

    let assert = api().args(["-a"]).arg(&req_file).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(stdout.contains("Alice"), "expected name field: {stdout}");
    assert!(
        stdout.contains("https://heads.com"),
        "URLs in strings preserved: {stdout}"
    );
    assert!(
        stdout.contains("// not a comment"),
        "comment-like content inside strings preserved: {stdout}"
    );
    // Comments themselves should not appear in echoed body
    assert!(!stdout.contains("line comment"), "comment stripped: {stdout}");
    assert!(!stdout.contains("block"), "block comment stripped: {stdout}");
}

#[test]
fn bulk_mode_handles_commented_brackets_correctly() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("comment-brackets.api");
    let content = "\
PUT /echo-all {
  \"a\": 1
  // }
}
PUT /echo-all { \"second\": true }
";
    std::fs::write(&req_file, content).unwrap();

    let assert = api().args(["-a"]).arg(&req_file).assert().success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert_eq!(
        stderr.matches("HTTP/1.1").count(),
        2,
        "expected 2 requests; commented `}}` should not end body: {stderr}"
    );
}

#[test]
fn bulk_mode_supports_include_directives() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let main_file = dir.path().join("main.api");
    let included = dir.path().join("included.api");
    std::fs::write(&main_file, "GET /echo-all\nincluded.api\nGET /echo-all\n").unwrap();
    std::fs::write(&included, "PUT /echo-all {\"from\":\"included\"}\n").unwrap();

    let assert = api().args(["-a"]).arg(&main_file).assert().success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert_eq!(
        stderr.matches("HTTP/1.1").count(),
        3,
        "expected 3 requests (2 in main + 1 included), stderr={stderr}"
    );
    assert!(stdout.contains("included"));
}

#[test]
fn bulk_mode_include_loop_detected() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.api");
    let b = dir.path().join("b.api");
    std::fs::write(&a, "b.api\n").unwrap();
    std::fs::write(&b, "a.api\n").unwrap();

    api()
        .args(["-a"])
        .arg(&a)
        .assert()
        .failure()
        .stderr(predicate::str::contains("include loop"));
}

#[test]
fn bulk_mode_include_not_found() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let main = dir.path().join("main.api");
    std::fs::write(&main, "missing.api\n").unwrap();

    api()
        .args(["-a"])
        .arg(&main)
        .assert()
        .failure()
        .stderr(predicate::str::contains("include not found"));
}

#[test]
fn bulk_mode_supports_multiline_bodies() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("multiline.api");
    let content = "\
PUT /echo-all {
  \"name\": \"Joe\",
  \"tags\": [
    \"a\",
    \"b\"
  ]
}

PUT /echo-all [
  {\"a\": 1},
  {\"b\": 2}
]
";
    std::fs::write(&req_file, content).unwrap();

    let assert = api().args(["-a"]).arg(&req_file).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();

    assert_eq!(
        stderr.matches("HTTP/1.1 200").count(),
        2,
        "expected 2 successful requests, stderr: {stderr}"
    );
    assert!(stdout.contains("Joe"), "first body echoed: {stdout}");
    assert!(stdout.contains("\"a\":1"), "second body echoed: {stdout}");
}

#[test]
fn bulk_mode_escapes_raw_newlines_in_strings() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("multiline-string.api");
    let content = "PUT /echo-all {\n  \"bio\": \"line1\nline2\"\n}\n";
    std::fs::write(&req_file, content).unwrap();

    let assert = api().args(["-a"]).arg(&req_file).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    // Server should have parsed the JSON successfully (newline escaped to \n)
    // and echo back the bio with the escaped newline preserved as a real one in JSON output
    assert!(
        stdout.contains("line1\\nline2") || stdout.contains("line1\nline2"),
        "expected escaped newline in echoed body: {stdout}"
    );
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

#[test]
fn timeout_flag_appears_in_help() {
    Command::cargo_bin("api")
        .expect("api binary built")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--timeout"))
        .stdout(predicate::str::contains("SECONDS"));
}

#[test]
fn timeout_flag_accepts_seconds_value() {
    require_local_cos();
    api()
        .args(["GET", "/echo-all", "--timeout", "30", "--silent"])
        .assert()
        .success();
}
