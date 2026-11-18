//! End-to-end CLI tests.
//!
//! What each test needs:
//!
//!   - **A local CommerceOS and a credentials file**: every test that calls
//!     `require_local_cos()`, about fifty of them. They send to `/echo-all`
//!     (which echoes what it receives, as an array), `/about` and `/assert`,
//!     so nothing is persisted, and they panic with instructions when the
//!     server or the credentials are missing. Copy
//!     `.api-credentials-sample.json` to `.api-credentials.json` in the repo
//!     root and fill in the key for http://localhost:5000, or set
//!     `API_TEST_BASE_URI` + `API_TEST_KEY`. The server must have the
//!     `/assert` endpoint: `fail_fast_against_the_assert_endpoint_of_a_local_cos`
//!     fails on one that has not.
//!   - **Nothing but this machine**: the rest. They start a small server of
//!     their own on a free port of 127.0.0.1 (`answering_server`,
//!     `whole_request_server`, `flipping_server`, …) or send nothing at all,
//!     and are where a test belongs whose point is what was sent.
//!   - **The system clipboard**: the tests with `clipboard` in their name
//!     copy to it, and overwrite what it held. They take turns inside this
//!     suite, but run them on their own and one at a time:
//!     `cargo test --test cli -- clipboard --test-threads=1`. On macOS
//!     `export_to_the_clipboard_…` reads it back with `pbpaste`.
//!   - **git** on the `PATH`, for the import tests (local repositories only).
//!
//! No test contacts a host other than this machine. Tests run with
//! `--no-keychain`, so the OS keychain is never unlocked.
//!
//! Run with: `cargo test --test cli -- --skip clipboard`

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

/// The system clipboard is one per machine, and macOS refuses a write while
/// another is under way (`NSPasteboard#writeObjects: returned false`). Tests
/// that copy to it hold this for as long as they do, so they take turns.
static CLIPBOARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn clipboard_turn() -> std::sync::MutexGuard<'static, ()> {
    // A test that failed while holding it has not broken the clipboard.
    CLIPBOARD.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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

    // One array: the files in sorted order, an object as one element and an
    // array flattened into its elements.
    let echoed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
    assert_eq!(
        echoed,
        serde_json::json!([
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"},
            {"id": 3, "name": "Carol"},
            {"id": 4, "name": "Dan"}
        ]),
        "{stdout}"
    );
}

#[test]
fn glob_at_file_combines_ndjson_streams() {
    // What is sent is the point, so a server that keeps the request whole.
    let (port, server) = whole_request_server(vec![("200 OK", "null")]);
    let dir = tempdir().unwrap();
    // Written out of order: the files are sent in sorted order.
    std::fs::write(dir.path().join("b.ndjson"), "{\"row\":3}\n{\"row\":4}\n").unwrap();
    std::fs::write(dir.path().join("a.ndjson"), "{\"row\":1}\n{\"row\":2}\n").unwrap();

    let pattern = format!("@{}/*.ndjson", dir.path().display());
    let out = api_against_port(port).args(["PUT", "/things", &pattern]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let seen = server.join().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].starts_with("PUT /api/v1/things HTTP/1.1\r\n"), "{}", seen[0]);
    assert_eq!(header(&seen[0], "content-type"), Some("application/x-ndjson"), "{}", seen[0]);
    // One stream, a record per line.
    let body = seen[0].split_once("\r\n\r\n").unwrap().1;
    assert_eq!(body.lines().collect::<Vec<_>>(), [r#"{"row":1}"#, r#"{"row":2}"#, r#"{"row":3}"#, r#"{"row":4}"#], "{body:?}");
}

#[test]
fn glob_with_no_matches_errors() {
    let (port, server) = answering_server(vec![OK]);
    let dir = tempdir().unwrap();
    let pattern = format!("@{}/nothing-*.json", dir.path().display());
    let out = api_against_port(port).args(["PUT", "/things", &pattern]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no files match"), "{}", String::from_utf8_lossy(&out.stderr));
    // And nothing was sent in the body's place.
    assert_eq!(server.join().unwrap(), Vec::<String>::new());
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
    let _turn = clipboard_turn();
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
    let _turn = clipboard_turn();
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

/// Send one request to a throwaway local server and return the raw request
/// headers it received. The real COS doesn't reflect headers back, so this is
/// the only way to assert on what was actually sent.
fn captured_request_headers(args: &[&str], env: &[(&str, &str)]) -> String {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap_or(0);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]",
        );
        let _ = stream.flush();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    // Built directly rather than via api(): that helper may pass `-b` from the
    // environment, which would collide with the dummy server here.
    let mut cmd = Command::cargo_bin("api").expect("api binary built");
    cmd.arg("--no-keychain");
    cmd.env("API_CREDENTIALS_FILE", credentials_file());
    cmd.args(["-b", &format!("http://127.0.0.1:{port}"), "-k", "dummy-key"]);
    cmd.args(["GET", "/echo-all"]).args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.assert().success();

    handle.join().expect("server thread")
}

#[test]
fn streaming_is_off_unless_asked_for() {
    // The server advertising response:streaming is no longer enough — the
    // client must be told to use it.
    let headers = captured_request_headers(&[], &[]);
    assert!(
        !headers.contains("stream=true"),
        "default run should not request streaming: {headers}"
    );
}

#[test]
fn stream_flag_enables_streaming() {
    let headers = captured_request_headers(&["--stream"], &[]);
    assert!(
        headers.contains("stream=true"),
        "--stream should request streaming: {headers}"
    );
}

#[test]
fn api_streaming_env_var_enables_streaming() {
    let headers = captured_request_headers(&[], &[("API_STREAMING", "1")]);
    assert!(
        headers.contains("stream=true"),
        "API_STREAMING=1 should request streaming: {headers}"
    );
    // A non-truthy value leaves it off rather than enabling on mere presence.
    let headers = captured_request_headers(&[], &[("API_STREAMING", "0")]);
    assert!(
        !headers.contains("stream=true"),
        "API_STREAMING=0 should not request streaming: {headers}"
    );
}

#[test]
fn no_streaming_beats_stream_and_env_var() {
    let headers =
        captured_request_headers(&["--stream", "--no-streaming"], &[("API_STREAMING", "1")]);
    assert!(
        !headers.contains("stream=true"),
        "--no-streaming should win over both: {headers}"
    );
}

#[test]
fn streamed_outfile_matches_buffered_outfile() {
    // Both runs hit a mock server that returns the same bytes whatever the
    // request's media type, so any difference in the files is the client's
    // doing — which is what this test is for. (Against real COS the two runs
    // legitimately differ: it emits a trailing blank line for plain
    // `application/x-ndjson` but not for `;stream=true`, and the client writes
    // whatever it receives verbatim.)
    const BODY: &str = "{\"id\":1}\n{\"id\":2}\n";
    let dir = tempdir().unwrap();
    let streamed = dir.path().join("streamed.ndjson");
    let buffered = dir.path().join("buffered.ndjson");

    let (port, server) = flipping_server(vec![BODY, BODY]);
    // NDJSON so neither path pretty-prints — the bytes are directly comparable.
    api_against_port(port)
        .args([
            "PUT",
            &format!("/echo-all > {}", streamed.display()),
            r#"{"id":1}"#,
            "--ndjson",
            "--stream",
        ])
        .assert()
        .success();
    api_against_port(port)
        .args([
            "PUT",
            &format!("/echo-all > {}", buffered.display()),
            r#"{"id":1}"#,
            "--ndjson",
        ])
        .assert()
        .success();
    let seen = server.join().expect("server thread");
    assert_eq!(seen.len(), 2, "both runs should have reached the server");
    assert!(
        seen[0].contains("application/x-ndjson;stream=true"),
        "the first run should have asked to stream: {}",
        seen[0]
    );

    let a = std::fs::read(&streamed).expect("streamed outfile written");
    let b = std::fs::read(&buffered).expect("buffered outfile written");
    assert_eq!(a, BODY.as_bytes(), "streamed outfile should hold the server's bytes verbatim");
    assert_eq!(a, b, "streaming must not change the bytes written");
}

#[test]
fn streamed_stdout_matches_buffered_stdout() {
    require_local_cos();
    // Piped stdout streams rather than buffering, so the two paths must still
    // emit identical bytes — including the trailing newline.
    let streamed = api()
        .args(["PUT", "/echo-all", r#"{"id":1}"#, "-r", "--stream"])
        .output()
        .expect("spawn api");
    let buffered = api()
        .args(["PUT", "/echo-all", r#"{"id":1}"#, "-r"])
        .output()
        .expect("spawn api");
    assert!(!streamed.stdout.is_empty(), "streamed stdout should not be empty");
    assert_eq!(
        String::from_utf8_lossy(&streamed.stdout),
        String::from_utf8_lossy(&buffered.stdout),
        "streaming must not change what reaches stdout"
    );
}

#[test]
fn streaming_still_writes_an_outfile_for_a_chain() {
    require_local_cos();
    // The chain's truthiness comes from the retained prefix, so a streamed
    // first segment must still let the second one run. The first segment
    // echoes a body back so its answer is truthy; a bare GET echoes `null`,
    // which rightly stops a `&&` chain.
    let dir = tempdir().unwrap();
    let out = dir.path().join("chained.json");
    api()
        .args([
            "--stream",
            "PUT",
            "/echo-all",
            &format!("{{\"a\":1}} && GET /echo-all > {}", out.display()),
        ])
        .assert()
        .success();
    assert!(out.exists(), "second segment should have run");
}

#[test]
fn one_shot_chain_stops_on_a_falsy_first_segment() {
    require_local_cos();
    // Before one-shot chains existed this line went out as ONE request to a
    // garbled path, which wrote the file. Now `GET /echo-all` answers `null`
    // and `&&` skips the rest.
    let dir = tempdir().unwrap();
    let out = dir.path().join("skipped.json");
    let assert = api()
        .args(["GET", &format!("/echo-all && GET /echo-all > {}", out.display())])
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(!out.exists(), "second segment must not run after a falsy first");
    assert!(stderr.contains("skipped 1 request"), "{stderr}");
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

/// The `(size)` suffix of a `> target (…)` marker line on stderr.
fn marker_size(stderr: &str, prefix: &str) -> String {
    let line = stderr
        .lines()
        .find(|l| l.contains(prefix))
        .unwrap_or_else(|| panic!("no `{prefix}` marker line in stderr={stderr}"));
    let open = line.rfind('(').unwrap_or_else(|| panic!("no size on marker line: {line}"));
    let close = line.rfind(')').unwrap_or_else(|| panic!("no size on marker line: {line}"));
    line[open + 1..close].to_string()
}

#[test]
fn outfile_marker_reports_bytes_written() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let outfile = dir.path().join("out.json");
    let uri_with_outfile = format!("/echo-all > {}", outfile.display());

    // Buffered and streamed writes both report the size of the file they left.
    for extra in [&[][..], &["--stream"][..]] {
        let assert = api()
            .args(extra)
            .args(["PUT", &uri_with_outfile, r#"{"saved":true}"#])
            .assert()
            .success();
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
        let on_disk = std::fs::metadata(&outfile).expect("outfile written").len();
        assert!(on_disk < 1024, "fixture assumed a sub-KB body, got {on_disk}");
        assert_eq!(marker_size(&stderr, "> "), format!("{} B", on_disk), "args={extra:?}");
    }

    // `>>` reports the growth of the file, as a `+` delta.
    let before = std::fs::metadata(&outfile).unwrap().len();
    let uri_append = format!("/echo-all >> {}", outfile.display());
    let assert = api()
        .args(["PUT", &uri_append, r#"{"saved":true}"#])
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let grown = std::fs::metadata(&outfile).unwrap().len() - before;
    assert_eq!(marker_size(&stderr, ">> "), format!("+{} B", grown));
}

#[test]
fn clipboard_marker_reports_bytes_copied() {
    let _turn = clipboard_turn();
    require_local_cos();
    let assert = api()
        .args(["GET", "/echo-all > clipboard"])
        .assert()
        .success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    let size = marker_size(&stderr, "> clipboard");
    assert!(
        size.ends_with(" B") || size.ends_with(" KB"),
        "expected a short size on the clipboard marker, got `{size}` in stderr={stderr}"
    );
}

#[test]
fn append_outfile_merges_arrays_across_bulk_runs() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let outfile = dir.path().join("collected.json");
    let req_file = dir.path().join("append.api");
    // Two `>>` writes to the same target: array payloads must merge into one
    // array rather than the second overwriting the first.
    let content = format!(
        "PUT /echo-all [{{\"id\":1}}] >> {out}\nPUT /echo-all [{{\"id\":2}}] >> {out}\n",
        out = outfile.display()
    );
    std::fs::write(&req_file, content).unwrap();

    api().args(["-sa"]).arg(&req_file).assert().success();

    let written = std::fs::read_to_string(&outfile).expect("outfile written");
    let v: serde_json::Value = serde_json::from_str(&written).expect("merged file is valid JSON");
    let arr = v.as_array().expect("merged file is one array");
    assert_eq!(arr.len(), 2, "expected both payloads in one array, got: {written}");

    // A plain `>` to the same target still overwrites.
    let req2 = dir.path().join("overwrite.api");
    std::fs::write(
        &req2,
        format!("PUT /echo-all [{{\"id\":9}}] > {}\n", outfile.display()),
    )
    .unwrap();
    api().args(["-sa"]).arg(&req2).assert().success();
    let written = std::fs::read_to_string(&outfile).unwrap();
    let v: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(v.as_array().map(|a| a.len()), Some(1), "`>` must overwrite: {written}");
}

#[test]
fn append_outfile_wraps_repeated_object_responses_into_an_array() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let outfile = dir.path().join("foo.json");
    // The reported scenario: /about returns a single object; two `>>` runs must
    // leave one two-element array, not two newline-separated objects.
    let req_file = dir.path().join("about.api");
    std::fs::write(
        &req_file,
        format!("GET /about >> {out}\nGET /about >> {out}\n", out = outfile.display()),
    )
    .unwrap();

    api().args(["-sa"]).arg(&req_file).assert().success();

    let written = std::fs::read_to_string(&outfile).expect("outfile written");
    let v: serde_json::Value = serde_json::from_str(&written)
        .expect("file must be valid JSON after repeated appends");
    let arr = v.as_array().expect("repeated object responses should merge into an array");
    assert_eq!(arr.len(), 2, "expected both responses in one array, got: {written}");
    assert!(
        arr.iter().all(|e| e.get("@type").is_some()),
        "elements should be the /about objects: {written}"
    );
}

#[test]
fn or_chain_runs_fallback_on_falsy_and_skips_on_truthy() {
    require_local_cos();
    let dir = tempdir().unwrap();

    // Falsy condition (404) → the || fallback runs.
    let req = dir.path().join("or-falsy.api");
    std::fs::write(&req, "GET /no-such-endpoint || PUT /echo-all [{\"fallback\":1}]\n").unwrap();
    let assert = api().args(["-sa"]).arg(&req).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert_eq!(
        stdout.matches("└─HTTP/1.1").count(),
        2,
        "fallback should have run after the 404: {stdout}"
    );
    assert!(!stdout.contains("skipped"), "nothing should be skipped: {stdout}");

    // Truthy condition → the || fallback is skipped.
    let req = dir.path().join("or-truthy.api");
    std::fs::write(&req, "GET /about || PUT /echo-all [{\"fallback\":1}]\n").unwrap();
    let assert = api().args(["-sa"]).arg(&req).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert_eq!(stdout.matches("└─HTTP/1.1").count(), 1, "fallback should be skipped: {stdout}");
    assert!(stdout.contains("skipped 1 request"), "expected the skip note: {stdout}");
}

#[test]
fn mixed_chain_behaves_as_if_then_else() {
    // Which branch was sent is the point: a server that says what it got.
    let chain = "GET /cond && PUT /then {\"then\":1} || PUT /else {\"else\":1}\nGET /after\n";

    // Truthy condition: the && branch runs and the || branch is skipped.
    let run = run_fail_fast("-sa", chain, vec![OK]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /cond", "PUT /then", "GET /after"]);
    assert!(run.stdout.contains("skipped 1 request"), "else-branch skipped: {}", run.stdout);

    // Falsy condition: the && branch is skipped and the || branch runs.
    let run = run_fail_fast("-sa", chain, vec![NOT_FOUND, OK]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /cond", "PUT /else", "GET /after"]);
    assert!(run.stdout.contains("skipped 1 request"), "then-branch skipped: {}", run.stdout);
}

/// A tiny HTTP server that answers each request with the next body from
/// `bodies` (repeating the last one), and reports how many requests it saw and
/// what it received. Lets a `sleep while` test drive a condition that flips.
fn flipping_server(bodies: Vec<&'static str>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(false).unwrap();
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for i in 0.. {
            // Stop once the client is done: give it a second to reconnect.
            listener
                .set_nonblocking(true)
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let accepted = loop {
                match listener.accept() {
                    Ok(pair) => break Some(pair),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() > deadline {
                            break None;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            let Some((mut stream, _)) = accepted else { break };
            stream.set_nonblocking(false).unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            seen.push(String::from_utf8_lossy(&buf[..n]).to_string());
            let body = bodies[i.min(bodies.len() - 1)];
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            );
            let _ = stream.flush();
        }
        seen
    });
    (port, handle)
}

fn api_against_port(port: u16) -> Command {
    let mut cmd = Command::cargo_bin("api").expect("api binary built");
    cmd.arg("--no-keychain");
    cmd.env("API_CREDENTIALS_FILE", credentials_file());
    cmd.args(["-b", &format!("http://127.0.0.1:{port}"), "-k", "dummy-key"]);
    cmd
}

#[test]
fn sleep_while_polls_until_falsy_and_logs_once() {
    // Count is 2, then 1, then 0 → three checks, two sleeps.
    let (port, server) = flipping_server(vec!["2", "1", "0", "[]"]);
    let dir = tempdir().unwrap();
    let req = dir.path().join("poll.api");
    std::fs::write(
        &req,
        "sleep 200ms while GET /people~count/==0\nGET /after\n",
    )
    .unwrap();

    let started = std::time::Instant::now();
    let assert = api_against_port(port).args(["-sa"]).arg(&req).assert().success();
    let elapsed = started.elapsed();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    let seen = server.join().expect("server thread");
    let polls = seen.iter().filter(|r| r.contains("/people~count/==0")).count();
    assert_eq!(polls, 3, "expected three polls, saw: {seen:?}");
    assert!(seen.iter().any(|r| r.contains("GET /api/v1/after")), "the next step should run: {seen:?}");
    assert!(elapsed >= std::time::Duration::from_millis(400), "two intervals should elapse: {elapsed:?}");

    // One start line, one summary line, and no per-poll status lines: the only
    // status line belongs to GET /after.
    assert!(stdout.contains("sleep 200ms while GET /people~count/==0"), "{stdout}");
    assert!(stdout.contains("waited ") && stdout.contains("(3 checks)"), "{stdout}");
    assert_eq!(stdout.matches("└─HTTP/1.1").count(), 1, "polls must be silent: {stdout}");
}

#[test]
fn sleep_while_not_polls_until_truthy() {
    // 0, 0, then 5 → three checks.
    let (port, server) = flipping_server(vec!["0", "0", "5"]);
    let dir = tempdir().unwrap();
    let req = dir.path().join("poll-not.api");
    std::fs::write(&req, "sleep 100ms while not /people~count\n").unwrap();

    let assert = api_against_port(port).args(["-sa"]).arg(&req).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let seen = server.join().expect("server thread");
    assert_eq!(seen.len(), 3, "saw: {seen:?}");
    assert!(stdout.contains("sleep 100ms while not GET /people~count"), "{stdout}");
    assert!(stdout.contains("(3 checks)"), "{stdout}");
}

#[test]
fn sleep_while_is_silent_outside_silent_bulk_mode() {
    let (port, server) = flipping_server(vec!["1", "0"]);
    let dir = tempdir().unwrap();
    let req = dir.path().join("poll-quiet.api");
    std::fs::write(&req, "sleep 50ms while GET /x\n").unwrap();

    let assert = api_against_port(port).args(["-a"]).arg(&req).assert().success();
    let out = assert.get_output();
    assert!(out.stdout.is_empty(), "stdout: {}", String::from_utf8_lossy(&out.stdout));
    assert!(out.stderr.is_empty(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(server.join().unwrap().len(), 2);
}

#[test]
fn uri_without_leading_slash_does_not_duplicate_the_api_prefix() {
    // A path copied out of a URL or a log: `api/v1/...` must go out as
    // `/api/v1/...`, not `/api/v1api/v1/...`.
    let captured = captured_request_headers(
        &["--silent"],
        &[],
    );
    assert!(captured.starts_with("GET /api/v1/echo-all "), "sanity: {captured}");

    let (port, server) = flipping_server(vec!["[]"]);
    api_against_port(port)
        .args(["-s", "GET", "api/v1/stock-transfers/key=8298~map(no.omnium.outbound-stock-transfer)"])
        .assert()
        .success();
    let seen = server.join().expect("server thread");
    let line = seen.first().expect("one request").lines().next().unwrap_or("").to_string();
    assert_eq!(
        line,
        "GET /api/v1/stock-transfers/key=8298~map(no.omnium.outbound-stock-transfer) HTTP/1.1",
        "got: {line}"
    );

    // A bare resource name still gets the default prefix.
    let (port, server) = flipping_server(vec!["[]"]);
    api_against_port(port).args(["-s", "GET", "people"]).assert().success();
    let seen = server.join().expect("server thread");
    assert!(
        seen[0].starts_with("GET /api/v1/people "),
        "got: {}",
        seen[0].lines().next().unwrap_or("")
    );
}

#[test]
fn assert_passes_and_continues_without_printing_the_body() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req = dir.path().join("assert-ok.api");
    std::fs::write(&req, "assert GET /about\nGET /about\n").unwrap();

    // -sa: the assert line is echoed with a status, and the next request runs.
    let assert = api().args(["-sa"]).arg(&req).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(stdout.contains("assert GET /about"), "{stdout}");
    assert_eq!(stdout.matches("└─HTTP/1.1").count(), 2, "{stdout}");

    // -a: only the second request's body reaches stdout.
    let assert = api().args(["-a"]).arg(&req).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert_eq!(stdout.matches("@type").count(), 1, "assert body must not print: {stdout}");
    assert_eq!(stderr.matches("HTTP/1.1 200").count(), 2, "both statuses shown: {stderr}");
}

#[test]
fn assert_failure_stops_the_batch_with_a_reason() {
    require_local_cos();
    let dir = tempdir().unwrap();
    let req = dir.path().join("assert-fail.api");
    std::fs::write(&req, "assert GET /no-such-endpoint\nGET /about\n").unwrap();
    let assert = api().args(["-sa"]).arg(&req).assert().failure();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(stderr.contains("assertion failed: assert GET /no-such-endpoint (404 Not Found)"), "{stderr}");
    assert_eq!(stdout.matches("└─HTTP/1.1").count(), 1, "the next request must not run: {stdout}");
}

#[test]
fn assert_not_inverts_and_reports_the_falsy_body() {
    // `assert not` passes on a falsy answer and fails on a truthy one, quoting it.
    let (port, server) = flipping_server(vec!["0", "213"]);
    let dir = tempdir().unwrap();
    let req = dir.path().join("assert-not.api");
    std::fs::write(&req, "assert not /people~count\nassert /people~count\nassert not /people~count\n").unwrap();
    let assert = api_against_port(port).args(["-sa"]).arg(&req).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(stderr.contains("assertion failed: assert not GET /people~count (213)"), "{stderr}");
    assert_eq!(server.join().unwrap().len(), 3);
}

/// A server that answers each request with the next status in `statuses`
/// (repeating the last), an empty JSON object as the body. Returns the
/// request heads it saw once the client has gone quiet.
fn status_server(statuses: Vec<&'static str>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for i in 0.. {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let accepted = loop {
                match listener.accept() {
                    Ok(pair) => break Some(pair),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() > deadline {
                            break None;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            let Some((mut stream, _)) = accepted else { break };
            stream.set_nonblocking(false).unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            seen.push(String::from_utf8_lossy(&buf[..n]).to_string());
            let status = statuses[i.min(statuses.len() - 1)];
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{{}}"
                )
                .as_bytes(),
            );
            let _ = stream.flush();
        }
        seen
    });
    (port, handle)
}

/// A server that takes its time: it waits before the headers, then sends the
/// body in pieces with pauses between, long enough for a progress line to
/// have been due. `chunked` picks the transfer encoding, so both the
/// known-length and the unknown-length read are covered.
fn slow_server(body: &'static str, chunked: bool) -> (u16, std::thread::JoinHandle<Vec<String>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        loop {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let accepted = loop {
                match listener.accept() {
                    Ok(pair) => break Some(pair),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() > deadline {
                            break None;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            let Some((mut stream, _)) = accepted else { break };
            stream.set_nonblocking(false).unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            seen.push(String::from_utf8_lossy(&buf[..n]).to_string());

            let pause = std::time::Duration::from_millis(250);
            std::thread::sleep(pause);
            let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n";
            let framing = if chunked {
                "Transfer-Encoding: chunked\r\n\r\n".to_string()
            } else {
                format!("Content-Length: {}\r\n\r\n", body.len())
            };
            let _ = stream.write_all(format!("{head}{framing}").as_bytes());
            let _ = stream.flush();
            for piece in body.as_bytes().chunks(body.len().div_ceil(3)) {
                std::thread::sleep(pause);
                if chunked {
                    let _ = stream.write_all(format!("{:x}\r\n", piece.len()).as_bytes());
                    let _ = stream.write_all(piece);
                    let _ = stream.write_all(b"\r\n");
                } else {
                    let _ = stream.write_all(piece);
                }
                let _ = stream.flush();
            }
            if chunked {
                let _ = stream.write_all(b"0\r\n\r\n");
            }
            let _ = stream.flush();
        }
        seen
    });
    (port, handle)
}

const SLOW_BODY: &str = r#"[{"id":1,"name":"Åsa"},{"id":2,"name":"Björn"},{"id":3,"name":"Örjan"}]"#;

/// The progress line is drawn only on a terminal. A test's pipes are not one,
/// so whatever a slow request prints here is what an agent or a CI log sees.
fn assert_no_progress_in(stderr: &str) {
    assert!(!stderr.contains("waiting for response"), "progress leaked into a pipe: {stderr:?}");
    assert!(!stderr.contains("received"), "progress leaked into a pipe: {stderr:?}");
    assert!(!stderr.contains('\r'), "a redraw leaked into a pipe: {stderr:?}");
}

#[test]
fn a_slow_body_arrives_whole_and_prints_no_progress_when_piped() {
    for chunked in [false, true] {
        let (port, handle) = slow_server(SLOW_BODY, chunked);
        let out = api_against_port(port).args(["GET", "/x", "-r"]).output().expect("spawn api");
        let _ = handle.join();
        assert!(out.status.success(), "chunked={chunked}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim_end(),
            SLOW_BODY,
            "chunked={chunked}: the body must survive being read in pieces"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("200 OK"), "status line still printed: {stderr}");
        assert_no_progress_in(&stderr);
    }
}

#[test]
fn a_slow_streamed_outfile_is_complete_and_prints_no_progress_when_piped() {
    for chunked in [false, true] {
        let (port, handle) = slow_server(SLOW_BODY, chunked);
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("slow.json");
        let line = format!("GET /x > {}", target.display());
        let out = api_against_port(port).args(["--stream", &line]).output().expect("spawn api");
        let _ = handle.join();
        assert!(out.status.success(), "chunked={chunked}");
        assert_eq!(
            std::fs::read_to_string(&target).expect("outfile written"),
            SLOW_BODY,
            "chunked={chunked}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!("({} B)", SLOW_BODY.len())),
            "marker reports the bytes written: {stderr}"
        );
        assert_no_progress_in(&stderr);
    }
}

#[test]
fn a_slow_batch_run_logs_only_request_and_status_lines() {
    let (port, handle) = slow_server(SLOW_BODY, true);
    let out = api_against_port(port)
        .args(["-sa", "-"])
        .write_stdin("GET /x\nassert GET /x\n")
        .output()
        .expect("spawn api");
    let _ = handle.join();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.matches("200 OK").count(), 2, "{stdout}");
    assert_no_progress_in(&stdout);
    assert_no_progress_in(&String::from_utf8_lossy(&out.stderr));
}

const ORANGE_404: &str = "\x1b[38;5;208m404 Not Found";
const RED_404: &str = "\x1b[31m404 Not Found";

/// `api_against_port` with colours forced on, since the test's pipes would
/// otherwise turn them off.
fn api_in_colour(port: u16) -> Command {
    let mut cmd = api_against_port(port);
    cmd.env("CLICOLOR_FORCE", "1").env_remove("NO_COLOR");
    cmd
}

#[test]
fn assert_not_prints_its_expected_404_in_orange() {
    let (port, server) = status_server(vec!["404 Not Found"]);
    let dir = tempdir().unwrap();
    let req = dir.path().join("expected.api");
    std::fs::write(&req, "assert not GET /mapped-types/x\n").unwrap();
    let assert = api_in_colour(port).args(["-sa"]).arg(&req).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(stdout.contains(ORANGE_404), "{stdout:?}");
    assert!(!stdout.contains(RED_404), "{stdout:?}");
    server.join().unwrap();
}

#[test]
fn a_404_nobody_asked_for_stays_red() {
    // A failing `assert`, and a plain request.
    let (port, server) = status_server(vec!["404 Not Found"]);
    let dir = tempdir().unwrap();
    let req = dir.path().join("plain.api");
    std::fs::write(&req, "GET /people/1\nassert GET /people/1\n").unwrap();
    let assert = api_in_colour(port).args(["-sa"]).arg(&req).assert().failure();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert_eq!(stdout.matches(RED_404).count(), 2, "{stdout:?}");
    assert!(!stdout.contains(ORANGE_404), "{stdout:?}");
    server.join().unwrap();
}

#[test]
fn an_error_status_is_red_even_under_assert_not() {
    let (port, server) = status_server(vec!["500 Internal Server Error"]);
    let dir = tempdir().unwrap();
    let req = dir.path().join("error.api");
    std::fs::write(&req, "assert not GET /people/1\n").unwrap();
    let assert = api_in_colour(port).args(["-sa"]).arg(&req).assert().failure();
    let out = assert.get_output();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(all.contains("\x1b[31m500 Internal Server Error"), "{all:?}");
    assert!(!all.contains("\x1b[38;5;208m"), "{all:?}");
    server.join().unwrap();
}

#[test]
fn a_chain_condition_prints_its_404_in_orange_but_the_last_segment_in_red() {
    // `GET || PUT`: the GET's 404 is what sends the chain on, so it's
    // expected. The PUT is the point of the line, so its 404 is not.
    let (port, server) = status_server(vec!["404 Not Found"]);
    let dir = tempdir().unwrap();
    let req = dir.path().join("chain.api");
    std::fs::write(&req, "GET /people/1 || PUT /people/1 {\"name\":\"Joe\"}\n").unwrap();
    let assert = api_in_colour(port).args(["-sa"]).arg(&req).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let orange = stdout.find(ORANGE_404).unwrap_or_else(|| panic!("no orange 404: {stdout:?}"));
    let red = stdout.find(RED_404).unwrap_or_else(|| panic!("no red 404: {stdout:?}"));
    assert!(orange < red, "condition first, then the write: {stdout:?}");
    assert_eq!(server.join().unwrap().len(), 2);
}

// One-shot arguments accept the same syntax as a .api line: directives,
// chains, and a whole line in one argument all go through the batch runner.

#[test]
fn one_shot_chain_runs_both_segments_split_or_quoted() {
    let (port, server) = flipping_server(vec!["1"]);
    // Split by the shell into separate arguments…
    api_against_port(port).args(["-s", "GET", "/a", "&&", "GET", "/b"]).assert().success();
    // …or quoted as one line.
    api_against_port(port).args(["-s", "GET /c && GET /d"]).assert().success();
    let seen = server.join().unwrap();
    let paths: Vec<&str> = seen.iter().map(|r| r.split_whitespace().nth(1).unwrap_or("")).collect();
    assert_eq!(paths, ["/api/v1/a", "/api/v1/b", "/api/v1/c", "/api/v1/d"], "{seen:?}");
}

#[test]
fn one_shot_assert_exits_one_on_failure_and_zero_on_success() {
    let (port, server) = flipping_server(vec!["213", "213"]);
    api_against_port(port).args(["assert", "/people~count"]).assert().success();
    let assert = api_against_port(port).args(["assert", "not", "/people~count"]).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(stderr.contains("assertion failed: assert not GET /people~count (213)"), "{stderr}");
    assert_eq!(server.join().unwrap().len(), 2);
}

#[test]
fn one_shot_unknown_word_is_an_error_not_a_request() {
    // Before: `api peple` sent nothing and opened the TUI, and `api sleep 2`
    // sent GET /2. Both are now reported without touching the server.
    let (port, server) = flipping_server(vec!["{}"]);
    let assert = api_against_port(port).arg("peple").assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(stderr.contains("not a request or .api file: peple"), "{stderr}");
    let assert = api_against_port(port).args(["sleep", "abc"]).assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(stderr.contains("invalid sleep duration"), "{stderr}");
    // Unblock the server's accept loop with one real request, then check
    // that it was the only one.
    api_against_port(port).args(["-s", "GET", "/only"]).assert().success();
    let seen = server.join().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
}

#[test]
fn one_shot_runs_an_api_file_named_as_the_argument() {
    let (port, server) = flipping_server(vec!["{}"]);
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("seed.api"), "GET /from-file\n").unwrap();
    // Relative to the working directory, like an include. An absolute path
    // works too, told from a URI by its `.api` suffix — see tests/parity.rs.
    api_against_port(port).current_dir(dir.path()).arg("seed.api").assert().success();
    let seen = server.join().unwrap();
    assert!(seen.iter().any(|r| r.contains("GET /api/v1/from-file")), "{seen:?}");
}

#[test]
fn sleep_while_aborts_on_error_status() {
    // A 401 on the poll is Errored, not falsy: the run must stop with exit 1
    // and say why, rather than retry forever.
    let run = run_fail_fast("-sa", "sleep 100ms while GET /q\nGET /never\n", vec![("401 Unauthorized", "{}"), OK]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /q"]);
    assert_eq!(run.stdout.matches("└─HTTP/1.1 401").count(), 1, "the 401 should be shown once: {}", run.stdout);
    assert!(run.stderr.contains("could not be evaluated"), "{}", run.stderr);
    assert!(!run.stdout.contains("waited"), "must not report success: {}", run.stdout);
}

#[test]
fn or_chain_does_not_catch_errors() {
    // A 401 is Errored, not Falsy: the || fallback must NOT run, and the run
    // aborts with exit 1.
    let run = run_fail_fast("-sa", "GET /q || PUT /fallback {\"fallback\":1}\nGET /never\n", vec![("401 Unauthorized", "{}"), OK]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /q"], "the fallback must not run on a 401");
    assert_eq!(run.stdout.matches("└─HTTP/1.1").count(), 1, "{}", run.stdout);
}


#[test]
fn outfile_csv_extension_sets_csv_accept() {
    let (port, server) = whole_request_server(vec![("200 OK", "a,b\n1,2\n")]);
    let dir = tempdir().unwrap();
    let outfile = dir.path().join("out.csv");
    let uri_with_outfile = format!("/things > {}", outfile.display());

    let out = api_against_port(port).args(["GET", &uri_with_outfile]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let seen = server.join().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(header(&seen[0], "accept"), Some("text/csv"), "{}", seen[0]);
    // And what came back is in the file as it came.
    assert_eq!(std::fs::read_to_string(&outfile).unwrap(), "a,b\n1,2\n");
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
    // `/version/foo` is NOT a version prefix: it is a path under the default
    // one, `/api/v1/version/foo`.
    let (port, server) = whole_request_server(vec![("200 OK", "null")]);
    let out = api_against_port(port).args(["GET", "/version/foo"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let seen = server.join().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].starts_with("GET /api/v1/version/foo HTTP/1.1\r\n"), "{}", seen[0]);
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

#[test]
fn url_gate_allows_matching_base() {
    let (port, server) = answering_server(vec![OK]);
    let dir = tempdir().unwrap();
    let req_file = dir.path().join("gated-ok.api");
    // Two lines are an allowlist: one that fits is enough.
    std::fs::write(&req_file, format!("url has nowhere.example.invalid\nurl has 127.0.0.1:{port}\nGET /gated\n")).unwrap();

    let out = api_against_port(port).args(["-a"]).arg(&req_file).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(server.join().unwrap(), vec!["GET /gated"]);
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

    // The server read the body as JSON, so the newline was sent escaped, and
    // the value it echoes holds the newline. Printed, it is escaped again:
    // the raw form in the output would be JSON nobody can read back.
    assert!(stdout.contains("line1\\nline2"), "expected the escaped newline in the echoed body: {stdout}");
    let echoed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
    let record = echoed.get(0).unwrap_or(&echoed);
    assert_eq!(record["bio"], "line1\nline2", "{stdout}");
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

    // The environment once, then each request line with its compact status
    // under it, and nothing else: no line is left over for a body, whatever
    // the server answered.
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "{stdout}");
    assert!(lines[0].starts_with("[http") && lines[0].ends_with(']'), "{stdout}");
    assert_eq!(lines[1], "PUT /echo-all [{\"name\":\"Joe\"}]", "{stdout}");
    assert!(lines[2].starts_with("└─HTTP/1.1 200 OK "), "{stdout}");
    assert_eq!(lines[3], "GET /echo-all", "{stdout}");
    assert!(lines[4].starts_with("└─HTTP/1.1 200 OK "), "{stdout}");
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

#[test]
fn timeout_help_states_the_default_and_the_disable_value() {
    // The help text used to claim "no timeout", which was never true — reqwest's
    // blocking client applied a hidden 30s default.
    Command::cargo_bin("api")
        .expect("api binary built")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("600"))
        .stdout(predicate::str::contains("10 minutes"));
}

#[test]
fn timeout_zero_disables_the_timeout() {
    require_local_cos();
    api()
        .args(["GET", "/echo-all", "--timeout", "0", "--silent"])
        .assert()
        .success();
}

#[test]
fn timeout_expiry_reports_the_timeout_not_a_dead_server() {
    // A 1s timeout against a host that accepts the connection but never answers.
    // The old code discarded the error and always blamed the server.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    // Accept connections but never respond, so the client waits for headers.
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });

    // Built directly rather than via api(): that helper may already pass `-b`
    // from the environment, which would collide with the dummy server here.
    let mut cmd = Command::cargo_bin("api").expect("api binary built");
    cmd.arg("--no-keychain");
    cmd.env("API_CREDENTIALS_FILE", credentials_file());
    let assert = cmd
        .args([
            "-b",
            &format!("http://127.0.0.1:{port}"),
            "-k",
            "dummy-key",
            "--timeout",
            "1",
            "GET",
            "/echo-all",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();

    assert!(stderr.contains("Timed out after 1s"), "expected timeout message, got: {stderr}");
    assert!(stderr.contains("--timeout"), "expected the remedy, got: {stderr}");
    assert!(
        !stderr.contains("Is COS running"),
        "a timeout must not be reported as a dead server: {stderr}"
    );
}

// ----- the HTTP client itself: methods, credentials, TLS -----

/// A server that answers each request with the next `(status, body)` of
/// `answers` (repeating the last) and returns every request whole, head and
/// body, as it arrived.
fn whole_request_server(answers: Vec<(&'static str, &'static str)>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for i in 0.. {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let accepted = loop {
                match listener.accept() {
                    Ok(pair) => break Some(pair),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() > deadline {
                            break None;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            let Some((mut stream, _)) = accepted else { break };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
            // Head and body may come in separate writes: read until the
            // body is as long as the head says. What is no HTTP at all (a TLS
            // hello) ends when nothing more comes.
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
                let text = String::from_utf8_lossy(&request);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
            }
            let request = String::from_utf8_lossy(&request).to_string();
            let (status, body) = answers[i.min(answers.len() - 1)];
            // A HEAD is answered without a body, as HTTP has it.
            let body = if request.starts_with("HEAD ") { "" } else { body };
            seen.push(request);
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = stream.flush();
        }
        seen
    });
    (port, handle)
}

/// The value of `name` among a request's headers, whatever its case.
fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request
        .split("\r\n\r\n")
        .next()?
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

#[test]
fn every_method_reaches_the_server_with_its_body() {
    for (method, body) in [
        ("GET", None),
        ("POST", Some(r#"[{"a":1}]"#)),
        ("PUT", Some(r#"{"a":1}"#)),
        ("PATCH", Some(r#"{"a":1}"#)),
        ("DELETE", None),
        ("HEAD", None),
        ("OPTIONS", None),
    ] {
        let (port, server) = whole_request_server(vec![("200 OK", "{}")]);
        let mut cmd = api_against_port(port);
        cmd.args(["-s", method, "/things/1"]);
        if let Some(body) = body {
            cmd.arg(body);
        }
        let out = cmd.output().expect("api runs");
        let seen = server.join().expect("server thread");
        assert!(out.status.success(), "{method}: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(seen.len(), 1, "{method}: {seen:?}");
        assert!(seen[0].starts_with(&format!("{method} /api/v1/things/1 HTTP/1.1\r\n")), "{method}: {}", seen[0]);
        let sent_body = seen[0].split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        assert_eq!(sent_body, body.unwrap_or(""), "{method}");
        if body.is_some() {
            assert_eq!(header(&seen[0], "content-type"), Some("application/json"), "{method}: {}", seen[0]);
        }
    }
}

#[test]
fn a_key_is_sent_as_basic_and_a_token_as_bearer() {
    let run = |args: &[&str]| {
        let (port, server) = whole_request_server(vec![("200 OK", "{}")]);
        let mut cmd = Command::cargo_bin("api").expect("api binary built");
        cmd.arg("--no-keychain")
            .env("API_CREDENTIALS_FILE", "/nonexistent/credentials.json")
            .args(["-b", &format!("http://127.0.0.1:{port}"), "-s"])
            .args(args)
            .args(["GET", "/things"]);
        let out = cmd.output().expect("api runs");
        let seen = server.join().expect("server thread");
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(seen.len(), 1, "{args:?}: {seen:?}");
        header(&seen[0], "authorization").unwrap_or("").to_string()
    };

    // An API key is the password of a Basic login with no user name.
    use base64::Engine;
    let basic = base64::engine::general_purpose::STANDARD.encode(":my-key");
    assert_eq!(run(&["-k", "my-key"]), format!("Basic {basic}"));
    assert_eq!(run(&["--token", "tok-123"]), "Bearer tok-123");
    // A token wins over a key given with it.
    assert_eq!(run(&["-k", "my-key", "--token", "tok-123"]), "Bearer tok-123");
    // A key that is a JWT is a token and goes as one.
    let jwt = format!("eyJhbGciOiJIUzI1NiJ9.{}.sig", "a".repeat(200));
    assert_eq!(run(&["-k", &jwt]), format!("Bearer {jwt}"));
}

#[test]
fn an_oauth2_connection_exchanges_its_secret_for_a_token_first() {
    let dir = tempdir().unwrap();
    let credentials = dir.path().join("credentials.json");
    let write = |port: u16| {
        std::fs::write(
            &credentials,
            format!(
                r#"{{"connections":[{{"name":"local","url":"http://127.0.0.1:{port}","auth_type":"oauth2","credential":"s3cret","client_id":"my-client"}}],"default":"local"}}"#
            ),
        )
        .unwrap();
    };
    let run = || {
        let mut cmd = Command::cargo_bin("api").expect("api binary built");
        cmd.arg("--no-keychain").env("API_CREDENTIALS_FILE", &credentials).args(["-s", "GET", "/things"]);
        cmd.output().expect("api runs")
    };

    let (port, server) = whole_request_server(vec![("200 OK", r#"{"access_token":"tok-from-exchange","expires_in":60}"#), ("200 OK", "{}")]);
    write(port);
    let out = run();
    let seen = server.join().expect("server thread");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(seen[0].starts_with("POST /oauth2/v1/token HTTP/1.1\r\n"), "{}", seen[0]);
    assert_eq!(header(&seen[0], "content-type"), Some("application/x-www-form-urlencoded"));
    assert!(seen[0].ends_with("grant_type=client_credentials&client_id=my-client&client_secret=s3cret"), "{}", seen[0]);
    assert!(seen[1].starts_with("GET /api/v1/things HTTP/1.1\r\n"), "{}", seen[1]);
    assert_eq!(header(&seen[1], "authorization"), Some("Bearer tok-from-exchange"));
    // The secret goes to the token endpoint only.
    assert!(!seen[1].contains("s3cret"), "{}", seen[1]);

    // A refused exchange is an error, and the request is not sent without a token.
    let (port, server) = whole_request_server(vec![("401 Unauthorized", r#"{"error":"invalid_client"}"#), ("200 OK", "{}")]);
    write(port);
    let out = run();
    let seen = server.join().expect("server thread");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("401"), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(seen.len(), 1, "{seen:?}");
}

/// An https server on this machine with a certificate nobody signed.
/// Returns what the handshake came to and every byte of HTTP that got
/// through it.
fn self_signed_https_server() -> (u16, std::thread::JoinHandle<(bool, String)>) {
    use std::io::{Read, Write};
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()]).expect("certificate");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .expect("server config");
    let config = std::sync::Arc::new(config);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let (mut shook, mut heard) = (false, String::new());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        while std::time::Instant::now() < deadline {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut tls = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut channel = rustls::Stream::new(&mut tls, &mut stream);
            let mut buf = [0u8; 4096];
            if let Ok(n) = channel.read(&mut buf) {
                heard.push_str(&String::from_utf8_lossy(&buf[..n]));
                let _ = channel.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            }
            shook |= !tls.is_handshaking();
        }
        (shook, heard)
    });
    (port, handle)
}

#[test]
fn a_port_that_speaks_no_tls_and_one_nobody_listens_on_are_told_apart() {
    // Plain http behind an https URL: there is a server, and that is said.
    let (port, server) = whole_request_server(vec![("200 OK", "{}")]);
    let run = |port: u16| {
        Command::cargo_bin("api")
            .unwrap()
            .arg("--no-keychain")
            .env("API_CREDENTIALS_FILE", "/nonexistent/credentials.json")
            .env("NO_COLOR", "1")
            .args(["-b", &format!("https://127.0.0.1:{port}"), "-k", "k", "--timeout", "5", "GET", "/x"])
            .output()
            .expect("api runs")
    };
    let out = run(port);
    drop(server);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains(&format!("No secure connection to 127.0.0.1:{port}: ")), "{stderr}");
    assert!(!stderr.contains("Is COS running"), "{stderr}");

    // Nothing there at all is still asked about as before.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let out = run(free);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains(&format!("Is COS running on 127.0.0.1:{free}?")), "{stderr}");
}

#[test]
fn a_certificate_nobody_signed_is_refused_and_nothing_is_sent_over_it() {
    for host in ["localhost", "127.0.0.1"] {
        let (port, server) = self_signed_https_server();
        let out = Command::cargo_bin("api")
            .unwrap()
            .arg("--no-keychain")
            .env("API_CREDENTIALS_FILE", "/nonexistent/credentials.json")
            .env("NO_COLOR", "1")
            .args(["-b", &format!("https://{host}:{port}"), "-k", "my-secret-key", "--timeout", "5", "PUT", "/things/1", r#"{"a":1}"#])
            .output()
            .expect("api runs");
        let (shook, heard) = server.join().expect("server thread");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{host}: {stderr}");
        // The handshake is where it ends: no request, and so no key, got through.
        assert!(!shook, "{host}: the client accepted the certificate");
        assert_eq!(heard, "", "{host}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "", "{host}");
        // And it is said as what it is, not as a server that isn't there.
        assert!(
            stderr.contains(&format!("The certificate of {host}:{port} is not trusted: it is not signed by a public certificate authority.")),
            "{host}: {stderr}"
        );
        assert!(!stderr.contains("Is COS running"), "{host}: {stderr}");
    }
}

/// The same in a batch: the run ends at the first line, with the certificate
/// named and nothing sent, as it does for a single request.
#[test]
fn a_certificate_nobody_signed_ends_a_batch_at_its_first_request() {
    let (port, server) = self_signed_https_server();
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("batch.api"), "GET /first\nGET /never\n").unwrap();
    for flags in ["-sa", "-sfa"] {
        let out = Command::cargo_bin("api")
            .unwrap()
            .arg("--no-keychain")
            .env("API_CREDENTIALS_FILE", "/nonexistent/credentials.json")
            .env("NO_COLOR", "1")
            .current_dir(dir.path())
            .args(["-b", &format!("https://127.0.0.1:{port}"), "-k", "my-secret-key", "--timeout", "5", flags, "batch.api"])
            .output()
            .expect("api runs");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{flags}: {stderr}");
        assert_eq!(
            stderr.trim(),
            format!("The certificate of 127.0.0.1:{port} is not trusted: it is not signed by a public certificate authority."),
            "{flags}"
        );
        // The log got as far as the request that could not be sent.
        assert_eq!(String::from_utf8_lossy(&out.stdout), format!("[https://127.0.0.1:{port}]\nGET /first\n"), "{flags}");
    }
    let (shook, heard) = server.join().expect("server thread");
    assert!(!shook, "the client accepted the certificate");
    assert_eq!(heard, "");
}

// ----- -f / --fail-fast -----

/// A server that answers each request with the next `(status, body)` of
/// `answers` (repeating the last one) and reports what it received.
fn answering_server(answers: Vec<(&'static str, &'static str)>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for i in 0.. {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let accepted = loop {
                match listener.accept() {
                    Ok(pair) => break Some(pair),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() > deadline {
                            break None;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            let Some((mut stream, _)) = accepted else { break };
            stream.set_nonblocking(false).unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            seen.push(request.lines().next().unwrap_or("").replace(" HTTP/1.1", "").replace("/api/v1", ""));
            let (status, body) = answers[i.min(answers.len() - 1)];
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = stream.flush();
        }
        seen
    });
    (port, handle)
}

/// What `PUT /v1/assert` answers when an assertion fails, as the API's own
/// reference describes it: a 409 `failed assertion` with an entry per failed
/// path. The client passes the body on untouched.
const ASSERT_FAILED: (&str, &str) = (
    "409 Conflict",
    r#"{"@type":"failed assertion","error":"One or more assertions failed.","details":"1 of 1 assertion failed.","failures":{"api/v1/people~count":{"was":2,"expected":{"is":3}}}}"#,
);
/// What it answers when every assertion holds.
const ASSERT_HELD: (&str, &str) = ("200 OK", "null");
/// What it answers to a request it can't read: no failure, a 400.
const ASSERT_INVALID: (&str, &str) =
    ("400 Bad Request", r#"{"@type":"bad request","error":"The request was invalid and could not be processed."}"#);
const OK: (&str, &str) = ("200 OK", r#"{"ok":true}"#);
const NOT_FOUND: (&str, &str) = ("404 Not Found", r#"{"@type":"not found"}"#);

struct FailFastRun {
    ok: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
    seen: Vec<String>,
}

/// Run `batch` as a file with `flags` against a server giving `answers`.
fn run_fail_fast(flags: &str, batch: &str, answers: Vec<(&'static str, &'static str)>) -> FailFastRun {
    let (port, server) = answering_server(answers);
    let dir = tempdir().unwrap();
    let file = dir.path().join("batch.api");
    std::fs::write(&file, batch).unwrap();
    let out = api_against_port(port)
        .env("NO_COLOR", "1")
        .current_dir(dir.path())
        .arg(flags)
        .arg(&file)
        .output()
        .expect("api runs");
    FailFastRun {
        ok: out.status.success(),
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        seen: server.join().expect("server thread"),
    }
}

const ASSERT_BATCH: &str =
    "GET /before\nPUT /assert {\n  \"api/v1/people~count\": { \"is\": 3 }\n}\nGET /never\n";

#[test]
fn without_fail_fast_a_failed_request_does_not_stop_a_batch() {
    let run = run_fail_fast("-sa", ASSERT_BATCH, vec![OK, ASSERT_FAILED, OK]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /before", "PUT /assert", "GET /never"]);
    // And `-sa` prints no bodies, the failed one included.
    assert!(!run.stdout.contains("failed assertion"), "{}", run.stdout);
}

#[test]
fn fail_fast_stops_a_silent_batch_at_a_failed_assert_and_ends_stdout_with_its_body() {
    let run = run_fail_fast("-sfa", ASSERT_BATCH, vec![OK, ASSERT_FAILED, OK]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(run.code, Some(1));
    assert_eq!(run.seen, vec!["GET /before", "PUT /assert"]);

    let lines: Vec<&str> = run.stdout.lines().collect();
    // The log up to the failure, the status line of the request that failed…
    assert!(lines.contains(&r#"PUT /assert {"api/v1/people~count":{"is":3}}"#), "{}", run.stdout);
    assert!(lines[lines.len() - 2].contains("HTTP/1.1 409 Conflict"), "{}", run.stdout);
    // …and, last, the body exactly as the server sent it, for tooling to read.
    assert_eq!(lines[lines.len() - 1], ASSERT_FAILED.1, "{}", run.stdout);
    assert!(run.stdout.ends_with("}\n"), "{:?}", run.stdout);
    assert!(!run.stdout.contains("GET /never"), "{}", run.stdout);
    // The body of the request that worked is still not printed in `-sa`.
    assert!(!run.stdout.contains(r#"{"ok":true}"#), "{}", run.stdout);
    let parsed: serde_json::Value = serde_json::from_str(lines[lines.len() - 1]).unwrap();
    assert_eq!(parsed["@type"], "failed assertion");
    assert_eq!(parsed["failures"]["api/v1/people~count"]["was"], 2);
}

#[test]
fn fail_fast_lets_a_held_assert_pass_and_stops_on_an_invalid_one() {
    // Every assertion holding is `200` with `null`: nothing to stop for.
    let run = run_fail_fast("-sfa", ASSERT_BATCH, vec![OK, ASSERT_HELD, OK]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /before", "PUT /assert", "GET /never"]);
    assert!(!run.stdout.lines().any(|l| l == "null"), "{}", run.stdout);

    // A request the server can't read is a 400, which stops the run as well.
    let run = run_fail_fast("-sfa", ASSERT_BATCH, vec![OK, ASSERT_INVALID, OK]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /before", "PUT /assert"]);
    assert_eq!(run.stdout.lines().last().unwrap(), ASSERT_INVALID.1);
}

#[test]
fn fail_fast_in_a_plain_batch_prints_the_bodies_so_far_then_the_failing_one() {
    let run = run_fail_fast("-fa", ASSERT_BATCH, vec![OK, ASSERT_FAILED, OK]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(run.seen.len(), 2);
    assert_eq!(run.stdout, format!("{}\n{}\n", OK.1, ASSERT_FAILED.1));
    // The status lines are on stderr, as without `-f`.
    assert!(run.stderr.contains("HTTP/1.1 200 OK") && run.stderr.contains("HTTP/1.1 409 Conflict"), "{}", run.stderr);
}

#[test]
fn fail_fast_trips_on_every_status_from_400_up() {
    for answer in [
        ("400 Bad Request", "bad"),
        ("401 Unauthorized", "who"),
        NOT_FOUND,
        ("422 Unprocessable Entity", "{}"),
        ("500 Internal Server Error", "boom"),
        ("503 Service Unavailable", ""),
    ] {
        let run = run_fail_fast("-sfa", "PUT /x {\"a\":1}\nGET /never\n", vec![answer, OK]);
        assert_eq!(run.code, Some(1), "{}: {}", answer.0, run.stderr);
        assert_eq!(run.seen, vec!["PUT /x"], "{}", answer.0);
        // A body that isn't JSON, or has no newline of its own, is still
        // passed on as it came, with one newline to end the line. An empty
        // body adds nothing.
        let last = run.stdout.lines().last().unwrap_or_default();
        if answer.1.is_empty() {
            assert!(last.contains(&format!("HTTP/1.1 {}", answer.0)), "{}: {:?}", answer.0, run.stdout);
        } else {
            assert_eq!(last, answer.1, "{}: {:?}", answer.0, run.stdout);
        }
        assert!(run.stdout.ends_with('\n') && !run.stdout.ends_with("\n\n"), "{}: {:?}", answer.0, run.stdout);
    }
    // Below 400 nothing trips, whatever the body says.
    let run = run_fail_fast("-sfa", "GET /a\nGET /b\n", vec![("200 OK", "false"), ("204 No Content", "")]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.seen.len(), 2);
}

#[test]
fn fail_fast_leaves_questions_alone() {
    // Every request here is a question that is answered "no": a chain
    // condition, an `assert not`, and a poll. None of them ends the run.
    let batch = "GET /people/1 || PUT /people/1 {\"name\":\"Ann\"}\n\
                 assert not GET /people/2\n\
                 sleep 10ms while GET /imports/running\n\
                 GET /after\n";
    let run = run_fail_fast("-sfa", batch, vec![NOT_FOUND, OK, NOT_FOUND, NOT_FOUND, OK]);
    assert!(run.ok, "{}\n{}", run.stdout, run.stderr);
    assert_eq!(
        run.seen,
        vec!["GET /people/1", "PUT /people/1", "GET /people/2", "GET /imports/running", "GET /after"]
    );
}

#[test]
fn a_request_timeout_and_a_rate_limit_are_never_an_answer() {
    // 408 and 429 say "not now", not "no": a question that gets one ends
    // the run wherever it was asked, and `-f` puts the body on stdout.
    for status in ["408 Request Timeout", "429 Too Many Requests"] {
        // A chain condition: the run ends and the body says why.
        for batch in ["GET /q || PUT /x {\"a\":1}\nGET /never\n", "GET /q && PUT /x {\"a\":1}\nGET /never\n"] {
            let run = run_fail_fast("-sfa", batch, vec![(status, "slow down"), OK]);
            assert_eq!(run.code, Some(1), "{status}: {batch}\n{}", run.stderr);
            assert_eq!(run.seen, vec!["GET /q"], "{status}: {batch}");
            assert!(run.stdout.ends_with("slow down\n"), "{status}: {batch}\n{:?}", run.stdout);
        }
        // An assert and a poll say so themselves, and `-f` adds the body:
        // last on stdout, as for any response that ends a run.
        for (batch, says) in [
            ("assert not GET /q\nGET /never\n", "assert not GET /q — could not be evaluated"),
            ("sleep 10ms while GET /q\nGET /never\n", "condition could not be evaluated (check 1)"),
        ] {
            let run = run_fail_fast("-sfa", batch, vec![(status, "slow down"), OK]);
            assert_eq!(run.code, Some(1), "{status}: {batch}\n{}", run.stderr);
            assert_eq!(run.seen, vec!["GET /q"], "{status}: {batch}");
            assert!(run.stderr.contains(says), "{status}: {batch}\n{}", run.stderr);
            assert!(run.stdout.ends_with("s\nslow down\n"), "{status}: {batch}\n{:?}", run.stdout);
            // Without `-f` the body stays out, as it always did.
            let run = run_fail_fast("-sa", batch, vec![(status, "slow down"), OK]);
            assert_eq!(run.code, Some(1), "{status}: {batch}\n{}", run.stderr);
            assert!(run.stderr.contains(says), "{status}: {batch}\n{}", run.stderr);
            assert!(!run.stdout.contains("slow down"), "{status}: {batch}\n{:?}", run.stdout);
        }
        // Without `-f` it ends the run from a question all the same…
        let run = run_fail_fast("-sa", "GET /q || PUT /x {\"a\":1}\nGET /never\n", vec![(status, "slow down"), OK]);
        assert_eq!(run.code, Some(1), "{status}: {}", run.stderr);
        assert_eq!(run.seen, vec!["GET /q"], "{status}");
        // …and a plain request that gets one is logged and passed, as any failure is.
        let run = run_fail_fast("-sa", "GET /q\nGET /after\n", vec![(status, "slow down"), OK]);
        assert!(run.ok, "{status}: {}", run.stderr);
        assert_eq!(run.seen, vec!["GET /q", "GET /after"], "{status}");
    }
}

#[test]
fn fail_fast_trips_on_the_last_request_of_a_chain() {
    let batch = "GET /people/1 && PUT /people/1 {\"name\":\"Ann\"}\nGET /never\n";
    let run = run_fail_fast("-sfa", batch, vec![OK, ASSERT_FAILED, OK]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /people/1", "PUT /people/1"]);
    assert!(run.stdout.ends_with(&format!("{}\n", ASSERT_FAILED.1)), "{:?}", run.stdout);
}

#[test]
fn fail_fast_prints_the_body_of_a_condition_that_could_not_be_answered() {
    // A 500 is not a "no". The chain aborted on it before `-f` too; with it,
    // the body says why.
    let batch = "GET /people/1 || PUT /people/1 {\"name\":\"Ann\"}\nGET /never\n";
    let run = run_fail_fast("-sfa", batch, vec![("500 Internal Server Error", "database is down"), OK]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /people/1"]);
    assert!(run.stdout.ends_with("database is down\n"), "{:?}", run.stdout);
}

#[test]
fn the_assert_keyword_still_reports_its_own_failure_under_fail_fast() {
    let run = run_fail_fast("-sfa", "assert GET /people/1\nGET /never\n", vec![NOT_FOUND, OK]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /people/1"]);
    assert!(run.stderr.contains("assertion failed: assert GET /people/1 (404 Not Found)"), "{}", run.stderr);
    // An assert is a verdict: its body is not printed, with or without `-f`.
    assert!(!run.stdout.contains("not found"), "{}", run.stdout);
}

#[test]
fn fail_fast_does_not_write_an_error_into_an_outfile() {
    let batch = "GET /export > out.json\nGET /never\n";
    for (flags, expect_file) in [("-sa", true), ("-sfa", false)] {
        let (port, server) = answering_server(vec![NOT_FOUND, OK]);
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("batch.api"), batch).unwrap();
        let out = api_against_port(port)
            .env("NO_COLOR", "1")
            .current_dir(dir.path())
            .args([flags, "batch.api"])
            .output()
            .unwrap();
        server.join().unwrap();
        assert_eq!(dir.path().join("out.json").exists(), expect_file, "{flags}");
        assert_eq!(out.status.success(), expect_file, "{flags}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(stdout.contains(NOT_FOUND.1), !expect_file, "{flags}: {stdout}");
    }
}

#[test]
fn fail_fast_makes_a_one_shot_request_exit_one_with_the_body() {
    for (flags, ok, status_shown) in [
        (vec![], true, true),
        (vec!["-f"], false, true),
        (vec!["--fail-fast"], false, true),
        (vec!["-sf"], false, false),
    ] {
        let (port, server) = answering_server(vec![ASSERT_FAILED]);
        let out = api_against_port(port)
            .env("NO_COLOR", "1")
            .args(&flags)
            .args(["PUT", "/assert", r#"{"api/v1/people~count":{"is":3}}"#])
            .output()
            .unwrap();
        assert_eq!(server.join().unwrap().len(), 1, "{flags:?}");
        assert_eq!(out.status.success(), ok, "{flags:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{}\n", ASSERT_FAILED.1), "{flags:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(stderr.contains("409 Conflict"), status_shown, "{flags:?}: {stderr}");
    }
    // A request that works is untouched by the flag.
    let (port, server) = answering_server(vec![OK]);
    let out = api_against_port(port).args(["-f", "GET", "/people"]).output().unwrap();
    server.join().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{}\n", OK.1));
}

#[test]
fn fail_fast_stops_a_one_shot_program_line_and_a_batch_on_stdin() {
    let (port, server) = answering_server(vec![ASSERT_FAILED, OK]);
    let out = api_against_port(port)
        .env("NO_COLOR", "1")
        .args(["-sf", r#"PUT /assert {"api/v1/x":{"is":1}} && GET /never"#])
        .output()
        .unwrap();
    assert_eq!(server.join().unwrap(), vec!["PUT /assert"]);
    // The condition said no, which is an answer: the chain is cut short, not
    // the run, and no body is put on stdout.
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("failed assertion"), "{}", String::from_utf8_lossy(&out.stdout));

    // A program of two lines in one argument: the first line is a plain
    // request, so its 409 stops the run before the second.
    let (port, server) = answering_server(vec![ASSERT_FAILED, OK]);
    let out = api_against_port(port)
        .env("NO_COLOR", "1")
        .args(["-sf", "PUT /assert {\"api/v1/x\":{\"is\":1}}\nGET /never"])
        .output()
        .unwrap();
    assert_eq!(server.join().unwrap(), vec!["PUT /assert"]);
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).ends_with(&format!("{}\n", ASSERT_FAILED.1)));

    let (port, server) = answering_server(vec![ASSERT_FAILED, OK]);
    let out = api_against_port(port)
        .env("NO_COLOR", "1")
        .args(["-sfa", "-"])
        .write_stdin("PUT /assert {\"api/v1/x\":{\"is\":1}}\nGET /never\n")
        .output()
        .unwrap();
    assert_eq!(server.join().unwrap(), vec!["PUT /assert"]);
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).ends_with(&format!("{}\n", ASSERT_FAILED.1)));
}

/// The server pretty-prints its JSON: a failing body of several lines is
/// passed on whole, after the last status line.
#[test]
fn fail_fast_passes_on_a_body_of_several_lines_whole() {
    const PRETTY: &str = "{\n  \"@type\": \"failed assertion\",\n  \"failures\": {\n    \"api/v1/x\": {\n      \"was\": 1\n    }\n  }\n}\n";
    let run = run_fail_fast("-sfa", "GET /before\nPUT /assert {\"api/v1/x\":{\"is\":2}}\n", vec![OK, ("409 Conflict", PRETTY)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    let (log, body) = run.stdout.rsplit_once("HTTP/1.1 409 Conflict").expect("a 409 status line");
    assert!(log.ends_with("└─"), "{log:?}");
    let body = body.split_once('\n').expect("the rest of the status line").1;
    assert_eq!(body, PRETTY);
    assert!(serde_json::from_str::<serde_json::Value>(body).is_ok());
}

/// The real endpoint, on a local CommerceOS that has it. Asserting changes
/// nothing on the server.
#[test]
fn fail_fast_against_the_assert_endpoint_of_a_local_cos() {
    require_local_cos();
    // `GET /assert` answers `200` with `{}` where the endpoint exists and a
    // 404 on a server from before it.
    let probe = api().args(["-sr", "GET", "/assert"]).output().unwrap();
    // A server without it is not one this suite can run against: a test
    // that returned here would pass having checked nothing.
    assert_eq!(
        String::from_utf8_lossy(&probe.stdout).trim(),
        "{}",
        "the local CommerceOS has no /assert endpoint: this suite needs a build that has it\nstderr: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let dir = tempdir().unwrap();
    let run = |name: &str, batch: &str| {
        let file = dir.path().join(name);
        std::fs::write(&file, batch).unwrap();
        let out = api().env("NO_COLOR", "1").args(["-sfa"]).arg(&file).output().unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stdout).to_string())
    };

    // Every assertion holds: `200`, and the batch goes on.
    let (code, stdout) = run(
        "holds.api",
        "PUT /assert {\n  \"api/v1/echo-all~count\": { \"is not\": 5 },\n  \"api/v1/about/cos-tag\": { \"is not\": null }\n}\nGET /echo-all\n",
    );
    assert_eq!(code, Some(0), "{stdout}");
    assert_eq!(stdout.matches("HTTP/1.1 200 OK").count(), 2, "{stdout}");

    // One does not: `409`, the batch stops and the failure document ends stdout.
    let (code, stdout) = run(
        "fails.api",
        "GET /echo-all\nPUT /assert {\n  \"api/v1/about/cos-tag\": { \"is\": \"not-the-tag-of-any-build\" }\n}\nGET /echo-all\n",
    );
    assert_eq!(code, Some(1), "{stdout}");
    assert_eq!(stdout.matches("GET /echo-all").count(), 1, "the request after the assert was sent: {stdout}");
    let body = stdout.rsplit_once("HTTP/1.1 409 Conflict").expect("a 409").1.split_once('\n').unwrap().1;
    let failure: serde_json::Value = serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"));
    assert_eq!(failure["@type"], "failed assertion");
    assert_eq!(failure["failures"]["api/v1/about/cos-tag"]["expected"]["is"], "not-the-tag-of-any-build");

    // A body that is no assert request: `400`, which stops the batch too.
    let (code, stdout) = run("invalid.api", "PUT /assert [1, 2]\nGET /echo-all\n");
    assert_eq!(code, Some(1), "{stdout}");
    assert!(stdout.contains("HTTP/1.1 400 Bad Request") && !stdout.contains("GET /echo-all"), "{stdout}");
}

// ----- --export -----

const SEED: &str = "com.heads.seedID";

/// A user as the API prints one: its own record has only a database key, the
/// agent below it and the client have another identifier as well, and a
/// secret is masked.
const USERS: &str = r#"[{"name":"Integration","@type":"user","identifiers":{"@type":"user identifiers","key":"2a196c5b"},"agent":{"@type":"agent","identifiers":{"key":"c59cf786","com.heads.seedID":"root-organization"},"name":"System"},"oauth2Clients":[{"identifiers":{"key":"6ac6a3b8","clientID":"mock"},"secret":"********"}]}]"#;
/// The same as seed data, on one line.
const USERS_EXPORTED: &str = r#"[{"@type":"user","identifiers":{"@type":"user identifiers","key?":"2a196c5b","com.heads.seedID":"2a196c5b"},"name":"Integration","agent":{"@type":"agent","identifiers":{"com.heads.seedID":"root-organization"},"name":"System"},"oauth2Clients":[{"identifiers":{"clientID":"mock"}}]}]"#;
/// What is said about `USERS`: where the masked value was, from the top of
/// the response, without positions in lists.
const MASKED_WARNING: &str = "warning: response had masked data, left out at oauth2Clients/secret";

struct ExportRun {
    ok: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
    seen: Vec<String>,
    dir: tempfile::TempDir,
}

/// Run the client with `args` in a fresh directory against a server giving
/// `answers`.
fn run_export(args: &[&str], answers: Vec<(&'static str, &'static str)>) -> ExportRun {
    let (port, server) = answering_server(answers);
    let dir = tempdir().unwrap();
    let out = api_against_port(port)
        .env("NO_COLOR", "1")
        .current_dir(dir.path())
        .args(args)
        .output()
        .expect("api runs");
    ExportRun {
        ok: out.status.success(),
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        seen: server.join().expect("server thread"),
        dir,
    }
}

fn compact(json: &str) -> String {
    serde_json::to_string(&serde_json::from_str::<serde_json::Value>(json).unwrap_or_else(|e| panic!("{e}: {json}"))).unwrap()
}

#[test]
fn export_rewrites_a_response_as_seed_data() {
    let run = run_export(&["--export", SEED, "GET", "/users"], vec![("200 OK", USERS)]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /users"]);
    // Indented, the members in the server's order behind `@type` and `identifiers`.
    assert!(run.stdout.starts_with("[\n  {\n    \"@type\": \"user\",\n    \"identifiers\": {\n"), "{}", run.stdout);
    assert_eq!(compact(&run.stdout), USERS_EXPORTED);
    // No `key` is left. `key?` stands on the one record whose name was made
    // from its key, not on the two that had another identifier.
    assert!(!run.stdout.contains("\"key\""), "{}", run.stdout);
    assert_eq!(run.stdout.matches("\"key?\"").count(), 1, "{}", run.stdout);
    // The status line and the warning go to stderr; stdout is the data alone.
    assert!(run.stderr.contains("HTTP/1.1 200 OK"), "{}", run.stderr);
    assert!(run.stderr.contains(MASKED_WARNING), "{}", run.stderr);

    // `-r` prints it on one line; `-s` drops the status line, not the warning.
    let run = run_export(&["--export", SEED, "-sr", "GET", "/users"], vec![("200 OK", USERS)]);
    assert_eq!(run.stdout, format!("{USERS_EXPORTED}\n"));
    assert_eq!(run.stderr.trim(), MASKED_WARNING);

    // Without the flag the response is what the server sent.
    let run = run_export(&["-sr", "GET", "/users"], vec![("200 OK", USERS)]);
    assert_eq!(run.stdout, format!("{USERS}\n"));
    assert_eq!(run.stderr, "");
}

#[test]
fn export_with_include_nulls_keeps_the_identity_of_a_record_that_has_only_a_key() {
    // With `-i` an identifier the record does not have arrives as null. It
    // was counted as one the record has, the key was dropped for it, and the
    // record came out with nothing to find it by.
    const CLIENTS: &str = r#"[{"identifiers":{"key":"k1","clientID":null},"name":"a"},{"identifiers":{"key":"k2","clientID":"mock"},"name":"b"},{"identifiers":{"key":"k3"},"name":"c"}]"#;
    let run = run_export(&["--export", SEED, "-i", "-sr", "GET", "/oauth2-clients"], vec![("200 OK", CLIENTS)]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        r#"[{"identifiers":{"key?":"k1","com.heads.seedID":"k1","clientID":null},"name":"a"},{"identifiers":{"clientID":"mock"},"name":"b"},{"identifiers":{"key?":"k3","com.heads.seedID":"k3"},"name":"c"}]"#
    );
    // Every record can be found by something that is not null.
    let records: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    for record in records.as_array().unwrap() {
        let found_by = record["identifiers"].as_object().unwrap().iter().any(|(name, v)| name != "key?" && !v.is_null());
        assert!(found_by, "{record}");
    }
}

#[test]
fn export_names_two_masked_places_and_counts_the_rest() {
    const MASKED: &str = r#"[{"password":"********","clients":[{"secret":"********","pin":"*******"}],"apiKey":"********"},{"password":"********"}]"#;
    let run = run_export(&["--export", SEED, "-sr", "GET", "/users"], vec![("200 OK", MASKED)]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.stderr.trim(), "warning: response had masked data, left out at password, clients/secret and 2 other places");
    // Each record is there, without what was masked in it. Nothing is `null`
    // in a secret's place: written back, that would clear it.
    assert_eq!(run.stdout.trim(), r#"[{"clients":[{}]},{}]"#);
}

/// A masked member is left out of an export with `-i` too, where every other
/// member that is not set is `null`. A list that held a mask is left out
/// whole, and a record whose only other member was masked keeps its
/// identifiers.
#[test]
fn export_leaves_a_masked_member_out_with_and_without_include_nulls() {
    const RECORDS: &str = r#"[{"identifiers":{"key":"k1"},"secret":"********"},{"identifiers":{"key":"k2","clientID":"********"},"note":null,"pins":["1","*******"],"name":"b"}]"#;
    const EXPORTED: &str = r#"[{"identifiers":{"key?":"k1","com.heads.seedID":"k1"}},{"identifiers":{"key?":"k2","com.heads.seedID":"k2"},"note":null,"name":"b"}]"#;
    for flags in [&["-sr"][..], &["-sri"], &["-r"]] {
        let mut args = vec!["--export", SEED];
        args.extend(flags);
        args.extend(["GET", "/clients"]);
        let run = run_export(&args, vec![("200 OK", RECORDS)]);
        assert!(run.ok, "{flags:?}: {}", run.stderr);
        assert_eq!(run.stdout.trim(), EXPORTED, "{flags:?}");
        assert!(!run.stdout.contains('*'), "{flags:?}: {}", run.stdout);
        // The warning names the places, under `-s` too, and one request
        // says it once: the closing line is a batch's.
        let warning = "warning: response had masked data, left out at secret, identifiers/clientID and 1 other place";
        assert!(run.stderr.lines().any(|line| line == warning), "{flags:?}: {}", run.stderr);
        assert!(!run.stderr.contains("responses had") && !run.stderr.contains("1 response had"), "{flags:?}: {}", run.stderr);
    }
}

/// A batch in which an export left masked data out says so once more where
/// it ends, with how many responses it was, and still exits 0: the warning
/// under one request is easily lost in a long log.
#[test]
fn a_batch_ends_with_how_many_responses_had_masked_data_left_out() {
    const MASKED: (&str, &str) = ("200 OK", r#"{"identifiers":{"key":"k"},"secret":"********"}"#);
    const PLAIN: (&str, &str) = ("200 OK", r#"{"identifiers":{"key":"k"},"n":1}"#);
    const TOTAL: &str = "masked data left out of the export; read those members out with ~just or ~without";
    let run_batch = |flags: &[&str], batch: &str, answers: Vec<(&'static str, &'static str)>| {
        let (port, server) = answering_server(answers);
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("batch.api"), batch).unwrap();
        let out = api_against_port(port).env("NO_COLOR", "1").current_dir(dir.path()).args(flags).arg("batch.api").output().unwrap();
        let written = |name: &str| std::fs::read_to_string(dir.path().join(name)).map(|text| compact(&text)).ok();
        (out.status.code(), String::from_utf8_lossy(&out.stderr).to_string(), server.join().unwrap().len(), written("a.json"), written("c.json"))
    };

    // Two of three responses: the warning under each, and the closing line last.
    let batch = "GET /a > a.json
GET /b > b.json
GET /c > c.json
";
    let (code, stderr, sent, a, c) = run_batch(&["--export", SEED, "-sa"], batch, vec![MASKED, PLAIN, MASKED]);
    assert_eq!((code, sent), (Some(0), 3), "{stderr}");
    assert_eq!(stderr.matches("warning: response had masked data, left out at secret").count(), 2, "{stderr}");
    assert_eq!(stderr.trim_end().lines().last(), Some(format!("warning: 2 responses had {TOTAL}").as_str()), "{stderr}");
    const EXPORTED: &str = r#"{"identifiers":{"key?":"k","com.heads.seedID":"k"}}"#;
    assert_eq!((a.as_deref(), c.as_deref()), (Some(EXPORTED), Some(EXPORTED)));

    // One: said in the singular. Under a `set export` line as under the option.
    let (code, stderr, _, _, _) = run_batch(&["-sa"], "GET /a
set export com.heads.seedID
GET /b > a.json
", vec![PLAIN, MASKED]);
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(stderr.trim_end().lines().last(), Some(format!("warning: 1 response had {TOTAL}").as_str()), "{stderr}");

    // None: nothing is said, with export on or off.
    let (code, stderr, _, _, _) = run_batch(&["--export", SEED, "-sa"], batch, vec![PLAIN]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(!stderr.contains("masked data"), "{stderr}");
    let (_, stderr, _, _, _) = run_batch(&["-sa"], batch, vec![MASKED]);
    assert!(!stderr.contains("masked data"), "{stderr}");

    // A batch that is stopped ends with the line too, under the reason.
    let (code, stderr, sent, _, _) =
        run_batch(&["--export", SEED, "-sfa"], "GET /a > a.json
GET /refused
GET /never
", vec![MASKED, ("409 Conflict", "{}")]);
    assert_eq!((code, sent), (Some(1), 2), "{stderr}");
    assert_eq!(stderr.trim_end().lines().last(), Some(format!("warning: 1 response had {TOTAL}").as_str()), "{stderr}");
}

#[test]
fn export_wants_a_namespaced_key_before_it_sends_anything() {
    for name in ["GET", "seedID", "com.heads", "com.heads.seed.ID", "my-co.heads.seedID", "com.heads.seed ID"] {
        let run = run_export(&["--export", name, "GET", "/users"], vec![("200 OK", USERS)]);
        assert!(!run.ok, "{name}");
        assert!(run.stderr.contains(&format!("invalid export identifier: {name}")), "{name}: {}", run.stderr);
        assert!(run.stderr.contains("three dot-separated segments"), "{name}: {}", run.stderr);
        assert_eq!(run.seen, Vec::<String>::new(), "{name}");
        assert_eq!(run.stdout, "");
    }
    // What the server takes as a namespaced key is taken here: `_` anywhere,
    // `-` in the second and third segment, `$` in the third.
    for name in ["com.heads.seed_ID", "my_co.my-org.seed-id$"] {
        let run = run_export(&["--export", name, "-sr", "GET", "/users"], vec![("200 OK", r#"{"identifiers":{"key":"k"}}"#)]);
        assert!(run.ok, "{name}: {}", run.stderr);
        assert_eq!(run.stdout.trim(), format!(r#"{{"identifiers":{{"key?":"k","{name}":"k"}}}}"#), "{name}");
    }
}

#[test]
fn export_writes_seed_data_to_an_outfile_and_appends_it() {
    let batch = "GET /users > users.json\nGET /users >> users.json\nGET /users\n";
    let (port, server) = answering_server(vec![("200 OK", USERS)]);
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("batch.api"), batch).unwrap();
    let out = api_against_port(port)
        .env("NO_COLOR", "1")
        .current_dir(dir.path())
        .args(["--export", SEED, "-sa", "batch.api"])
        .output()
        .unwrap();
    assert_eq!(server.join().unwrap().len(), 3);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    // The file holds the seed data of both requests, spliced into one list.
    let written: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.path().join("users.json")).unwrap()).unwrap();
    let one: serde_json::Value = serde_json::from_str(USERS_EXPORTED).unwrap();
    assert_eq!(written, serde_json::json!([one[0], one[0]]));
    // `-sa` still prints no body, exported or not; the warning is once per response.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("seedID") && !stdout.contains("2a196c5b"), "{stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stderr.matches(MASKED_WARNING).count(), 3);
    assert!(stderr.trim_end().ends_with("warning: 3 responses had masked data left out of the export; read those members out with ~just or ~without"), "{stderr}");

    // One request, redirected.
    let run = run_export(&["--export", SEED, "GET", "/users", ">", "one.json"], vec![("200 OK", USERS)]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.stdout, "");
    assert_eq!(compact(&std::fs::read_to_string(run.dir.path().join("one.json")).unwrap()), USERS_EXPORTED);
}

#[test]
fn export_leaves_an_error_body_as_the_server_sent_it() {
    const REFUSED: &str = r#"{"@type":"conflict","identifiers":{"key":"abc"},"secret":"********"}"#;
    for flags in [&["--export", SEED, "-sr"][..], &["--export", SEED, "-sfr"]] {
        let run = run_export(&[flags, &["GET", "/users"]].concat(), vec![("409 Conflict", REFUSED)]);
        assert_eq!(run.stdout, format!("{REFUSED}\n"), "{flags:?}");
        assert!(!run.stderr.contains("masked data") && !run.stderr.contains("WARNING"), "{flags:?}: {}", run.stderr);
        assert_eq!(run.ok, !flags.contains(&"-sfr"), "{flags:?}");
    }
}

#[test]
fn a_chain_is_judged_on_what_the_server_said_not_on_the_seed_data() {
    // A masked value is a "yes" from the server, and `null` once exported:
    // a response that is nothing but a mask has nothing to be left out of.
    let run = run_export(
        &["--export", SEED, "-sr", "GET /secret && GET /users"],
        vec![("200 OK", r#""********""#), ("200 OK", USERS)],
    );
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /secret", "GET /users"]);
}

#[test]
fn an_assert_and_a_poll_are_judged_on_what_the_server_said_not_on_the_seed_data() {
    // The masked value is a "yes" to each of them, though it exports as `null`.
    let (port, server) = answering_server(vec![("200 OK", r#""********""#), ("200 OK", r#""********""#), ("200 OK", USERS)]);
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("batch.api"),
        "assert GET /secret\nsleep 10ms while not GET /secret\nGET /users > users.json\n",
    )
    .unwrap();
    let out = api_against_port(port)
        .env("NO_COLOR", "1")
        .current_dir(dir.path())
        .args(["--export", SEED, "-sa", "batch.api"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(server.join().unwrap(), vec!["GET /secret", "GET /secret", "GET /users"]);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(compact(&std::fs::read_to_string(dir.path().join("users.json")).unwrap()), USERS_EXPORTED);
    // A question's answer is not data: only the response that was written warns.
    assert_eq!(stderr.matches("response had masked data, left out at").count(), 1, "{stderr}");

    // And the other way round: `assert not` on a masked value fails.
    let run = run_export(&["--export", SEED, "-s", "assert not GET /secret"], vec![("200 OK", r#""********""#)]);
    assert_eq!(run.code, Some(1), "{}", run.stderr);
    assert!(run.stderr.contains("assertion failed"), "{}", run.stderr);
}

#[test]
fn export_to_the_clipboard_and_appended_to_ndjson_is_seed_data_too() {
    let _turn = clipboard_turn();
    // The response is kept off stdout and the masked place is still named.
    let run = run_export(&["--export", SEED, "GET", "/users", ">", "clipboard"], vec![("200 OK", USERS)]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.seen, vec!["GET /users"]);
    assert_eq!(run.stdout, "");
    // On macOS the clipboard can be read back, and holds the seed data. The
    // tests that copy take turns (`clipboard_turn`), so it is still this one's.
    if cfg!(target_os = "macos") {
        match std::process::Command::new("pbpaste").output() {
            Ok(pasted) if pasted.status.success() => {
                let pasted = String::from_utf8_lossy(&pasted.stdout).to_string();
                assert_eq!(compact(&pasted), USERS_EXPORTED, "{pasted}");
            }
            other => eprintln!("export_to_the_clipboard…: the clipboard was NOT read back, pbpaste did not run: {other:?}"),
        }
    } else {
        eprintln!("export_to_the_clipboard…: the clipboard was NOT read back (only done on macOS)");
    }
    assert!(run.stderr.contains(MASKED_WARNING), "{}", run.stderr);
    assert!(!run.dir.path().join("clipboard").exists());

    // Appended to an NDJSON file: the lines of each response, exported.
    const LINES: &str = "{\"identifiers\":{\"key\":\"a\"},\"n\":1}\n{\"identifiers\":{\"key\":\"b\",\"com.x.y\":\"1\"}}\n";
    let (port, server) = answering_server(vec![("200 OK", LINES)]);
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("batch.api"), "GET /people >> people.ndjson\nGET /people >> people.ndjson\n").unwrap();
    let out = api_against_port(port)
        .env("NO_COLOR", "1")
        .current_dir(dir.path())
        .args(["--export", SEED, "-sa", "batch.api"])
        .output()
        .unwrap();
    assert_eq!(server.join().unwrap().len(), 2);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let written = std::fs::read_to_string(dir.path().join("people.ndjson")).unwrap();
    let exported = "{\"identifiers\":{\"key?\":\"a\",\"com.heads.seedID\":\"a\"},\"n\":1}\n{\"identifiers\":{\"com.x.y\":\"1\"}}\n";
    assert_eq!(written, exported.repeat(2));
}

#[test]
fn an_ndjson_outfile_holds_one_compact_value_per_line_whatever_was_answered() {
    // One record is one line of NDJSON and one JSON value at once. Written to
    // a file it was indented like JSON; a second `>>` then added a compact line.
    const RECORD: &str = r#"{"@type":"api version info","schema-version":"1.1"}"#;
    const LIST: &str = r#"[{"id":1},{"id":2}]"#;
    let run = |answer: &'static str, batch: &str, flags: &[&str]| {
        let (port, server) = answering_server(vec![("200 OK", answer)]);
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("batch.api"), batch).unwrap();
        let out = api_against_port(port)
            .env("NO_COLOR", "1")
            .current_dir(dir.path())
            .args(flags)
            .arg("batch.api")
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(out.status.success(), "{batch}: {}", String::from_utf8_lossy(&out.stderr));
        let read = |name: &str| std::fs::read_to_string(dir.path().join(name)).unwrap_or_default();
        (read("out.ndjson"), read("out.njson"), read("out.json"), String::from_utf8_lossy(&out.stderr).to_string())
    };
    let line = format!("{RECORD}\n");

    // With and without `-s`: the two code paths that write a file.
    for flags in [&["-sa"][..], &["-a"]] {
        let (ndjson, ..) = run(RECORD, "GET /about > out.ndjson\n", flags);
        assert_eq!(ndjson, line, "{flags:?}");
        let (ndjson, ..) = run(RECORD, "GET /about >> out.ndjson\nGET /about >> out.ndjson\nGET /about >> out.ndjson\n", flags);
        assert_eq!(ndjson, line.repeat(3), "{flags:?}");
        // A list, from a server that answers JSON whatever it is asked for.
        let (ndjson, njson, ..) = run(LIST, "GET /things > out.ndjson\nGET /things >> out.njson\nGET /things >> out.njson\n", flags);
        assert_eq!(ndjson, "{\"id\":1}\n{\"id\":2}\n", "{flags:?}");
        assert_eq!(njson, "{\"id\":1}\n{\"id\":2}\n".repeat(2), "{flags:?}");
        // A `.json` target is indented as before.
        let (_, _, json, _) = run(RECORD, "GET /about > out.json\n", flags);
        assert_eq!(json, "{\n  \"@type\": \"api version info\",\n  \"schema-version\": \"1.1\"\n}", "{flags:?}");
    }
    // The size that is reported is the size that was written.
    let (_, _, _, stderr) = run(RECORD, "GET /about > out.ndjson\n", &["-a"]);
    assert!(stderr.contains(&format!("> out.ndjson ({} B)", line.len())), "{stderr}");

    // And as seed data: the same shape, exported.
    let (ndjson, ..) = run(
        r#"{"identifiers":{"key":"a"},"n":1}"#,
        "GET /one > out.ndjson\nGET /one >> out.ndjson\n",
        &["--export", SEED, "-sa"],
    );
    assert_eq!(ndjson, "{\"identifiers\":{\"key?\":\"a\",\"com.heads.seedID\":\"a\"},\"n\":1}\n".repeat(2));
}

#[test]
fn export_rewrites_ndjson_by_line_and_leaves_csv_alone() {
    const LINES: &str = "{\"identifiers\":{\"key\":\"a\"},\"n\":1}\n{\"identifiers\":{\"key\":\"b\",\"com.x.y\":\"1\"},\"secret\":\"********\"}\n";
    let run = run_export(&["--export", SEED, "-s", "--ndjson", "GET", "/people"], vec![("200 OK", LINES)]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "{\"identifiers\":{\"key?\":\"a\",\"com.heads.seedID\":\"a\"},\"n\":1}\n{\"identifiers\":{\"com.x.y\":\"1\"}}\n"
    );
    assert_eq!(run.stderr.trim(), "warning: response had masked data, left out at secret");

    // One line asked for as NDJSON stays one line.
    let run = run_export(&["--export", SEED, "-s", "--ndjson", "GET", "/people"], vec![("200 OK", "{\"identifiers\":{\"key\":\"a\"}}\n")]);
    assert_eq!(run.stdout, "{\"identifiers\":{\"key?\":\"a\",\"com.heads.seedID\":\"a\"}}\n");

    // Not JSON: passed on unchanged, with a warning that it was.
    const CSV: &str = "key,name\nabc,Ann\n";
    let run = run_export(&["--export", SEED, "-s", "GET", "/people", ">", "people.csv"], vec![("200 OK", CSV)]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(std::fs::read_to_string(run.dir.path().join("people.csv")).unwrap(), CSV);
    assert!(run.stderr.contains("WARNING: --export left a response that is not JSON unchanged"), "{}", run.stderr);

    // An empty answer is nothing to export and nothing to warn about: the
    // output is what it is without the flag.
    let plain = run_export(&["-s", "DELETE", "/people/1"], vec![("204 No Content", "")]);
    let run = run_export(&["--export", SEED, "-s", "DELETE", "/people/1"], vec![("204 No Content", "")]);
    assert!(run.ok);
    assert_eq!((run.stdout.as_str(), run.stderr.as_str()), (plain.stdout.as_str(), ""));
}

#[test]
fn export_does_not_ask_for_a_streamed_response() {
    let headers = captured_request_headers(&["--stream", "--export", SEED], &[]);
    assert!(!headers.contains("stream=true"), "--export reads the whole body: {headers}");
    let headers = captured_request_headers(&["--export", SEED], &[("API_STREAMING", "1")]);
    assert!(!headers.contains("stream=true"), "{headers}");
    // And with `--stream` the seed data is what is written, whole.
    let run = run_export(&["--export", SEED, "--stream", "-sr", "GET", "/users", ">", "users.json"], vec![("200 OK", USERS)]);
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(std::fs::read_to_string(run.dir.path().join("users.json")).unwrap(), USERS_EXPORTED);
}

// ----- `export <name>` in a .api file -----

/// What a server answers every request with here: a record with only a key.
const KEYED: &str = r#"{"identifiers":{"key":"k"},"n":1}"#;

struct ExportLines {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    seen: Vec<String>,
    dir: tempfile::TempDir,
}

impl ExportLines {
    /// The name a written file's record was exported under, `None` when it
    /// was written as the server sent it.
    fn exported(&self, file: &str) -> Option<String> {
        let text = std::fs::read_to_string(self.dir.path().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file}: {e}: {text}"));
        let identifiers = value["identifiers"].as_object().unwrap_or_else(|| panic!("{file}: {text}"));
        if identifiers.contains_key("key") {
            assert_eq!(identifiers.len(), 1, "{file}: {text}");
            return None;
        }
        assert_eq!(identifiers["key?"], "k", "{file}: {text}");
        let name = identifiers.keys().find(|k| *k != "key?").unwrap_or_else(|| panic!("{file}: {text}"));
        Some(name.clone())
    }
}

/// Write `files` to a fresh directory and run `batch.api` among them with
/// `flags`, against a server that answers `KEYED` to everything.
fn run_export_lines(flags: &[&str], files: &[(&str, &str)]) -> ExportLines {
    let (port, server) = answering_server(vec![("200 OK", KEYED)]);
    let dir = tempdir().unwrap();
    for (name, contents) in files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let out = api_against_port(port)
        .env("NO_COLOR", "1")
        .current_dir(dir.path())
        .args(flags)
        .arg("batch.api")
        .write_stdin("n\n")
        .output()
        .expect("api runs");
    ExportLines {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        seen: server.join().expect("server thread"),
        dir,
    }
}

#[test]
fn a_set_export_line_holds_from_where_it_is_written_to_the_end_of_its_file() {
    let run = run_export_lines(
        &["-sa"],
        &[(
            "batch.api",
            "GET /a > a.json\n\
             set export com.heads.seedID\n\
             GET /b > b.json\n\
             GET /c && GET /d > d.json\n\
             set export other.name.id\n\
             GET /e > e.json\n\
             set export off\n\
             GET /f > f.json\n\
             SET EXPORT com.heads.seedID\n\
             GET /g > g.json\n",
        )],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.seen.len(), 7);
    let seed = Some("com.heads.seedID".to_string());
    assert_eq!(run.exported("a.json"), None, "before the line");
    assert_eq!(run.exported("b.json"), seed);
    assert_eq!(run.exported("d.json"), seed, "the last request of a chain");
    assert_eq!(run.exported("e.json"), Some("other.name.id".to_string()), "a second line replaces the name");
    assert_eq!(run.exported("f.json"), None, "after `set export off`");
    assert_eq!(run.exported("g.json"), seed, "and on again");
    // The log has each line where it took effect.
    let at = |needle: &str| run.stdout.find(needle).unwrap_or_else(|| panic!("{needle:?} not in\n{}", run.stdout));
    assert!(at("GET /a > a.json") < at("\nset export com.heads.seedID\n"), "{}", run.stdout);
    assert!(at("\nset export com.heads.seedID\n") < at("GET /b > b.json"), "{}", run.stdout);
    assert!(at("\nset export other.name.id\n") < at("\nset export off\n"), "{}", run.stdout);
    assert!(!run.stdout.contains("ignored"), "{}", run.stdout);
}

/// Under a `set export` line, as under `--export`, a chain, an `assert` and a
/// poll are judged on what the server said. A masked value is a "yes" from
/// the server, and `null` once exported.
#[test]
fn under_a_set_export_line_a_chain_and_a_check_are_judged_on_what_the_server_said() {
    const MASKED: (&str, &str) = ("200 OK", r#""********""#);
    let (port, server) = answering_server(vec![MASKED, MASKED, MASKED, MASKED, MASKED, ("200 OK", USERS)]);
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("batch.api"),
        "set export com.heads.seedID\n\
         GET /secret && GET /then\n\
         GET /secret || GET /never\n\
         assert GET /secret\n\
         sleep 10ms while not GET /secret\n\
         GET /users > users.json\n",
    )
    .unwrap();
    let out = api_against_port(port).env("NO_COLOR", "1").current_dir(dir.path()).args(["-sa", "batch.api"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        server.join().unwrap(),
        vec!["GET /secret", "GET /then", "GET /secret", "GET /secret", "GET /secret", "GET /users"],
        "{stderr}"
    );
    assert!(out.status.success(), "{stderr}");
    assert_eq!(compact(&std::fs::read_to_string(dir.path().join("users.json")).unwrap()), USERS_EXPORTED);
    // The answer to an `assert` or a poll is not data. The three requests of
    // the chains and the one that was written are, and each is warned about.
    assert_eq!(stderr.matches("response had masked data, left out at").count(), 4, "{stderr}");

    // And the other way round: `assert not` on a masked value fails, and a
    // poll that waits for a "no" does not take the exported `null` for one.
    let (port, server) = answering_server(vec![MASKED]);
    std::fs::write(dir.path().join("not.api"), "set export com.heads.seedID\nassert not GET /secret\nGET /never\n").unwrap();
    let out = api_against_port(port).env("NO_COLOR", "1").current_dir(dir.path()).args(["-sa", "not.api"]).output().unwrap();
    assert_eq!(server.join().unwrap(), vec!["GET /secret"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("assertion failed"), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_set_export_line_is_its_own_files_and_no_included_or_imported_files() {
    let run = run_export_lines(
        &["-sa"],
        &[
            (
                "batch.api",
                "import dir lib { \"path\": \"libdir\" }\n\
                 set export com.heads.seedID\n\
                 GET /before > before.json\n\
                 inc/plain.api\n\
                 GET /between > between.json\n\
                 lib/imported.api\n\
                 inc/own.api\n\
                 GET /after > after.json\n",
            ),
            // No line of its own: not exported, though its includer is.
            ("inc/plain.api", "GET /plain > plain.json\n"),
            ("libdir/imported.api", "GET /imported > imported.json\n"),
            // A line of its own, around a file it includes in turn.
            (
                "inc/own.api",
                "GET /own-before > own-before.json\n\
                 set export inner.name.id\n\
                 GET /own > own.json\n\
                 deep.api\n\
                 GET /own-after > own-after.json\n",
            ),
            ("inc/deep.api", "GET /deep > deep.json\n"),
        ],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let seed = Some("com.heads.seedID".to_string());
    let inner = Some("inner.name.id".to_string());
    assert_eq!(run.exported("before.json"), seed);
    assert_eq!(run.exported("plain.json"), None, "an included file");
    assert_eq!(run.exported("between.json"), seed, "back on after the include");
    assert_eq!(run.exported("imported.json"), None, "an imported file");
    assert_eq!(run.exported("own-before.json"), None, "an included file starts without");
    assert_eq!(run.exported("own.json"), inner);
    assert_eq!(run.exported("deep.json"), None, "two includes down");
    assert_eq!(run.exported("own-after.json"), inner, "back on in the included file");
    assert_eq!(run.exported("after.json"), seed, "the includer's name again, not the included file's");
}

#[test]
fn an_included_files_set_export_line_ends_with_that_file() {
    let run = run_export_lines(
        &["-sa"],
        &[
            ("batch.api", "GET /a > a.json\ninc.api\nGET /b > b.json\n"),
            ("inc.api", "set export com.heads.seedID\nGET /i > i.json\n"),
        ],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.exported("a.json"), None);
    assert_eq!(run.exported("i.json"), Some("com.heads.seedID".to_string()));
    assert_eq!(run.exported("b.json"), None, "the included file's mode did not leak out");
}

#[test]
fn export_on_the_command_line_overrides_every_set_export_line() {
    let run = run_export_lines(
        &["--export", "from.the.cli", "-sa"],
        &[
            (
                "batch.api",
                "GET /a > a.json\nset export com.heads.seedID\nGET /b > b.json\ninc.api\nset export off\nGET /c > c.json\n",
            ),
            ("inc.api", "set export inner.name.id\nGET /i > i.json\n"),
        ],
    );
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let cli = Some("from.the.cli".to_string());
    for file in ["a.json", "b.json", "i.json", "c.json"] {
        assert_eq!(run.exported(file), cli, "{file}");
    }
    // The log says that a line was passed over, and for what.
    assert_eq!(run.stdout.matches("↳ ignored: --export from.the.cli is set").count(), 3, "{}", run.stdout);
}

#[test]
fn a_set_line_that_names_nothing_usable_stops_the_batch_before_any_request() {
    for (line, says) in [
        ("set", "set needs a setting: `set include-nulls` (one of export, include-nulls, fail-fast, ndjson, raw, stream, timeout)"),
        ("set export", "set export needs a name: `set export com.heads.seedID`, or `set export off`"),
        ("set export seedID", "invalid export identifier: seedID"),
        ("set export com.heads", "invalid export identifier: com.heads"),
        ("set export com.heads.seedID extra", "set takes a setting and one value: `set export com.heads.seedID extra`"),
        ("set export off now", "set takes a setting and one value: `set export off now`"),
        ("set nulls", "unknown setting `nulls` (one of export, include-nulls, fail-fast, ndjson, raw, stream, timeout)"),
        ("set include-nulls maybe", "set include-nulls takes `on` or `off`, not `maybe`"),
        ("set timeout", "set timeout needs whole seconds: `set timeout 30` (0 is no timeout), or `set timeout off`"),
        ("set timeout soon", "set timeout needs whole seconds"),
        // What says where a request goes, and with what, is not a setting.
        ("set base-uri http://elsewhere.example.com", "unknown setting `base-uri`"),
        ("set key abc", "unknown setting `key`"),
        // The line the client had before `set`.
        ("export com.heads.seedID", "not a request or .api file: export"),
        // A directive is not a step of a chain, in either place.
        ("GET /a && set export com.heads.seedID", "chain segment is not a request"),
        ("set export com.heads.seedID && GET /a", "a `set` line can't be part of a `&&`/`||` chain"),
    ] {
        let run = run_export_lines(&["-sa"], &[("batch.api", &format!("GET /first\n{line}\nGET /never\n"))]);
        assert_eq!(run.code, Some(1), "{line}");
        assert!(run.stderr.contains(says), "{line}: {}", run.stderr);
        assert_eq!(run.seen, Vec::<String>::new(), "{line}");
    }
    // The same in a file that is only included.
    let run = run_export_lines(&["-sa"], &[("batch.api", "GET /first\ninc.api\n"), ("inc.api", "set export nope\n")]);
    assert_eq!(run.code, Some(1));
    assert_eq!(run.seen, Vec::<String>::new());
}

#[test]
fn the_preview_lists_set_lines_and_an_error_body_is_left_alone() {
    let files = [("batch.api", "GET /a\nset export com.heads.seedID\nGET /b\ninc.api\nset export off\nGET /c\n"), ("inc.api", "GET /i\n")];
    let run = run_export_lines(&["-spa"], &files);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.seen, Vec::<String>::new());
    let listed: Vec<&str> = run.stderr.lines().filter(|l| l.starts_with("  ")).map(str::trim).collect();
    // What the parser puts around the include is its own and is not shown.
    assert_eq!(listed, ["GET /a", "set export com.heads.seedID", "GET /b", "GET /i", "set export off", "GET /c"], "{}", run.stderr);
    assert!(run.stderr.contains("Preview — 4 requests | GET"), "{}", run.stderr);

    // Without `-s` the bodies are printed: seed data under the line, the
    // server's own above it.
    let run = run_export_lines(&["-ra"], &[("batch.api", "GET /a\nset export com.heads.seedID\nGET /b\n")]);
    assert_eq!(
        run.stdout,
        format!("{KEYED}\n{}\n", r#"{"identifiers":{"key?":"k","com.heads.seedID":"k"},"n":1}"#),
        "{}",
        run.stderr
    );

    // An error is no seed data, and `-f` passes it on as it came.
    let (port, server) = answering_server(vec![("409 Conflict", KEYED)]);
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("batch.api"), "set export com.heads.seedID\nGET /refused\nGET /never\n").unwrap();
    let out = api_against_port(port).env("NO_COLOR", "1").current_dir(dir.path()).args(["-sfa", "batch.api"]).output().unwrap();
    assert_eq!(server.join().unwrap(), vec!["GET /refused"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).ends_with(&format!("{KEYED}\n")));
}

#[test]
fn a_set_line_works_from_stdin_and_in_one_argument_but_not_alone() {
    const EXPORTED: &str = r#"{"identifiers":{"key?":"k","com.heads.seedID":"k"},"n":1}"#;
    // The program on stdin.
    let (port, server) = answering_server(vec![("200 OK", KEYED)]);
    let out = api_against_port(port)
        .env("NO_COLOR", "1")
        .args(["-ra", "-"])
        .write_stdin("GET /a\nset export com.heads.seedID\nGET /b\n")
        .output()
        .unwrap();
    assert_eq!(server.join().unwrap().len(), 2);
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{KEYED}\n{EXPORTED}\n"));

    // Several lines in one argument are a program like any other.
    let (port, server) = answering_server(vec![("200 OK", KEYED)]);
    let out = api_against_port(port).env("NO_COLOR", "1").args(["-r", "set export com.heads.seedID\nGET /b"]).output().unwrap();
    assert_eq!(server.join().unwrap(), vec!["GET /b"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{EXPORTED}\n"));

    // The line alone would set a mode and send nothing: that is an option's job.
    for args in [&["set", "export", "com.heads.seedID"][..], &["set export com.heads.seedID"], &["set", "export", "off"], &["set", "include-nulls"]] {
        let (port, server) = answering_server(vec![("200 OK", KEYED)]);
        let out = api_against_port(port).env("NO_COLOR", "1").args(args).output().unwrap();
        assert_eq!(server.join().unwrap(), Vec::<String>::new(), "{args:?}");
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("`set` alone sends nothing. Give the setting as an option with a request"), "{args:?}: {stderr}");
    }
}

/// Against a local CommerceOS: what is echoed, and what is really there.
/// Nothing is stored by either.
#[test]
fn export_against_a_local_cos() {
    require_local_cos();
    // An echo answers the body it was sent. The body names no `@type`: one
    // that does is read as that type, and a made-up key is then refused.
    let echoed = api()
        .env("NO_COLOR", "1")
        .args([
            "--export", SEED, "-sr", "PUT", "/echo-all",
            r#"[{"name":"Ann","identifiers":{"key":"k1"},"secret":"********","boss":{"identifiers":{"key":"k2","com.mi6.id":"M"}}}]"#,
        ])
        .output()
        .unwrap();
    assert!(echoed.status.success(), "{}", String::from_utf8_lossy(&echoed.stderr));
    assert_eq!(
        String::from_utf8_lossy(&echoed.stdout).trim(),
        r#"[{"identifiers":{"key?":"k1","com.heads.seedID":"k1"},"name":"Ann","boss":{"identifiers":{"com.mi6.id":"M"}}}]"#
    );
    assert!(String::from_utf8_lossy(&echoed.stderr).contains("warning: response had masked data, left out at secret"));

    // Real records: no `key` is left, each record has an identifier to be
    // found by, and `key?` stands only beside the name made from it.
    fn check(value: &serde_json::Value, records: &mut usize) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(serde_json::Value::Object(identifiers)) = object.get("identifiers") {
                    *records += 1;
                    assert!(!identifiers.contains_key("key"), "a key was left: {identifiers:?}");
                    assert!(
                        identifiers.keys().any(|name| name != "@type" && name != "key?"),
                        "nothing but the key to find it by: {object:?}"
                    );
                    if let Some(optional) = identifiers.get("key?") {
                        assert_eq!(optional.as_str().map(str::len), Some(32), "{identifiers:?}");
                        assert_eq!(identifiers.get(SEED), Some(optional), "`key?` without its name: {identifiers:?}");
                        assert_eq!(identifiers.keys().filter(|name| *name != "@type").count(), 2, "{identifiers:?}");
                    }
                    let leading: Vec<&String> = object.keys().take(2).collect();
                    assert!(leading.contains(&&"identifiers".to_string()), "identifiers not in front: {leading:?}");
                }
                object.values().for_each(|member| check(member, records));
            }
            serde_json::Value::Array(items) => items.iter().for_each(|item| check(item, records)),
            _ => {}
        }
    }
    for uri in ["/users~take(5)", "/people~take(5)", "/companies~take(5)"] {
        let out = api().args(["--export", SEED, "-s", "GET", uri]).output().unwrap();
        assert!(out.status.success(), "{uri}: {}", String::from_utf8_lossy(&out.stderr));
        let seed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{uri}: {e}"));
        let mut records = 0;
        check(&seed, &mut records);
        assert!(records > 0, "{uri} answered no records to check");
    }
}

// ----- import git -----

fn git_in(dir: &std::path::Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Commit `files` into the repository at `repo` (created on first use) and
/// return the new commit.
fn commit_files(repo: &std::path::Path, files: &[(&str, &str)]) -> String {
    if !repo.join(".git").exists() {
        std::fs::create_dir_all(repo).unwrap();
        git_in(repo, &["init", "-q", "-b", "main"]);
    }
    for (name, contents) in files {
        std::fs::write(repo.join(name), contents).unwrap();
    }
    git_in(repo, &["add", "-A"]);
    git_in(repo, &["commit", "-q", "-m", "change"]);
    git_in(repo, &["rev-parse", "HEAD"])
}

/// Run `batch` in `dir` with `-sa` against a throwaway server, with the
/// import cache kept in `dir`. Returns (success, stdout, stderr, requests).
fn run_import_batch(dir: &std::path::Path, batch: &str) -> (bool, String, String, Vec<String>) {
    let (port, server) = flipping_server(vec!["1"]);
    let file = dir.join("batch.api");
    std::fs::write(&file, batch).unwrap();
    let out = api_against_port(port)
        .env("API_IMPORT_CACHE", dir.join(".import-cache"))
        .env("NO_COLOR", "1")
        .current_dir(dir)
        .args(["-sa"])
        .arg(&file)
        .output()
        .expect("api runs");
    let seen = server.join().expect("server thread");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        seen,
    )
}

#[test]
fn import_follows_a_branch_and_logs_the_commit_it_ran() {
    let dir = tempdir().unwrap();
    let dir = dir.path().canonicalize().unwrap();
    let repo = dir.join("gitrepo");
    let first = commit_files(&repo, &[("sv.api", "GET /first\n")]);
    let batch = format!(
        "import git cl {{ \"url\": \"file://{}\", \"ref\": \"main\" }}\ncl/sv.api\n",
        repo.display()
    );

    let (ok, stdout, stderr, seen) = run_import_batch(&dir, &batch);
    assert!(ok, "{stderr}");
    assert!(stdout.contains(&format!("main ({})", &first[..7])), "{stdout}");
    assert!(seen.iter().any(|r| r.contains("GET /api/v1/first")), "{seen:?}");

    // The branch moves; the next run is the new commit, and says so.
    let second = commit_files(&repo, &[("sv.api", "GET /second\n")]);
    let (ok, stdout, stderr, seen) = run_import_batch(&dir, &batch);
    assert!(ok, "{stderr}");
    assert!(stdout.contains(&format!("main ({})", &second[..7])), "{stdout}");
    assert!(seen.iter().any(|r| r.contains("GET /api/v1/second")), "{seen:?}");
    assert!(!seen.iter().any(|r| r.contains("/first")), "{seen:?}");
}

#[test]
fn import_falls_back_to_its_cached_copy_when_the_remote_is_gone() {
    let dir = tempdir().unwrap();
    let dir = dir.path().canonicalize().unwrap();
    let repo = dir.join("gitrepo");
    let sha = commit_files(&repo, &[("sv.api", "GET /cached\n")]);
    git_in(&repo, &["tag", "1.0"]);
    let by_tag = format!(
        "import git cl {{ \"url\": \"file://{}\", \"ref\": \"1.0\" }}\ncl/sv.api\n",
        repo.display()
    );
    let by_sha = format!(
        "import git cl {{ \"url\": \"file://{}\", \"ref\": \"{sha}\" }}\ncl/sv.api\n",
        repo.display()
    );
    let (ok, _, stderr, _) = run_import_batch(&dir, &by_tag);
    assert!(ok, "{stderr}");

    std::fs::remove_dir_all(&repo).unwrap();

    // A tag has to be looked up, so the log says the lookup failed.
    let (ok, stdout, stderr, seen) = run_import_batch(&dir, &by_tag);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("cached copy: remote unreachable"), "{stdout}");
    assert!(seen.iter().any(|r| r.contains("GET /api/v1/cached")), "{seen:?}");

    // A commit already in the cache needs no remote at all.
    let (ok, stdout, stderr, seen) = run_import_batch(&dir, &by_sha);
    assert!(ok, "{stderr}");
    assert!(!stdout.contains("cached copy"), "{stdout}");
    assert!(seen.iter().any(|r| r.contains("GET /api/v1/cached")), "{seen:?}");

    // Nothing cached for this ref: that is an error, before any request.
    let never_seen = by_tag.replace("\"1.0\"", "\"2.0\"");
    let (ok, _, stderr, seen) = run_import_batch(&dir, &never_seen);
    assert!(!ok);
    assert!(stderr.contains("could not reach import"), "{stderr}");
    assert!(seen.is_empty(), "{seen:?}");
}

#[test]
fn an_imported_url_gate_stops_the_batch_before_any_request() {
    let dir = tempdir().unwrap();
    let dir = dir.path().canonicalize().unwrap();
    let repo = dir.join("gitrepo");
    commit_files(&repo, &[("sv.api", "url has production.example.com\nGET /gated\n")]);
    let batch = format!(
        "url has 127.0.0.1\nimport git cl {{ \"url\": \"file://{}\", \"ref\": \"main\" }}\nGET /own\ncl/sv.api\n",
        repo.display()
    );
    let (ok, _, stderr, seen) = run_import_batch(&dir, &batch);
    assert!(!ok);
    assert!(stderr.contains("import cl: URL gate failed"), "{stderr}");
    assert!(stderr.contains("url has production.example.com"), "{stderr}");
    assert!(seen.is_empty(), "nothing may be sent: {seen:?}");
}

// ----- import archive -----

/// A `.tar.gz` holding `files`.
fn tar_gz(files: &[(&str, &str)]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    for (name, contents) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, contents.as_bytes()).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// A server that is both the place an archive is downloaded from and the API
/// the batch then runs against: `/lib.tar.gz` answers with `archive` (401
/// unless the request carries `Bearer <token>`, when a token is asked for),
/// anything else answers `1`. Returns every request it saw, headers included.
fn archive_server(archive: Vec<u8>, token: Option<&'static str>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        loop {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let accepted = loop {
                match listener.accept() {
                    Ok(pair) => break Some(pair),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() > deadline {
                            break None;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            let Some((mut stream, _)) = accepted else { break };
            stream.set_nonblocking(false).unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let authorised = token.is_none_or(|t| {
                request.to_ascii_lowercase().contains(&format!("authorization: bearer {t}").to_ascii_lowercase())
            });
            let (status, kind, body): (&str, &str, &[u8]) = if !request.starts_with("GET /lib.tar.gz") {
                ("200 OK", "application/json", b"1")
            } else if authorised {
                ("200 OK", "application/gzip", &archive)
            } else {
                ("401 Unauthorized", "text/plain", b"no")
            };
            seen.push(request);
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(body);
            let _ = stream.flush();
        }
        seen
    });
    (port, handle)
}

/// Run `batch` in `dir` with `-sa` against the server on `port`, with the
/// import cache kept in `dir`. Returns (success, stdout, stderr).
fn run_archive_batch(dir: &std::path::Path, port: u16, batch: &str, token: Option<&str>) -> (bool, String, String) {
    let file = dir.join("batch.api");
    std::fs::write(&file, batch).unwrap();
    let mut cmd = api_against_port(port);
    cmd.env("API_IMPORT_CACHE", dir.join(".import-cache"))
        .env("NO_COLOR", "1")
        .env_remove("IMPORT_TEST_TOKEN")
        .current_dir(dir)
        .args(["-sa"])
        .arg(&file);
    if let Some(token) = token {
        cmd.env("IMPORT_TEST_TOKEN", token);
    }
    let out = cmd.output().expect("api runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn import_archive_downloads_with_its_own_token_and_never_the_api_key() {
    let dir = tempdir().unwrap();
    let dir = dir.path().canonicalize().unwrap();
    let archive = tar_gz(&[("lib-1.0/sv.api", "GET /from-archive\n")]);
    let (port, server) = archive_server(archive, Some("s3cret"));
    let batch = format!(
        "import archive cl {{ \"url\": \"http://127.0.0.1:{port}/lib.tar.gz\", \"token_env\": \"IMPORT_TEST_TOKEN\" }}\ncl/sv.api\n"
    );

    // The wrong token: the download is refused, and nothing is sent.
    let (ok, _, stderr) = run_archive_batch(&dir, port, &batch, Some("wrong"));
    assert!(!ok);
    assert!(stderr.contains("could not reach import") && stderr.contains("401 Unauthorized"), "{stderr}");
    // No token at all is a mistake in the setup, said as one.
    let (ok, _, stderr) = run_archive_batch(&dir, port, &batch, None);
    assert!(!ok);
    assert!(stderr.contains("environment variable IMPORT_TEST_TOKEN is not set"), "{stderr}");

    let (ok, stdout, stderr) = run_archive_batch(&dir, port, &batch, Some("s3cret"));
    assert!(ok, "{stderr}");
    assert!(stdout.contains(&format!("import cl http://127.0.0.1:{port}/lib.tar.gz (sha256 ")), "{stdout}");

    let seen = server.join().expect("server thread");
    let downloads: Vec<&String> = seen.iter().filter(|r| r.starts_with("GET /lib.tar.gz")).collect();
    assert_eq!(downloads.len(), 2, "{seen:?}");
    for download in &downloads {
        let lower = download.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer "), "{download}");
        assert!(!lower.contains("authorization: basic"), "the API key went to the archive host: {download}");
    }
    // Only the good run reached the API, and it did so with the API key.
    let api: Vec<&String> = seen.iter().filter(|r| r.starts_with("GET /api/v1/from-archive")).collect();
    assert_eq!(api.len(), 1, "{seen:?}");
    assert!(api[0].to_ascii_lowercase().contains("authorization: basic"), "{}", api[0]);
    assert!(!api[0].contains("s3cret"), "the import's token went to the API: {}", api[0]);
}

#[test]
fn an_unpinned_archive_is_downloaded_every_run_and_a_pinned_one_once() {
    let dir = tempdir().unwrap();
    let dir = dir.path().canonicalize().unwrap();
    let archive = tar_gz(&[("sv.api", "GET /from-archive\n")]);
    let sha = {
        use sha2::Digest;
        sha2::Sha256::digest(&archive).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let (port, server) = archive_server(archive, None);
    let url = format!("http://127.0.0.1:{port}/lib.tar.gz");
    let unpinned = format!("import archive cl {{ \"url\": \"{url}\" }}\ncl/sv.api\n");
    let pinned = format!("import archive cl {{ \"url\": \"{url}\", \"sha256\": \"{sha}\" }}\ncl/sv.api\n");

    for batch in [&unpinned, &unpinned, &pinned, &pinned] {
        let (ok, stdout, stderr) = run_archive_batch(&dir, port, batch, None);
        assert!(ok, "{stderr}");
        assert!(stdout.contains(&format!("(sha256 {})", &sha[..7])), "{stdout}");
    }
    let seen = server.join().expect("server thread");
    // Twice for the unpinned runs; the pinned ones found the hash in the cache.
    assert_eq!(seen.iter().filter(|r| r.starts_with("GET /lib.tar.gz")).count(), 2, "{seen:?}");
    assert_eq!(seen.iter().filter(|r| r.starts_with("GET /api/v1/from-archive")).count(), 4, "{seen:?}");

    // The archive's server is gone now. Unpinned falls back to the copy it
    // last served and says so; the batch itself still runs.
    let (api_port, api_server) = flipping_server(vec!["1"]);
    let (ok, stdout, stderr) = run_archive_batch(&dir, api_port, &unpinned, None);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("cached copy: remote unreachable"), "{stdout}");
    let seen = api_server.join().expect("server thread");
    assert!(seen.iter().any(|r| r.contains("GET /api/v1/from-archive")), "{seen:?}");
}

#[test]
fn a_download_that_is_no_archive_fails_cleanly() {
    let dir = tempdir().unwrap();
    let dir = dir.path().canonicalize().unwrap();
    let (port, server) = archive_server(b"<html>not found</html>".to_vec(), None);
    let batch = format!("import archive cl {{ \"url\": \"http://127.0.0.1:{port}/lib.tar.gz\" }}\nGET /never\n");
    let (ok, _, stderr) = run_archive_batch(&dir, port, &batch, None);
    assert!(!ok);
    assert!(stderr.contains("not a .tar.gz, .tar or .zip archive"), "{stderr}");
    let seen = server.join().expect("server thread");
    assert!(!seen.iter().any(|r| r.contains("/never")), "{seen:?}");
    // Nothing half-unpacked is left in the cache.
    let archives = dir.join(".import-cache/archives");
    let left: Vec<String> = std::fs::read_dir(&archives)
        .expect("the archive cache was made")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(left, Vec::<String>::new());
}

#[test]
fn import_dir_runs_a_local_directory_and_logs_where_it_is() {
    let dir = tempdir().unwrap();
    let dir = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(dir.join("shared-lib")).unwrap();
    std::fs::write(dir.join("shared-lib/sv.api"), "GET /from-dir\n").unwrap();
    let (ok, stdout, stderr, seen) =
        run_import_batch(&dir, "import dir cl { \"path\": \"shared-lib\" }\ncl/sv.api\n");
    assert!(ok, "{stderr}");
    assert!(stdout.contains(&format!("import cl {}", dir.join("shared-lib").display())), "{stdout}");
    assert!(seen.iter().any(|r| r.contains("GET /api/v1/from-dir")), "{seen:?}");
    // Used in place: there is nothing to cache.
    assert!(!dir.join(".import-cache").exists());
}

// ----- describe blocks: --describe, -m, --assert -----
//
// None of these reach a server: `--describe` and `--assert` send nothing, and
// the `-m` runs are declined at the preview.

/// The api binary with nothing configured, in `dir`.
fn bare_api(dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("api").expect("api binary built");
    cmd.current_dir(dir)
        .env("NO_COLOR", "1")
        .env("LANG", "sv_SE.UTF-8")
        .env_remove("LC_ALL")
        .env_remove("LC_MESSAGES")
        .env_remove("API_CREDENTIALS_FILE");
    cmd
}

const DESCRIBED: &str = r#"# Catalog seed
url has localhost
{
  "title": { "sv-se": "Katalog", "en-US": "Catalog" },
  // what it is for
  "description": { "sv-SE": "Innehåller x y z." },
  "docsLink": "https://link-to-docs.com"
}

PUT /assert { "api/v1/people~count": { "is": 3 } }
PUT /people/x { "name": "X" }
PUT /assert { "api/v1/people~count": { "is": 4 } }
"#;

#[test]
fn describe_prints_the_block_and_needs_no_connection() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("cat.api"), DESCRIBED).unwrap();
    std::fs::write(dir.path().join("none.api"), "GET /a\n").unwrap();

    bare_api(dir.path())
        .args(["--describe", "cat.api"])
        .assert()
        .success()
        .stderr("")
        .stdout(concat!(
            "{\n  \"title\": {\n    \"sv-SE\": \"Katalog\",\n    \"en-US\": \"Catalog\"\n  },\n",
            "  \"description\": {\n    \"sv-SE\": \"Innehåller x y z.\"\n  },\n",
            "  \"docsLink\": \"https://link-to-docs.com\"\n}\n"
        ));
    // -r on one line; a file without a block is `null`; stdin is a file too.
    bare_api(dir.path())
        .args(["-r", "--describe", "cat.api"])
        .assert()
        .success()
        .stdout("{\"title\":{\"sv-SE\":\"Katalog\",\"en-US\":\"Catalog\"},\"description\":{\"sv-SE\":\"Innehåller x y z.\"},\"docsLink\":\"https://link-to-docs.com\"}\n");
    bare_api(dir.path()).args(["--describe", "none.api"]).assert().success().stdout("null\n").stderr("");
    bare_api(dir.path())
        .args(["-r", "--describe", "-"])
        .write_stdin("{ \"title\": { \"en\": \"Piped\" } }\nGET /a\n")
        .assert()
        .success()
        .stdout("{\"title\":{\"en\":\"Piped\"}}\n");
    bare_api(dir.path())
        .args(["--describe", "missing.api"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::starts_with("error: could not read missing.api"));
}

#[test]
fn describe_warns_about_a_shape_that_is_off_and_fails_on_a_block_out_of_place() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("off.api"),
        "{ \"title\": { \"sv_SE\": \"x\" }, \"docsLink\": 5, \"owner\": \"me\" }\nGET /a\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("late.api"), "GET /a\n{ \"title\": {} }\n").unwrap();
    std::fs::write(dir.path().join("low.api"), "PUT /a\n{ \"x\": 1 }\n").unwrap();
    std::fs::write(dir.path().join("bad.api"), "{ \"title\": }\nGET /a\n").unwrap();

    // Off shape: a warning per thing, the block printed all the same, exit 0.
    bare_api(dir.path())
        .args(["-r", "--describe", "off.api"])
        .assert()
        .success()
        .stdout("{\"title\":{\"sv_SE\":\"x\"},\"docsLink\":5,\"owner\":\"me\"}\n")
        .stderr(concat!(
            "warning: describe block: title/sv_SE is not a locale\n",
            "warning: describe block: docsLink is not an http(s) link\n",
            "warning: describe block: owner is not a member of a describe block (title, description, docsLink)\n"
        ));
    // The same warnings when the file is run, before anything is sent.
    bare_api(dir.path())
        .args(["--no-keychain", "-b", "http://127.0.0.1:1", "-k", "x", "-spa", "off.api"])
        .write_stdin("n\n")
        .assert()
        .success()
        .stderr(predicate::str::starts_with("warning: describe block: title/sv_SE is not a locale\n"))
        .stderr(predicate::str::contains("aborted"));

    for (file, says) in [
        ("late.api", "error: a describe block must come before the first request\n"),
        ("low.api", "error: a describe block must come before the first request (a body starts on the request line)\n"),
    ] {
        bare_api(dir.path()).args(["--describe", file]).assert().failure().stdout("").stderr(says);
        // Running it stops at the same thing, with nothing sent.
        bare_api(dir.path())
            .args(["--no-keychain", "-b", "http://127.0.0.1:1", "-k", "x", "-sa", file])
            .assert()
            .failure()
            .stdout("")
            .stderr(says);
    }
    bare_api(dir.path())
        .args(["--describe", "bad.api"])
        .assert()
        .failure()
        .stderr(predicate::str::starts_with("error: invalid describe block: "));
}

#[test]
fn describe_first_prints_the_block_in_the_readers_language_above_the_preview() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("cat.api"), DESCRIBED).unwrap();
    let run = |lang: &str, args: &[&str]| {
        let out = bare_api(dir.path())
            .env("LANG", lang)
            .args(["--no-keychain", "-b", "http://localhost:1", "-k", "x"])
            .args(args)
            .write_stdin("n\n")
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: nothing was sent, so nothing is logged");
        String::from_utf8(out.stderr).unwrap()
    };

    let swedish = "Katalog\nInnehåller x y z.\nhttps://link-to-docs.com\n\nPreview — 3 requests";
    assert!(run("sv_SE.UTF-8", &["-spma", "cat.api"]).starts_with(swedish));
    // Long form, and the file named as a one-shot argument.
    assert!(run("sv_SE.UTF-8", &["-sp", "--describe-first", "-a", "cat.api"]).starts_with(swedish));
    assert!(run("sv_SE.UTF-8", &["-spm", "cat.api"]).starts_with(swedish));
    // English where it is the reader's language or the reader's has no text;
    // the description has only the Swedish.
    let english = "Catalog\nInnehåller x y z.\nhttps://link-to-docs.com\n\nPreview";
    for lang in ["en_GB.UTF-8", "de_DE.UTF-8", "C"] {
        assert!(run(lang, &["-spma", "cat.api"]).starts_with(english), "{lang}");
    }
    // Without -m the preview is all there is.
    assert!(run("sv_SE.UTF-8", &["-spa", "cat.api"]).starts_with("Preview — 3 requests"));
    // A file with no block prints nothing for it.
    std::fs::write(dir.path().join("none.api"), "GET /a\n").unwrap();
    assert!(run("sv_SE.UTF-8", &["-spma", "none.api"]).starts_with("Preview — 1 request"));
}

#[test]
fn a_describe_block_alone_as_an_argument_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    bare_api(dir.path())
        .args(["--no-keychain", "-b", "http://127.0.0.1:1", "-k", "x", "{\"title\":{}}"])
        .assert()
        .failure()
        .stdout("")
        .stderr("error: a describe block alone sends nothing. It goes at the top of a .api file.\n");
}

#[test]
fn assert_flag_lists_every_put_assert_body_in_one_array() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("cat.api"), format!("{DESCRIBED}shared/more.api\nPUT /assert @asserts.json\n")).unwrap();
    std::fs::create_dir(dir.path().join("shared")).unwrap();
    std::fs::write(
        dir.path().join("shared/more.api"),
        "GET /a && PUT v1/assert {\n  \"api/v1/now\": { \"is not\": null } // chained\n}\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("asserts.json"), "{ \"api/v1/file\": { \"is\": 1 } }").unwrap();
    std::fs::write(dir.path().join("none.api"), "GET /a\nassert GET /b\n").unwrap();
    std::fs::write(dir.path().join("broken.api"), "PUT /assert { \"a\": }\n").unwrap();

    bare_api(dir.path())
        .args(["-r", "--assert", "cat.api"])
        .assert()
        .success()
        .stderr("")
        .stdout(concat!(
            r#"[{"api/v1/people~count":{"is":3}},"#,
            r#"{"api/v1/people~count":{"is":4}},"#,
            r#"{"api/v1/now":{"is not":null}},"#,
            r#"{"api/v1/file":{"is":1}}]"#,
            "\n"
        ));
    bare_api(dir.path())
        .args(["--assert", "none.api"])
        .assert()
        .success()
        .stdout("[]\n");
    bare_api(dir.path())
        .args(["--assert", "broken.api"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::starts_with("error: the body of `PUT /assert` is not JSON: "));
    bare_api(dir.path())
        .args(["--assert", "cat.api", "--describe", "cat.api"])
        .assert()
        .failure()
        .stdout("")
        .stderr("error: --describe and --assert each print a document of their own: use one\n");
}

#[test]
fn describe_reads_a_file_however_it_is_named_or_encoded() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // A byte order mark and CRLF line ends, as Windows Notepad writes them.
    std::fs::write(d.join("bom.api"), "\u{feff}{ \"title\": { \"en\": \"Bom\" } }\r\nGET /a\r\n").unwrap();
    bare_api(d).args(["-r", "--describe", "bom.api"]).assert().success().stdout("{\"title\":{\"en\":\"Bom\"}}\n").stderr("");
    // `~/` is the home directory.
    bare_api(d)
        .env("HOME", d)
        .args(["-r", "--describe", "~/bom.api"])
        .assert()
        .success()
        .stdout("{\"title\":{\"en\":\"Bom\"}}\n");

    // What would stop a run stops this too, with nothing on stdout.
    for (text, says) in [
        ("{ \"title\": {} }\n{ \"title\": {} }\nGET /a\n", "error: a file has one describe block, and this is a second\n"),
        ("[ { \"title\": {} } ]\nGET /a\n", "error: a describe block is a JSON object, not an array\n"),
        ("{ \"title\": {\nGET /a\n", "error: unclosed describe block (depth 2)\n"),
        // A directive is one line, whatever brackets it holds.
        ("confirm Send [x?\n{ \"title\": {} }\n", "error: a describe block must come before the first request\n"),
    ] {
        std::fs::write(d.join("stop.api"), text).unwrap();
        bare_api(d).args(["--describe", "stop.api"]).assert().failure().stdout("").stderr(says);
    }
    // A `url` line may stand above the block, with a bracket it never closes.
    std::fs::write(d.join("gated.api"), "url has [x\n{ \"title\": { \"en\": \"T\" } }\nGET /a\n").unwrap();
    bare_api(d).args(["-r", "--describe", "gated.api"]).assert().success().stdout("{\"title\":{\"en\":\"T\"}}\n");
}

#[test]
fn describe_first_follows_the_locale_and_prints_only_the_file_that_is_run() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("cat.api"), DESCRIBED).unwrap();
    std::fs::write(d.join("only.api"), "{ \"title\": { \"en\": \"Only\" } }\n").unwrap();
    std::fs::write(d.join("inc.api"), "{ \"title\": { \"en\": \"Included\" } }\nGET /inc\n").unwrap();
    std::fs::write(d.join("main.api"), "{ \"title\": { \"en\": \"Main\" } }\ninc.api\n").unwrap();
    let connected = |d: &std::path::Path| {
        let mut cmd = bare_api(d);
        cmd.args(["--no-keychain", "-b", "http://localhost:1", "-k", "x"]);
        cmd
    };
    let declined = |env: &[(&str, &str)], args: &[&str]| {
        let mut cmd = connected(d);
        cmd.env("LANG", "en_GB.UTF-8");
        for (name, value) in env {
            cmd.env(name, value);
        }
        let out = cmd.args(args).write_stdin("n\n").output().unwrap();
        // Declined: exit 0, and `aborted` says nothing was sent.
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).ends_with("aborted\n"), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stderr).unwrap()
    };

    // `LC_MESSAGES` is asked before `LANG`, and `LC_ALL` before both.
    assert!(declined(&[], &["-spma", "cat.api"]).starts_with("Catalog\n"));
    assert!(declined(&[("LC_MESSAGES", "sv_SE.UTF-8")], &["-spma", "cat.api"]).starts_with("Katalog\n"));
    assert!(declined(&[("LC_MESSAGES", "sv_SE.UTF-8"), ("LC_ALL", "en_GB.UTF-8")], &["-spma", "cat.api"]).starts_with("Catalog\n"));
    assert!(declined(&[("LC_ALL", "sv_SE.UTF-8")], &["-spma", "cat.api"]).starts_with("Katalog\n"));

    // The block of an included file is that file's: it is not printed.
    let shown = declined(&[], &["-spma", "main.api"]);
    assert!(shown.starts_with("Main\n\nPreview — 1 request"), "{shown}");
    assert!(!shown.contains("Included"), "{shown}");
    // A file named with `~/`.
    let mut home = connected(d);
    let out = home.env("HOME", d).env("LANG", "en_GB.UTF-8").args(["-spm", "~/cat.api"]).write_stdin("n\n").output().unwrap();
    let shown = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(0), "{shown}");
    assert!(shown.starts_with("Catalog\n") && shown.ends_with("aborted\n"), "{shown}");

    // Without `-p`, and for a file that only describes: the block is
    // printed, nothing is sent, and that is no failure.
    for args in [&["-sma", "only.api"][..], &["-ma", "only.api"]] {
        let out = connected(d).env("LANG", "en_GB.UTF-8").args(args).output().unwrap();
        assert!(out.status.success(), "{args:?}");
        assert!(String::from_utf8(out.stderr).unwrap().starts_with("Only\n"), "{args:?}");
    }
    // The same file read from stdin.
    let out = connected(d)
        .env("LANG", "en_GB.UTF-8")
        .args(["-sma", "-"])
        .write_stdin("{ \"title\": { \"en\": \"Piped\" } }\n")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stderr).unwrap().starts_with("Piped\n"));
}

#[test]
fn assert_flag_reads_every_kind_of_body_and_says_what_it_cannot_read() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = |name: &str, text: &[u8]| std::fs::write(d.join(name), text).unwrap();
    std::fs::create_dir(d.join("people")).unwrap();
    file("asserts.csv", b"{\"api/v1/m\":{\"is\":1}}");
    file("people/a.json", b"{\"api/v1/p1\":{\"is\":1}}");
    file("people/b.json", b"[{\"api/v1/p2\":{\"is\":2}}]");
    // A body function on the file, and a glob, which is the one array the
    // request would send.
    file("files.api", b"PUT /assert @asserts.csv~map(com.heads.x)\nPUT /assert @people/*.json\nPUT /assert?x=1 {\"q\":{\"is\":1}}\n");
    bare_api(d)
        .args(["-r", "--assert", "files.api"])
        .assert()
        .success()
        .stdout("[{\"api/v1/m\":{\"is\":1}},[{\"api/v1/p1\":{\"is\":1}},{\"api/v1/p2\":{\"is\":2}}],{\"q\":{\"is\":1}}]\n");

    // Indented unless `-r`, from a file and from stdin.
    let indented = "[\n  {\n    \"a\": {\n      \"is\": 1\n    }\n  }\n]\n";
    file("one.api", b"PUT /assert {\"a\":{\"is\":1}}\n");
    bare_api(d).args(["--assert", "one.api"]).assert().success().stdout(indented);
    bare_api(d).args(["--assert", "-"]).write_stdin("PUT /assert {\"a\":{\"is\":1}}\n").assert().success().stdout(indented);

    // A byte order mark and CRLF, and the endpoint under `--me`.
    file("bom.api", "\u{feff}{ \"title\": {} }\r\nPUT /assert { \"a\": { \"is\": 1 } }\r\n".as_bytes());
    bare_api(d).args(["-r", "--assert", "bom.api"]).assert().success().stdout("[{\"a\":{\"is\":1}}]\n");
    file("me.api", b"PUT /assert { \"x\": { \"is\": 1 } }\nPUT /api/me/v1/assert { \"y\": { \"is\": 2 } }\nPUT /people/assert { \"z\": 1 }\n");
    for flags in [&["-r", "--assert", "me.api"][..], &["--me", "-r", "--assert", "me.api"]] {
        bare_api(d).args(flags).assert().success().stdout("[{\"x\":{\"is\":1}},{\"y\":{\"is\":2}}]\n");
    }

    // What can't be read is an error, with nothing on stdout.
    file("nobody.api", b"PUT /assert\nGET /a\n");
    file("bin.json", b"\xff\xfe{}");
    file("bin.api", b"PUT /assert @bin.json\n");
    file("inc.api", b"nope/missing.api\n");
    file("nofile.api", b"PUT /assert @gone.json\n");
    for (name, says) in [
        ("nobody.api", "error: the body of `PUT /assert` is not JSON: "),
        ("bin.api", "error: not UTF-8 text: @bin.json"),
        ("inc.api", "error: include not found: nope/missing.api"),
        ("nofile.api", "error: "),
        ("missing.api", "error: could not read missing.api"),
    ] {
        bare_api(d).args(["--assert", name]).assert().failure().stdout("").stderr(predicate::str::starts_with(says));
    }
}
