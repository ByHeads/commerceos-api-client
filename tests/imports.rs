//! End-to-end tests for `import git`, `import dir` and `import archive`.
//!
//! Most of them run the tree in `tests/fixtures/import` against a recording
//! server on this machine and need nothing else: the tree is imported as a
//! directory, as a git repository built from it, and as an archive of it.
//! Repositories that import each other are built the same way, in a
//! temporary directory.
//!
//! The last group fetches this client's own repository from GitHub, over
//! https and over ssh, and so needs the network (and, for ssh, a key GitHub
//! accepts). Set `API_TEST_OFFLINE=1` to skip that group.
//!
//! Run with: `cargo test --test imports`
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

// ----- a recording server -----

/// Answers every request and records it as `METHOD /path` or
/// `METHOD /path body`, the `/api/v1` prefix dropped.
///
/// - `/lib.tar.gz` answers with the archive it was started with.
/// - `/moved` redirects there; `/moved-off` redirects to a plain-http host.
/// - A path with `missing` in it is a 404.
/// - Anything else is the API, and answers `answer` as JSON.
struct Server {
    port: u16,
    log: Arc<Mutex<Vec<String>>>,
    /// `path=value` for every request that carried an `X-Request-Map` header.
    maps: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    fn start(answer: &'static str, archive: Vec<u8>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let maps = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_log, thread_maps, thread_stop) = (log.clone(), maps.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => respond(stream, port, answer, &archive, &thread_log, &thread_maps),
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Server { port, log, maps, stop, thread: Some(thread) }
    }

    /// The `X-Request-Map` headers seen since the last call, as `path=value`.
    fn maps(&self) -> Vec<String> {
        std::mem::take(&mut *self.maps.lock().unwrap())
    }

    /// What has been requested since the last call, without the archive
    /// download an `import archive` makes on its way.
    fn api_requests(&self) -> Vec<String> {
        self.sent().into_iter().filter(|r| r != "GET /lib.tar.gz").collect()
    }

    /// What has been requested since the last call.
    fn sent(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn respond(
    mut stream: std::net::TcpStream,
    port: u16,
    answer: &str,
    archive: &[u8],
    log: &Mutex<Vec<String>>,
    maps: &Mutex<Vec<String>>,
) {
    // An accepted socket inherits the listener's non-blocking mode on macOS.
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    let split = loop {
        if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&data[..split]).to_string();
    let mut body = data[split + 4..].to_vec();
    let mut request = head.lines().next().unwrap_or("").split_whitespace();
    let method = request.next().unwrap_or("").to_string();
    let path = request.next().unwrap_or("").to_string();
    let length: usize = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    while body.len() < length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
        }
    }

    let shown = path.strip_prefix("/api/v1").unwrap_or(&path);
    let map = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("x-request-map"));
    if let Some((_, value)) = map {
        maps.lock().unwrap().push(format!("{shown}={}", value.trim()));
    }
    let body_text = String::from_utf8_lossy(&body).trim().to_string();
    log.lock().unwrap().push(if body_text.is_empty() {
        format!("{method} {shown}")
    } else {
        format!("{method} {shown} {body_text}")
    });

    let (status, extra, payload): (&str, String, &[u8]) = match path.as_str() {
        "/lib.tar.gz" => ("200 OK", "Content-Type: application/gzip\r\n".to_string(), archive),
        "/moved" => ("302 Found", format!("Location: http://127.0.0.1:{port}/lib.tar.gz\r\n"), b""),
        "/moved-off" => ("302 Found", "Location: http://plain-http.example.invalid/lib.tar.gz\r\n".to_string(), b""),
        missing if missing.contains("missing") => {
            ("404 Not Found", "Content-Type: application/json\r\n".to_string(), b"null")
        }
        _ => ("200 OK", "Content-Type: application/json\r\n".to_string(), answer.as_bytes()),
    };
    let _ = stream.write_all(
        format!("HTTP/1.1 {status}\r\n{extra}Connection: close\r\nContent-Length: {}\r\n\r\n", payload.len())
            .as_bytes(),
    );
    let _ = stream.write_all(payload);
    let _ = stream.flush();
}

// ----- running the client -----

struct Ran {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// The client, pointed at the server on `port`, with its import cache kept in
/// `dir` so no test touches `~/.cache` or another test's checkouts.
///
/// It runs in a session of its own, without a terminal: `-p` then reads its
/// answer from stdin instead of from the terminal `cargo test` was started in.
fn api(dir: &Path, port: u16) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("api"));
    cmd.args(["--no-keychain", "-b", &format!("http://127.0.0.1:{port}"), "-k", "api-key"])
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("API_IMPORT_CACHE", dir.join(".import-cache"))
        .env_remove("API_STREAMING")
        .env_remove("API_CREDENTIALS_FILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd
}

fn finish(mut cmd: Command, typed: &str) -> Ran {
    let mut child = cmd.spawn().expect("spawn api");
    child.stdin.take().unwrap().write_all(typed.as_bytes()).unwrap();
    let out = child.wait_with_output().expect("api runs");
    Ran {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// Write `batch` to `dir/batch.api` and run it with `flags` (`-sa`, `-a`, …).
fn run_batch(dir: &Path, port: u16, flags: &str, batch: &str) -> Ran {
    std::fs::write(dir.join("batch.api"), batch).unwrap();
    let mut cmd = api(dir, port);
    cmd.args([flags, "batch.api"]);
    finish(cmd, "")
}

// ----- the fixture, three ways -----

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/import")
}

/// Every file of the fixture, as a path relative to it, with its contents.
fn fixture_files() -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                let name = path.strip_prefix(root).unwrap().to_string_lossy().to_string();
                out.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut files = Vec::new();
    walk(&fixture(), &fixture(), &mut files);
    assert!(files.iter().any(|(name, _)| name == "seed.api"), "the fixture is missing");
    files
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The fixture as a git repository at `repo`, tagged `1.0`. Returns its
/// `file://` url and the commit.
fn fixture_repository(repo: &Path) -> (String, String) {
    let files = fixture_files();
    let sha = commit(repo, &files.iter().map(|(name, c)| (name.as_str(), &c[..])).collect::<Vec<_>>(), Some("1.0"));
    (repo_url(repo), sha)
}

fn repo_url(repo: &Path) -> String {
    format!("file://{}", repo.display())
}

/// Commit `files` to the repository at `repo` (created on first use, on
/// branch `main`), tag the commit if asked to, and return it.
fn commit(repo: &Path, files: &[(&str, &[u8])], tag: Option<&str>) -> String {
    if !repo.join(".git").exists() {
        std::fs::create_dir_all(repo).unwrap();
        git(repo, &["init", "-q", "-b", "main"]);
    }
    for (name, contents) in files {
        let path = repo.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-q", "-m", "files"]);
    if let Some(tag) = tag {
        git(repo, &["tag", tag]);
    }
    git(repo, &["rev-parse", "HEAD"])
}

/// One `import … lib …` line per kind, each making the fixture available as
/// `lib`: the directory itself, a repository built from it in `dir`, and the
/// archive `server` serves. Paired with a name for failure messages.
fn each_kind(dir: &Path, server: &Server) -> Vec<(&'static str, String)> {
    let (repo, _) = fixture_repository(&dir.join("fixture-repo"));
    vec![
        ("dir", format!("import dir lib {{ \"path\": \"{}\" }}", fixture().display())),
        ("git", format!("import git lib {{ \"url\": \"{repo}\", \"ref\": \"1.0\" }}")),
        ("archive", format!("import archive lib {{ \"url\": \"{}\" }}", server.url("/lib.tar.gz"))),
    ]
}

/// The fixture as a `.tar.gz`, packed under one top directory the way a
/// release is.
fn fixture_archive() -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    for (name, contents) in fixture_files() {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, format!("fixture-1.0/{name}"), &contents[..]).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

fn temp() -> (tempfile::TempDir, PathBuf) {
    let guard = tempfile::tempdir().unwrap();
    let path = guard.path().canonicalize().unwrap();
    (guard, path)
}

const BODY: &str = r#"{"from":"import fixture"}"#;

/// What `lib/seed.api`, `lib/chain.api` and `lib/with-json.api` send.
fn fixture_requests() -> Vec<String> {
    vec![
        "GET /seed".to_string(),
        format!("PUT /seed/body {BODY}"),
        "GET /parts/a".to_string(),
        format!("PUT /parts/b {BODY}"),
        "GET /chain/first".to_string(),
        format!("PUT /chain/second {BODY}"),
        "GET /parts/a".to_string(),
    ]
}

const RUN_THE_FIXTURE: &str = "lib/seed.api\nlib/chain.api\nlib/with-json.api\n";

#[test]
fn the_fixture_sends_the_same_requests_as_a_directory_a_repository_and_an_archive() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let (repo_url, sha) = fixture_repository(&dir.join("gitrepo"));
    let archive_url = server.url("/lib.tar.gz");

    let kinds = [
        (
            format!("import dir lib {{ \"path\": \"{}\" }}", fixture().display()),
            format!("import lib {}", fixture().canonicalize().unwrap().display()),
        ),
        (
            format!("import git lib {{ \"url\": \"{repo_url}\", \"ref\": \"1.0\" }}"),
            format!("import lib {repo_url} 1.0 ({})", &sha[..7]),
        ),
        (
            format!("import archive lib {{ \"url\": \"{archive_url}\" }}"),
            format!("import lib {archive_url} (sha256 "),
        ),
    ];
    for (import, logged) in kinds {
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\n{RUN_THE_FIXTURE}"));
        assert!(ran.ok, "{import}\n{}", ran.stderr);
        assert!(ran.stdout.contains(&logged), "{import}: expected {logged:?} in\n{}", ran.stdout);
        let sent: Vec<String> = server.sent().into_iter().filter(|r| r != "GET /lib.tar.gz").collect();
        assert_eq!(sent, fixture_requests(), "{import}");
    }
}

#[test]
fn the_import_json_may_come_from_a_file_in_the_working_directory() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    std::fs::write(
        dir.join("fixture.json"),
        format!("{{\n  // where the fixture is\n  \"path\": \"{}\"\n}}\n", fixture().display()),
    )
    .unwrap();
    let ran = run_batch(&dir, server.port, "-sa", &format!("import dir lib @fixture.json\n{RUN_THE_FIXTURE}"));
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), fixture_requests());
}

#[test]
fn an_imported_gate_an_escaping_body_and_a_loop_each_stop_the_batch_before_any_request() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let import = format!("import dir lib {{ \"path\": \"{}\" }}", fixture().display());
    for (file, says) in [
        // The batch allows this server; the import only allows production.
        ("gated.api", "import lib: URL gate failed"),
        ("escape.api", "must be a relative path inside the import"),
        ("loop.api", "include loop detected"),
    ] {
        let batch = format!("url has 127.0.0.1\n{import}\nGET /own\nlib/{file}\n");
        let ran = run_batch(&dir, server.port, "-sa", &batch);
        assert!(!ran.ok, "{file}");
        assert!(ran.stderr.contains(says), "{file}: {}", ran.stderr);
        assert_eq!(server.sent(), Vec::<String>::new(), "{file}");
    }
}

// ----- what an imported file may hold -----

/// The body of a logged `METHOD /path body` line, as JSON.
fn json_body(line: &str) -> serde_json::Value {
    let body = line.splitn(3, ' ').nth(2).unwrap_or_else(|| panic!("no body in {line:?}"));
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{line:?}: {e}"))
}

#[test]
fn directives_and_chains_in_an_imported_file_run_as_they_would_in_the_batch() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    for (kind, import) in each_kind(&dir, &server) {
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nlib/directives.api\nGET /after\n"));
        assert!(ran.ok, "{kind}: {}", ran.stderr);
        assert_eq!(
            server.api_requests(),
            vec![
                "GET /directives/exists",
                "GET /directives/missing",
                "GET /directives/ready",
                // Found, so its fallback is skipped.
                "GET /directives/found",
                // Missing, so its fallback runs.
                "GET /directives/missing",
                r#"PUT /directives/create { "made": true }"#,
                // If-then-else: the then, not the else.
                "GET /directives/found",
                r#"PATCH /directives/update { "seen": true }"#,
                "GET /after",
            ],
            "{kind}"
        );
        assert!(ran.stdout.contains("while not GET /directives/ready"), "{kind}: {}", ran.stdout);
        assert_eq!(ran.stdout.matches("skipped 1 request").count(), 2, "{kind}: {}", ran.stdout);
    }
}

#[test]
fn every_kind_of_body_in_an_imported_file_is_read_from_the_import() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    // A file of the same name in the working directory must not be the one sent.
    std::fs::create_dir_all(dir.join("data/people")).unwrap();
    std::fs::write(dir.join("data/people/zed.json"), r#"{"name":"local"}"#).unwrap();
    std::fs::write(dir.join("data/events.ndjson"), "{\"event\":\"local\"}\n").unwrap();

    for (kind, import) in each_kind(&dir, &server) {
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nlib/bodies.api\n"));
        assert!(ran.ok, "{kind}: {}", ran.stderr);
        let sent = server.api_requests();
        assert_eq!(sent.len(), 4, "{kind}: {sent:?}");
        // Comments stripped, the raw newline escaped.
        assert!(sent[0].starts_with("PUT /bodies/inline "), "{kind}: {}", sent[0]);
        assert_eq!(json_body(&sent[0]), serde_json::json!({ "name": "Ann", "note": "two\nlines" }), "{kind}");
        // The glob: sorted, an array file flattened into the rest.
        assert!(sent[1].starts_with("PUT /bodies/people "), "{kind}: {}", sent[1]);
        assert_eq!(
            json_body(&sent[1]),
            serde_json::json!([{ "name": "Ann" }, { "name": "Bob" }, { "name": "Cy" }, { "name": "Di" }]),
            "{kind}"
        );
        assert_eq!(sent[2], "PUT /bodies/events {\"event\":1}\n{\"event\":2}", "{kind}");
        assert_eq!(sent[3], "PUT /bodies/rows id,name\n1,Ann\n2,Bob", "{kind}");
        assert_eq!(server.maps(), vec!["/bodies/rows=com.heads.test-rows"], "{kind}");
    }
}

#[test]
fn includes_of_an_imported_file_resolve_next_to_it_at_any_depth() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    // Nor is a directory of the same name in the working directory used.
    std::fs::create_dir_all(dir.join("deep")).unwrap();
    std::fs::write(dir.join("deep/leaf.api"), "GET /local/leaf\n").unwrap();

    for (kind, import) in each_kind(&dir, &server) {
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nlib/nested/index.api\n"));
        assert!(ran.ok, "{kind}: {}", ran.stderr);
        assert_eq!(
            server.api_requests(),
            vec![
                "GET /nested/index".to_string(),
                "GET /nested/deep/leaf".to_string(),
                format!("PUT /nested/deep/body {BODY}"),
                "GET /parts/a".to_string(),
            ],
            "{kind}"
        );
    }
}

#[test]
fn an_outfile_in_an_imported_file_is_written_in_the_working_directory() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    for (kind, import) in each_kind(&dir, &server) {
        let out = dir.join("import-out.json");
        let _ = std::fs::remove_file(&out);
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nlib/outfile.api\n"));
        assert!(ran.ok, "{kind}: {}", ran.stderr);
        assert_eq!(server.api_requests(), vec!["GET /outfile/export"], "{kind}");
        assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), "1", "{kind}");
    }
    // And nowhere in the import itself.
    assert!(!fixture().join("import-out.json").exists());
}

#[test]
fn an_alias_is_not_inherited_and_not_declared_twice_in_an_imported_file() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    for (kind, import) in each_kind(&dir, &server) {
        for (file, says) in [
            ("scoped.api", "include not found: lib/parts/a.api"),
            ("twice.api", "import alias `p` is declared twice"),
        ] {
            let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nGET /own\nlib/{file}\n"));
            assert!(!ran.ok, "{kind} {file}");
            assert!(ran.stderr.contains(says), "{kind} {file}: {}", ran.stderr);
            assert_eq!(server.api_requests(), Vec::<String>::new(), "{kind} {file}");
        }
    }
}

#[test]
fn an_include_that_climbs_out_of_a_directory_import_is_refused() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    // `outside.api` names `../../../example1.api`, which exists in this
    // repository's working tree, outside the imported directory.
    assert!(fixture().join("../../../example1.api").is_file());
    let batch = format!("import dir lib {{ \"path\": \"{}\" }}\nGET /own\nlib/outside.api\n", fixture().display());
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(!ran.ok);
    assert!(ran.stderr.contains("import lib: include leaves the import: ../../../example1.api"), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());
}

#[test]
fn a_failed_assert_in_an_imported_file_stops_the_batch_there() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    for (kind, import) in each_kind(&dir, &server) {
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nGET /own\nlib/assert-fails.api\nGET /after\n"));
        assert!(!ran.ok, "{kind}");
        assert!(ran.stderr.contains("assertion failed: assert GET /assert/missing (404 Not Found)"), "{kind}: {}", ran.stderr);
        // Unlike a gate or a bad path, an assert is a step: what came before it ran.
        assert_eq!(server.api_requests(), vec!["GET /own", "GET /assert/before", "GET /assert/missing"], "{kind}");
    }
}

// ----- preview and the plain log -----

#[test]
fn the_preview_lists_the_imports_and_a_declined_preview_sends_nothing() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let (repo_url, sha) = fixture_repository(&dir.join("gitrepo"));
    let batch = format!("import git lib {{ \"url\": \"{repo_url}\", \"ref\": \"1.0\" }}\nlib/seed.api\n");
    std::fs::write(dir.join("batch.api"), &batch).unwrap();

    let mut declined = api(&dir, server.port);
    declined.args(["-spa", "batch.api"]);
    let ran = finish(declined, "n\n");
    assert!(ran.ok, "declining is not a failure: {}", ran.stderr);
    let import_line = format!("import lib {repo_url} 1.0 ({})", &sha[..7]);
    let at = |needle: &str| ran.stderr.find(needle).unwrap_or_else(|| panic!("{needle:?} not in\n{}", ran.stderr));
    // The import comes first, then the requests it brought.
    assert!(at(&import_line) < at("GET /seed"), "{}", ran.stderr);
    assert!(at("GET /seed") < at("GET /parts/a"), "{}", ran.stderr);
    assert!(ran.stderr.contains("4 requests"), "{}", ran.stderr);
    assert!(ran.stderr.contains("aborted"), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());

    let mut accepted = api(&dir, server.port);
    accepted.args(["-spa", "batch.api"]);
    let ran = finish(accepted, "y\n");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent().len(), 4);
}

#[test]
fn a_cached_copy_standing_in_for_the_remote_is_a_warning_outside_the_silent_log() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let repo = dir.join("gitrepo");
    let (repo_url, _) = fixture_repository(&repo);
    let batch = format!("import git lib {{ \"url\": \"{repo_url}\", \"ref\": \"1.0\" }}\nlib/parts/a.api\n");

    // Reachable: plain `-a` says nothing about the import at all.
    let ran = run_batch(&dir, server.port, "-a", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert!(!ran.stdout.contains("import lib") && !ran.stderr.contains("import lib"), "{}{}", ran.stdout, ran.stderr);
    assert_eq!(server.sent(), vec!["GET /parts/a".to_string()]);

    std::fs::remove_dir_all(&repo).unwrap();
    let ran = run_batch(&dir, server.port, "-a", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert!(
        ran.stderr.contains(&format!("warning: import lib {repo_url} 1.0 (")) && ran.stderr.contains("cached copy: remote unreachable"),
        "{}",
        ran.stderr
    );
    // The warning is on stderr; stdout stays the responses alone.
    assert!(!ran.stdout.contains("import lib"), "{}", ran.stdout);
    assert_eq!(server.sent(), vec!["GET /parts/a".to_string()]);
}

// ----- archive redirects -----

#[test]
fn an_archive_download_follows_a_redirect_but_not_onto_plain_http() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());

    let batch = format!("import archive lib {{ \"url\": \"{}\" }}\nlib/parts/a.api\n", server.url("/moved"));
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), vec!["GET /moved", "GET /lib.tar.gz", "GET /parts/a"]);

    let batch = format!("import archive lib {{ \"url\": \"{}\" }}\nGET /never\n", server.url("/moved-off"));
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(!ran.ok);
    assert!(ran.stderr.contains("could not reach import"), "{}", ran.stderr);
    assert!(ran.stderr.contains("redirected to a url that is not https"), "{}", ran.stderr);
    // The redirect was refused, not followed and failed: nothing was sent on.
    assert_eq!(server.sent(), vec!["GET /moved-off"]);
}

// ----- git itself -----

#[test]
fn a_symlink_in_a_repository_is_checked_out_as_a_plain_file() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let repo = dir.join("gitrepo");
    std::fs::create_dir_all(&repo).unwrap();
    // A file only this machine has, and a repository that links to it.
    std::fs::write(dir.join("secret.json"), r#"{"secret":"local"}"#).unwrap();
    std::os::unix::fs::symlink(dir.join("secret.json"), repo.join("link.json")).unwrap();
    std::fs::write(repo.join("link.api"), "PUT /link @link.json\n").unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "a link"]);
    let sha = git(&repo, &["rev-parse", "HEAD"]);

    let batch = format!("import git lib {{ \"url\": \"file://{}\", \"ref\": \"main\" }}\nlib/link.api\n", repo.display());
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);

    // What was sent is where the link points, as text, not what is there.
    let sent = server.sent();
    assert_eq!(sent, vec![format!("PUT /link {}", dir.join("secret.json").display())]);
    assert!(!sent[0].contains("local"));
    let cache = dir.join(".import-cache");
    let checkout = std::fs::read_dir(&cache)
        .unwrap()
        .flatten()
        .map(|e| e.path().join(&sha))
        .find(|p| p.is_dir())
        .expect("a checkout in the cache");
    let link = std::fs::symlink_metadata(checkout.join("link.json")).unwrap();
    assert!(link.file_type().is_file(), "the link was checked out as a link");
}

#[test]
fn without_git_on_the_path_a_git_import_says_so_and_the_other_kinds_still_work() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let (repo_url, _) = fixture_repository(&dir.join("gitrepo"));
    let empty = dir.join("empty-path");
    std::fs::create_dir_all(&empty).unwrap();
    let run_without_git = |batch: &str| {
        std::fs::write(dir.join("batch.api"), batch).unwrap();
        let mut cmd = api(&dir, server.port);
        cmd.env("PATH", &empty).args(["-sa", "batch.api"]);
        finish(cmd, "")
    };

    let ran = run_without_git(&format!(
        "import git lib {{ \"url\": \"{repo_url}\", \"ref\": \"1.0\" }}\nlib/parts/a.api\n"
    ));
    assert!(!ran.ok);
    assert!(ran.stderr.contains("an import needs `git` on the PATH"), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());

    let ran = run_without_git(&format!(
        "import dir lib {{ \"path\": \"{}\" }}\nlib/parts/a.api\n",
        fixture().display()
    ));
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), vec!["GET /parts/a"]);

    let ran = run_without_git(&format!(
        "import archive lib {{ \"url\": \"{}\" }}\nlib/parts/a.api\n",
        server.url("/lib.tar.gz")
    ));
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), vec!["GET /lib.tar.gz", "GET /parts/a"]);
}

// ----- repositories that import repositories -----

fn import_git(alias: &str, url: &str, git_ref: &str) -> String {
    format!("import git {alias} {{ \"url\": \"{url}\", \"ref\": \"{git_ref}\" }}\n")
}

/// Three repositories, each importing the next, the innermost being the
/// fixture. Every one of them calls its import `lib`, which is no clash:
/// an alias belongs to the file that declares it.
///
/// ```text
/// batch ── lib ─▶ outer ── lib ─▶ middle ── lib ─▶ fixture
///                   └── packed ─▶ the fixture as an archive
///                                   └── mine ─▶ a directory of middle itself
/// ```
fn nested_repositories(dir: &Path, server: &Server) -> (String, String, String) {
    let (fixture_url, _) = fixture_repository(&dir.join("repos/fixture"));
    let middle = dir.join("repos/middle");
    let mid = format!(
        "{}import dir mine {{ \"path\": \"own\" }}\n\nGET /middle\nlib/parts/a.api\nmine/o.api\n",
        import_git("lib", &fixture_url, "1.0")
    );
    let mid_gated = format!("{}lib/gated.api\n", import_git("lib", &fixture_url, "1.0"));
    commit(
        &middle,
        &[
            ("mid.api", mid.as_bytes()),
            ("mid-gated.api", mid_gated.as_bytes()),
            ("own/o.api", b"GET /middle/own\nPUT /middle/own @o.json\n"),
            ("own/o.json", br#"{"from":"middle"}"#),
        ],
        None,
    );
    let outer = dir.join("repos/outer");
    let top = format!(
        "{}import archive packed {{ \"url\": \"{}\" }}\n\nGET /outer\nlib/mid.api\npacked/parts/a.api\n",
        import_git("lib", &repo_url(&middle), "main"),
        server.url("/lib.tar.gz")
    );
    let top_gated = format!("{}lib/mid-gated.api\n", import_git("lib", &repo_url(&middle), "main"));
    commit(&outer, &[("top.api", top.as_bytes()), ("top-gated.api", top_gated.as_bytes())], None);
    (repo_url(&outer), repo_url(&middle), fixture_url)
}

#[test]
fn a_repository_can_import_a_repository_that_imports_another() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let (outer, middle, fixture_url) = nested_repositories(&dir, &server);

    let batch = format!("url has 127.0.0.1\n{}GET /batch\nlib/top.api\nGET /after\n", import_git("lib", &outer, "main"));
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(
        server.api_requests(),
        vec![
            "GET /batch",
            "GET /outer",
            "GET /middle",
            // From the fixture, two imports down.
            "GET /parts/a",
            "GET /middle/own",
            r#"PUT /middle/own {"from":"middle"}"#,
            // From the archive the outer repository imported.
            "GET /parts/a",
            "GET /after",
        ]
    );

    // Every import is logged, in the order the files declared them.
    let at = |needle: String| ran.stdout.find(&needle).unwrap_or_else(|| panic!("{needle:?} not in\n{}", ran.stdout));
    let positions = [
        at(format!("import lib {outer} main (")),
        at(format!("import lib {middle} main (")),
        at(format!("import packed {} (sha256 ", server.url("/lib.tar.gz"))),
        at(format!("import lib {fixture_url} 1.0 (")),
        at("import mine ".to_string()),
        at("GET /batch".to_string()),
    ];
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{positions:?}\n{}", ran.stdout);

    // Each repository is in the cache once, with the archive beside them.
    let cached: Vec<String> = std::fs::read_dir(dir.join(".import-cache"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(cached.len(), 4, "{cached:?}");
    assert!(cached.contains(&"archives".to_string()), "{cached:?}");

    // The preview shows the same thing without sending any of it.
    let mut preview = api(&dir, server.port);
    preview.args(["-spa", "batch.api"]);
    let ran = finish(preview, "n\n");
    assert!(ran.ok, "{}", ran.stderr);
    assert!(ran.stderr.contains(&format!("import lib {fixture_url} 1.0 (")), "{}", ran.stderr);
    assert!(ran.stderr.contains("8 requests"), "{}", ran.stderr);
    assert_eq!(server.api_requests(), Vec::<String>::new());
}

#[test]
fn a_gate_two_imports_down_still_stops_the_batch() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let (outer, _, _) = nested_repositories(&dir, &server);
    // The batch allows this server; the fixture's gated.api, reached through
    // two other repositories, allows production only.
    let batch = format!("url has 127.0.0.1\n{}GET /batch\nlib/top-gated.api\n", import_git("lib", &outer, "main"));
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(!ran.ok);
    assert!(ran.stderr.contains("import lib: URL gate failed"), "{}", ran.stderr);
    assert!(ran.stderr.contains("url has production.example.com"), "{}", ran.stderr);
    assert_eq!(server.api_requests(), Vec::<String>::new());
}

#[test]
fn repositories_that_import_each_other_are_an_include_loop() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let (one, two) = (dir.join("repos/one"), dir.join("repos/two"));
    let one_api = format!("{}GET /one\ntwo/two.api\n", import_git("two", &repo_url(&two), "main"));
    let two_api = format!("{}GET /two\none/one.api\n", import_git("one", &repo_url(&one), "main"));
    commit(&one, &[("one.api", one_api.as_bytes())], None);
    commit(&two, &[("two.api", two_api.as_bytes())], None);

    let batch = format!("{}GET /batch\none/one.api\n", import_git("one", &repo_url(&one), "main"));
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(!ran.ok);
    assert!(ran.stderr.contains("include loop detected:") && ran.stderr.contains("one.api"), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());
    // Each was fetched once on the way round.
    assert_eq!(std::fs::read_dir(dir.join(".import-cache")).unwrap().count(), 2);
}

#[test]
fn a_repository_may_import_another_commit_of_itself() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let repo = dir.join("repos/versions");
    // 1.0 hands over to 2.0, a tag that doesn't exist yet when 1.0 is made.
    let first = format!("{}GET /first\nnext/step.api\n", import_git("next", &repo_url(&repo), "2.0"));
    let old = commit(&repo, &[("step.api", first.as_bytes())], Some("1.0"));
    let new = commit(&repo, &[("step.api", b"GET /second\n")], Some("2.0"));

    let batch = format!("{}prev/step.api\n", import_git("prev", &repo_url(&repo), "1.0"));
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    // The same file name at two commits is two files, not a loop.
    assert_eq!(server.sent(), vec!["GET /first", "GET /second"]);
    assert!(ran.stdout.contains(&format!("1.0 ({})", &old[..7])), "{}", ran.stdout);
    assert!(ran.stdout.contains(&format!("2.0 ({})", &new[..7])), "{}", ran.stdout);

    // Pointing a commit at itself is one.
    let looping = format!("{}GET /again\nme/step.api\n", import_git("me", &repo_url(&repo), "3.0"));
    commit(&repo, &[("step.api", looping.as_bytes())], Some("3.0"));
    let ran = run_batch(&dir, server.port, "-sa", &format!("{}now/step.api\n", import_git("now", &repo_url(&repo), "3.0")));
    assert!(!ran.ok);
    assert!(ran.stderr.contains("include loop detected:"), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());
}

// ----- this client's own repository, over the network -----

const REPO_HTTPS: &str = "https://github.com/byheads/commerceos-api-client";
const REPO_SSH: &str = "git@github.com:byheads/commerceos-api-client.git";
const REPO_TARBALL: &str = "https://github.com/byheads/commerceos-api-client/archive/refs/tags/3.2.2.tar.gz";
/// A release that holds `example1.api`, `example2.api` and `example3.api`.
const TAG: &str = "3.2.2";
const TAG_COMMIT: &str = "154faa4762c01badbd555ab2acfd3916e57a5d20";

/// Whether the tests that need GitHub were asked to stand down.
fn offline(test: &str) -> bool {
    let offline = std::env::var_os("API_TEST_OFFLINE").is_some_and(|v| !v.is_empty());
    if offline {
        eprintln!("{test}: skipped, API_TEST_OFFLINE is set");
    }
    offline
}

/// `example3.api` of the release: a poll, then a write. The server answers
/// `0`, so the poll is over at its first check.
fn assert_example3_ran(sent: &[String], how: &str) {
    assert_eq!(sent.len(), 2, "{how}: {sent:?}");
    assert_eq!(sent[0], "GET /people/count/==213", "{how}");
    assert!(sent[1].starts_with("POST /people {") && sent[1].contains("\"name\": \"Mr 214\""), "{how}: {}", sent[1]);
}

#[test]
fn the_api_client_repository_imports_over_https() {
    if offline("the_api_client_repository_imports_over_https") {
        return;
    }
    let (_guard, dir) = temp();
    let server = Server::start("0", Vec::new());

    // By tag, then by the commit the tag names: one fetch, one checkout.
    for git_ref in [TAG, TAG_COMMIT] {
        let batch = format!("import git cl {{\n  \"url\": \"{REPO_HTTPS}\",\n  \"ref\": \"{git_ref}\"\n}}\n\ncl/example3.api\n");
        let ran = run_batch(&dir, server.port, "-sa", &batch);
        assert!(ran.ok, "{git_ref}: {}", ran.stderr);
        let logged = format!("import cl {REPO_HTTPS} {git_ref} ({})", &TAG_COMMIT[..7]);
        assert!(ran.stdout.contains(&logged), "{git_ref}: {}", ran.stdout);
        assert_example3_ran(&server.sent(), git_ref);
    }
    let repo_cache = std::fs::read_dir(dir.join(".import-cache")).unwrap().flatten().next().unwrap().path();
    assert!(repo_cache.join(TAG_COMMIT).join("example1.api").is_file());
    assert!(!repo_cache.join(TAG_COMMIT).join(".git").exists());

    // `example1.api` includes `example2.api` and writes into the home
    // directory, so it is previewed and declined, not run.
    std::fs::write(
        dir.join("batch.api"),
        format!("import git cl {{ \"url\": \"{REPO_HTTPS}\", \"ref\": \"{TAG}\" }}\ncl/example1.api\n"),
    )
    .unwrap();
    let mut cmd = api(&dir, server.port);
    cmd.args(["-spa", "batch.api"]);
    let ran = finish(cmd, "n\n");
    assert!(ran.ok, "{}", ran.stderr);
    for expected in [
        "PUT /people/com.mi6.id=007",
        "GET /people~with(com.heads.*) > ~/my-file.json",
        "PUT /people/com.mi6.id=006/addresses/main",
        // From example2.api, which example1.api includes.
        "PUT /people/com.mi6.id=006/addresses/invoice",
    ] {
        assert!(ran.stderr.contains(expected), "{expected:?} not in\n{}", ran.stderr);
    }
    assert_eq!(server.sent(), Vec::<String>::new());

    // A branch is looked up on the remote and logged with its commit.
    let ran = run_batch(
        &dir,
        server.port,
        "-sa",
        &format!("import git cl {{ \"url\": \"{REPO_HTTPS}\", \"ref\": \"master\" }}\n"),
    );
    assert!(ran.ok, "{}", ran.stderr);
    assert!(ran.stdout.contains(&format!("import cl {REPO_HTTPS} master (")), "{}", ran.stdout);

    // A ref the repository doesn't have.
    let ran = run_batch(
        &dir,
        server.port,
        "-sa",
        &format!("import git cl {{ \"url\": \"{REPO_HTTPS}\", \"ref\": \"no-such-ref\" }}\nGET /never\n"),
    );
    assert!(!ran.ok);
    assert!(ran.stderr.contains(&format!("import ref not found: no-such-ref in {REPO_HTTPS}")), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());
}

#[test]
fn the_api_client_repository_imports_over_ssh() {
    if offline("the_api_client_repository_imports_over_ssh") {
        return;
    }
    let (_guard, dir) = temp();
    let server = Server::start("0", Vec::new());
    let batch = format!("import git cl {{ \"url\": \"{REPO_SSH}\", \"ref\": \"{TAG}\" }}\ncl/example3.api\n");
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "ssh to GitHub needs a key it accepts: {}", ran.stderr);
    assert!(
        ran.stdout.contains(&format!("import cl {REPO_SSH} {TAG} ({})", &TAG_COMMIT[..7])),
        "{}",
        ran.stdout
    );
    assert_example3_ran(&server.sent(), "ssh");
}

#[test]
fn the_api_client_release_tarball_imports_over_https() {
    if offline("the_api_client_release_tarball_imports_over_https") {
        return;
    }
    let (_guard, dir) = temp();
    let server = Server::start("0", Vec::new());
    // GitHub redirects this to another host, over https. The tarball holds
    // one directory, `commerceos-api-client-3.2.2`, which the alias skips.
    let batch = format!("import archive cl {{ \"url\": \"{REPO_TARBALL}\" }}\ncl/example3.api\n");
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert!(ran.stdout.contains(&format!("import cl {REPO_TARBALL} (sha256 ")), "{}", ran.stdout);
    assert_example3_ran(&server.sent(), "tarball");

    // The hash the log printed pins it: the next run downloads nothing.
    let unpacked = std::fs::read_dir(dir.join(".import-cache/archives"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .find(|name| name.len() == 64)
        .expect("an unpacked archive");
    let pinned = format!(
        "import archive cl {{ \"url\": \"https://unreachable.example.invalid/x.tar.gz\", \"sha256\": \"{unpacked}\" }}\ncl/example3.api\n"
    );
    let ran = run_batch(&dir, server.port, "-sa", &pinned);
    assert!(ran.ok, "{}", ran.stderr);
    assert_example3_ran(&server.sent(), "pinned tarball");
}

/// The release this suite's own fixture tree first shipped in.
const FIXTURE_TAG: &str = "3.3.0";
const FIXTURE_TAG_COMMIT: &str = "7c4809ae00cd054d4de3e211d0a6e1dc30cc03ff";
const FIXTURE_TARBALL: &str = "https://github.com/byheads/commerceos-api-client/archive/refs/tags/3.3.0.tar.gz";
const FIXTURE_PATH: &str = "tests/fixtures/import";

/// The fixture as released, a subdirectory of the repository picked with
/// `path`, sends what the copy in the working tree does. Only the files that
/// release holds are run (`seed.api`, `chain.api`, `with-json.api`), which is
/// why those three must keep sending what `fixture_requests` lists.
#[test]
fn the_released_fixture_imports_from_a_subdirectory_of_the_repository() {
    if offline("the_released_fixture_imports_from_a_subdirectory_of_the_repository") {
        return;
    }
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let imports = [
        (
            format!("import git lib {{ \"url\": \"{REPO_HTTPS}\", \"ref\": \"{FIXTURE_TAG}\", \"path\": \"{FIXTURE_PATH}\" }}"),
            format!("import lib {REPO_HTTPS} {FIXTURE_TAG} ({})", &FIXTURE_TAG_COMMIT[..7]),
        ),
        (
            format!("import archive lib {{ \"url\": \"{FIXTURE_TARBALL}\", \"path\": \"{FIXTURE_PATH}\" }}"),
            format!("import lib {FIXTURE_TARBALL} (sha256 "),
        ),
    ];
    for (import, logged) in imports {
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\n{RUN_THE_FIXTURE}"));
        assert!(ran.ok, "{import}\n{}", ran.stderr);
        assert!(ran.stdout.contains(&logged), "{import}: {}", ran.stdout);
        assert_eq!(server.sent(), fixture_requests(), "{import}");

        // Its gate is refused from there as well.
        let ran = run_batch(&dir, server.port, "-sa", &format!("url has 127.0.0.1\n{import}\nlib/gated.api\n"));
        assert!(!ran.ok, "{import}");
        assert!(ran.stderr.contains("import lib: URL gate failed"), "{import}: {}", ran.stderr);
        assert_eq!(server.sent(), Vec::<String>::new(), "{import}");

        // `path` says where the alias starts, not where the import ends: the
        // whole repository was imported, so a file body that climbs above
        // `path` and stays in the repository is one of its own files.
        // `escape.api` names `../../../Cargo.toml`, the repository's own.
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nlib/escape.api\n"));
        assert!(ran.ok, "{import}: {}", ran.stderr);
        let sent = server.sent();
        assert_eq!(sent.len(), 2, "{import}: {sent:?}");
        assert_eq!(sent[0], "GET /escape/first", "{import}");
        assert!(sent[1].starts_with("PUT /escape [package]"), "{import}: {}", &sent[1][..sent[1].len().min(80)]);
        assert!(sent[1].contains("name = \"api-rust\"") && sent[1].contains("version = \"3.3.0\""), "{import}");
    }

    // A subdirectory the release doesn't have.
    let ran = run_batch(
        &dir,
        server.port,
        "-sa",
        &format!("import git lib {{ \"url\": \"{REPO_HTTPS}\", \"ref\": \"{FIXTURE_TAG}\", \"path\": \"tests/no-such-dir\" }}\n"),
    );
    assert!(!ran.ok);
    assert!(ran.stderr.contains("import lib: no directory `tests/no-such-dir`"), "{}", ran.stderr);
}

/// A nested import across the network: the fixture, imported from the working
/// tree and from a local repository, holds files that import this client's
/// repository from GitHub themselves, as a repository and as a tarball.
#[test]
fn an_imported_file_can_import_the_api_client_repository_from_github() {
    if offline("an_imported_file_can_import_the_api_client_repository_from_github") {
        return;
    }
    let (_guard, dir) = temp();
    let server = Server::start("0", fixture_archive());
    for (kind, import) in each_kind(&dir, &server) {
        for (file, logged) in [
            ("nested-git.api", format!("import examples {REPO_HTTPS} {TAG} ({})", &TAG_COMMIT[..7])),
            ("nested-archive.api", format!("import examples {REPO_TARBALL} (sha256 ")),
        ] {
            let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nlib/{file}\n"));
            assert!(ran.ok, "{kind} {file}: {}", ran.stderr);
            // The outer import first, then the one the imported file made.
            let outer = ran.stdout.find("import lib ").unwrap_or_else(|| panic!("{kind} {file}: {}", ran.stdout));
            let inner = ran.stdout.find(&logged).unwrap_or_else(|| panic!("{kind} {file}: {}", ran.stdout));
            assert!(outer < inner, "{kind} {file}: {}", ran.stdout);
            assert_example3_ran(&server.api_requests(), &format!("{kind} {file}"));
        }
    }
}
