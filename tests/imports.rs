//! End-to-end tests for `import git`, `import dir` and `import archive`.
//!
//! Most of them run the tree in `tests/fixtures/import` against a recording
//! server on this machine and need nothing else: the tree is imported as a
//! directory, as a git repository built from it, and as an archive of it.
//! Repositories that import each other are built the same way, in a
//! temporary directory.
//!
//! Five tests fetch this client's own repository from github.com and so
//! need the network: `the_api_client_repository_imports_over_https`,
//! `the_api_client_repository_imports_over_ssh`,
//! `the_api_client_release_tarball_imports_over_https`,
//! `the_released_fixture_imports_from_a_subdirectory_of_the_repository` and
//! `an_imported_file_can_import_the_api_client_repository_from_github`.
//! `API_TEST_OFFLINE=1` skips the five. The ssh one also needs an ssh key
//! that GitHub accepts, and skips itself where there is none. A skipped test
//! prints a line that starts with `SKIPPED` on stderr (shown with
//! `-- --nocapture`): it passes without having checked anything.
//!
//! Nothing here needs a local CommerceOS, a credentials file or a clipboard.
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
/// - `/moved` redirects there; `/moved-off` redirects to a plain-http host;
///   `/loop` redirects to itself.
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
        "/loop" => ("302 Found", format!("Location: http://127.0.0.1:{port}/loop\r\n"), b""),
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

/// A describe block is its file's: `-m` prints the batch's, not the one an
/// imported file opens with, and neither is sent. `--assert` follows the
/// import and lists what both files assert; `--describe` reads the batch
/// alone, so it answers with nothing fetched.
#[test]
fn a_describe_block_in_an_imported_file_stays_there_and_its_assertions_are_listed() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    const BLOCK: &str = r#"{ "title": { "en-US": "The batch" }, "docsLink": "https://link-to-docs.com" }"#;
    for (kind, import) in each_kind(&dir, &server) {
        let batch = format!(
            "{BLOCK}\n{import}\nlib/described.api\nPUT /assert {{ \"api/v1/described~count\": {{ \"is not\": 2 }} }}\n"
        );
        let ran = run_batch(&dir, server.port, "-sma", &batch);
        assert!(ran.ok, "{kind}: {}", ran.stderr);
        assert_eq!(
            server.api_requests(),
            vec![
                r#"PUT /assert { "api/v1/described~count": { "is": 1 } }"#,
                "GET /described/after",
                r#"PUT /assert { "api/v1/described~count": { "is not": 2 } }"#,
            ],
            "{kind}"
        );
        assert!(ran.stderr.starts_with("The batch\nhttps://link-to-docs.com\n\n"), "{kind}: {:?}", ran.stderr);
        assert!(!ran.stderr.contains("Described fixture"), "{kind}: {}", ran.stderr);
        assert!(!ran.stdout.contains("title"), "{kind}: {}", ran.stdout);

        // Without -m nothing of it is printed.
        let ran = run_batch(&dir, server.port, "-sa", &batch);
        assert!(ran.ok && ran.stderr.is_empty(), "{kind}: {}", ran.stderr);
        server.sent();

        let mut cmd = api(&dir, server.port);
        cmd.args(["-r", "--assert", "batch.api"]);
        let ran = finish(cmd, "");
        assert!(ran.ok, "{kind}: {}", ran.stderr);
        assert_eq!(
            ran.stdout,
            concat!(
                r#"[{"api/v1/described~count":{"is":1}},"#,
                r#"{"api/v1/described~count":{"is not":2}}]"#,
                "\n"
            ),
            "{kind}"
        );
        assert!(server.api_requests().is_empty(), "{kind}: --assert sends nothing");
    }

    // An import that can't be fetched: `--describe` never tries, `--assert`
    // has to and says why it could not.
    let batch = format!("{BLOCK}\nimport dir lib {{ \"path\": \"no-such-directory\" }}\nlib/described.api\n");
    std::fs::write(dir.join("batch.api"), batch).unwrap();
    let mut cmd = api(&dir, server.port);
    cmd.args(["-r", "--describe", "batch.api"]);
    let ran = finish(cmd, "");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(ran.stdout, "{\"title\":{\"en-US\":\"The batch\"},\"docsLink\":\"https://link-to-docs.com\"}\n");
    let mut cmd = api(&dir, server.port);
    cmd.args(["--assert", "batch.api"]);
    let ran = finish(cmd, "");
    assert!(!ran.ok && ran.stdout.is_empty(), "{}", ran.stdout);
    assert!(ran.stderr.starts_with("error: import lib: not a directory"), "{}", ran.stderr);
    assert!(server.sent().is_empty());
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

/// The path of an import is the client's own and is read as it is: only what
/// a line of the imported file wrote is a pattern. A directory, or a cache,
/// whose name holds `?`, `*` or `[` (as every canonical path on Windows
/// does) sends the same bodies as any other.
#[test]
fn a_file_body_of_an_import_is_not_a_pattern_for_what_the_imports_own_path_holds() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let kinds = each_kind(&dir, &server);

    for odd in ["lib?", "a[1]", "st*r", "[?]"] {
        // The fixture as a directory of that name, with a directory beside it
        // that the name would match as a pattern.
        let lib = dir.join(odd);
        for (name, contents) in fixture_files() {
            let path = lib.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        // The body of an `assert` and of a poll is a file body like any other.
        std::fs::write(
            lib.join("check.api"),
            "assert PUT /check/assert @data/body.json\nsleep 0 while not PUT /check/poll @data/body.json\n",
        )
        .unwrap();
        for decoy in ["libX", "a1", "star", "x"] {
            let people = dir.join(decoy).join("data/people");
            std::fs::create_dir_all(&people).unwrap();
            std::fs::write(people.join("zed.json"), r#"{"name":"decoy"}"#).unwrap();
            std::fs::write(dir.join(decoy).join("data/body.json"), r#"{"from":"decoy"}"#).unwrap();
        }
        let as_dir = ("dir", format!("import dir lib {{ \"path\": \"{}\" }}", lib.display()));
        // And a repository and an archive, kept in a cache of that name.
        for (kind, import) in std::iter::once(&as_dir).chain(kinds.iter().filter(|(kind, _)| *kind != "dir")) {
            let checks = if *kind == "dir" { "lib/check.api\n" } else { "" };
            let batch = format!("{import}\n{RUN_THE_FIXTURE}lib/bodies.api\n{checks}");
            std::fs::write(dir.join("batch.api"), batch).unwrap();
            let mut cmd = api(&dir, server.port);
            cmd.env("API_IMPORT_CACHE", dir.join("cache").join(odd)).args(["-sa", "batch.api"]);
            let ran = finish(cmd, "");
            assert!(ran.ok, "{odd} {kind}: {}", ran.stderr);
            let sent = server.api_requests();
            let checked = if *kind == "dir" { 2 } else { 0 };
            assert_eq!(sent.len(), fixture_requests().len() + 4 + checked, "{odd} {kind}: {sent:?}");
            // One file is sent as the file it is, not as a list of one.
            assert_eq!(sent[..fixture_requests().len()], fixture_requests(), "{odd} {kind}");
            let bodies = &sent[fixture_requests().len()..];
            // A pattern the line wrote still is one, below a path that is not.
            assert!(bodies[1].starts_with("PUT /bodies/people "), "{odd} {kind}: {}", bodies[1]);
            assert_eq!(
                json_body(&bodies[1]),
                serde_json::json!([{ "name": "Ann" }, { "name": "Bob" }, { "name": "Cy" }, { "name": "Di" }]),
                "{odd} {kind}"
            );
            assert_eq!(bodies[2], "PUT /bodies/events {\"event\":1}\n{\"event\":2}", "{odd} {kind}");
            assert_eq!(bodies[3], "PUT /bodies/rows id,name\n1,Ann\n2,Bob", "{odd} {kind}");
            if *kind == "dir" {
                assert_eq!(bodies[4..], [format!("PUT /check/assert {BODY}"), format!("PUT /check/poll {BODY}")], "{odd}");
            }
            // Logged as the line has it.
            assert!(ran.stdout.contains("PUT /bodies/rows @data/rows.csv~map(com.heads.test-rows)\n"), "{odd} {kind}: {}", ran.stdout);
        }
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

/// A request from an imported file is logged, and previewed, with its
/// `@file` body as the line has it, whatever the import is and wherever the
/// file really is: never the path in the import cache.
#[test]
fn a_file_body_of_an_import_is_logged_as_written_for_every_kind() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let written = [
        "PUT /seed/body @data/body.json\n",
        "PUT /bodies/people @data/people/*.json\n",
        "PUT /bodies/events @data/events.ndjson\n",
        // A body function stays on the path it follows.
        "PUT /bodies/rows @data/rows.csv~map(com.heads.test-rows)\n",
        // And so does a body in a segment of a chain.
        "PUT /chain/second @data/body.json~map(com.heads.test)\n",
    ];
    for (kind, import) in each_kind(&dir, &server) {
        let batch = format!("{import}\nlib/seed.api\nlib/bodies.api\nlib/chain.api\n");
        let ran = run_batch(&dir, server.port, "-sa", &batch);
        assert!(ran.ok, "{kind}: {}", ran.stderr);
        for line in written {
            assert!(ran.stdout.contains(line), "{kind}: {line:?} is not in\n{}", ran.stdout);
        }
        // Only the directory import's own log line names where it is.
        let requests: String = ran.stdout.lines().filter(|l| !l.starts_with("import ")).collect::<Vec<_>>().join("\n");
        assert!(!requests.contains(".import-cache"), "{kind}: {requests}");
        assert!(!requests.contains(&fixture().display().to_string()), "{kind}: {requests}");
        server.sent();

        // The preview lists them the same way, and sends nothing when declined.
        std::fs::write(dir.join("batch.api"), &batch).unwrap();
        let mut cmd = api(&dir, server.port);
        cmd.args(["-spa", "batch.api"]);
        let preview = finish(cmd, "n\n");
        for line in written {
            // A chain's later segment is listed behind its `&&`.
            assert!(preview.stderr.contains(&format!(" {line}")), "{kind}: {line:?} is not in\n{}", preview.stderr);
        }
        let listed: String = preview.stderr.lines().filter(|l| !l.trim_start().starts_with("import ")).collect::<Vec<_>>().join("\n");
        assert!(!listed.contains(".import-cache"), "{kind}: {listed}");
        assert_eq!(server.api_requests(), Vec::<String>::new(), "{kind}");
    }
}

/// A directory import whose files are made by the test: `lib/` in `dir`, and
/// the batch line that imports it.
fn own_import(dir: &Path, files: &[(&str, &str)]) -> String {
    for (name, contents) in files {
        let path = dir.join("libdir").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    "import dir lib { \"path\": \"libdir\" }".to_string()
}

/// The request of an `assert` and of a `sleep while` is a request of the
/// imported file like any other: its `@file` is read from the import, and one
/// that points outside is refused before anything is sent.
#[test]
fn the_body_of_an_assert_and_of_a_poll_in_an_imported_file_stays_inside() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    std::fs::write(dir.join("outside.json"), r#"{"secret":"outside"}"#).unwrap();
    // A file of the same name in the working directory must not be the one sent.
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::write(dir.join("data/a.json"), r#"{"from":"cwd"}"#).unwrap();
    let import = own_import(
        &dir,
        &[
            ("data/a.json", r#"{"from":"import"}"#),
            ("inside.api", "assert PUT /as @data/a.json\nsleep 0 while not PUT /sw @data/a.json\n"),
            ("assert-out.api", "assert PUT /as @../outside.json\n"),
            ("assert-abs.api", "assert PUT /as @/etc/shells\n"),
            ("poll-out.api", "sleep 0 while not PUT /sw @../outside.json\n"),
            ("poll-abs.api", "sleep 0 while not PUT /sw @/etc/shells\n"),
            ("poll-home.api", "sleep while PUT /sw @~/x.json\n"),
        ],
    );

    let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nlib/inside.api\n"));
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), [r#"PUT /as {"from":"import"}"#, r#"PUT /sw {"from":"import"}"#]);
    // Logged as the line has it, not as the path it was resolved to.
    assert!(ran.stdout.contains("assert PUT /as @data/a.json\n"), "{}", ran.stdout);

    for (file, written) in [
        ("assert-out", "../outside.json"),
        ("assert-abs", "/etc/shells"),
        ("poll-out", "../outside.json"),
        ("poll-abs", "/etc/shells"),
        ("poll-home", "~/x.json"),
    ] {
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nGET /first\nlib/{file}.api\n"));
        assert!(!ran.ok, "{file}");
        let refusal = format!("import lib: `@{written}` must be a relative path inside the import");
        assert!(ran.stderr.contains(&refusal), "{file}: {}", ran.stderr);
        assert_eq!(server.sent(), Vec::<String>::new(), "{file}");
    }
}

/// In a directory import, whose files are used where they are, a link is
/// followed only when it stays inside. That holds for every file a glob
/// matches and for a file reached through a linked directory.
#[test]
fn a_glob_body_does_not_follow_a_link_out_of_a_directory_import() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    std::fs::create_dir_all(dir.join("elsewhere")).unwrap();
    std::fs::write(dir.join("outside.json"), r#"{"secret":"outside"}"#).unwrap();
    std::fs::write(dir.join("elsewhere/x.json"), r#"{"secret":"elsewhere"}"#).unwrap();
    let import = own_import(
        &dir,
        &[
            ("data/a.json", r#"{"from":"dir"}"#),
            ("glob.api", "PUT /glob @data/*.json\n"),
            ("linked-file.api", "PUT /one @linkdir/x.json\n"),
            ("linked-glob.api", "PUT /ldg @linkdir/*.json\n"),
            ("check-glob.api", "assert PUT /as @data/*.json\n"),
        ],
    );
    let run = |file: &str| run_batch(&dir, server.port, "-sa", &format!("{import}\nGET /first\nlib/{file}.api\n"));

    // Nothing links out yet: the glob is the one file.
    let ran = run("glob");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), ["GET /first", r#"PUT /glob [{"from":"dir"}]"#]);

    // A link that stays inside is a file like any other.
    std::os::unix::fs::symlink(dir.join("libdir/data/a.json"), dir.join("libdir/data/b.json")).unwrap();
    let ran = run("glob");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), ["GET /first", r#"PUT /glob [{"from":"dir"},{"from":"dir"}]"#]);

    // One that leads out stops the batch, whatever kind of line the glob is on.
    std::fs::remove_file(dir.join("libdir/data/b.json")).unwrap();
    std::os::unix::fs::symlink(dir.join("outside.json"), dir.join("libdir/data/b.json")).unwrap();
    std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join("libdir/linkdir")).unwrap();
    for (file, written) in [
        ("glob", "data/*.json"),
        ("check-glob", "data/*.json"),
        ("linked-file", "linkdir/x.json"),
        ("linked-glob", "linkdir/*.json"),
    ] {
        let ran = run(file);
        assert!(!ran.ok, "{file}");
        let refusal = format!("import lib: `@{written}` must be a relative path inside the import");
        assert!(ran.stderr.contains(&refusal), "{file}: {}", ran.stderr);
        assert_eq!(server.sent(), Vec::<String>::new(), "{file}");
    }
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

    // A redirect that never arrives is given up on, not followed for ever.
    let batch = format!("import archive lib {{ \"url\": \"{}\" }}\nGET /never\n", server.url("/loop"));
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(!ran.ok);
    assert!(ran.stderr.contains("too many redirects"), "{}", ran.stderr);
    let sent = server.sent();
    assert!(sent.len() > 5 && sent.iter().all(|r| r == "GET /loop"), "{sent:?}");
}

// ----- archive formats -----

/// The fixture as a `.zip` under one top directory, with the directory
/// entries a zip tool writes, and as a `.tar` that is not compressed.
fn fixture_zip() -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    let mut dirs = std::collections::BTreeSet::new();
    zip.add_directory("fixture-1.0/", options).unwrap();
    for (name, contents) in fixture_files() {
        if let Some((parent, _)) = name.rsplit_once('/') {
            if dirs.insert(parent.to_string()) {
                zip.add_directory(format!("fixture-1.0/{parent}/"), options).unwrap();
            }
        }
        zip.start_file(format!("fixture-1.0/{name}"), options).unwrap();
        zip.write_all(&contents).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn fixture_tar() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, contents) in fixture_files() {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, format!("fixture-1.0/{name}"), &contents[..]).unwrap();
    }
    builder.into_inner().unwrap()
}

#[test]
fn a_zip_and_a_plain_tar_send_what_the_tar_gz_sends() {
    for (format, archive) in [("zip", fixture_zip()), ("tar", fixture_tar())] {
        let (_guard, dir) = temp();
        // Downloaded: the name says `.tar.gz`, the content says otherwise.
        let server = Server::start("1", archive.clone());
        let import = format!("import archive lib {{ \"url\": \"{}\" }}", server.url("/lib.tar.gz"));
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\n{RUN_THE_FIXTURE}"));
        assert!(ran.ok, "{format}: {}", ran.stderr);
        assert_eq!(server.api_requests(), fixture_requests(), "{format}");

        // From a file on this machine, every kind of body included.
        let file = dir.join(format!("fixture.{format}"));
        std::fs::write(&file, &archive).unwrap();
        let import = format!("import archive lib {{ \"url\": \"file://{}\" }}", file.display());
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\n{RUN_THE_FIXTURE}lib/nested/index.api\n"));
        assert!(ran.ok, "{format}: {}", ran.stderr);
        let sent = server.sent();
        assert_eq!(&sent[..fixture_requests().len()], &fixture_requests()[..], "{format}");
        assert!(sent.len() > fixture_requests().len(), "{format}: the nested include sent nothing");
    }
}

#[test]
fn a_truncated_archive_fails_before_any_request_and_leaves_nothing_in_the_cache() {
    for (format, archive) in [("zip", fixture_zip()), ("tar.gz", fixture_archive())] {
        let (_guard, dir) = temp();
        let server = Server::start("1", archive[..archive.len() / 2].to_vec());
        let batch = format!("import archive lib {{ \"url\": \"{}\" }}\nGET /never\n", server.url("/lib.tar.gz"));
        let ran = run_batch(&dir, server.port, "-sa", &batch);
        assert!(!ran.ok, "{format}");
        let says = format!("import archive {}: could not ", server.url("/lib.tar.gz"));
        assert!(ran.stderr.contains(&says), "{format}: {}", ran.stderr);
        assert_eq!(server.api_requests(), Vec::<String>::new(), "{format}");
        // The cache was there to unpack into, and holds nothing now: not
        // the half that was unpacked, and not the marker beside it.
        let left: Vec<String> = std::fs::read_dir(dir.join(".import-cache/archives"))
            .expect("the archive cache was made")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(left, Vec::<String>::new(), "{format}");
    }
}

// ----- what an import line may say -----

#[test]
fn a_pinned_archive_with_another_hash_is_refused_before_any_request() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let url = server.url("/lib.tar.gz");
    let wrong = "0".repeat(64);
    let batch = format!("import archive lib {{ \"url\": \"{url}\", \"sha256\": \"{wrong}\" }}\nGET /own\nlib/seed.api\n");
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(!ran.ok);
    assert!(ran.stderr.contains(&format!("import archive {url}: sha256 mismatch (expected {wrong}, got ")), "{}", ran.stderr);
    assert_eq!(server.api_requests(), Vec::<String>::new());

    // The hash it said it got is the one that pins it.
    let got = ran.stderr.split("got ").nth(1).unwrap().chars().take(64).collect::<String>();
    let batch = format!("import archive lib {{ \"url\": \"{url}\", \"sha256\": \"{got}\" }}\nlib/parts/a.api\n");
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.api_requests(), vec!["GET /parts/a"]);
    // Upper case is the same hash, and the cache now answers without a download.
    let batch = batch.replace(&got, &got.to_uppercase());
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), vec!["GET /parts/a"]);
}

#[test]
fn an_import_line_that_cannot_be_meant_stops_the_batch_before_any_request() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    std::fs::create_dir_all(dir.join("taken")).unwrap();
    std::fs::write(dir.join("not-json.json"), "{ \"path\": ").unwrap();
    std::fs::write(dir.join("a-list.json"), "[\"x\"]").unwrap();
    std::fs::write(dir.join("not-json-either.json"), "{ \"path\": nowhere }").unwrap();
    let here = fixture().display().to_string();
    for (import, says) in [
        // An archive over plain http from anywhere but this machine.
        (r#"import archive lib { "url": "http://example.invalid/lib.tar.gz" }"#.to_string(), "unsupported url"),
        (r#"import archive lib { "url": "ftp://example.invalid/lib.tar.gz" }"#.to_string(), "unsupported url"),
        (r#"import archive lib { "url": "file://relative/lib.tar.gz" }"#.to_string(), "unsupported url"),
        // A hash that is not one.
        (format!(r#"import archive lib {{ "url": "{}", "sha256": "abc" }}"#, server.url("/lib.tar.gz")), "import lib: `sha256` must be 64 hexadecimal characters"),
        // An alias that already names something next to the batch.
        (format!(r#"import dir taken {{ "path": "{here}" }}"#), "import alias `taken` clashes with"),
        // The same alias twice.
        (format!("import dir lib {{ \"path\": \"{here}\" }}\nimport dir lib {{ \"path\": \"{here}\" }}"), "import alias `lib` is declared twice"),
        // JSON that is not JSON, not an object, or has a key the kind doesn't take.
        (r#"import dir lib { "path": }"#.to_string(), "import lib: invalid JSON"),
        (r#"import dir lib ["x"]"#.to_string(), "invalid import: expected `import <git|dir|archive> <alias>"),
        ("import dir lib @a-list.json".to_string(), "import lib: expected a JSON object"),
        ("import dir lib @not-json.json".to_string(), "import file not-json.json: unclosed body"),
        ("import dir lib @not-json-either.json".to_string(), "import lib: invalid JSON"),
        ("import dir lib @no-such-file.json".to_string(), "error: File not found: no-such-file.json"),
        (r#"import dir lib { "path": "no-such-directory" }"#.to_string(), "import lib: not a directory: no-such-directory"),
        (r#"import svn lib { "url": "x" }"#.to_string(), "unknown import kind `svn` (expected `git`, `dir` or `archive`)"),
        // A `file://` url that names another machine, and a `\` in any url.
        (r#"import archive lib { "url": "file://fileserver/share/lib.tar.gz" }"#.to_string(), "a file:// url reads a file of this machine, not of the host `fileserver`"),
        (r#"import archive lib { "url": "https://example.invalid\\@127.0.0.1/lib.tar.gz" }"#.to_string(), "unsupported url"),
        (r#"import git lib { "url": "https://example.invalid\\@127.0.0.1/repo", "ref": "main" }"#.to_string(), "unsupported url"),
        (format!(r#"import git lib {{ "url": "file://{here}", "ref": "1.0", "path": "/etc" }}"#), "`path` must be a relative path inside the import"),
    ] {
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nGET /never\n"));
        assert!(!ran.ok, "{import}");
        assert!(ran.stderr.contains(says), "{import}: expected {says:?} in\n{}", ran.stderr);
        assert_eq!(server.sent(), Vec::<String>::new(), "{import}");
    }
}

#[test]
fn path_starts_the_alias_in_a_subdirectory_of_a_repository_and_of_an_archive() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let (repo, _) = fixture_repository(&dir.join("fixture-repo"));
    for (kind, import) in [
        ("git", format!("import git lib {{ \"url\": \"{repo}\", \"ref\": \"1.0\", \"path\": \"parts\" }}")),
        // Below the one top directory the archive is packed under.
        ("archive", format!("import archive lib {{ \"url\": \"{}\", \"path\": \"parts\" }}", server.url("/lib.tar.gz"))),
    ] {
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nlib/*.api\n"));
        assert!(ran.ok, "{kind}: {}", ran.stderr);
        // `b.api` sends a body from above `path`: still inside the import.
        assert_eq!(server.api_requests(), vec!["GET /parts/a".to_string(), format!("PUT /parts/b {BODY}")], "{kind}");

        // What is above `path` is not under the alias.
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nlib/seed.api\n"));
        assert!(!ran.ok, "{kind}");
        assert!(ran.stderr.contains("include not found: lib/seed.api"), "{kind}: {}", ran.stderr);
        assert_eq!(server.api_requests(), Vec::<String>::new(), "{kind}");

        // A `path` that is not in the import.
        let ran = run_batch(&dir, server.port, "-sa", &format!("{}\nGET /never\n", import.replace("\"parts\"", "\"no-such\"")));
        assert!(!ran.ok, "{kind}");
        assert!(ran.stderr.contains("import lib: no directory `no-such` in "), "{kind}: {}", ran.stderr);
        assert_eq!(server.api_requests(), Vec::<String>::new(), "{kind}");
    }
}

// ----- -f in an imported file -----

#[test]
fn fail_fast_stops_inside_an_imported_file_with_the_body_last_on_stdout() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    std::fs::create_dir_all(dir.join("mine")).unwrap();
    std::fs::write(dir.join("mine/steps.api"), "GET /lib/first\nPUT /lib/missing {\"a\":1}\nGET /lib/never\n").unwrap();
    let batch = "import dir lib { \"path\": \"mine\" }\nGET /own\nlib/steps.api\nGET /after\n";

    let ran = run_batch(&dir, server.port, "-sfa", batch);
    assert!(!ran.ok);
    assert_eq!(server.sent(), vec!["GET /own", "GET /lib/first", "PUT /lib/missing {\"a\":1}"]);
    assert!(ran.stdout.trim_end().ends_with("null"), "the 404's body is last: {:?}", ran.stdout);

    // Without `-f` the import runs to its end and so does the batch.
    let ran = run_batch(&dir, server.port, "-sa", batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent().len(), 5);

    // The same through a repository and an archive, with the fixture's own
    // failing step: a question (`assert`) that is answered "no".
    for (kind, import) in each_kind(&dir, &server) {
        let ran = run_batch(&dir, server.port, "-sfa", &format!("{import}\nlib/assert-fails.api\nGET /after\n"));
        assert!(!ran.ok, "{kind}");
        assert_eq!(server.api_requests(), vec!["GET /assert/before", "GET /assert/missing"], "{kind}");
    }
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

// ----- --imports -----

/// `api --imports batch.api` for `batch`, with further flags in front.
fn list_imports(dir: &Path, port: u16, flags: &[&str], batch: &str) -> Ran {
    std::fs::write(dir.join("batch.api"), batch).unwrap();
    let mut cmd = api(dir, port);
    cmd.args(flags).args(["--imports", "batch.api"]);
    finish(cmd, "")
}

fn listed(ran: &Ran) -> Vec<serde_json::Value> {
    assert!(ran.ok, "{}", ran.stderr);
    serde_json::from_str(&ran.stdout).unwrap_or_else(|e| panic!("{e}: {}", ran.stdout))
}

fn member<'a>(entry: &'a serde_json::Value, name: &str) -> &'a str {
    entry[name].as_str().unwrap_or_else(|| panic!("no `{name}` in {entry}"))
}

fn member_names(entry: &serde_json::Value) -> Vec<&str> {
    entry.as_object().unwrap().keys().map(String::as_str).collect()
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.chars().all(|c| c.is_ascii_hexdigit())
}

#[test]
fn imports_lists_each_kind_with_the_directory_its_alias_stands_for() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let batch_file = dir.join("batch.api").display().to_string();
    let seed = std::fs::read_to_string(fixture().join("seed.api")).unwrap();
    for (kind, import) in each_kind(&dir, &server) {
        let ran = list_imports(&dir, server.port, &[], &format!("{import}\nlib/seed.api\n"));
        let entries = listed(&ran);
        assert_eq!(entries.len(), 1, "{kind}: {}", ran.stdout);
        let entry = &entries[0];
        assert_eq!(member(entry, "file"), batch_file, "{kind}");
        assert_eq!(member(entry, "alias"), "lib", "{kind}");
        assert_eq!(member(entry, "kind"), kind);
        // The file `lib/seed.api` includes is `<directory>/seed.api`.
        let directory = Path::new(member(entry, "directory"));
        assert!(directory.is_absolute(), "{kind}: {entry}");
        assert_eq!(std::fs::read_to_string(directory.join("seed.api")).unwrap(), seed, "{kind}");
        match kind {
            "dir" => {
                assert_eq!(member_names(entry), ["file", "alias", "kind", "directory", "path"]);
                assert_eq!(member(entry, "path"), fixture().display().to_string());
            }
            "git" => {
                assert_eq!(member_names(entry), ["file", "alias", "kind", "directory", "url", "ref", "commit"]);
                assert_eq!(member(entry, "ref"), "1.0");
                assert!(import.contains(member(entry, "url")), "{entry}");
                assert!(is_hex(member(entry, "commit"), 40), "{entry}");
            }
            _ => {
                assert_eq!(member_names(entry), ["file", "alias", "kind", "directory", "url", "sha256"]);
                assert_eq!(member(entry, "url"), server.url("/lib.tar.gz"));
                // The hash of what was used, though the line pins none.
                assert!(is_hex(member(entry, "sha256"), 64), "{entry}");
                // Inside the one directory the archive is packed under.
                assert!(directory.ends_with("fixture-1.0"), "{entry}");
            }
        }
        // Nothing is sent to the API, and no gate is checked.
        assert_eq!(server.api_requests(), Vec::<String>::new(), "{kind}");
        let ran = list_imports(&dir, server.port, &[], &format!("url is https://elsewhere.example.com\n{import}\n"));
        assert_eq!(listed(&ran).len(), 1, "{kind}");
    }
}

#[test]
fn imports_applies_path_and_prints_it_as_written() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let (repo, _) = fixture_repository(&dir.join("fixture-repo"));
    for (kind, import) in [
        ("git", format!("import git lib {{ \"url\": \"{repo}\", \"ref\": \"1.0\", \"path\": \"parts\" }}")),
        ("archive", format!("import archive lib {{ \"url\": \"{}\", \"path\": \"parts\" }}", server.url("/lib.tar.gz"))),
    ] {
        let entries = listed(&list_imports(&dir, server.port, &[], &format!("{import}\n")));
        let directory = Path::new(member(&entries[0], "directory"));
        assert!(directory.ends_with("parts"), "{kind}: {}", entries[0]);
        assert!(directory.join("a.api").is_file(), "{kind}");
        assert_eq!(member(&entries[0], "path"), "parts", "{kind}");
        assert_eq!(member_names(&entries[0]).last(), Some(&"path"), "{kind}");
    }
}

#[test]
fn imports_follows_includes_and_imported_files_and_lists_a_line_once() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let (outer, middle, fixture_url) = nested_repositories(&dir, &server);

    // A file of the batch's own directory that declares an import, included
    // twice, and an alias in the batch that nothing includes from.
    std::fs::create_dir_all(dir.join("shared")).unwrap();
    std::fs::write(dir.join("shared/own.api"), format!("{}GET /own\n", import_git("fx", &fixture_url, "1.0"))).unwrap();
    let batch = format!(
        "{}{}shared/own.api\nshared/own.api\nlib/top.api\n",
        import_git("lib", &outer, "main"),
        import_git("unused", &fixture_url, "1.0"),
    );
    let ran = list_imports(&dir, server.port, &[], &batch);
    let entries = listed(&ran);
    let seen: Vec<(String, &str, &str)> = entries
        .iter()
        .map(|e| {
            let file = Path::new(member(e, "file")).file_name().unwrap().to_string_lossy().to_string();
            (file, member(e, "alias"), member(e, "kind"))
        })
        .collect();
    let expect = |file: &str, alias: &'static str, kind: &'static str| (file.to_string(), alias, kind);
    assert_eq!(
        seen,
        vec![
            expect("batch.api", "lib", "git"),
            expect("batch.api", "unused", "git"),
            expect("own.api", "fx", "git"),
            expect("top.api", "lib", "git"),
            expect("top.api", "packed", "archive"),
            expect("mid.api", "lib", "git"),
            expect("mid.api", "mine", "dir"),
        ],
        "{}",
        ran.stdout
    );
    assert_eq!(member(&entries[2], "file"), dir.join("shared/own.api").display().to_string());
    // An import declared in an imported file stands in the cache, in the
    // directory the import above it resolved to.
    let outer_directory = member(&entries[0], "directory");
    assert_eq!(member(&entries[3], "file"), Path::new(outer_directory).join("top.api").display().to_string());
    assert_eq!(member(&entries[3], "url"), middle);
    let middle_directory = member(&entries[3], "directory");
    assert_eq!(member(&entries[5], "file"), Path::new(middle_directory).join("mid.api").display().to_string());
    assert_eq!(member(&entries[6], "directory"), Path::new(middle_directory).join("own").display().to_string());
    assert_eq!(server.api_requests(), Vec::<String>::new());
}

#[test]
fn imports_prints_an_empty_list_one_line_with_r_and_reads_stdin() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let ran = list_imports(&dir, server.port, &[], "GET /a\n");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(ran.stdout, "[]\n");

    let import = format!("import dir lib {{ \"path\": \"{}\" }}\n", fixture().display());
    let ran = list_imports(&dir, server.port, &["-r"], &import);
    assert_eq!(ran.stdout.lines().count(), 1, "{}", ran.stdout);
    assert_eq!(listed(&ran).len(), 1);

    // From stdin there is no file to name.
    let mut cmd = api(&dir, server.port);
    cmd.args(["--imports", "-"]);
    let ran = finish(cmd, &import);
    let entries = listed(&ran);
    assert!(entries[0]["file"].is_null(), "{}", ran.stdout);
    assert_eq!(member(&entries[0], "directory"), fixture().canonicalize().unwrap().display().to_string());
    assert_eq!(server.sent(), Vec::<String>::new());
}

#[test]
fn imports_that_cannot_be_read_print_nothing_and_exit_1() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let (repo, _) = fixture_repository(&dir.join("fixture-repo"));
    for (batch, said) in [
        ("shared/none.api\n".to_string(), "error: include not found: shared/none.api"),
        (import_git("lib", &repo, "no-such-ref"), "error: "),
        (format!("{}lib/none.api\n", import_git("lib", &repo, "1.0")), "error: include not found: lib/none.api"),
    ] {
        let ran = list_imports(&dir, server.port, &[], &batch);
        assert!(!ran.ok, "{batch}");
        assert_eq!(ran.stdout, "", "{batch}");
        assert!(ran.stderr.starts_with(said), "{batch}: {}", ran.stderr);
    }
    // One document per run.
    let mut cmd = api(&dir, server.port);
    cmd.args(["--imports", "batch.api", "--assert", "batch.api"]);
    let ran = finish(cmd, "");
    assert!(!ran.ok);
    assert_eq!(ran.stderr, "error: --assert and --imports each print a document of their own: use one\n");
    assert_eq!(server.sent(), Vec::<String>::new());
}

#[test]
fn imports_never_prints_a_token_or_where_it_is_kept() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let batch = format!(
        "import archive lib {{ \"url\": \"{}\", \"token_env\": \"IMPORTS_TEST_TOKEN\" }}\n",
        server.url("/lib.tar.gz")
    );
    std::fs::write(dir.join("batch.api"), batch).unwrap();
    let mut cmd = api(&dir, server.port);
    cmd.env("IMPORTS_TEST_TOKEN", "s3cret-token").args(["--imports", "batch.api"]);
    let ran = finish(cmd, "");
    assert_eq!(listed(&ran).len(), 1);
    for hidden in ["token_env", "IMPORTS_TEST_TOKEN", "s3cret-token"] {
        assert!(!ran.stdout.contains(hidden) && !ran.stderr.contains(hidden), "{hidden}: {}{}", ran.stdout, ran.stderr);
    }
}

#[test]
fn imports_marks_a_cached_copy_that_stood_in_for_the_remote() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let (repo, _) = fixture_repository(&dir.join("fixture-repo"));
    let batch = import_git("lib", &repo, "1.0");
    let fresh = listed(&list_imports(&dir, server.port, &[], &batch));
    assert!(fresh[0].get("stale").is_none(), "{}", fresh[0]);
    // The repository is gone: the copy the tag last resolved to is used.
    std::fs::rename(dir.join("fixture-repo"), dir.join("moved-away")).unwrap();
    let cached = listed(&list_imports(&dir, server.port, &[], &batch));
    assert_eq!(cached[0]["stale"], serde_json::Value::Bool(true), "{}", cached[0]);
    assert_eq!(member(&cached[0], "commit"), member(&fresh[0], "commit"));
    assert_eq!(member(&cached[0], "directory"), member(&fresh[0], "directory"));
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

// ----- the cache -----

/// Set a file's modification time to `days` ago.
fn age(path: &Path, days: u64) {
    let then = std::time::SystemTime::now() - Duration::from_secs(days * 24 * 60 * 60);
    std::fs::File::open(path).unwrap().set_modified(then).unwrap();
}

#[test]
fn a_fetch_clears_out_checkouts_that_went_unused_for_a_month() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let repo = dir.join("repos/moving");
    let first = commit(&repo, &[("step.api", b"GET /first\n")], Some("1.0"));
    let on_main = format!("{}lib/step.api\n", import_git("lib", &repo_url(&repo), "main"));
    let on_tag = format!("{}lib/step.api\n", import_git("lib", &repo_url(&repo), "1.0"));

    let ran = run_batch(&dir, server.port, "-sa", &on_main);
    assert!(ran.ok, "{}", ran.stderr);
    let repo_cache = std::fs::read_dir(dir.join(".import-cache")).unwrap().flatten().next().unwrap().path();
    let (checkout, used) = (repo_cache.join(&first), repo_cache.join(format!("{first}.used")));
    assert!(checkout.is_dir() && used.is_file());

    // Unused for longer than a month. Running it again is a use, and nothing
    // new is fetched, so nothing is pruned and it counts as fresh again.
    age(&used, 45);
    let ran = run_batch(&dir, server.port, "-sa", &on_tag);
    assert!(ran.ok, "{}", ran.stderr);
    assert!(checkout.is_dir());
    let idle = std::fs::metadata(&used).unwrap().modified().unwrap().elapsed().unwrap();
    assert!(idle < Duration::from_secs(3600), "using a checkout should mark it used: {idle:?}");
    assert_eq!(server.sent(), vec!["GET /first", "GET /first"]);

    // The branch moves on while the old commit sits unused: the run that
    // fetches the new one clears the old one out.
    age(&used, 45);
    let second = commit(&repo, &[("step.api", b"GET /second\n")], None);
    let ran = run_batch(&dir, server.port, "-sa", &on_main);
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), vec!["GET /second"]);
    assert!(repo_cache.join(&second).is_dir());
    assert!(!checkout.exists() && !used.exists(), "the unused checkout should have been pruned");

    // It was only a copy: the tag fetches it again.
    let ran = run_batch(&dir, server.port, "-sa", &on_tag);
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), vec!["GET /first"]);
    // And the commit from a moment ago, used today, is still there.
    assert!(checkout.is_dir() && repo_cache.join(&second).is_dir());
}

#[test]
fn an_unused_unpacked_archive_is_cleared_out_too() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let batch = format!("import archive lib {{ \"url\": \"{}\" }}\nlib/parts/a.api\n", server.url("/lib.tar.gz"));
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    let archives = dir.join(".import-cache/archives");
    let unpacked = std::fs::read_dir(&archives)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_dir() && p.file_name().is_some_and(|n| n.len() == 64))
        .expect("an unpacked archive");
    let used = archives.join(format!("{}.used", unpacked.file_name().unwrap().to_string_lossy()));
    assert!(used.is_file());

    // A git fetch, a month and a half later, prunes across the whole cache.
    age(&used, 45);
    let repo = dir.join("repos/other");
    commit(&repo, &[("step.api", b"GET /other\n")], None);
    let ran = run_batch(&dir, server.port, "-sa", &format!("{}lib/step.api\n", import_git("lib", &repo_url(&repo), "main")));
    assert!(ran.ok, "{}", ran.stderr);
    assert!(!unpacked.exists() && !used.exists(), "the unused archive should have been pruned");
}

/// A `git` that writes each invocation's arguments to `log` and then runs
/// the real one. Returns the directory to put first on the `PATH`.
fn logging_git(dir: &Path, log: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let real = Command::new("sh").args(["-c", "command -v git"]).output().expect("sh runs");
    let real = String::from_utf8_lossy(&real.stdout).trim().to_string();
    assert!(!real.is_empty(), "git is not on the PATH");
    let bin = dir.join("logging-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let shim = bin.join("git");
    std::fs::write(&shim, format!("#!/bin/sh\necho \"$*\" >> '{}'\nexec '{real}' \"$@\"\n", log.display())).unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[test]
fn a_run_asks_the_remote_about_a_branch_once_however_often_it_is_imported() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let repo = dir.join("repos/asked");
    commit(&repo, &[("step.api", b"GET /step\n")], None);
    let import = import_git("lib", &repo_url(&repo), "main");
    let log = dir.join("git.log");
    let path = format!("{}:{}", logging_git(&dir, &log).display(), std::env::var("PATH").unwrap());
    let asked = |what: &str| {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        let _ = std::fs::remove_file(&log);
        text.lines().filter(|line| line.contains(what)).count()
    };

    // A batch whose included file imports the same branch under another name.
    std::fs::write(dir.join("inner.api"), format!("{}again/step.api\n", import.replace(" lib ", " again "))).unwrap();
    std::fs::write(dir.join("batch.api"), format!("{import}lib/step.api\ninner.api\n")).unwrap();
    let mut cmd = api(&dir, server.port);
    cmd.env("PATH", &path).args(["-sa", "batch.api"]);
    let ran = finish(cmd, "");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), vec!["GET /step", "GET /step"]);
    assert_eq!(asked("ls-remote"), 1, "one lookup for the whole run");

    // A one-shot line is parsed twice on its way to being run. Everything is
    // cached by now, so the lookup is all git is asked for, with the one
    // question about its own configuration (`core.sshCommand`) before it.
    let mut cmd = api(&dir, server.port);
    cmd.env("PATH", &path).arg(format!("{import}lib/step.api"));
    let ran = finish(cmd, "");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), vec!["GET /step"]);
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let asked: Vec<&str> = text.lines().filter(|line| !line.contains("config --get core.sshCommand")).collect();
    assert_eq!(asked.len(), 1, "{text}");
    assert!(asked[0].contains("ls-remote"), "{text}");
    assert_eq!(text.lines().count(), 2, "{text}");
}

// ----- this client's own repository, over the network -----

const REPO_HTTPS: &str = "https://github.com/byheads/commerceos-api-client";
const REPO_SSH: &str = "git@github.com:byheads/commerceos-api-client.git";
const REPO_TARBALL: &str = "https://github.com/byheads/commerceos-api-client/archive/refs/tags/3.2.2.tar.gz";
/// A release that holds `example1.api`, `example2.api` and `example3.api`.
const TAG: &str = "3.2.2";
const TAG_COMMIT: &str = "154faa4762c01badbd555ab2acfd3916e57a5d20";

/// Whether the tests that need GitHub were asked to stand down. A test that
/// is skipped says so on stderr: it has checked nothing.
fn offline(test: &str) -> bool {
    let offline = std::env::var_os("API_TEST_OFFLINE").is_some_and(|v| !v.is_empty());
    if offline {
        eprintln!("SKIPPED {test}: API_TEST_OFFLINE is set, so nothing was fetched from github.com and nothing was checked");
    }
    offline
}

/// Whether GitHub refuses this machine over ssh: no key, a key it does not
/// know, or a host key nobody has accepted. Asked the way the client asks
/// (`git ls-remote`, never stopping for a password), so the answer is the
/// one the import would get. Anything else that goes wrong (no network) is
/// not a reason to skip, and is left for the test to fail on.
fn ssh_to_github_is_refused(test: &str) -> bool {
    let out = Command::new("git")
        .args(["ls-remote", "--", REPO_SSH, TAG])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o ConnectTimeout=20")
        .stdin(Stdio::null())
        .output()
        .expect("git runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let refused = !out.status.success()
        && (stderr.contains("Permission denied") || stderr.contains("Host key verification failed"));
    if refused {
        eprintln!(
            "SKIPPED {test}: github.com refuses this machine over ssh, so nothing was checked.\n\
             It needs an ssh key that GitHub accepts and github.com among the known hosts.\n\
             git said: {}",
            stderr.trim()
        );
    }
    refused
}

/// `example3.api` of the release: a poll, then a write. The server answers
/// `0`, so the poll is over at its first check.
fn assert_example3_ran(sent: &[String], how: &str) {
    assert_eq!(sent.len(), 2, "{how}: {sent:?}");
    assert_eq!(sent[0], "GET /people/count/==213", "{how}");
    assert!(sent[1].starts_with("POST /people {") && sent[1].contains("\"name\": \"Mr 214\""), "{how}: {}", sent[1]);
}

/// Needs the network: the repository is fetched from github.com over https,
/// by tag, by commit and by branch.
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

/// Needs the network and an ssh key that GitHub accepts: the repository is
/// fetched from github.com over ssh. Without such a key it is skipped, and
/// says so.
#[test]
fn the_api_client_repository_imports_over_ssh() {
    if offline("the_api_client_repository_imports_over_ssh")
        || ssh_to_github_is_refused("the_api_client_repository_imports_over_ssh")
    {
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

/// Needs the network: a release tarball is downloaded from github.com.
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
///
/// Needs the network: the release is fetched from github.com, as a
/// repository and as a tarball.
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
///
/// Needs the network: both are fetched from github.com.
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

/// A file of an import was not written by whoever runs the batch, and what it
/// imports is fetched before the preview is shown. It names no token.
#[test]
fn an_imported_file_cannot_name_a_token_for_an_archive() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let nested = format!(
        "import archive packed {{ \"url\": \"{}\", \"token_env\": \"IMPORT_TEST_TOKEN\" }}\npacked/seed.api\n",
        server.url("/lib.tar.gz")
    );
    let import = own_import(&dir, &[("takes.api", &nested)]);
    for flags in ["-sa", "-spa"] {
        std::fs::write(dir.join("batch.api"), format!("{import}\nGET /first\nlib/takes.api\n")).unwrap();
        let mut cmd = api(&dir, server.port);
        cmd.args([flags, "batch.api"]).env("IMPORT_TEST_TOKEN", "s3cret-token");
        let ran = finish(cmd, "");
        assert!(!ran.ok, "{flags}");
        assert!(ran.stderr.contains("import packed: an imported file can't name a `token_env`"), "{flags}: {}", ran.stderr);
        // Nothing was sent, and the archive was not asked for either.
        assert_eq!(server.sent(), Vec::<String>::new(), "{flags}");
    }
    // The file that is run may, as before, and its token goes along.
    let archive = fixture_archive();
    let (named, served) = answer_once(move |_| {
        let mut reply =
            format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", archive.len()).into_bytes();
        reply.extend_from_slice(&archive);
        reply
    });
    let top = format!(
        "import archive packed {{ \"url\": \"http://127.0.0.1:{named}/lib.tar.gz\", \"token_env\": \"IMPORT_TEST_TOKEN\" }}\npacked/parts/a.api\n"
    );
    std::fs::write(dir.join("batch.api"), top).unwrap();
    let mut cmd = api(&dir, server.port);
    cmd.args(["-sa", "batch.api"]).env("IMPORT_TEST_TOKEN", "s3cret-token");
    let ran = finish(cmd, "");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(served.join().unwrap().as_deref(), Some("GET /lib.tar.gz HTTP/1.1 Bearer s3cret-token"));
    assert_eq!(server.sent(), ["GET /parts/a"]);
}

/// One request answered on a port of its own: what it asked for and the
/// `Authorization` it carried (`-` for none) come back when the thread ends.
fn answer_once(reply: impl FnOnce(u16) -> Vec<u8> + Send + 'static) -> (u16, JoinHandle<Option<String>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let thread = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(_) if start.elapsed() > Duration::from_secs(8) => return None,
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        while !data.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => data.extend_from_slice(&buf[..n]),
            }
        }
        let head = String::from_utf8_lossy(&data).to_string();
        let authorization = head
            .lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map_or("-".to_string(), |(_, v)| v.trim().to_string());
        let _ = stream.write_all(&reply(port));
        let _ = stream.flush();
        Some(format!("{} {}", head.lines().next().unwrap_or(""), authorization))
    });
    (port, thread)
}

/// The token of an `import archive` goes to the host the file names. When
/// that host sends the download elsewhere, the token does not go along, and
/// neither it nor the client's API key ever reaches the other side.
#[test]
fn an_archive_token_is_not_sent_on_to_where_a_redirect_leads() {
    let (_guard, dir) = temp();
    let api_server = Server::start("1", Vec::new());
    let archive = fixture_archive();
    let (elsewhere, served) = answer_once(move |_| {
        let mut reply =
            format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", archive.len()).into_bytes();
        reply.extend_from_slice(&archive);
        reply
    });
    let (named, redirected) = answer_once(move |_| {
        format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{elsewhere}/lib.tar.gz\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .into_bytes()
    });

    let batch = format!(
        "import archive lib {{ \"url\": \"http://127.0.0.1:{named}/first.tar.gz\", \"token_env\": \"IMPORT_TEST_TOKEN\" }}\nlib/parts/a.api\n"
    );
    std::fs::write(dir.join("batch.api"), batch).unwrap();
    let mut cmd = api(&dir, api_server.port);
    cmd.args(["-sa", "batch.api"]).env("IMPORT_TEST_TOKEN", "s3cret-token");
    let ran = finish(cmd, "");
    assert!(ran.ok, "{}", ran.stderr);

    assert_eq!(redirected.join().unwrap().as_deref(), Some("GET /first.tar.gz HTTP/1.1 Bearer s3cret-token"));
    assert_eq!(served.join().unwrap().as_deref(), Some("GET /lib.tar.gz HTTP/1.1 -"));
    // The API got its key, and nothing of the token.
    assert_eq!(api_server.sent(), ["GET /parts/a"]);
    assert!(!ran.stdout.contains("s3cret-token") && !ran.stderr.contains("s3cret-token"));
}

// ----- what a file of an import may reach -----

/// Environment that makes git read `https://origin.invalid/…` from the
/// repositories under `repos`, so a test has files that came from a host
/// without there being one.
fn origin_is(cmd: &mut Command, repos: &Path) {
    cmd.env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", format!("url.file://{}/.insteadOf", repos.display()))
        .env("GIT_CONFIG_VALUE_0", "https://origin.invalid/");
}

/// A file fetched from a host imports from that host and from nowhere else:
/// not another host, and not this machine, whose files and servers it would
/// otherwise reach with the rights of whoever runs the batch. Its imports are
/// fetched before the preview, so the refusal comes before any of them is.
#[test]
fn a_file_from_a_host_imports_from_no_other_host_and_not_from_this_machine() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let repos = dir.join("repos");
    let (local_repo, _) = fixture_repository(&repos.join("local/fixture"));
    let local_archive = format!("file://{}", dir.join("lib.tar.gz").display());
    std::fs::write(dir.join("lib.tar.gz"), fixture_archive()).unwrap();
    let on_this_machine = server.url("/lib.tar.gz");
    let archive = |url: &str| format!("import archive x {{ \"url\": \"{url}\" }}\n");
    let refused = [
        ("other-host.api", import_git("x", "https://other.invalid/team/repo", "main"), "https://other.invalid/team/repo"),
        ("other-archive.api", archive("https://other.invalid/lib.tar.gz"), "https://other.invalid/lib.tar.gz"),
        ("file-git.api", import_git("x", &local_repo, "1.0"), local_repo.as_str()),
        ("file-archive.api", archive(&local_archive), local_archive.as_str()),
        ("localhost.api", archive(&on_this_machine), on_this_machine.as_str()),
    ];
    let mut files: Vec<(String, String)> =
        refused.iter().map(|(file, import, _)| (file.to_string(), format!("{import}GET /never\nx/seed.api\n"))).collect();
    // The same host is fine, which is what shows the files have one.
    files.push(("same.api".to_string(), format!("{}x/dep.api\n", import_git("x", "https://origin.invalid/team/dep", "main"))));
    // But not with a user in front of it.
    let with_user = "https://someone@origin.invalid/team/dep";
    files.push(("user.api".to_string(), format!("{}x/dep.api\n", import_git("x", with_user, "main"))));
    commit(
        &repos.join("team/lib"),
        &files.iter().map(|(name, text)| (name.as_str(), text.as_bytes())).collect::<Vec<_>>(),
        None,
    );
    commit(&repos.join("team/dep"), &[("dep.api", b"GET /dep\n")], None);

    let log = dir.join("git.log");
    let path = format!("{}:{}", logging_git(&dir, &log).display(), std::env::var("PATH").unwrap());
    let run = |file: &str| {
        let batch = format!("{}GET /own\nlib/{file}\n", import_git("lib", "https://origin.invalid/team/lib", "main"));
        std::fs::write(dir.join("batch.api"), batch).unwrap();
        let mut cmd = api(&dir, server.port);
        cmd.env("PATH", &path).args(["-sa", "batch.api"]);
        origin_is(&mut cmd, &repos);
        finish(cmd, "")
    };

    let ran = run("same.api");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), ["GET /own", "GET /dep"]);

    for (file, _, url) in &refused {
        let ran = run(file);
        assert!(!ran.ok, "{file}");
        let says = format!("import x: a file imported from origin.invalid can import only from origin.invalid, not {url}");
        assert!(ran.stderr.contains(&says), "{file}: {}", ran.stderr);
        // Neither the API nor the archive on this machine was asked.
        assert_eq!(server.sent(), Vec::<String>::new(), "{file}");
    }
    let ran = run("user.api");
    assert!(!ran.ok);
    let says = format!("import x: an imported file can't name a user or a password in a url: {with_user}");
    assert!(ran.stderr.contains(&says), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());

    // And git was asked for the origin alone, every time.
    let asked = std::fs::read_to_string(&log).unwrap();
    assert!(asked.contains("ls-remote -- https://origin.invalid/team/lib main"), "{asked}");
    for line in asked.lines().filter(|line| line.contains("ls-remote") || line.contains(" fetch ")) {
        assert!(line.contains("https://origin.invalid/team/"), "{line}");
        assert!(!line.contains("someone@"), "{line}");
    }
}

/// In a directory import, whose files are used where they are, an include is
/// followed through a link only when the link stays inside.
#[test]
fn an_include_through_a_link_that_leads_out_of_a_directory_import_is_refused() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    std::fs::create_dir_all(dir.join("elsewhere")).unwrap();
    std::fs::write(dir.join("elsewhere/secret.api"), "GET /outside/secret\n").unwrap();
    let import = own_import(
        &dir,
        &[
            ("inside.api", "GET /lib/inside\n"),
            ("single.api", "GET /lib/single\nout.api\n"),
            ("globbed.api", "GET /lib/globbed\nlinks/*.api\n"),
            ("through.api", "GET /lib/through\nlinkdir/secret.api\n"),
            ("through-glob.api", "GET /lib/through-glob\nlinkdir/*.api\n"),
            ("links/a.api", "GET /lib/links/a\n"),
            ("stays.api", "in.api\n"),
        ],
    );
    let lib = dir.join("libdir");
    std::os::unix::fs::symlink(lib.join("inside.api"), lib.join("in.api")).unwrap();
    let run = |line: &str| run_batch(&dir, server.port, "-sa", &format!("{import}\nGET /first\n{line}\n"));

    // A link that stays inside is a file like any other, and so far the
    // glob matches only files of the import.
    let ran = run("lib/stays.api\nlib/globbed.api");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), ["GET /first", "GET /lib/inside", "GET /lib/globbed", "GET /lib/links/a"]);

    std::os::unix::fs::symlink(dir.join("elsewhere/secret.api"), lib.join("out.api")).unwrap();
    std::os::unix::fs::symlink(dir.join("elsewhere/secret.api"), lib.join("links/b.api")).unwrap();
    std::os::unix::fs::symlink(dir.join("elsewhere"), lib.join("linkdir")).unwrap();
    for (line, written) in [
        // From a file of the import: one file, one of a glob's, and a file
        // and a glob below a linked directory.
        ("lib/single.api", "out.api"),
        ("lib/globbed.api", "links/*.api"),
        ("lib/through.api", "linkdir/secret.api"),
        ("lib/through-glob.api", "linkdir/*.api"),
        // And from the batch, through the alias.
        ("lib/out.api", "lib/out.api"),
        ("lib/links/*.api", "lib/links/*.api"),
        ("lib/linkdir/*.api", "lib/linkdir/*.api"),
    ] {
        let ran = run(line);
        assert!(!ran.ok, "{line}");
        let refusal = format!("import lib: include leaves the import: {written}");
        assert!(ran.stderr.contains(&refusal), "{line}: {}", ran.stderr);
        assert_eq!(server.sent(), Vec::<String>::new(), "{line}");
    }
}

/// `path` says where the alias starts, not where the import ends: a file
/// under it includes a file above it, as it may send one.
#[test]
fn a_file_under_path_may_include_a_file_above_it() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let (repo, _) = fixture_repository(&dir.join("fixture-repo"));
    for (kind, import) in [
        ("git", format!("import git lib {{ \"url\": \"{repo}\", \"ref\": \"1.0\", \"path\": \"nested\" }}")),
        ("archive", format!("import archive lib {{ \"url\": \"{}\", \"path\": \"nested\" }}", server.url("/lib.tar.gz"))),
    ] {
        // `index.api` includes `../parts/a.api`, and `deep/leaf.api` sends
        // `../../data/body.json`.
        let ran = run_batch(&dir, server.port, "-sa", &format!("{import}\nlib/index.api\n"));
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

// ----- how git is run -----

/// A `git` that writes `GIT_TERMINAL_PROMPT`, `GIT_SSH_COMMAND`, `LC_ALL` and
/// its arguments to `log`, and then either fails the way `FAKE_GIT_SAYS`
/// says, if that is set and this is an `ls-remote`, or runs the real one.
fn telling_git(dir: &Path, log: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let real = Command::new("sh").args(["-c", "command -v git"]).output().expect("sh runs");
    let real = String::from_utf8_lossy(&real.stdout).trim().to_string();
    assert!(!real.is_empty(), "git is not on the PATH");
    let bin = dir.join("telling-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let shim = bin.join("git");
    let script = format!(
        "#!/bin/sh\n\
         echo \"prompt=$GIT_TERMINAL_PROMPT ssh=[$GIT_SSH_COMMAND] lc=$LC_ALL args=$*\" >> '{}'\n\
         case \"$FAKE_GIT_SAYS:$*\" in\n\
         :*) ;;\n\
         *ls-remote*) echo \"$FAKE_GIT_SAYS\" >&2; exit 128 ;;\n\
         esac\n\
         case \"$FAKE_GIT_FETCH_SAYS:$*\" in\n\
         :*) ;;\n\
         *' fetch '*) echo \"$FAKE_GIT_FETCH_SAYS\" >&2; exit 128 ;;\n\
         esac\n\
         exec '{real}' \"$@\"\n",
        log.display()
    );
    std::fs::write(&shim, script).unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

/// The client with `telling_git` first on its `PATH`.
fn api_with_telling_git(dir: &Path, port: u16, log: &Path) -> Command {
    let path = format!("{}:{}", telling_git(dir, log).display(), std::env::var("PATH").unwrap());
    let mut cmd = api(dir, port);
    cmd.env("PATH", path).env_remove("GIT_SSH_COMMAND").env_remove("GIT_SSH").env_remove("FAKE_GIT_SAYS");
    // What the machine's own git configuration says is not the test's.
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1");
    cmd
}

/// Nobody is there to answer when a batch runs: git may not ask for a
/// password, and neither may the ssh it starts. A regression here is a batch
/// that hangs.
#[test]
fn git_is_run_so_that_it_never_stops_to_ask() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let repo = dir.join("repos/asked");
    commit(&repo, &[("step.api", b"GET /step\n")], None);
    let log = dir.join("git.log");
    std::fs::write(dir.join("batch.api"), format!("{}lib/step.api\n", import_git("lib", &repo_url(&repo), "main"))).unwrap();

    let mut cmd = api_with_telling_git(&dir, server.port, &log);
    cmd.args(["-sa", "batch.api"]).env("LC_ALL", "sv_SE.UTF-8");
    let ran = finish(cmd, "");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), ["GET /step"]);
    let told = std::fs::read_to_string(&log).unwrap();
    // The lookup, and everything the fetch is made of.
    for command in ["ls-remote", " init ", " fetch ", "rev-parse", " checkout "] {
        assert!(told.lines().any(|line| line.contains(command)), "{command}: {told}");
    }
    // One question to git's own configuration, and no ssh command there.
    assert_eq!(told.lines().filter(|line| line.contains("config --get core.sshCommand")).count(), 1, "{told}");
    for line in told.lines().filter(|line| !line.contains("config --get")) {
        assert!(line.starts_with("prompt=0 ssh=[ssh -oBatchMode=yes "), "{line}");
        // It gives up on a remote that does not answer, over ssh and https.
        assert!(line.contains("-oConnectTimeout=30 -oServerAliveInterval=15"), "{line}");
        assert!(line.contains("-c http.lowSpeedLimit=1 -c http.lowSpeedTime=60"), "{line}");
        // And says why in the words the client knows, whatever the locale.
        assert!(line.contains("] lc=C args="), "{line}");
    }

    // An ssh command of the user's own is theirs to make quiet.
    std::fs::remove_file(&log).unwrap();
    std::fs::remove_dir_all(dir.join(".import-cache")).unwrap();
    let mut cmd = api_with_telling_git(&dir, server.port, &log);
    cmd.args(["-sa", "batch.api"]).env("GIT_SSH_COMMAND", "ssh -i my-key");
    let ran = finish(cmd, "");
    assert!(ran.ok, "{}", ran.stderr);
    let told = std::fs::read_to_string(&log).unwrap();
    assert!(told.lines().count() >= 5, "{told}");
    for line in told.lines() {
        assert!(line.starts_with("prompt=0 ssh=[ssh -i my-key] "), "{line}");
    }

    // So is one in git's configuration (`core.sshCommand`), which a
    // `GIT_SSH_COMMAND` of the client's would win over.
    std::fs::remove_file(&log).unwrap();
    std::fs::remove_dir_all(dir.join(".import-cache")).unwrap();
    std::fs::write(dir.join("with-ssh.gitconfig"), "[core]\n\tsshCommand = ssh -i configured-key\n").unwrap();
    let mut cmd = api_with_telling_git(&dir, server.port, &log);
    cmd.args(["-sa", "batch.api"]).env("GIT_CONFIG_GLOBAL", dir.join("with-ssh.gitconfig"));
    let ran = finish(cmd, "");
    assert!(ran.ok, "{}", ran.stderr);
    let told = std::fs::read_to_string(&log).unwrap();
    assert!(told.lines().count() >= 6, "{told}");
    for line in told.lines() {
        assert!(line.starts_with("prompt=0 ssh=[] "), "{line}");
    }
}

/// A remote that answers the lookup and then fails the fetch stops the batch
/// with what git said, nothing sent, and leaves nothing in the cache that a
/// later run could take for the checkout.
#[test]
fn a_fetch_that_fails_after_the_lookup_stops_the_batch_and_leaves_no_checkout() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let repo = dir.join("repos/breaks");
    commit(&repo, &[("step.api", b"GET /step\n")], None);
    let url = repo_url(&repo);
    let log = dir.join("git.log");
    std::fs::write(dir.join("batch.api"), format!("{}GET /own\nlib/step.api\n", import_git("lib", &url, "main"))).unwrap();
    let run = |says: Option<&str>| {
        let mut cmd = api_with_telling_git(&dir, server.port, &log);
        cmd.args(["-sa", "batch.api"]).env_remove("FAKE_GIT_FETCH_SAYS");
        if let Some(says) = says {
            cmd.env("FAKE_GIT_FETCH_SAYS", says);
        }
        finish(cmd, "")
    };
    fn files_named(dir: &Path, name: &str) -> usize {
        let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
        entries
            .flatten()
            .map(|entry| match entry.path() {
                path if path.is_dir() => files_named(&path, name),
                path => usize::from(path.file_name().is_some_and(|n| n == name)),
            })
            .sum()
    }

    let said = "fatal: the remote end hung up unexpectedly";
    let ran = run(Some(said));
    assert!(!ran.ok);
    assert!(ran.stderr.contains(&format!("could not fetch import {url} main: ")), "{}", ran.stderr);
    assert!(ran.stderr.contains(said), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());
    let told = std::fs::read_to_string(&log).unwrap();
    assert!(told.contains("ls-remote") && told.contains(" fetch "), "{told}");
    assert_eq!(files_named(&dir.join(".import-cache"), "step.api"), 0, "a checkout was left behind");

    // The next run fetches, and runs.
    let ran = run(None);
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), ["GET /own", "GET /step"]);
    assert_eq!(files_named(&dir.join(".import-cache"), "step.api"), 1);
}

/// The cached copy stands in for a remote that gave no answer, and for no
/// other failure: a remote that refuses the login, or says there is no such
/// repository, has answered, and the files of last time are not what it said.
#[test]
fn a_cached_copy_stands_in_only_for_a_git_remote_that_gave_no_answer() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let repo = dir.join("repos/moving");
    let first = commit(&repo, &[("step.api", b"GET /step\n")], Some("1.0"));
    let url = repo_url(&repo);
    let log = dir.join("git.log");
    let run = |git_ref: &str, says: Option<&str>| {
        std::fs::write(dir.join("batch.api"), format!("{}GET /own\nlib/step.api\n", import_git("lib", &url, git_ref))).unwrap();
        let mut cmd = api_with_telling_git(&dir, server.port, &log);
        cmd.args(["-sa", "batch.api"]);
        if let Some(says) = says {
            cmd.env("FAKE_GIT_SAYS", says);
        }
        finish(cmd, "")
    };

    // No copy and no answer: an error, with what git said.
    let silent = "fatal: unable to access 'https://example.invalid/r/': Could not resolve host: example.invalid";
    let ran = run("main", Some(silent));
    assert!(!ran.ok);
    assert!(ran.stderr.contains(&format!("could not reach import {url}: {silent}")), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());

    for git_ref in ["main", "1.0"] {
        let ran = run(git_ref, None);
        assert!(ran.ok, "{git_ref}: {}", ran.stderr);
        assert_eq!(server.sent(), ["GET /own", "GET /step"], "{git_ref}");
    }

    // No answer: the commit the branch, and the tag, last resolved to.
    for said in [
        silent,
        "ssh: connect to host example.invalid port 22: Operation timed out\nfatal: Could not read from remote repository.",
        "fatal: unable to access 'https://127.0.0.1:9/r/': Failed to connect to 127.0.0.1 port 9 after 0 ms: Couldn't connect to server",
    ] {
        for git_ref in ["main", "1.0"] {
            let ran = run(git_ref, Some(said));
            assert!(ran.ok, "{git_ref} {said}: {}", ran.stderr);
            let logged = format!("import lib {url} {git_ref} ({}, cached copy: remote unreachable)", &first[..7]);
            assert!(ran.stdout.contains(&logged), "{git_ref} {said}: {}", ran.stdout);
            assert_eq!(server.sent(), ["GET /own", "GET /step"], "{git_ref} {said}");
        }
    }

    // An answer that is a refusal stops the batch, cached copy or not.
    for said in [
        "fatal: Authentication failed for 'https://example.invalid/r/'",
        "fatal: could not read Username for 'https://example.invalid': terminal prompts disabled",
        "remote: Repository not found.\nfatal: repository 'https://example.invalid/r/' not found",
        "git@example.invalid: Permission denied (publickey).\nfatal: Could not read from remote repository.",
    ] {
        for git_ref in ["main", "1.0"] {
            let ran = run(git_ref, Some(said));
            assert!(!ran.ok, "{git_ref} {said}");
            let reason = said.replace('\n', "; ");
            assert!(ran.stderr.contains(&format!("could not reach import {url}: {reason}")), "{git_ref} {said}: {}", ran.stderr);
            assert!(!ran.stdout.contains("cached copy") && !ran.stderr.contains("cached copy"), "{git_ref} {said}");
            assert_eq!(server.sent(), Vec::<String>::new(), "{git_ref} {said}");
        }
    }
}

/// A server on a port of its own that answers one request with each of
/// `replies` in turn and is gone after the last.
fn answers_in_turn(replies: Vec<Vec<u8>>) -> (u16, JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let thread = std::thread::spawn(move || {
        for reply in replies {
            let Ok((mut stream, _)) = listener.accept() else { return };
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut data = Vec::new();
            let mut buf = [0u8; 4096];
            while !data.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => data.extend_from_slice(&buf[..n]),
                }
            }
            let _ = stream.write_all(&reply);
            let _ = stream.flush();
        }
    });
    (port, thread)
}

/// The same for an archive: a status is an answer. Only a url that nothing
/// answers at all is stood in for by what it served last.
#[test]
fn a_cached_copy_stands_in_only_for_an_archive_url_that_gave_no_answer() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let archive = fixture_archive();
    let mut served = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", archive.len()).into_bytes();
    served.extend_from_slice(&archive);
    let statuses = ["404 Not Found", "401 Unauthorized", "403 Forbidden", "500 Internal Server Error"];
    let mut replies = vec![served];
    for status in statuses {
        replies.push(format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").into_bytes());
    }
    let (port, answering) = answers_in_turn(replies);
    let url = format!("http://127.0.0.1:{port}/lib.tar.gz");
    let batch = format!("import archive lib {{ \"url\": \"{url}\" }}\nGET /own\nlib/parts/a.api\n");

    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), ["GET /own", "GET /parts/a"]);

    // It is in the cache now, and the url says no: that is what stands.
    for status in statuses {
        let ran = run_batch(&dir, server.port, "-sa", &batch);
        assert!(!ran.ok, "{status}");
        assert!(ran.stderr.contains(&format!("could not reach import {url}: {status}")), "{status}: {}", ran.stderr);
        assert!(!ran.stdout.contains("cached copy") && !ran.stderr.contains("cached copy"), "{status}");
        assert_eq!(server.sent(), Vec::<String>::new(), "{status}");
    }

    // Nothing listens there any more: no answer, and the copy is used.
    answering.join().unwrap();
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert!(ran.stdout.contains(&format!("import lib {url} (sha256 ")), "{}", ran.stdout);
    assert!(ran.stdout.contains(", cached copy: remote unreachable)"), "{}", ran.stdout);
    assert_eq!(server.sent(), ["GET /own", "GET /parts/a"]);
}

// ----- the order things are checked in -----

/// Imports are fetched while the file is read, ahead of the `url` gate: a
/// batch with both wrong is told about the import.
#[test]
fn a_bad_import_is_reported_ahead_of_a_failing_url_gate() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let gate = "url has production.example.com\n";
    for (import, says) in [
        ("import dir lib { \"path\": \"no-such-directory\" }".to_string(), "import lib: not a directory: no-such-directory".to_string()),
        (
            format!("import archive lib {{ \"url\": \"{}\" }}", server.url("/missing.tar.gz")),
            format!("could not reach import {}: 404 Not Found", server.url("/missing.tar.gz")),
        ),
        (
            format!("import git lib {{ \"url\": \"file://{}/no-such-repo\", \"ref\": \"main\" }}", dir.display()),
            format!("could not reach import file://{}/no-such-repo: ", dir.display()),
        ),
    ] {
        // Above the gate and below it.
        for batch in [format!("{import}\n{gate}GET /never\n"), format!("{gate}{import}\nGET /never\n")] {
            let ran = run_batch(&dir, server.port, "-sa", &batch);
            assert!(!ran.ok, "{batch}");
            assert!(ran.stderr.contains(&says), "{batch}: {}", ran.stderr);
            assert!(!ran.stderr.contains("URL gate failed"), "{batch}: {}", ran.stderr);
            assert!(server.api_requests().iter().all(|r| r == "GET /missing.tar.gz"), "{batch}");
        }
    }
    // With the import right, the gate is what stops it.
    let batch = format!("import dir lib {{ \"path\": \"{}\" }}\n{gate}GET /never\n", fixture().display());
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(!ran.ok);
    assert!(ran.stderr.contains("URL gate failed"), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());
}

// ----- a pinned archive and its token -----

/// Once a pinned archive is in the cache a run needs no network, and so no
/// token either: the variable may be unset.
#[test]
fn a_pinned_archive_in_the_cache_runs_with_its_token_variable_unset() {
    use sha2::Digest;
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let sha: String = sha2::Sha256::digest(fixture_archive()).iter().map(|b| format!("{b:02x}")).collect();
    let pinned = |sha: &str| {
        format!(
            "import archive lib {{ \"url\": \"{}\", \"sha256\": \"{sha}\", \"token_env\": \"IMPORT_TEST_TOKEN\" }}\nlib/parts/a.api\n",
            server.url("/lib.tar.gz")
        )
    };
    let run = |batch: &str, token: Option<&str>| {
        std::fs::write(dir.join("batch.api"), batch).unwrap();
        let mut cmd = api(&dir, server.port);
        cmd.args(["-sa", "batch.api"]).env_remove("IMPORT_TEST_TOKEN");
        if let Some(token) = token {
            cmd.env("IMPORT_TEST_TOKEN", token);
        }
        finish(cmd, "")
    };

    // Not in the cache yet: it has to be downloaded, and that takes the token.
    let ran = run(&pinned(&sha), None);
    assert!(!ran.ok);
    assert!(ran.stderr.contains("environment variable IMPORT_TEST_TOKEN is not set"), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());

    let ran = run(&pinned(&sha), Some("s3cret-token"));
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), ["GET /lib.tar.gz", "GET /parts/a"]);

    // Cached: no download, no token, set to nothing or not set at all.
    for token in [None, Some("")] {
        let ran = run(&pinned(&sha), token);
        assert!(ran.ok, "{token:?}: {}", ran.stderr);
        assert_eq!(server.sent(), ["GET /parts/a"], "{token:?}");
    }
    // Another hash is another archive, and not in the cache.
    let ran = run(&pinned(&"0".repeat(64)), None);
    assert!(!ran.ok);
    assert!(ran.stderr.contains("environment variable IMPORT_TEST_TOKEN is not set"), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());
}

// ----- --assert -----

/// `--assert` answers what a run would assert, so it follows imports, and
/// fetches one that is not in the cache: by default the one under the home
/// directory.
#[test]
fn listing_assertions_fetches_an_import_into_the_default_cache_under_home() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    for (kind, import) in each_kind(&dir, &server) {
        std::fs::write(dir.join("batch.api"), format!("{import}\nGET /own\nlib/described.api\n")).unwrap();
        let mut cmd = api(&dir, server.port);
        cmd.args(["-r", "--assert", "batch.api"]).env_remove("API_IMPORT_CACHE").env("HOME", &home);
        let ran = finish(cmd, "");
        assert!(ran.ok, "{kind}: {}", ran.stderr);
        assert_eq!(ran.stdout.trim(), r#"[{"api/v1/described~count":{"is":1}}]"#, "{kind}");
        // Nothing was sent to the API; only the archive was asked for.
        assert_eq!(server.api_requests(), Vec::<String>::new(), "{kind}");
    }
    // A repository and an archive are in the cache now, and it is the one
    // under the home directory: nothing was made beside the batch.
    let cache = home.join(".cache/api/imports");
    let cached: Vec<String> = std::fs::read_dir(&cache)
        .expect("the default cache was made")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(cached.len(), 2, "{cached:?}");
    assert!(cached.contains(&"archives".to_string()), "{cached:?}");
    assert!(!dir.join(".import-cache").exists());
}

// ----- what the cache clears out -----

/// The cache directory may be one that holds other things. Pruning removes
/// what the client marked as its own, and nothing that only looks like it.
#[test]
fn a_fetch_clears_out_nothing_that_the_client_did_not_put_in_the_cache() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let cache = dir.join(".import-cache");
    let hash = |c: char, n: usize| c.to_string().repeat(n);
    let foreign = [
        cache.join("my-project").join(hash('a', 40)),
        cache.join("my-project").join(".tmp-build"),
        cache.join("archives").join(hash('b', 64)),
        cache.join("archives").join(".tmp-1-2-3"),
    ];
    for path in &foreign {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join("precious"), "x").unwrap();
        age(path, 400);
    }
    // A fetch of each kind, each of which prunes the whole cache.
    let repo = dir.join("repos/other");
    commit(&repo, &[("step.api", b"GET /step\n")], None);
    let batch = format!(
        "{}import archive packed {{ \"url\": \"{}\" }}\nlib/step.api\npacked/parts/a.api\n",
        import_git("lib", &repo_url(&repo), "main"),
        server.url("/lib.tar.gz")
    );
    let ran = run_batch(&dir, server.port, "-sa", &batch);
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.api_requests(), ["GET /step", "GET /parts/a"]);
    for path in &foreign {
        assert!(path.join("precious").is_file(), "{} was removed", path.display());
    }
    // What the fetches left of their own work is the checkout and its
    // marker: no scratch directory, and no marker of one.
    for group in std::fs::read_dir(&cache).unwrap().flatten() {
        for entry in std::fs::read_dir(group.path()).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let known = foreign.iter().any(|f| *f == entry.path());
            assert!(known || !name.starts_with(".tmp-"), "left behind: {}", entry.path().display());
        }
    }
}

/// `import … @x.json` reads its JSON as a request reads an `@file` body:
/// from the working directory, not from beside the `.api` file. A file of
/// that name beside the `.api` file is not the one.
#[test]
fn the_import_json_is_relative_to_the_working_directory_not_to_the_file() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    std::fs::create_dir_all(dir.join("batches")).unwrap();
    std::fs::write(dir.join("batches/batch.api"), format!("import dir lib @where.json\n{RUN_THE_FIXTURE}")).unwrap();
    let run = || {
        let mut cmd = api(&dir, server.port);
        cmd.args(["-sa", "batches/batch.api"]);
        finish(cmd, "")
    };

    // Only beside the `.api` file: not found, and nothing is sent.
    std::fs::write(dir.join("batches/where.json"), format!("{{\"path\": \"{}\"}}", fixture().display())).unwrap();
    let ran = run();
    assert!(!ran.ok, "{}", ran.stdout);
    assert!(ran.stderr.contains("where.json"), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());

    // In the working directory: read, and the one beside the file is not.
    std::fs::write(dir.join("batches/where.json"), "{\"path\": \"no-such-directory\"}").unwrap();
    std::fs::write(dir.join("where.json"), format!("{{\"path\": \"{}\"}}", fixture().display())).unwrap();
    let ran = run();
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), fixture_requests());
}

/// `~/` is the home directory in the path of an `import dir` and in the
/// `@file` an import's JSON is read from.
#[test]
fn a_tilde_path_of_an_import_is_in_the_home_directory() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let home = dir.join("home");
    let work = dir.join("work");
    std::fs::create_dir_all(home.join("libs/own")).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(home.join("libs/own/x.api"), "GET /from-home\n").unwrap();
    std::fs::write(home.join("where.json"), "{\"path\": \"~/libs/own\"}").unwrap();
    for import in ["import dir own {\"path\": \"~/libs/own\"}", "import dir own @~/where.json"] {
        std::fs::write(work.join("batch.api"), format!("{import}\nown/x.api\n")).unwrap();
        let mut cmd = api(&work, server.port);
        cmd.env("HOME", &home).args(["-sa", "batch.api"]);
        let ran = finish(cmd, "");
        assert!(ran.ok, "{import}: {}", ran.stderr);
        assert_eq!(server.sent(), ["GET /from-home"], "{import}");
        assert!(ran.stdout.contains(&format!("import own {}", home.join("libs/own").display())), "{import}: {}", ran.stdout);
    }
}

/// A directory inside a repository that came from a host is of that host
/// too: a file reached through `import dir` there imports from nowhere else
/// and names no token, as the file that imported the directory could not.
#[test]
fn a_directory_inside_an_import_from_a_host_is_of_that_host() {
    let (_guard, dir) = temp();
    let server = Server::start("1", fixture_archive());
    let repos = dir.join("repos");
    let other = import_git("x", "https://other.invalid/team/repo", "main");
    let token = "import archive x { \"url\": \"https://origin.invalid/lib.tar.gz\", \"token_env\": \"IMPORT_TEST_TOKEN\" }\n";
    commit(
        &repos.join("team/lib"),
        &[
            ("via-dir.api", b"import dir inner { \"path\": \"sub\" }\nGET /in-lib\ninner/ok.api\n" as &[u8]),
            ("other.api", b"import dir inner { \"path\": \"sub\" }\ninner/other.api\n"),
            ("token.api", b"import dir inner { \"path\": \"sub\" }\ninner/token.api\n"),
            ("sub/ok.api", b"GET /in-sub\n"),
            ("sub/other.api", format!("{other}GET /never\n").as_bytes()),
            ("sub/token.api", format!("{token}GET /never\n").as_bytes()),
        ],
        None,
    );
    let run = |file: &str| {
        let batch = format!("{}GET /own\nlib/{file}\n", import_git("lib", "https://origin.invalid/team/lib", "main"));
        std::fs::write(dir.join("batch.api"), batch).unwrap();
        let mut cmd = api(&dir, server.port);
        cmd.args(["-sa", "batch.api"]).env("IMPORT_TEST_TOKEN", "s3cret-token");
        origin_is(&mut cmd, &repos);
        finish(cmd, "")
    };

    let ran = run("via-dir.api");
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(server.sent(), ["GET /own", "GET /in-lib", "GET /in-sub"]);

    let ran = run("other.api");
    assert!(!ran.ok);
    let says = "a file imported from origin.invalid can import only from origin.invalid, not https://other.invalid/team/repo";
    assert!(ran.stderr.contains(says), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());

    let ran = run("token.api");
    assert!(!ran.ok);
    assert!(ran.stderr.contains("an imported file can't name a `token_env`"), "{}", ran.stderr);
    assert_eq!(server.sent(), Vec::<String>::new());
}

/// A pattern can match `..` (`.?`, `.*`): what it finds above the import is
/// outside it like anything else, for a body and for an include, in a
/// directory, a repository and an archive.
#[test]
fn a_pattern_that_matches_the_directory_above_does_not_leave_the_import() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    std::fs::write(dir.join("secret.json"), r#"{"secret":"outside"}"#).unwrap();
    std::fs::write(dir.join("outside.api"), "GET /outside\n").unwrap();
    let files = [
        ("deep/body.api", "PUT /x @.?/.?/secret.json\n"),
        ("deep/star.api", "PUT /x @.*/.*/secret.json\n"),
        // A `..` behind a `**`, which stands for no directory too.
        ("deep/climb.api", "PUT /x @sub/**/../../../secret.json\n"),
        ("deep/include.api", ".?/.?/outside.api\n"),
        // From the root of the disk down, were it walked.
        ("deep/walk.api", ".*/.*/.*/.*/.*/.*/.*/.*/.*/.*/.*/.*/**/*.api\n"),
        ("deep/ok.api", "GET /ok\n"),
    ];
    let import = own_import(&dir, &files);
    // The same files as a repository, checked out in a cache beside the
    // files that are not its own.
    let repo = dir.join("repo");
    commit(&repo, &files.iter().map(|(name, text)| (*name, text.as_bytes())).collect::<Vec<_>>(), Some("1.0"));
    let imports = [("dir", import), ("git", import_git("lib", &repo_url(&repo), "1.0"))];
    for (kind, import) in &imports {
        let run = |file: &str| run_batch(&dir, server.port, "-sa", &format!("{import}\nGET /first\nlib/deep/{file}.api\n"));
        let ran = run("ok");
        assert!(ran.ok, "{kind}: {}", ran.stderr);
        assert_eq!(server.sent(), ["GET /first", "GET /ok"], "{kind}");
        // A checkout is two directories down in the cache: the same files
        // stand two above `deep/` there as they do beside the directory.
        if *kind == "git" {
            let checkouts: Vec<PathBuf> =
                std::fs::read_dir(dir.join(".import-cache")).unwrap().map(|entry| entry.unwrap().path()).filter(|path| path.is_dir()).collect();
            assert!(!checkouts.is_empty());
            for above in checkouts {
                std::fs::write(above.join("secret.json"), r#"{"secret":"outside"}"#).unwrap();
                std::fs::write(above.join("outside.api"), "GET /outside\n").unwrap();
            }
        }
        for (file, says) in [
            ("body", "`@.?/.?/secret.json` must be a relative path inside the import"),
            ("star", "`@.*/.*/secret.json` must be a relative path inside the import"),
            ("climb", "`@sub/**/../../../secret.json` must be a relative path inside the import"),
            ("include", "include leaves the import: .?/.?/outside.api"),
            ("walk", "include leaves the import: .*/.*/.*/.*/.*/.*/.*/.*/.*/.*/.*/.*/**/*.api"),
        ] {
            let asked = std::time::Instant::now();
            let ran = run(file);
            assert!(!ran.ok, "{kind} {file}");
            assert!(ran.stderr.contains(says), "{kind} {file}: {}", ran.stderr);
            assert_eq!(server.sent(), Vec::<String>::new(), "{kind} {file}");
            // Refused by what the line says: nothing above the import is
            // walked to find out what the pattern matches.
            assert!(asked.elapsed() < std::time::Duration::from_secs(10), "{kind} {file}: {:?}", asked.elapsed());
        }
    }
}

// ----- --imports and the cache -----

/// A checkout that `--imports` lists counts as used: a tool that reads the
/// files of an import where the listing says they are does not have them
/// cleared out by the next fetch. Without the listing the same checkout,
/// unused for longer than a month, is pruned.
#[test]
fn imports_marks_a_listed_checkout_used_so_the_next_fetch_does_not_clear_it_out() {
    for listed_first in [true, false] {
        let (_guard, dir) = temp();
        let server = Server::start("1", Vec::new());
        let repo = dir.join("repos/moving");
        let first = commit(&repo, &[("step.api", b"GET /first\n")], Some("1.0"));
        let on_main = format!("{}lib/step.api\n", import_git("lib", &repo_url(&repo), "main"));

        let ran = run_batch(&dir, server.port, "-sa", &on_main);
        assert!(ran.ok, "{}", ran.stderr);
        let repo_cache = std::fs::read_dir(dir.join(".import-cache")).unwrap().flatten().next().unwrap().path();
        let (checkout, used) = (repo_cache.join(&first), repo_cache.join(format!("{first}.used")));
        assert!(checkout.is_dir() && used.is_file());

        age(&used, 45);
        if listed_first {
            let ran = list_imports(&dir, server.port, &[], &import_git("lib", &repo_url(&repo), "1.0"));
            let entries = listed(&ran);
            assert_eq!(member(&entries[0], "directory"), checkout.display().to_string(), "{}", ran.stdout);
            let idle = std::fs::metadata(&used).unwrap().modified().unwrap().elapsed().unwrap();
            assert!(idle < Duration::from_secs(3600), "listing a checkout should mark it used: {idle:?}");
        }

        // The branch moves on: the run that fetches the new commit prunes.
        let second = commit(&repo, &[("step.api", b"GET /second\n")], None);
        let ran = run_batch(&dir, server.port, "-sa", &on_main);
        assert!(ran.ok, "{}", ran.stderr);
        assert_eq!(server.sent(), vec!["GET /first", "GET /second"]);
        assert!(repo_cache.join(&second).is_dir());
        match listed_first {
            true => assert!(checkout.is_dir() && used.is_file(), "the listed checkout should have been kept"),
            false => assert!(!checkout.exists() && !used.exists(), "the unused checkout should have been pruned"),
        }
    }
}

/// A pinned archive that is in the cache is listed without the network and
/// without its token: nothing listens at the url any more and the variable
/// is not set. The hash is the pin, and the copy is not a stale one.
#[test]
fn imports_lists_a_pinned_archive_in_the_cache_without_the_network_or_its_token() {
    use sha2::Digest;
    let (_guard, dir) = temp();
    let archive = fixture_archive();
    let sha: String = sha2::Sha256::digest(&archive).iter().map(|b| format!("{b:02x}")).collect();
    let mut served = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", archive.len()).into_bytes();
    served.extend_from_slice(&archive);
    let (port, answering) = answers_in_turn(vec![served]);
    let url = format!("http://127.0.0.1:{port}/lib.tar.gz");
    let batch =
        format!("import archive lib {{ \"url\": \"{url}\", \"sha256\": \"{sha}\", \"token_env\": \"IMPORT_TEST_TOKEN\" }}\n");
    std::fs::write(dir.join("batch.api"), batch).unwrap();
    let list = |token: Option<&str>| {
        let mut cmd = api(&dir, port);
        cmd.args(["--imports", "batch.api"]).env_remove("IMPORT_TEST_TOKEN");
        if let Some(token) = token {
            cmd.env("IMPORT_TEST_TOKEN", token);
        }
        finish(cmd, "")
    };

    let ran = list(Some("s3cret-token"));
    let fresh = listed(&ran);
    assert_eq!(member(&fresh[0], "sha256"), sha, "{}", ran.stdout);

    // Nothing listens there any more, and there is no token to send.
    answering.join().unwrap();
    let ran = list(None);
    let cached = listed(&ran);
    assert_eq!(cached.len(), 1, "{}", ran.stdout);
    assert_eq!(member_names(&cached[0]), ["file", "alias", "kind", "directory", "url", "sha256"], "{}", ran.stdout);
    assert_eq!(member(&cached[0], "sha256"), sha, "{}", ran.stdout);
    assert_eq!(member(&cached[0], "url"), url);
    assert_eq!(member(&cached[0], "directory"), member(&fresh[0], "directory"));
    assert!(Path::new(member(&cached[0], "directory")).join("seed.api").is_file(), "{}", ran.stdout);
    assert_eq!(ran.stderr, "");
}

/// An archive url without a pin is asked on every run. When nothing answers
/// there, the copy it served last is listed, and marked as one.
#[test]
fn imports_marks_a_cached_archive_that_stood_in_for_its_url() {
    let (_guard, dir) = temp();
    let archive = fixture_archive();
    let mut served = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", archive.len()).into_bytes();
    served.extend_from_slice(&archive);
    let (port, answering) = answers_in_turn(vec![served]);
    let batch = format!("import archive lib {{ \"url\": \"http://127.0.0.1:{port}/lib.tar.gz\" }}\n");

    let fresh = listed(&list_imports(&dir, port, &[], &batch));
    assert!(fresh[0].get("stale").is_none(), "{}", fresh[0]);
    // Nothing listens there any more: no answer, and the copy is used.
    answering.join().unwrap();
    let cached = listed(&list_imports(&dir, port, &[], &batch));
    assert_eq!(cached[0]["stale"], serde_json::Value::Bool(true), "{}", cached[0]);
    assert_eq!(member(&cached[0], "sha256"), member(&fresh[0], "sha256"));
    assert_eq!(member(&cached[0], "directory"), member(&fresh[0], "directory"));
}

/// A relative `path` of an `import dir` is relative to the file that
/// declares it, not to the working directory. The listing prints it as it
/// is written, beside the absolute directory it names and the absolute path
/// of the declaring file.
#[test]
fn imports_prints_a_relative_directory_path_as_written_beside_where_it_leads() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    std::fs::create_dir_all(dir.join("lib")).unwrap();
    std::fs::create_dir_all(dir.join("work")).unwrap();
    std::fs::write(dir.join("lib/step.api"), "GET /step\n").unwrap();
    std::fs::write(dir.join("work/batch.api"), "import dir lib { \"path\": \"../lib\" }\nlib/step.api\n").unwrap();

    let mut cmd = api(&dir, server.port);
    cmd.args(["--imports", "work/batch.api"]);
    let ran = finish(cmd, "");
    let entries = listed(&ran);
    assert_eq!(entries.len(), 1, "{}", ran.stdout);
    assert_eq!(member_names(&entries[0]), ["file", "alias", "kind", "directory", "path"], "{}", ran.stdout);
    assert_eq!(member(&entries[0], "path"), "../lib", "{}", ran.stdout);
    assert_eq!(member(&entries[0], "directory"), dir.join("lib").display().to_string(), "{}", ran.stdout);
    assert_eq!(member(&entries[0], "file"), dir.join("work/batch.api").display().to_string(), "{}", ran.stdout);
    assert_eq!(server.sent(), Vec::<String>::new());
}

/// `--imports` sends nothing and so needs no connection: with no base URL,
/// no key and no credentials file it lists the imports and exits 0.
#[test]
fn imports_needs_no_connection() {
    let (_guard, dir) = temp();
    let (repo, sha) = fixture_repository(&dir.join("fixture-repo"));
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let batch = format!("import dir here {{ \"path\": \"{}\" }}\n{}", fixture().display(), import_git("lib", &repo, "1.0"));
    std::fs::write(dir.join("batch.api"), batch).unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("api"));
    cmd.args(["--no-keychain", "--imports", "batch.api"])
        .current_dir(&dir)
        .env("NO_COLOR", "1")
        .env("HOME", &home)
        .env("API_IMPORT_CACHE", dir.join(".import-cache"))
        .env_remove("API_CREDENTIALS_FILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let ran = finish(cmd, "");
    assert!(ran.ok, "{}{}", ran.stdout, ran.stderr);
    let entries = listed(&ran);
    let seen: Vec<(&str, &str)> = entries.iter().map(|e| (member(e, "alias"), member(e, "kind"))).collect();
    assert_eq!(seen, [("here", "dir"), ("lib", "git")], "{}", ran.stdout);
    assert_eq!(member(&entries[1], "commit"), sha, "{}", ran.stdout);
    assert!(Path::new(member(&entries[1], "directory")).join("seed.api").is_file(), "{}", ran.stdout);
    assert_eq!(ran.stderr, "");
    assert!(!dir.join(".api-credentials.json").exists());
}

/// `--describe` and `--imports` each print a document of their own: both on
/// one command line is an error, and neither is printed.
#[test]
fn describe_and_imports_on_one_command_line_are_refused() {
    let (_guard, dir) = temp();
    let server = Server::start("1", Vec::new());
    let batch = format!("{{ \"title\": {{ \"en-US\": \"Seed\" }} }}\nimport dir lib {{ \"path\": \"{}\" }}\n", fixture().display());
    std::fs::write(dir.join("batch.api"), batch).unwrap();
    for args in [["--describe", "batch.api", "--imports", "batch.api"], ["--imports", "batch.api", "--describe", "batch.api"]] {
        let mut cmd = api(&dir, server.port);
        cmd.args(args);
        let ran = finish(cmd, "");
        assert!(!ran.ok, "{args:?}: {}", ran.stdout);
        assert_eq!(ran.stdout, "", "{args:?}");
        assert_eq!(ran.stderr, "error: --describe and --imports each print a document of their own: use one\n", "{args:?}");
    }
    assert_eq!(server.sent(), Vec::<String>::new());
}
