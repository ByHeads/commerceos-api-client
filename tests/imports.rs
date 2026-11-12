//! End-to-end tests for `import git`, `import dir` and `import archive`.
//!
//! Most of them run the tree in `tests/fixtures/import` against a recording
//! server on this machine and need nothing else. The last group fetches this
//! client's own repository from GitHub, over https and over ssh, and so needs
//! the network (and, for ssh, a key GitHub accepts). Set `API_TEST_OFFLINE=1`
//! to skip that group.
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
/// - Anything else is the API, and answers `answer` as JSON.
struct Server {
    port: u16,
    log: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    fn start(answer: &'static str, archive: Vec<u8>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_log, thread_stop) = (log.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => respond(stream, port, answer, &archive, &thread_log),
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Server { port, log, stop, thread: Some(thread) }
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

fn respond(mut stream: std::net::TcpStream, port: u16, answer: &str, archive: &[u8], log: &Mutex<Vec<String>>) {
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
    for (name, contents) in fixture_files() {
        let path = repo.join(&name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    git(repo, &["init", "-q", "-b", "main"]);
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-q", "-m", "fixture"]);
    git(repo, &["tag", "1.0"]);
    (format!("file://{}", repo.display()), git(repo, &["rev-parse", "HEAD"]))
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
