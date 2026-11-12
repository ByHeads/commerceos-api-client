//! One grammar, three doors. A line can be handed to the client in a `.api`
//! file, as one-shot arguments (split by the shell or quoted whole), or typed
//! at the interactive prompt, and it must mean the same request each way.
//!
//! Every case in `cases` is run through all of them against a recording
//! server, and what reached the server is compared — first between the
//! entry points, then against what the case says it should be.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Records every request as `METHOD /path` or `METHOD /path body`, the
/// `/api/v1` prefix dropped. The client's own housekeeping calls (`/about`,
/// the OpenAPI spec, mapped types) are answered but not recorded.
struct RecordingServer {
    port: u16,
    log: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl RecordingServer {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log2, stop2) = (Arc::clone(&log), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let log = Arc::clone(&log2);
                        std::thread::spawn(move || answer(stream, &log));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        });
        RecordingServer { port, log, stop, handle: Some(handle) }
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }

    fn seen(&self) -> usize {
        self.log.lock().unwrap().len()
    }

    /// Wait until no request has arrived for `quiet`, or `cap` has passed.
    fn settle(&self, quiet: Duration, cap: Duration) {
        let start = Instant::now();
        let mut last = (self.seen(), Instant::now());
        loop {
            std::thread::sleep(Duration::from_millis(25));
            let n = self.seen();
            if n != last.0 {
                last = (n, Instant::now());
            }
            if last.1.elapsed() >= quiet || start.elapsed() >= cap {
                return;
            }
        }
    }
}

impl Drop for RecordingServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn answer(mut stream: std::net::TcpStream, log: &Mutex<Vec<String>>) {
    // An accepted socket inherits the listener's non-blocking mode on macOS.
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    while !data.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    }
    let split = data.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&data[..split]).to_string();
    let mut body = data[split + 4..].to_vec();
    let mut lines = head.lines();
    let mut request = lines.next().unwrap_or("").split_whitespace();
    let method = request.next().unwrap_or("").to_string();
    let path = request.next().unwrap_or("").to_string();
    let length: usize = lines
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
    let body = String::from_utf8_lossy(&body).to_string();

    let housekeeping = ["/about", "/openapi", "/api-docs", "/mapped-types"];
    if !housekeeping.iter().any(|h| path.contains(h)) {
        let shown = path.strip_prefix("/api/v1").unwrap_or(&path);
        let entry = if body.is_empty() {
            format!("{method} {shown}")
        } else {
            format!("{method} {shown} {body}")
        };
        log.lock().unwrap().push(entry);
    }

    let (status, payload) = if path.contains("/missing") {
        ("404 Not Found", "{}".to_string())
    } else if path.contains("/zero") {
        ("200 OK", "0".to_string())
    } else if path.contains("/boom") {
        ("500 Internal Server Error", "{}".to_string())
    } else if path.contains("/about") {
        ("200 OK", r#"{"feature-flags":[]}"#.to_string())
    } else {
        ("200 OK", format!(r#"{{"ok":"{path}"}}"#))
    };
    let payload = if method == "HEAD" { String::new() } else { payload };
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        )
        .as_bytes(),
    );
    let _ = stream.flush();
}

/// One line and what it must do. `argv` is the line as a user would split it
/// on the command line; `None` when there is no natural split (several lines).
struct Case {
    label: &'static str,
    line: String,
    argv: Option<Vec<String>>,
    /// What the server must have seen, in order.
    sent: Vec<&'static str>,
    /// What the prompt sends, when that legitimately differs from `sent`.
    prompt_sent: Option<Vec<&'static str>>,
    exit_ok: bool,
    /// A phrase that must be shown to the user (stderr, or the screen).
    says: Option<&'static str>,
    /// A file the line must have written.
    writes: Option<PathBuf>,
}

fn case(label: &'static str, line: &str, argv: Option<&[&str]>, sent: &[&'static str]) -> Case {
    Case {
        label,
        line: line.to_string(),
        argv: argv.map(|a| a.iter().map(|s| s.to_string()).collect()),
        sent: sent.to_vec(),
        prompt_sent: None,
        exit_ok: true,
        says: None,
        writes: None,
    }
}

impl Case {
    fn fails(mut self, says: &'static str) -> Self {
        self.exit_ok = false;
        self.says = Some(says);
        self
    }
    fn says(mut self, says: &'static str) -> Self {
        self.says = Some(says);
        self
    }
    fn writes(mut self, path: PathBuf) -> Self {
        self.writes = Some(path);
        self
    }
    fn at_the_prompt(mut self, sent: &[&'static str]) -> Self {
        self.prompt_sent = Some(sent.to_vec());
        self
    }
}

/// The fixtures every entry point runs against, in `dir`: an `@` body, an
/// include, and a directory of includes for a glob.
fn prepare(dir: &Path) {
    std::fs::write(dir.join("body.json"), r#"{"from":"file"}"#).unwrap();
    std::fs::write(dir.join("seed.api"), "GET /inc1\nGET /inc2\n").unwrap();
    std::fs::create_dir_all(dir.join("inc")).unwrap();
    std::fs::write(dir.join("inc/a.api"), "GET /g1\n").unwrap();
    std::fs::write(dir.join("inc/b.api"), "GET /g2\n").unwrap();

    // A git repository to import, tagged `1.0`, with a body file of its own
    // that shares a name with the one above.
    let repo = dir.join("gitrepo");
    std::fs::create_dir_all(repo.join("data")).unwrap();
    std::fs::write(repo.join("sv.api"), "GET /imp1\nPUT /imp2 @data/body.json\n").unwrap();
    std::fs::write(repo.join("data/body.json"), r#"{"from":"repo"}"#).unwrap();
    for args in [
        &["init", "-q", "-b", "main"][..],
        &["add", "-A"],
        &["commit", "-q", "-m", "seed"],
        &["tag", "1.0"],
    ] {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }
    // A directory to import as it is, and a zip of another.
    std::fs::create_dir_all(dir.join("libdir")).unwrap();
    std::fs::write(dir.join("libdir/d.api"), "GET /dir1\nPUT /dir2 @body.json\n").unwrap();
    std::fs::write(dir.join("libdir/body.json"), r#"{"from":"dir"}"#).unwrap();
    let mut zip = zip::ZipWriter::new(std::fs::File::create(dir.join("lib.zip")).unwrap());
    zip.start_file("lib-1.0/z.api", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(b"GET /zip1\n").unwrap();
    zip.finish().unwrap();

    std::fs::write(
        dir.join("cloddy.json"),
        format!(r#"{{ "url": "{}", "ref": "1.0" }}"#, repo_url(dir)),
    )
    .unwrap();
}

fn repo_url(dir: &Path) -> String {
    format!("file://{}", dir.canonicalize().unwrap().join("gitrepo").display())
}

fn cases(dir: &Path) -> Vec<Case> {
    let out = |name: &str| dir.join(name);
    let abs_seed = dir.join("seed.api").display().to_string();
    let out1 = out("out1.json").display().to_string();
    let out2 = out("out2.json").display().to_string();
    let out3 = out("out3.json").display().to_string();
    let out4 = out("out4.json").display().to_string();
    let redirect2 = format!("> {out2}");
    let redirect3 = format!("> {out3}");
    let append4 = format!(">> {out4}");
    let uri_with_redirect1 = format!("/a > {out1}");
    let uri_with_append2 = format!("/a >> {out2}");
    let import_json = format!(r#"{{"url":"{}","ref":"1.0"}}"#, repo_url(dir));
    let import_inline = format!("import git cl {import_json}");
    let import_and_include = format!("import git cl {{\n  \"url\": \"{}\", // pinned\n  \"ref\": \"1.0\"\n}}\ncl/sv.api", repo_url(dir));
    let import_dir = "import dir d {\"path\":\"libdir\"}\nd/d.api";
    let import_archive = format!(
        "import archive z {{\"url\":\"file://{}\"}}\nz/z.api",
        dir.canonicalize().unwrap().join("lib.zip").display()
    );
    let import_missing_ref = format!(r#"import git cl {{"url":"{}","ref":"9.9"}}"#, repo_url(dir));
    vec![
        // Requests
        case("plain GET", "GET /a", Some(&["GET", "/a"]), &["GET /a"]),
        case("implied GET", "/a", Some(&["/a"]), &["GET /a"]),
        case("lowercase method", "get /a", Some(&["get", "/a"]), &["GET /a"]),
        case("slashless URI", "GET api/v1/a", Some(&["GET", "api/v1/a"]), &["GET /a"]),
        case("HEAD", "HEAD /a", Some(&["HEAD", "/a"]), &["HEAD /a"]),
        case("OPTIONS", "OPTIONS /a", Some(&["OPTIONS", "/a"]), &["OPTIONS /a"]),
        case("DELETE", "DELETE /a", Some(&["DELETE", "/a"]), &["DELETE /a"]),
        case("500 is still an answer", "GET /boom", Some(&["GET", "/boom"]), &["GET /boom"]),
        // Bodies
        case("inline body", r#"PUT /a {"x":1}"#, Some(&["PUT", "/a", r#"{"x":1}"#]), &[r#"PUT /a {"x":1}"#]),
        case(
            "body keeps its spacing",
            r#"PUT /a { "x": 1, "y": "a  b" }"#,
            Some(&["PUT", "/a", r#"{ "x": 1, "y": "a  b" }"#]),
            &[r#"PUT /a { "x": 1, "y": "a  b" }"#],
        ),
        case(
            "block comment in body",
            r#"PUT /a {"x":1 /* note */}"#,
            Some(&["PUT", "/a", r#"{"x":1 /* note */}"#]),
            &[r#"PUT /a {"x":1 }"#],
        ),
        case(
            "line comment in body",
            "PUT /a {\"x\":1 // note\n}",
            Some(&["PUT", "/a", "{\"x\":1 // note\n}"]),
            &["PUT /a {\"x\":1 \n}"],
        ),
        case(
            "hash comment in body",
            "PUT /a {\n  # note\n  \"x\":1\n}",
            Some(&["PUT", "/a", "{\n  # note\n  \"x\":1\n}"]),
            &["PUT /a {\n  \n  \"x\":1\n}"],
        ),
        case(
            "raw newline in a string",
            "PUT /a {\"x\":\"l1\nl2\"}",
            Some(&["PUT", "/a", "{\"x\":\"l1\nl2\"}"]),
            &[r#"PUT /a {"x":"l1\nl2"}"#],
        ),
        case(
            "multi-line body",
            "PUT /a {\n  \"x\": \"l1\nl2\", // note\n  \"y\": 2\n}",
            Some(&["PUT", "/a", "{\n  \"x\": \"l1\nl2\", // note\n  \"y\": 2\n}"]),
            &["PUT /a {\n  \"x\": \"l1\\nl2\", \n  \"y\": 2\n}"],
        ),
        case("array body", r#"POST /a [{"x":1}]"#, Some(&["POST", "/a", r#"[{"x":1}]"#]), &[r#"POST /a [{"x":1}]"#]),
        case("@file body", "PUT /a @body.json", Some(&["PUT", "/a", "@body.json"]), &[r#"PUT /a {"from":"file"}"#]),
        // The prompt opens its body editor for a body-less write; the others
        // send the request as written.
        case("body-less PUT", "PUT /a", Some(&["PUT", "/a"]), &["PUT /a"]).at_the_prompt(&[]),
        // Outfiles
        case("> outfile", &format!("GET /a > {out1}"), Some(&["GET", "/a", ">", &out1]), &["GET /a"]).writes(out("out1.json")),
        case("> outfile as one argument", &format!("GET /a > {out2}"), Some(&["GET", "/a", &redirect2]), &["GET /a"])
            .writes(out("out2.json")),
        case(
            "body then > outfile",
            &format!(r#"PUT /a {{"x":1}} > {out3}"#),
            Some(&["PUT", "/a", r#"{"x":1}"#, &redirect3]),
            &[r#"PUT /a {"x":1}"#],
        )
        .writes(out("out3.json")),
        case(">> append", &format!("GET /a >> {out4}"), Some(&["GET", "/a", &append4]), &["GET /a"]).writes(out("out4.json")),
        // The redirect in the URI argument and the body after it — the shape
        // the one-shot form has always taken.
        case(
            "> outfile in the URI argument, body after",
            &format!(r#"PUT /a {{"x":1}} > {out1}"#),
            Some(&["PUT", &uri_with_redirect1, r#"{"x":1}"#]),
            &[r#"PUT /a {"x":1}"#],
        )
        .writes(out("out1.json")),
        case(
            ">> append in the URI argument, body after",
            &format!(r#"PUT /a {{"x":1}} >> {out2}"#),
            Some(&["PUT", &uri_with_append2, r#"{"x":1}"#]),
            &[r#"PUT /a {"x":1}"#],
        )
        .writes(out("out2.json")),
        // Chains
        case("&& chain", "GET /a && GET /b", Some(&["GET", "/a", "&&", "GET", "/b"]), &["GET /a", "GET /b"]),
        case("|| chain", "GET /missing || GET /b", Some(&["GET", "/missing", "||", "GET", "/b"]), &["GET /missing", "GET /b"]),
        case("&& stops on falsy", "GET /zero && GET /b", Some(&["GET", "/zero", "&&", "GET", "/b"]), &["GET /zero"]),
        case("|| skips on truthy", "GET /a || GET /b", Some(&["GET", "/a", "||", "GET", "/b"]), &["GET /a"]),
        case(
            "if-then-else",
            "GET /zero && GET /then || GET /else",
            Some(&["GET", "/zero", "&&", "GET", "/then", "||", "GET", "/else"]),
            &["GET /zero", "GET /else"],
        ),
        case(
            "chain with a body",
            r#"GET /a && PUT /b {"x":"a && b"}"#,
            Some(&["GET", "/a", "&&", "PUT", "/b", r#"{"x":"a && b"}"#]),
            &["GET /a", r#"PUT /b {"x":"a && b"}"#],
        ),
        case(
            "chain with an outfile",
            &format!("GET /a > {out1} && GET /b"),
            Some(&["GET", "/a", ">", &out1, "&&", "GET", "/b"]),
            &["GET /a", "GET /b"],
        )
        .writes(out("out1.json")),
        case("directive in a chain", "GET /a && sleep 100ms", Some(&["GET", "/a", "&&", "sleep", "100ms"]), &[])
            .fails("chain segment is not a request: `sleep 100ms`"),
        case("typo in a chain", "GET /a && peple", Some(&["GET", "/a", "&&", "peple"]), &[])
            .fails("chain segment is not a request: `peple`"),
        // Directives
        case("sleep", "sleep 100ms", Some(&["sleep", "100ms"]), &[]),
        case("sleep with a bad duration", "sleep abc", Some(&["sleep", "abc"]), &[]).fails("invalid sleep duration"),
        case("assert passes", "assert GET /a", Some(&["assert", "GET", "/a"]), &["GET /a"]),
        case("assert with implied GET", "assert /a", Some(&["assert", "/a"]), &["GET /a"]),
        case("assert fails", "assert GET /missing", Some(&["assert", "GET", "/missing"]), &["GET /missing"])
            .fails("assertion failed: assert GET /missing (404 Not Found)"),
        case("assert on a falsy body", "assert /zero", Some(&["assert", "/zero"]), &["GET /zero"])
            .fails("assertion failed: assert GET /zero (0)"),
        case("assert not passes", "assert not /missing", Some(&["assert", "not", "/missing"]), &["GET /missing"]),
        case("assert not fails", "assert not /a", Some(&["assert", "not", "/a"]), &["GET /a"]).fails("assertion failed"),
        case("assert on a chain", "assert GET /a && GET /b", Some(&["assert", "GET", "/a", "&&", "GET", "/b"]), &[])
            .fails("assert condition can't be a `&&`/`||` chain"),
        case("sleep while", "sleep 100ms while GET /zero", Some(&["sleep", "100ms", "while", "GET", "/zero"]), &["GET /zero"]),
        case("sleep while not", "sleep 100ms while not /a", Some(&["sleep", "100ms", "while", "not", "/a"]), &["GET /a"]),
        case("url gate passes", "url has 127.0.0.1\nGET /a", None, &["GET /a"]),
        case("url gate fails", "url has nowhere.example\nGET /a", None, &[]).fails("URL gate failed"),
        case("url is", "url is http://127.0.0.1:0\nGET /a", None, &[]).fails("URL gate failed"),
        // Includes
        case("include", "seed.api", Some(&["seed.api"]), &["GET /inc1", "GET /inc2"]),
        case("absolute include", &abs_seed, Some(&[&abs_seed]), &["GET /inc1", "GET /inc2"]),
        case("glob include", "inc/*.api", Some(&["inc/*.api"]), &["GET /g1", "GET /g2"]),
        // Imports
        case("import alone sends nothing", &import_inline, Some(&["import", "git", "cl", &import_json]), &[]),
        case(
            "import then include",
            &import_and_include,
            None,
            &["GET /imp1", r#"PUT /imp2 {"from":"repo"}"#],
        ),
        case(
            "import from an @file",
            "import git cl @cloddy.json\ncl/*.api",
            None,
            &["GET /imp1", r#"PUT /imp2 {"from":"repo"}"#],
        ),
        case("import of a directory", import_dir, None, &["GET /dir1", r#"PUT /dir2 {"from":"dir"}"#]),
        case("import of an archive", &import_archive, None, &["GET /zip1"]),
        case("import of an unknown kind", r#"import svn x {"url":"https://example.com/r"}"#, None, &[])
            .fails("unknown import kind `svn`"),
        case("import of a missing ref", &import_missing_ref, None, &[]).fails("import ref not found: 9.9"),
        case("import without a ref", r#"import git cl {"url":"https://example.com/r"}"#, None, &[])
            .fails("`ref` is required"),
        case("include then request", "seed.api\nGET /after", None, &["GET /inc1", "GET /inc2", "GET /after"]),
        case("missing include", "nope.api", Some(&["nope.api"]), &[]).fails("include not found: nope.api"),
        // Several lines and noise
        case("three lines", "GET /a\nsleep 100ms\nGET /b", None, &["GET /a", "GET /b"]),
        case("comment line", "# just a note", Some(&["#", "just", "a", "note"]), &[]),
        case("comment then request", "# note\nGET /a", None, &["GET /a"]),
        case("unknown word", "peple", Some(&["peple"]), &[]).fails("not a request or .api file: peple"),
        case("unknown word with more", "peple /a", Some(&["peple", "/a"]), &[]).fails("not a request or .api file: peple"),
        case("stops after a failed assert", "assert /missing\nGET /never", None, &["GET /missing"]).fails("assertion failed"),
        case("stops after an error status", "GET /a && GET /boom && GET /never", None, &["GET /a", "GET /boom"])
            .fails("500 Internal Server Error"),
    ]
}

/// What one entry point did with a line.
#[derive(Debug, PartialEq)]
struct Outcome {
    sent: Vec<String>,
    exit_ok: bool,
}

fn api(port: u16, dir: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("api"));
    cmd.args(["--no-keychain", "-b", &format!("http://127.0.0.1:{port}"), "-k", "k"])
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("API_IMPORT_CACHE", dir.join(".import-cache"))
        .env_remove("API_STREAMING")
        .env_remove("API_CREDENTIALS_FILE")
        .stdin(std::process::Stdio::null());
    cmd
}

fn run_cli(server: &RecordingServer, dir: &Path, args: &[String]) -> (Outcome, String) {
    server.take();
    let out = api(server.port, dir).args(args).output().expect("spawn api");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (Outcome { sent: server.take(), exit_ok: out.status.success() }, stderr)
}

fn check(case: &Case, how: &str, got: &Outcome, shown: &str, expected_sent: &[&str]) {
    let expected = Outcome {
        sent: expected_sent.iter().map(|s| s.to_string()).collect(),
        exit_ok: case.exit_ok,
    };
    assert_eq!(got, &expected, "[{}] {how}: `{}`\nshown:\n{shown}", case.label, case.line);
    if let Some(phrase) = case.says {
        assert!(shown.contains(phrase), "[{}] {how}: expected {phrase:?} to be shown, got:\n{shown}", case.label);
    }
    if let Some(path) = &case.writes {
        assert!(path.is_file(), "[{}] {how}: {} was not written", case.label, path.display());
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn a_line_means_the_same_in_a_file_and_as_split_or_quoted_arguments() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());

    for case in cases(dir.path()) {
        // As a .api file.
        std::fs::write(dir.path().join("case.api"), format!("{}\n", case.line)).unwrap();
        let (from_file, shown) = run_cli(&server, dir.path(), &["-a".to_string(), "case.api".to_string()]);
        check(&case, "file", &from_file, &shown, &case.sent);

        // As one quoted argument.
        let (quoted, shown) = run_cli(&server, dir.path(), &[case.line.clone()]);
        check(&case, "one quoted argument", &quoted, &shown, &case.sent);
        assert_eq!(quoted, from_file, "[{}] quoted argument differs from the file", case.label);

        // As the shell would split it.
        if let Some(argv) = &case.argv {
            let (split, shown) = run_cli(&server, dir.path(), argv);
            check(&case, "split arguments", &split, &shown, &case.sent);
            assert_eq!(split, from_file, "[{}] split arguments differ from the file", case.label);
        }
    }
}

#[test]
fn a_file_read_from_stdin_is_the_same_file() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    for case in cases(dir.path()).into_iter().filter(|c| c.writes.is_none()) {
        server.take();
        let out = api(server.port, dir.path())
            .args(["-a", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                child.stdin.take().unwrap().write_all(format!("{}\n", case.line).as_bytes())?;
                child.wait_with_output()
            })
            .expect("spawn api");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        let got = Outcome { sent: server.take(), exit_ok: out.status.success() };
        let shown = String::from_utf8_lossy(&out.stderr).to_string();
        check(&case, "stdin", &got, &shown, &case.sent);
    }
}

#[cfg(unix)]
mod pty {
    use super::*;
    use std::os::unix::process::CommandExt;

    /// The client running at its interactive prompt in a pseudo-terminal.
    pub struct Prompt {
        master: i32,
        child: std::process::Child,
        pub screen: String,
    }

    impl Prompt {
        pub fn open(mut cmd: std::process::Command) -> Self {
            let (mut master, mut slave) = (0, 0);
            let mut size = libc::winsize { ws_row: 50, ws_col: 200, ws_xpixel: 0, ws_ypixel: 0 };
            let rc = unsafe {
                libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), &mut size)
            };
            assert_eq!(rc, 0, "openpty");
            unsafe {
                cmd.pre_exec(move || {
                    libc::setsid();
                    libc::ioctl(slave, libc::TIOCSCTTY as _, 0);
                    for fd in 0..3 {
                        libc::dup2(slave, fd);
                    }
                    libc::close(slave);
                    libc::close(master);
                    Ok(())
                });
            }
            cmd.env("TERM", "xterm-256color").env_remove("NO_COLOR");
            let child = cmd.spawn().expect("spawn api in a pty");
            unsafe { libc::close(slave) };
            Prompt { master, child, screen: String::new() }
        }

        pub fn send(&mut self, bytes: &[u8]) {
            let mut written = 0;
            while written < bytes.len() {
                let n = unsafe {
                    libc::write(self.master, bytes[written..].as_ptr() as *const _, bytes.len() - written)
                };
                assert!(n > 0, "write to pty");
                written += n as usize;
            }
        }

        pub fn paste(&mut self, text: &str) {
            self.send(b"\x1b[200~");
            self.send(text.as_bytes());
            self.send(b"\x1b[201~");
        }

        /// Collect output for `d`, answering the cursor-position query the
        /// client sends when it starts.
        pub fn pump(&mut self, d: Duration) {
            let end = Instant::now() + d;
            loop {
                let left = end.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return;
                }
                let mut pfd = libc::pollfd { fd: self.master, events: libc::POLLIN, revents: 0 };
                let rc = unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(50) as i32) };
                if rc <= 0 {
                    continue;
                }
                if pfd.revents & libc::POLLIN == 0 {
                    return;
                }
                let mut buf = [0u8; 65536];
                let n = unsafe { libc::read(self.master, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n <= 0 {
                    return;
                }
                let chunk = &buf[..n as usize];
                if chunk.windows(4).any(|w| w == b"\x1b[6n") {
                    self.send(b"\x1b[50;1R");
                }
                self.screen.push_str(&String::from_utf8_lossy(chunk));
            }
        }

        pub fn wait_for(&mut self, text: &str, timeout: Duration) {
            let start = Instant::now();
            while !self.screen.contains(text) {
                assert!(start.elapsed() < timeout, "{text:?} never appeared:\n{}", self.screen);
                self.pump(Duration::from_millis(100));
            }
        }
    }

    impl Drop for Prompt {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            unsafe { libc::close(self.master) };
        }
    }

    /// The screen without its escape sequences.
    pub fn plain(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    while let Some(&d) = chars.peek() {
                        chars.next();
                        if d.is_ascii_alphabetic() || d == '~' {
                            break;
                        }
                    }
                }
                continue;
            }
            out.push(c);
        }
        out
    }
}

#[cfg(unix)]
#[test]
fn the_prompt_reads_the_same_lines() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());

    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));

    let mut extra = cases(dir.path());
    extra.push(case("confirm, answered yes", "confirm Go on", None, &[]).says("Go on?"));
    extra.push(case("confirm then request", "confirm\nGET /a", None, &["GET /a"]));

    for case in extra {
        // ctrl+u clears whatever the last line left; then the line is pasted
        // whole, as a user would paste it from a file.
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        prompt.paste(&case.line);
        prompt.pump(Duration::from_millis(60));
        let mark = prompt.screen.len();
        prompt.send(b"\r");
        prompt.pump(Duration::from_millis(120));
        if case.label.starts_with("confirm") {
            prompt.send(b"y");
        }
        // Done once the server has been quiet for a moment.
        let start = Instant::now();
        let mut quiet = 0;
        while quiet < 2 && start.elapsed() < Duration::from_secs(4) {
            let before = server.seen();
            prompt.pump(Duration::from_millis(120));
            quiet = if server.seen() == before { quiet + 1 } else { 0 };
        }
        // Leave the body editor if one opened; harmless otherwise.
        prompt.send(b"\x1b");
        prompt.pump(Duration::from_millis(60));

        let got = Outcome { sent: server.take(), exit_ok: case.exit_ok };
        let shown = plain(&prompt.screen[mark..]);
        let expected = case.prompt_sent.clone().unwrap_or_else(|| case.sent.clone());
        check(&case, "prompt", &got, &shown, &expected);
    }
}

/// `-f` means the same from a file, from stdin and as arguments: the run
/// stops at the first response of 400 or above, exits 1, and the body of
/// that response is the last thing on stdout.
#[test]
fn fail_fast_stops_the_same_way_in_a_file_from_stdin_and_as_arguments() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let run = |args: &[&str], stdin: Option<&str>| {
        server.take();
        let mut cmd = api(server.port, dir.path());
        cmd.args(args);
        if stdin.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        }
        cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().expect("spawn api");
        if let Some(text) = stdin {
            child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        (server.take(), out.status.success(), String::from_utf8_lossy(&out.stdout).to_string())
    };

    // (the lines, what is sent, whether the run succeeds)
    let cases: [(&str, &[&str], bool); 6] = [
        // The recording server answers `/missing` with a 404 and `/boom` with a 500.
        ("GET /a\nGET /missing\nGET /b", &["GET /a", "GET /missing"], false),
        ("GET /boom\nGET /b", &["GET /boom"], false),
        // A question answered "no" is not a failure…
        ("GET /missing || PUT /made {\"x\":1}\nGET /b", &["GET /missing", "PUT /made {\"x\":1}", "GET /b"], true),
        ("assert not GET /missing\nGET /b", &["GET /missing", "GET /b"], true),
        // …the last request of a chain is one.
        ("GET /a && GET /missing\nGET /b", &["GET /a", "GET /missing"], false),
        ("seed.api\nGET /missing\nGET /b", &["GET /inc1", "GET /inc2", "GET /missing"], false),
    ];
    for (lines, sent, ok) in cases {
        std::fs::write(dir.path().join("case.api"), format!("{lines}\n")).unwrap();
        let from_file = run(&["-sfa", "case.api"], None);
        let from_stdin = run(&["-sfa"], Some(lines));
        let quoted = run(&["-sf", lines], None);
        for (how, got) in [("file", &from_file), ("stdin", &from_stdin), ("one quoted argument", &quoted)] {
            assert_eq!(got.0, sent, "{how}: {lines:?}");
            assert_eq!(got.1, ok, "{how}: {lines:?}");
            // The failing body, `{}` from this server, ends stdout.
            assert_eq!(got.2.ends_with("\n{}\n"), !ok, "{how}: {lines:?}\n{}", got.2);
        }
        // Without the flag every line is sent and the run succeeds.
        let unflagged = run(&["-sa", "case.api"], None);
        assert!(unflagged.1 && unflagged.0.len() >= sent.len(), "{lines:?}: {unflagged:?}");
    }

    // One request, split by the shell or not.
    for args in [&["-f", "GET", "/missing"][..], &["-f", "GET /missing"], &["GET", "/missing", "-f"]] {
        let got = run(args, None);
        assert_eq!((got.0, got.1, got.2.as_str()), (vec!["GET /missing".to_string()], false, "{}\n"), "{args:?}");
    }
}

/// At the prompt `-f` stops the program that was running, not the session.
#[cfg(unix)]
#[test]
fn fail_fast_at_the_prompt_stops_a_pasted_block_and_keeps_the_session() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());

    let mut cmd = api(server.port, dir.path());
    cmd.arg("-f");
    let mut prompt = Prompt::open(cmd);
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));

    let mut run = |paste: &str| {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        prompt.paste(paste);
        prompt.pump(Duration::from_millis(80));
        let mark = prompt.screen.len();
        prompt.send(b"\r");
        let start = Instant::now();
        let mut quiet = 0;
        while quiet < 2 && start.elapsed() < Duration::from_secs(4) {
            let before = server.seen();
            prompt.pump(Duration::from_millis(120));
            quiet = if server.seen() == before { quiet + 1 } else { 0 };
        }
        (server.take(), plain(&prompt.screen[mark..]))
    };

    let (sent, shown) = run("GET /a\rGET /missing\rGET /b\r");
    assert_eq!(sent, ["GET /a", "GET /missing"]);
    assert!(shown.contains("stopped at 404 (--fail-fast)"), "{shown}");

    // A question answered "no" lets the block run on.
    let (sent, shown) = run("GET /missing || PUT /made {\"x\":1}\rGET /b\r");
    assert_eq!(sent, ["GET /missing", "PUT /made {\"x\":1}", "GET /b"]);
    assert!(!shown.contains("--fail-fast"), "{shown}");

    // A file run from the prompt stops the same way, and the session is
    // still there for the next line.
    std::fs::write(dir.path().join("failing.api"), "GET /boom\nGET /b\n").unwrap();
    let (sent, shown) = run("failing.api");
    assert_eq!(sent, ["GET /boom"]);
    assert!(shown.contains("stopped at 500 (--fail-fast)"), "{shown}");
    let (sent, _) = run("GET /a");
    assert_eq!(sent, ["GET /a"]);
}

/// A terminal sends a pasted newline as `\r`. Pasted over the `GET /` the
/// prompt starts with, a block of directive lines must still arrive as a
/// block and run line by line, not as one request to `/assert GET /a…`.
#[cfg(unix)]
#[test]
fn a_pasted_block_with_carriage_returns_runs_line_by_line() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());

    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));

    // No ctrl+u: the default `GET /` is on the line, as it is for a user who
    // pastes right after starting the client.
    server.take();
    prompt.paste("assert GET /a\rassert GET /b\rassert GET /c\r");
    prompt.pump(Duration::from_millis(80));
    let mark = prompt.screen.len();
    prompt.send(b"\r");
    let start = Instant::now();
    let mut quiet = 0;
    while quiet < 2 && start.elapsed() < Duration::from_secs(4) {
        let before = server.seen();
        prompt.pump(Duration::from_millis(120));
        quiet = if server.seen() == before { quiet + 1 } else { 0 };
    }
    assert_eq!(server.take(), ["GET /a", "GET /b", "GET /c"]);
    let shown = plain(&prompt.screen[mark..]);
    assert!(!shown.contains("/assert"), "the block was sent as one request:\n{shown}");
}

/// A failed `assert` leaves its verdict in the scrollback, under a request
/// line that says it was an assert. The hint line fades; the log must not.
#[cfg(unix)]
#[test]
fn a_failed_assert_at_the_prompt_is_logged_as_one() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());

    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));

    let lines: [(&str, &str, &[&str]); 3] = [
        ("assert /zero", "↳ assertion failed (0)", &["assert GET /zero"]),
        ("assert not /a", "↳ assertion failed (", &["assert not GET /a"]),
        // A passing assert is logged with its prefix and no note.
        ("assert /a", "", &["assert GET /a"]),
    ];
    for (line, note, logged) in lines {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        prompt.paste(line);
        prompt.pump(Duration::from_millis(60));
        let mark = prompt.screen.len();
        prompt.send(b"\r");
        let start = Instant::now();
        let mut quiet = 0;
        while quiet < 2 && start.elapsed() < Duration::from_secs(4) {
            let before = server.seen();
            prompt.pump(Duration::from_millis(120));
            quiet = if server.seen() == before { quiet + 1 } else { 0 };
        }
        assert_eq!(server.seen(), 1, "{line}");
        let shown = plain(&prompt.screen[mark..]);
        for l in logged {
            assert!(shown.contains(l), "{line}: {l:?} not logged:\n{shown}");
        }
        if note.is_empty() {
            assert!(!shown.contains("↳"), "{line}: unexpected note:\n{shown}");
        } else {
            let at = shown.find(note).unwrap_or_else(|| panic!("{line}: {note:?} not shown:\n{shown}"));
            // The note follows the status line, not the hint line.
            let status = shown.find("HTTP/1.1").unwrap();
            assert!(at > status, "{line}: note before the status line:\n{shown}");
        }
    }
}

#[cfg(unix)]
#[test]
fn tab_completes_an_include_at_the_prompt() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());

    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));

    // Each entry is typed key by key; `\t` is Tab. `body.json` also starts
    // with a letter of its own but is never offered, not being a `.api` file.
    let lines: [(&[&str], &str, &[&str]); 3] = [
        (&["se", "\t"], "seed.api", &["GET /inc1", "GET /inc2"]),
        (&["in", "\t", "b", "\t"], "inc/b.api", &["GET /g2"]),
        (&["./in", "\t", "\t", "a", "\t"], "./inc/a.api", &["GET /g1"]),
    ];
    for (keys, completed, sent) in lines {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        let mark = prompt.screen.len();
        for key in keys {
            prompt.send(key.as_bytes());
            prompt.pump(Duration::from_millis(80));
        }
        let shown = plain(&prompt.screen[mark..]);
        assert!(shown.contains(completed), "{completed} not on the input line:\n{shown}");

        server.take();
        prompt.send(b"\r");
        // Done once the server has been quiet for a moment.
        let start = Instant::now();
        let mut quiet = 0;
        while quiet < 2 && start.elapsed() < Duration::from_secs(4) {
            let before = server.seen();
            prompt.pump(Duration::from_millis(120));
            quiet = if server.seen() == before { quiet + 1 } else { 0 };
        }
        assert_eq!(server.take(), sent, "after completing to {completed}");
    }
}

/// The rows the client's last cursor move climbed before clearing downwards:
/// what it took off the screen on its way out.
#[cfg(unix)]
fn last_move_up(screen: &str) -> Option<u16> {
    let mut last = None;
    let mut rest = screen;
    while let Some(i) = rest.find("\x1b[") {
        rest = &rest[i + 2..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if rest[digits.len()..].starts_with('A') {
            last = digits.parse().ok();
        }
    }
    last
}

/// Press ctrl+c twice and collect what the client prints while it leaves.
#[cfg(unix)]
fn quit(prompt: &mut pty::Prompt) {
    prompt.send(b"\x03");
    prompt.wait_for("ctrl+c again to exit", Duration::from_secs(3));
    prompt.send(b"\x03");
    prompt.pump(Duration::from_millis(400));
}

/// A session that was only opened and closed takes its splash with it: the
/// final clear starts above the box, not just above the input area.
#[cfg(unix)]
#[test]
fn closing_an_unused_prompt_clears_the_splash() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());

    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    assert!(prompt.screen.contains("CommerceOS API Client"), "no splash:\n{}", prompt.screen);

    quit(&mut prompt);
    // ruler + input line + hint, then the five splash lines above them
    assert_eq!(last_move_up(&prompt.screen), Some(3 + 5), "exit clear:\n{}", pty::plain(&prompt.screen));
}

/// Once a request has been sent, its output stays in the scrollback like a
/// shell session's history: leaving clears only the input area.
#[cfg(unix)]
#[test]
fn closing_a_used_prompt_keeps_its_history() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());

    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));

    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    prompt.paste("GET /a");
    prompt.pump(Duration::from_millis(60));
    prompt.send(b"\r");
    let start = Instant::now();
    while server.seen() == 0 && start.elapsed() < Duration::from_secs(4) {
        prompt.pump(Duration::from_millis(120));
    }
    assert_eq!(server.take(), vec!["GET /a".to_string()]);
    prompt.pump(Duration::from_millis(300));

    quit(&mut prompt);
    assert_eq!(last_move_up(&prompt.screen), Some(3), "exit clear:\n{}", pty::plain(&prompt.screen));
}
