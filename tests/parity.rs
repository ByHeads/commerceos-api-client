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
    /// The headers of every recorded request, in the same order: see `heads`.
    heads: Arc<Mutex<Vec<String>>>,
    /// How many tokens the token endpoint has handed out.
    tokens: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl RecordingServer {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let tokens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tokens2 = Arc::clone(&tokens);
        let (log2, heads2, stop2) = (Arc::clone(&log), Arc::clone(&heads), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (log, heads, tokens) = (Arc::clone(&log2), Arc::clone(&heads2), Arc::clone(&tokens2));
                        std::thread::spawn(move || answer(stream, &log, &heads, &tokens));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        });
        RecordingServer { port, log, heads, tokens, stop, handle: Some(handle) }
    }

    fn take(&self) -> Vec<String> {
        self.heads.lock().unwrap().clear();
        std::mem::take(&mut *self.log.lock().unwrap())
    }

    /// What each recorded request carried, one line per request:
    /// `accept=…; content-type=…; authorization=…; x-request-map=…`, a header
    /// that was not sent as `-`. Cleared by `take`, so read it first.
    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
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

fn answer(
    mut stream: std::net::TcpStream,
    log: &Mutex<Vec<String>>,
    heads: &Mutex<Vec<String>>,
    tokens: &std::sync::atomic::AtomicUsize,
) {
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
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let header = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let length: usize = header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
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
        // Both under the one lock, so the two lists stay in step.
        let mut log = log.lock().unwrap();
        heads.lock().unwrap().push(format!(
            "accept={}; content-type={}; authorization={}; x-request-map={}",
            header("accept").unwrap_or("-"),
            header("content-type").unwrap_or("-"),
            header("authorization").unwrap_or("-"),
            header("x-request-map").unwrap_or("-"),
        ));
        log.push(entry);
    }

    // Responses that go wrong after the status line.
    let broken: Option<(&str, Duration)> = if path.contains("/trunc") {
        // Promises 1000 bytes, sends 9 and hangs up.
        Some(("Content-Length: 1000\r\n\r\n{\"a\":1234", Duration::ZERO))
    } else if path.contains("/stall") {
        // The same, but keeps the connection open: only a timeout ends it.
        Some(("Content-Length: 1000\r\n\r\n{\"a\":1234", Duration::from_secs(6)))
    } else if path.contains("/midfail") {
        // A chunked body that stops after its first chunk.
        Some(("Transfer-Encoding: chunked\r\n\r\n9\r\n[{\"a\":1},\r\n", Duration::from_millis(100)))
    } else {
        None
    };
    if let Some((rest, hold)) = broken {
        let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{rest}").as_bytes());
        let _ = stream.flush();
        std::thread::sleep(hold);
        return;
    }

    let (status, payload) = if path.contains("/oauth2/v1/token") {
        // The first token handed out has already run out by the time it is
        // used; every later one is good.
        let token = if tokens.fetch_add(1, Ordering::SeqCst) == 0 { "stale" } else { "fresh" };
        ("200 OK", format!(r#"{{"access_token":"{token}","expires_in":3600}}"#))
    } else if path.contains("/expired") && header("authorization") != Some("Bearer fresh") {
        // Only the token the token endpoint hands out is let in.
        ("401 Unauthorized", r#"{"error":"token expired"}"#.to_string())
    } else if path.contains("/missing") {
        ("404 Not Found", "{}".to_string())
    } else if path.contains("/zero") {
        ("200 OK", "0".to_string())
    } else if path.contains("/boom") {
        ("500 Internal Server Error", "{}".to_string())
    } else if path.contains("/keyed") {
        // A record with only a database key and a masked value, for `--export`.
        ("200 OK", r#"{"name":"Ann","identifiers":{"key":"k1"},"secret":"********"}"#.to_string())
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
    let out5 = out("out5.json").display().to_string();
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
        // Describe blocks: read, never sent
        case("describe block then request", "{ \"title\": { \"sv-SE\": \"Katalog\" } }\nGET /a", None, &["GET /a"]),
        case(
            "describe block over several lines",
            "# seed\n{\n  \"title\": { \"sv-SE\": \"Katalog\" }, // name\n  \"docsLink\": \"https://link-to-docs.com\"\n}\n\nGET /a\nGET /b",
            None,
            &["GET /a", "GET /b"],
        ),
        case("describe block after a request", "GET /a\n\n{ \"title\": {} }", None, &[])
            .fails("a describe block must come before the first request"),
        case("body a line under its request", "PUT /a\n{ \"x\": 1 }", None, &[])
            .fails("a body starts on the request line"),
        case("array where a describe block goes", "[1]\nGET /a", None, &[])
            .fails("a describe block is a JSON object, not an array"),
        // A `>` inside a JSON string or a URI operator is the request's own
        case(
            "> inside a JSON string",
            r#"PUT /a {"x":"b > c"}"#,
            Some(&["PUT", "/a", r#"{"x":"b > c"}"#]),
            &[r#"PUT /a {"x":"b > c"}"#],
        ),
        case(
            "> inside a JSON string, then an outfile",
            &format!(r#"PUT /a {{"x":"b > c"}} > {out5}"#),
            Some(&["PUT", "/a", r#"{"x":"b > c"}"#, ">", &out5]),
            &[r#"PUT /a {"x":"b > c"}"#],
        )
        .writes(out("out5.json")),
        case(
            "> inside a URI operator",
            r#"GET /a~where(n="x > y")"#,
            Some(&["GET", r#"/a~where(n="x > y")"#]),
            &["GET /a~where(n=%22x%20%3E%20y%22)"],
        ),
        case("appending to the clipboard", r#"PUT /a {"x":1} >> clipboard"#, Some(&["PUT", "/a", r#"{"x":1}"#, ">>", "clipboard"]), &[])
            .fails("cannot append to clipboard"),
        // Directives are read in any case and with any blanks between words
        case("URL gate in capitals", "URL has 127.0.0.1\nGET /a", None, &["GET /a"]),
        case("url gate with doubled blanks", "url  has  127.0.0.1\nGET /a", None, &["GET /a"]),
        case("a sleep no clock can hold", "sleep 1e20", Some(&["sleep", "1e20"]), &[])
            .fails("invalid sleep duration: `1e20`"),
        // `||` and `&&` inside the parentheses of a URI operator are the URI's
        case(
            "|| inside parentheses",
            "GET /a~where(x=1||y=2)",
            Some(&["GET", "/a~where(x=1||y=2)"]),
            &["GET /a~where(x=1||y=2)"],
        ),
        case(
            "&& inside parentheses, then a chain",
            "GET /a~where(x=1&&y=2) && GET /b",
            Some(&["GET", "/a~where(x=1&&y=2)", "&&", "GET", "/b"]),
            &["GET /a~where(x=1&&y=2)", "GET /b"],
        ),
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
        // The prompt keeps a history file in the home directory: not the
        // real one, when it is a test that types.
        .env("HOME", dir)
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

/// One request and the headers it must carry: `(flags, line, accept,
/// content-type, x-request-map)`. `{d}` in a line is the working directory.
#[cfg(unix)]
type HeaderRow = (&'static [&'static str], &'static str, &'static str, &'static str, &'static str);

#[cfg(unix)]
const JSON: &str = "application/json";
#[cfg(unix)]
const NDJSON: &str = "application/x-ndjson";

#[cfg(unix)]
fn header_rows() -> Vec<HeaderRow> {
    vec![
        (&[], "GET /h", JSON, JSON, "-"),
        // The outfile's extension chooses Accept, in any case.
        (&[], "GET /h > {d}/h.csv", "text/csv", JSON, "-"),
        (&[], "GET /h > {d}/h.CSV", "text/csv", JSON, "-"),
        (&[], "GET /h > {d}/h.ndjson", NDJSON, JSON, "-"),
        (&[], "GET /h > {d}/h.njson", NDJSON, JSON, "-"),
        (&[], "GET /h > {d}/h.NDJSON", NDJSON, JSON, "-"),
        (&[], "GET /h > {d}/h.sql", "application/sql", JSON, "-"),
        (&[], "GET /h > {d}/h.txt", JSON, JSON, "-"),
        (&[], "GET /h >> {d}/h2.csv", "text/csv", JSON, "-"),
        // Flags
        (&["-i"], "GET /h", "application/json;skipNulls=false", JSON, "-"),
        (&["-i"], "GET /h > {d}/i.csv", "text/csv;skipNulls=false", JSON, "-"),
        (&["--ndjson"], "GET /h", NDJSON, NDJSON, "-"),
        // File bodies
        (&[], "PUT /h @data.csv", JSON, "text/csv", "-"),
        (&[], "PUT /h @data.csv~map(com.heads.t)", JSON, "text/csv", "com.heads.t"),
        (&[], "PUT /h @data.csv~map(com.heads.t) > {d}/o.csv", "text/csv", "text/csv", "com.heads.t"),
        (&[], "PUT /h @rows.ndjson", NDJSON, NDJSON, "-"),
        (&["-i"], "PUT /h @rows.ndjson", "application/x-ndjson;skipNulls=false", NDJSON, "-"),
        (&[], r#"PUT /h {"x":1}"#, JSON, JSON, "-"),
    ]
}

#[cfg(unix)]
fn header_fixtures(dir: &Path) {
    std::fs::write(dir.join("data.csv"), "a,b\n1,2\n").unwrap();
    std::fs::write(dir.join("rows.ndjson"), "{\"a\":1}\n{\"a\":2}\n").unwrap();
}

#[cfg(unix)]
fn expected_head(row: &HeaderRow, authorization: &str) -> String {
    format!("accept={}; content-type={}; authorization={}; x-request-map={}", row.2, row.3, authorization, row.4)
}

/// The headers of a request are the same whether it is a one-shot, a line of
/// a file or typed at the prompt: one function builds them.
#[cfg(unix)]
#[test]
fn a_request_carries_the_same_headers_from_every_entry_point() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    header_fixtures(dir.path());
    let d = dir.path().display().to_string();
    // `:k` as Basic.
    let basic = "Basic Oms=";

    for row in header_rows() {
        let line = row.1.replace("{d}", &d);
        // One-shot, as one quoted argument.
        server.take();
        let mut args: Vec<String> = row.0.iter().map(|f| f.to_string()).collect();
        args.push(line.clone());
        let out = api(server.port, dir.path()).args(&args).output().expect("spawn api");
        server.settle(Duration::from_millis(100), Duration::from_secs(3));
        assert_eq!(server.heads(), [expected_head(&row, basic)], "one-shot {:?} `{line}`\n{}", row.0, String::from_utf8_lossy(&out.stderr));

        // A line of a file.
        server.take();
        std::fs::write(dir.path().join("h.api"), format!("{line}\n")).unwrap();
        let mut args: Vec<String> = row.0.iter().map(|f| f.to_string()).collect();
        args.extend(["-sa".to_string(), "h.api".to_string()]);
        api(server.port, dir.path()).args(&args).output().expect("spawn api");
        server.settle(Duration::from_millis(100), Duration::from_secs(3));
        assert_eq!(server.heads(), [expected_head(&row, basic)], "file {:?} `{line}`", row.0);
    }

    // At the prompt, one session per set of flags.
    for flags in [&[][..], &["-i"][..], &["--ndjson"][..]] {
        let mut cmd = api(server.port, dir.path());
        cmd.args(flags);
        let mut prompt = Prompt::open(cmd);
        prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
        prompt.pump(Duration::from_millis(400));
        for row in header_rows().into_iter().filter(|row| row.0 == flags) {
            let line = row.1.replace("{d}", &d);
            prompt.send(b"\x15");
            prompt.pump(Duration::from_millis(60));
            server.take();
            prompt.paste(&line);
            prompt.pump(Duration::from_millis(60));
            prompt.send(b"\r");
            let start = Instant::now();
            while server.seen() == 0 && start.elapsed() < Duration::from_secs(5) {
                prompt.pump(Duration::from_millis(50));
            }
            prompt.pump(Duration::from_millis(150));
            assert_eq!(server.heads(), [expected_head(&row, basic)], "prompt {flags:?} `{line}`\n{}", pty::plain(&prompt.screen));
        }
    }

    // `--stream` adds `;stream=true` to both.
    server.take();
    api(server.port, dir.path()).args(["--stream", "GET", "/h"]).output().expect("spawn api");
    server.settle(Duration::from_millis(100), Duration::from_secs(3));
    assert_eq!(
        server.heads(),
        ["accept=application/json;stream=true; content-type=application/json;stream=true; authorization=Basic Oms=; x-request-map=-"]
    );

    // A token is Bearer; so is a key that has the shape of a JWT.
    let jwt = format!("ey{}", "a".repeat(200));
    for (flag, value, authorization) in [("--token", "tok", "Bearer tok".to_string()), ("-k", jwt.as_str(), format!("Bearer {jwt}"))] {
        server.take();
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("api"));
        cmd.args(["--no-keychain", "-b", &format!("http://127.0.0.1:{}", server.port), flag, value, "GET", "/h"])
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .env_remove("API_STREAMING")
            .env_remove("API_CREDENTIALS_FILE")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn api");
        server.settle(Duration::from_millis(100), Duration::from_secs(3));
        assert_eq!(
            server.heads(),
            [format!("accept=application/json; content-type=application/json; authorization={authorization}; x-request-map=-")]
        );
    }
}

/// The client run with flags of its own choosing (`api` adds `-b` and `-k`).
fn api_bare(dir: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("api"));
    cmd.arg("--no-keychain")
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env("HOME", dir)
        .env_remove("API_STREAMING")
        .env_remove("API_CREDENTIALS_FILE")
        .stdin(std::process::Stdio::null());
    cmd
}

/// What a run printed and how it ended.
struct Ran {
    sent: Vec<String>,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn ran(server: &RecordingServer, mut cmd: std::process::Command) -> Ran {
    server.take();
    let out = cmd.output().expect("spawn api");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    Ran {
        sent: server.log.lock().unwrap().clone(),
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

fn run_in(server: &RecordingServer, dir: &Path, args: &[&str]) -> Ran {
    let mut cmd = api(server.port, dir);
    cmd.args(args);
    ran(server, cmd)
}

/// A response that stops before its end is not an empty response. The run
/// ends with exit 1, with or without `-f`, nothing is written to the outfile
/// and nothing after it is sent.
#[test]
fn a_response_cut_short_ends_the_run() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = |name: &str, text: &str| std::fs::write(d.join(name), text).unwrap();

    // One request.
    let one = run_in(&server, d, &["GET", "/trunc", ">", "w.json"]);
    assert_eq!(one.code, Some(1), "{}", one.stderr);
    assert!(one.stderr.contains("The response was cut short"), "{}", one.stderr);
    assert!(!d.join("w.json").exists(), "an outfile was written");
    let plain = run_in(&server, d, &["GET", "/trunc"]);
    assert_eq!((plain.code, plain.stdout.as_str()), (Some(1), ""), "{}", plain.stderr);

    // A line of a file, with and without `-f`: the next line is not sent.
    file("cut.api", "GET /trunc > w.json\nGET /never\n");
    for flags in ["-sa", "-sfa", "-a"] {
        let batch = run_in(&server, d, &[flags, "cut.api"]);
        assert_eq!(batch.code, Some(1), "{flags}: {}", batch.stderr);
        assert_eq!(batch.sent, ["GET /trunc"], "{flags}");
        assert!(!d.join("w.json").exists(), "{flags}: an outfile was written");
    }

    // A chain does not take the empty body for an answer.
    file("chain.api", "GET /trunc && GET /never\n");
    let chain = run_in(&server, d, &["-sa", "chain.api"]);
    assert_eq!((chain.code, &chain.sent[..]), (Some(1), &["GET /trunc".to_string()][..]), "{}", chain.stderr);
    file("or.api", "GET /trunc || GET /never\n");
    let or = run_in(&server, d, &["-sa", "or.api"]);
    assert_eq!((or.code, &or.sent[..]), (Some(1), &["GET /trunc".to_string()][..]), "{}", or.stderr);

    // Neither does a check: `assert not` must not pass on it.
    file("assert.api", "assert not GET /trunc\nGET /never\n");
    let assert_not = run_in(&server, d, &["-sa", "assert.api"]);
    assert_eq!((assert_not.code, &assert_not.sent[..]), (Some(1), &["GET /trunc".to_string()][..]), "{}", assert_not.stderr);
    file("poll.api", "sleep 1 while not GET /trunc\nGET /never\n");
    let poll = run_in(&server, d, &["-sa", "poll.api"]);
    assert_eq!((poll.code, &poll.sent[..]), (Some(1), &["GET /trunc".to_string()][..]), "{}", poll.stderr);

    // A body that stalls past the timeout.
    let stalled = run_in(&server, d, &["--timeout", "1", "GET", "/stall", ">", "s.json"]);
    assert_eq!(stalled.code, Some(1), "{}", stalled.stderr);
    assert!(stalled.stderr.contains("Timed out after"), "{}", stalled.stderr);
    assert!(!d.join("s.json").exists());
}

/// With `--stream` a body that fails partway leaves the outfile as it was:
/// no partial file that looks complete, and no `.part` file.
#[test]
fn a_stream_that_fails_leaves_no_partial_outfile() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    let one = run_in(&server, d, &["--stream", "GET", "/midfail", ">", "part.json"]);
    assert_eq!(one.code, Some(1), "{}", one.stderr);
    assert!(one.stderr.contains("The response was cut short"), "{}", one.stderr);
    assert!(!d.join("part.json").exists(), "a partial outfile is left");
    assert!(!d.join("part.json.part").exists(), "the .part file is left");

    // What the file held before is still there.
    std::fs::write(d.join("kept.json"), "[\"before\"]").unwrap();
    std::fs::write(d.join("stream.api"), "GET /midfail > kept.json\nGET /never\n").unwrap();
    for flags in ["-sa", "-sfa"] {
        let batch = run_in(&server, d, &["--stream", flags, "stream.api"]);
        assert_eq!(batch.code, Some(1), "{flags}: {}", batch.stderr);
        assert_eq!(batch.sent, ["GET /midfail"], "{flags}");
        assert_eq!(std::fs::read_to_string(d.join("kept.json")).unwrap(), "[\"before\"]", "{flags}");
        assert!(!d.join("kept.json.part").exists(), "{flags}");
    }

    // To stdout, and drained in `-sa`: no answer either way.
    let to_pipe = run_in(&server, d, &["--stream", "GET", "/midfail"]);
    assert_eq!(to_pipe.code, Some(1), "{}", to_pipe.stderr);
    std::fs::write(d.join("drain.api"), "GET /midfail\nGET /never\n").unwrap();
    let drained = run_in(&server, d, &["--stream", "-sa", "drain.api"]);
    assert_eq!((drained.code, &drained.sent[..]), (Some(1), &["GET /midfail".to_string()][..]), "{}", drained.stderr);

    // A stream that ends well still lands in its file, whole.
    let good = run_in(&server, d, &["--stream", "GET", "/a", ">", "good.json"]);
    assert_eq!(good.code, Some(0), "{}", good.stderr);
    assert_eq!(std::fs::read_to_string(d.join("good.json")).unwrap(), r#"{"ok":"/api/v1/a"}"#);
    assert!(!d.join("good.json.part").exists());
}

/// An outfile that can't be written is a failure of the request: exit 1 for
/// one request and under `-f`, a stopped chain, and a reported line that a
/// plain batch goes on past, as it goes on past a failed request.
#[test]
fn an_outfile_that_cannot_be_written_is_a_failure() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = |name: &str, text: &str| std::fs::write(d.join(name), text).unwrap();

    for stream in [false, true] {
        let with = |args: &[&'static str]| -> Vec<&'static str> {
            let mut all = if stream { vec!["--stream"] } else { Vec::new() };
            all.extend_from_slice(args);
            all
        };
        let one = run_in(&server, d, &with(&["GET", "/a", ">", "no-such-dir/x.json"]));
        assert_eq!(one.code, Some(1), "stream={stream}: {}", one.stderr);
        assert!(one.stderr.contains("Error writing to no-such-dir/x.json"), "stream={stream}: {}", one.stderr);
        let appended = run_in(&server, d, &with(&["GET", "/a", ">>", "no-such-dir/x.json"]));
        assert_eq!(appended.code, Some(1), "stream={stream}: {}", appended.stderr);

        file("w.api", "GET /a > no-such-dir/x.json\nGET /b\n");
        let plain = run_in(&server, d, &with(&["-sa", "w.api"]));
        assert_eq!((plain.code, plain.sent.len()), (Some(0), 2), "stream={stream}: {}", plain.stderr);
        assert!(plain.stderr.contains("Error writing to no-such-dir/x.json"), "stream={stream}: {}", plain.stderr);
        let fail_fast = run_in(&server, d, &with(&["-sfa", "w.api"]));
        assert_eq!((fail_fast.code, &fail_fast.sent[..]), (Some(1), &["GET /a".to_string()][..]), "stream={stream}: {}", fail_fast.stderr);

        file("wc.api", "GET /a > no-such-dir/x.json && GET /never\n");
        let chain = run_in(&server, d, &with(&["-sa", "wc.api"]));
        assert_eq!((chain.code, &chain.sent[..]), (Some(1), &["GET /a".to_string()][..]), "stream={stream}: {}", chain.stderr);
    }
}

/// An OAuth2 token that has run out is renewed once, and the request that
/// got the 401 is sent again as it was: the same method, body and headers,
/// with only `Authorization` new. In a batch too, not just at the prompt.
#[cfg(unix)]
#[test]
fn a_token_that_ran_out_is_renewed_and_the_same_request_sent_again() {
    use pty::Prompt;

    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    header_fixtures(d);
    let credentials = |server: &RecordingServer| {
        std::fs::write(
            d.join(".api-credentials.json"),
            format!(
                r#"{{"connections":[{{"name":"o","url":"http://127.0.0.1:{}","auth_type":"oauth2","credential":"s&x=1+2%","client_id":"id 1"}}],"default":"o"}}"#,
                server.port
            ),
        )
        .unwrap();
    };
    let expect_retry = |server: &RecordingServer, how: &str| {
        let heads = server.heads();
        let sent = server.log.lock().unwrap().clone();
        let requests: Vec<(&String, &String)> = sent.iter().zip(&heads).filter(|(line, _)| line.starts_with("PUT /expired")).collect();
        assert_eq!(requests.len(), 2, "{how}: {sent:?}");
        // The same request twice…
        assert_eq!(requests[0].0, requests[1].0, "{how}");
        assert!(requests[0].0.starts_with("PUT /expired a,b"), "{how}: {}", requests[0].0);
        // …with the same headers but for the token.
        let common = "accept=text/csv;skipNulls=false; content-type=text/csv; authorization=Bearer ";
        assert_eq!(requests[0].1, &format!("{common}stale; x-request-map=com.heads.t"), "{how}");
        assert_eq!(requests[1].1, &format!("{common}fresh; x-request-map=com.heads.t"), "{how}");
        // The secret and the client ID reach the token endpoint form-encoded.
        let token_calls: Vec<&String> = sent.iter().filter(|line| line.contains("/oauth2/v1/token")).collect();
        assert_eq!(token_calls.len(), 2, "{how}: {sent:?}");
        assert!(token_calls[0].ends_with("grant_type=client_credentials&client_id=id+1&client_secret=s%26x%3D1%2B2%25"), "{how}: {}", token_calls[0]);
    };

    // In a batch: the request after it uses the new token straight away.
    let server = RecordingServer::start();
    credentials(&server);
    std::fs::write(d.join("o.api"), "PUT /expired @data.csv~map(com.heads.t) > out.csv\nGET /expired/again\n").unwrap();
    server.take();
    let mut cmd = api_bare(d);
    cmd.args(["-i", "-sfa", "o.api"]);
    let out = cmd.output().expect("spawn api");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    expect_retry(&server, "batch");
    let sent = server.log.lock().unwrap().clone();
    assert_eq!(sent.iter().filter(|line| line.contains("/expired/again")).count(), 1, "{sent:?}");
    assert!(std::fs::read_to_string(d.join("out.csv")).unwrap().contains("/api/v1/expired"));

    // One request.
    let server = RecordingServer::start();
    credentials(&server);
    server.take();
    let mut cmd = api_bare(d);
    cmd.args(["-i", "PUT", "/expired", "@data.csv~map(com.heads.t)", ">", "out1.csv"]);
    let out = cmd.output().expect("spawn api");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    expect_retry(&server, "one-shot");

    // At the prompt.
    let server = RecordingServer::start();
    credentials(&server);
    let mut cmd = api_bare(d);
    cmd.arg("-i");
    let mut prompt = Prompt::open(cmd);
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    server.take();
    prompt.paste("PUT /expired @data.csv~map(com.heads.t) > out2.csv");
    prompt.pump(Duration::from_millis(60));
    prompt.send(b"\r");
    prompt.wait_for("200 OK", Duration::from_secs(8));
    prompt.pump(Duration::from_millis(300));
    // The first token of this server went to the startup exchange, so here
    // the token endpoint is called once more.
    let heads = server.heads();
    let sent = server.log.lock().unwrap().clone();
    let requests: Vec<(&String, &String)> = sent.iter().zip(&heads).filter(|(line, _)| line.starts_with("PUT /expired")).collect();
    assert_eq!(requests.len(), 2, "prompt: {sent:?}\n{}", pty::plain(&prompt.screen));
    assert_eq!(requests[0].0, requests[1].0);
    let common = "accept=text/csv;skipNulls=false; content-type=text/csv; authorization=Bearer ";
    assert_eq!(requests[0].1, &format!("{common}stale; x-request-map=com.heads.t"));
    assert_eq!(requests[1].1, &format!("{common}fresh; x-request-map=com.heads.t"));
    assert!(std::fs::read_to_string(d.join("out2.csv")).unwrap().contains("/api/v1/expired"));
}

/// The prompt writes an outfile as a batch does: JSON indented, and under
/// `-f` an error is shown and not written to the file.
#[cfg(unix)]
#[test]
fn the_prompt_writes_an_outfile_as_a_batch_does() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    let one = run_in(&server, d, &["GET", "/a", ">", "batch.json"]);
    assert_eq!(one.code, Some(0), "{}", one.stderr);
    let from_batch = std::fs::read_to_string(d.join("batch.json")).unwrap();
    assert_eq!(from_batch, "{\n  \"ok\": \"/api/v1/a\"\n}");

    let mut cmd = api(server.port, d);
    cmd.arg("-f");
    let mut prompt = Prompt::open(cmd);
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    let mut enter = |prompt: &mut Prompt, line: &str, wait_for: &str| {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        let mark = prompt.screen.len();
        prompt.paste(line);
        prompt.pump(Duration::from_millis(60));
        prompt.send(b"\r");
        let start = Instant::now();
        while !plain(&prompt.screen[mark..]).contains(wait_for) && start.elapsed() < Duration::from_secs(6) {
            prompt.pump(Duration::from_millis(60));
        }
        prompt.pump(Duration::from_millis(250));
        plain(&prompt.screen[mark..])
    };

    let shown = enter(&mut prompt, "GET /a > prompt.json", "200 OK");
    assert!(shown.contains("> prompt.json"), "{shown}");
    assert_eq!(std::fs::read_to_string(d.join("prompt.json")).unwrap(), from_batch);
    // `>>` too: one indented value, then an array of two.
    enter(&mut prompt, "GET /a >> prompt2.json", "200 OK");
    assert_eq!(std::fs::read_to_string(d.join("prompt2.json")).unwrap(), from_batch);

    // Under `-f` the 404 is shown, and no file holds it.
    let shown = enter(&mut prompt, "GET /missing > error.json", "404");
    assert!(!d.join("error.json").exists(), "the error was written to the outfile\n{shown}");
    assert!(shown.contains("{}"), "{shown}");

    // A request that was never sent has no status: the one before it is not
    // reported as what stopped the block.
    let shown = enter(&mut prompt, "PUT /x @no-such-file.json\rGET /never", "File not found");
    assert!(shown.contains("File not found: no-such-file.json"), "{shown}");
    assert!(!shown.contains("stopped at 404"), "{shown}");
    assert!(!server.log.lock().unwrap().iter().any(|line| line.contains("/never")));

    // An outfile that can't be written is said, and stops a chain.
    server.take();
    let shown = enter(&mut prompt, "GET /a > no-such-dir/x.json && GET /never", "Error writing");
    assert!(shown.contains("Error writing to no-such-dir/x.json"), "{shown}");
    assert_eq!(server.log.lock().unwrap().clone(), ["GET /a"], "{shown}");
}

/// A credentials file in `dir` with these connections: `(name, url,
/// auth_type, credential, client_id)`.
fn write_credentials(dir: &Path, connections: &[(&str, String, &str, &str, &str)], default: &str) {
    let entries: Vec<String> = connections
        .iter()
        .map(|(name, url, auth_type, credential, client_id)| {
            format!(
                r#"{{"name":"{name}","url":"{url}","auth_type":"{auth_type}","credential":"{credential}","client_id":"{client_id}"}}"#
            )
        })
        .collect();
    std::fs::write(
        dir.join(".api-credentials.json"),
        format!(r#"{{"connections":[{}],"default":"{default}"}}"#, entries.join(",")),
    )
    .unwrap();
}

fn run_bare(server: &RecordingServer, dir: &Path, args: &[&str]) -> Ran {
    let mut cmd = api_bare(dir);
    cmd.args(args);
    ran(server, cmd)
}

/// The authorization of the one request a run sent.
fn authorization(server: &RecordingServer) -> String {
    let heads = server.heads();
    assert_eq!(heads.len(), 1, "{heads:?}");
    heads[0].split("authorization=").nth(1).unwrap().split(';').next().unwrap().to_string()
}

/// A saved connection is found by default, by alias and by URL, and what the
/// command line gives (`-k`, `--token`, `-b`) wins over what it has stored.
#[test]
fn flags_win_over_the_connection_chosen_with_c() {
    let server = RecordingServer::start();
    let other = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    let other_url = format!("http://127.0.0.1:{}", other.port);
    write_credentials(
        d,
        &[
            ("local", url.clone(), "key", "STOREDKEY", ""),
            ("tok", url.clone(), "token", "STOREDTOKEN", ""),
            ("oauth", url.clone(), "oauth2", "secret", "id"),
        ],
        "local",
    );
    // `:STOREDKEY` and `:CLIKEY` as Basic.
    let (stored, cli) = ("Basic OlNUT1JFREtFWQ==", "Basic OkNMSUtFWQ==");

    // Which connection.
    for (args, authorization_sent) in [
        (&["GET", "/a"][..], stored),
        (&["-c", "local", "GET", "/a"][..], stored),
        (&["-c", "tok", "GET", "/a"][..], "Bearer STOREDTOKEN"),
        (&["-c", &url, "GET", "/a"][..], stored),
        (&["-c", url.trim_start_matches("http://"), "GET", "/a"][..], stored),
        // Flags over the default connection…
        (&["-k", "CLIKEY", "GET", "/a"][..], cli),
        (&["--token", "T", "GET", "/a"][..], "Bearer T"),
        // …and over one chosen with -c, whatever kind it is.
        (&["-c", "local", "-k", "CLIKEY", "GET", "/a"][..], cli),
        (&["-c", "local", "--token", "T", "GET", "/a"][..], "Bearer T"),
        (&["-c", "tok", "-k", "CLIKEY", "GET", "/a"][..], cli),
        (&["-c", "tok", "--token", "T", "GET", "/a"][..], "Bearer T"),
        (&["-c", "oauth", "-k", "CLIKEY", "GET", "/a"][..], cli),
    ] {
        let got = run_bare(&server, d, args);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{args:?}: {}", got.stderr);
        assert_eq!(authorization(&server), authorization_sent, "{args:?}");
    }

    // `-b` sends the stored credential to another host.
    other.take();
    let got = run_bare(&server, d, &["-c", "local", "-b", &other_url, "GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 0), "{}", got.stderr);
    assert_eq!(other.log.lock().unwrap().clone(), ["GET /a"]);
    assert_eq!(authorization(&other), stored);

    // A connection that is not saved.
    let missing = run_bare(&server, d, &["-c", "nope", "GET", "/a"]);
    assert_eq!((missing.code, missing.sent.len()), (Some(1), 0));
    assert!(missing.stderr.contains("Connection \"nope\" not found. Saved connections: local, tok, oauth"), "{}", missing.stderr);

    // An entry without `client_id` is a whole entry.
    std::fs::write(
        d.join(".api-credentials.json"),
        format!(r#"{{"connections":[{{"name":"bare","url":"{url}","auth_type":"key","credential":"STOREDKEY"}}],"default":"bare"}}"#),
    )
    .unwrap();
    let bare = run_bare(&server, d, &["GET", "/a"]);
    assert_eq!((bare.code, &bare.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{}", bare.stderr);

    // A base URL is read in any case of its scheme, and without its prefix.
    for base in [url.replace("http://", "HTTP://"), format!("{url}/api/v1"), format!("{url}/")] {
        let got = run_bare(&server, d, &["-b", &base, "-k", "k", "GET", "/a"]);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{base}: {}", got.stderr);
    }
}

/// A credentials file that can't be read is said to be so, not taken for an
/// empty one, and is never written over.
#[cfg(unix)]
#[test]
fn a_malformed_credentials_file_is_reported_and_left_alone() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = d.join(".api-credentials.json");
    // One trailing comma.
    let broken = r#"{"connections":[{"name":"keep","url":"http://x","auth_type":"key","credential":"SECRET","client_id":""},],"default":"keep"}"#;
    std::fs::write(&file, broken).unwrap();

    let got = run_bare(&server, d, &["GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(1), 0));
    assert!(got.stderr.contains("WARNING: could not read"), "{}", got.stderr);
    assert!(got.stderr.contains(".api-credentials.json"), "{}", got.stderr);
    assert!(got.stderr.contains("no base URL specified"), "{}", got.stderr);

    // At the prompt, saving the connection in use does not replace the file.
    let mut prompt = Prompt::open(api(server.port, d));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    prompt.send(b"\x13");
    prompt.pump(Duration::from_millis(400));
    prompt.send(b"newone");
    prompt.pump(Duration::from_millis(200));
    prompt.send(b"\r");
    prompt.pump(Duration::from_millis(400));
    // The dialog may ask whether this is the default; either way.
    prompt.send(b"\r");
    prompt.pump(Duration::from_millis(600));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), broken, "{}", plain(&prompt.screen));
    assert!(plain(&prompt.screen).contains("left as it is"), "{}", plain(&prompt.screen));
    // ctrl+q says why there is nothing to pick from.
    prompt.send(b"\x11");
    prompt.pump(Duration::from_millis(500));
    assert_eq!(prompt.exited(), None);
    let shown = plain(&prompt.screen);
    assert!(shown.matches("could not read").count() >= 2, "{shown}");

    // A good file is still saved to, and what was in it is kept.
    write_credentials(d, &[("keep", "http://x".to_string(), "key", "SECRET", "")], "keep");
    let mut prompt = Prompt::open(api(server.port, d));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    prompt.send(b"\x13");
    prompt.pump(Duration::from_millis(400));
    prompt.send(b"newone");
    prompt.pump(Duration::from_millis(200));
    prompt.send(b"\r");
    prompt.wait_for("connection newone saved", Duration::from_secs(5));
    let saved = std::fs::read_to_string(&file).unwrap();
    assert!(saved.contains(r#""name":"keep""#) && saved.contains(r#""name":"newone""#), "{saved}");
    assert!(saved.contains(r#""default":"keep""#), "{saved}");
}

/// Switching connection with ctrl+q changes where requests go and what they
/// are signed with, and nothing else: the flags the session was started with
/// still hold.
#[cfg(unix)]
#[test]
fn switching_connection_at_the_prompt_keeps_the_flags() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    write_credentials(d, &[("other", url.clone(), "key", "STOREDKEY", "")], "");

    let mut cmd = api(server.port, d);
    cmd.args(["-i", "-f"]);
    let mut prompt = Prompt::open(cmd);
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    let mut get = |prompt: &mut Prompt, line: &str| {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        prompt.paste(line);
        prompt.pump(Duration::from_millis(60));
        prompt.send(b"\r");
        let start = Instant::now();
        while server.seen() == 0 && start.elapsed() < Duration::from_secs(5) {
            prompt.pump(Duration::from_millis(50));
        }
        prompt.pump(Duration::from_millis(250));
        server.heads()
    };
    let before = get(&mut prompt, "GET /a");
    assert_eq!(before, ["accept=application/json;skipNulls=false; content-type=application/json; authorization=Basic Oms=; x-request-map=-"]);

    prompt.send(b"\x11");
    prompt.wait_for("other", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\r");
    prompt.wait_for("connected to: other", Duration::from_secs(8));
    prompt.pump(Duration::from_millis(600));

    // `-i` still holds, and the stored key signs the request.
    let after = get(&mut prompt, "GET /a");
    assert_eq!(
        after,
        ["accept=application/json;skipNulls=false; content-type=application/json; authorization=Basic OlNUT1JFREtFWQ==; x-request-map=-"],
        "{}",
        plain(&prompt.screen)
    );
    // `-f` still holds: a pasted block stops at the 404.
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    server.take();
    prompt.paste("GET /missing\rGET /never");
    prompt.pump(Duration::from_millis(60));
    prompt.send(b"\r");
    prompt.wait_for("stopped at 404 (--fail-fast)", Duration::from_secs(6));
    assert_eq!(server.log.lock().unwrap().clone(), ["GET /missing"]);
}

/// A batch or a program line never opens the "New connection" form, even at
/// a terminal with a URL and no credential: it runs, as one request does.
#[cfg(unix)]
#[test]
fn a_batch_without_a_credential_runs_and_opens_no_form() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("one.api"), "GET /from-file\n").unwrap();
    let url = format!("http://127.0.0.1:{}", server.port);

    for (args, sent) in [
        (&["-b", &url, "-sa", "one.api"][..], &["GET /from-file"][..]),
        (&["-b", &url, "GET /x && GET /y"][..], &["GET /x", "GET /y"][..]),
        (&["-b", &url, "GET", "/z"][..], &["GET /z"][..]),
    ] {
        server.take();
        let mut cmd = api_bare(d);
        cmd.args(args);
        let mut prompt = Prompt::open(cmd);
        let start = Instant::now();
        while prompt.exited().is_none() && start.elapsed() < Duration::from_secs(8) {
            prompt.pump(Duration::from_millis(100));
        }
        let shown = plain(&prompt.screen);
        assert_eq!(prompt.exited(), Some(true), "{args:?}: still running\n{shown}");
        assert!(!shown.contains("API key:"), "{args:?}: the form was opened\n{shown}");
        assert_eq!(server.log.lock().unwrap().clone(), sent, "{args:?}\n{shown}");
    }
}

/// An OAuth2 connection whose token can't be fetched ends a batch with the
/// reason. At the prompt the connection dialog says so and stays.
#[cfg(unix)]
#[test]
fn a_failed_token_exchange_does_not_end_the_prompt() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // Nothing listens on the port of the OAuth2 connection.
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    write_credentials(d, &[("gone", format!("http://127.0.0.1:{dead}"), "oauth2", "secret", "id")], "");

    let batch = run_bare(&server, d, &["-c", "gone", "GET", "/a"]);
    assert_eq!((batch.code, batch.sent.len()), (Some(1), 0));
    assert!(batch.stderr.contains("OAuth2 token exchange failed"), "{}", batch.stderr);

    let mut prompt = Prompt::open(api(server.port, d));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    prompt.send(b"\x11");
    prompt.wait_for("gone", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\r");
    prompt.wait_for("OAuth2 token exchange failed", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(300));
    assert_eq!(prompt.exited(), None, "the client ended:\n{}", plain(&prompt.screen));
    // Esc leaves the dialog, and the session is the one it was.
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(500));
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    server.take();
    prompt.paste("GET /still-here");
    prompt.pump(Duration::from_millis(60));
    prompt.send(b"\r");
    prompt.wait_for("200 OK", Duration::from_secs(6));
    assert_eq!(server.log.lock().unwrap().clone(), ["GET /still-here"]);
}

/// A request from an imported file is logged as its line has it, with the
/// `@file` path as written and not the path the import resolved it to. And
/// an `@file` that is a link leading out of an imported directory is refused,
/// as an include through such a link is.
#[cfg(unix)]
#[test]
fn an_imported_file_body_is_logged_as_written_and_stays_inside() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    prepare(d);
    std::fs::write(d.join("main.api"), "import dir d {\"path\":\"libdir\"}\nd/d.api\n").unwrap();

    let batch = run_in(&server, d, &["-sa", "main.api"]);
    assert_eq!(batch.code, Some(0), "{}", batch.stderr);
    assert_eq!(batch.sent, ["GET /dir1", r#"PUT /dir2 {"from":"dir"}"#]);
    assert!(batch.stdout.contains("\nPUT /dir2 @body.json\n"), "{}", batch.stdout);
    assert!(!batch.stdout.contains("libdir/body.json"), "{}", batch.stdout);

    // The preview shows the same line.
    let preview = ask(&server, d, &["-spa", "main.api"], Some("n\n"));
    assert!(preview.stderr.contains("  PUT /dir2 @body.json\n"), "{}", preview.stderr);
    assert!(preview.sent.is_empty());

    // A file of the import that is a link to one outside it.
    std::fs::write(d.join("outside.json"), r#"{"secret":"outside"}"#).unwrap();
    std::os::unix::fs::symlink(d.join("outside.json"), d.join("libdir/link.json")).unwrap();
    std::fs::write(d.join("libdir/leak.api"), "PUT /leak @link.json\n").unwrap();
    std::fs::write(d.join("leak.api"), "import dir d {\"path\":\"libdir\"}\nGET /first\nd/leak.api\n").unwrap();
    let leak = run_in(&server, d, &["-sa", "leak.api"]);
    assert_eq!((leak.code, leak.sent.len()), (Some(1), 0), "{}", leak.stderr);
    assert!(leak.stderr.contains("`@link.json` must be a relative path inside the import"), "{}", leak.stderr);

    // A link that stays inside is a file like any other.
    std::fs::remove_file(d.join("libdir/link.json")).unwrap();
    std::os::unix::fs::symlink(d.join("libdir/body.json"), d.join("libdir/link.json")).unwrap();
    let inside = run_in(&server, d, &["-sa", "leak.api"]);
    assert_eq!(inside.code, Some(0), "{}", inside.stderr);
    assert_eq!(inside.sent, ["GET /first", r#"PUT /leak {"from":"dir"}"#]);
}

/// A body of several lines sent from the prompt is one entry of the history
/// file, which is the user's alone.
#[cfg(unix)]
#[test]
fn the_history_file_keeps_a_multi_line_entry_on_one_line() {
    use pty::Prompt;
    use std::os::unix::fs::PermissionsExt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let history = d.join(".api_history");
    {
        let mut prompt = Prompt::open(api(server.port, d));
        prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
        prompt.pump(Duration::from_millis(500));
        for line in ["GET /one", "PUT /two {\r  \"a\": 1\r}"] {
            prompt.send(b"\x15");
            prompt.pump(Duration::from_millis(60));
            server.take();
            prompt.paste(line);
            prompt.pump(Duration::from_millis(80));
            prompt.send(b"\r");
            let start = Instant::now();
            while server.seen() == 0 && start.elapsed() < Duration::from_secs(5) {
                prompt.pump(Duration::from_millis(50));
            }
            prompt.pump(Duration::from_millis(200));
        }
    }
    let text = std::fs::read_to_string(&history).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text:?}");
    assert_eq!(lines[0], "GET /one");
    assert!(lines[1].starts_with("PUT /two {") && lines[1].ends_with('}'), "{text:?}");
    assert_eq!(std::fs::metadata(&history).unwrap().permissions().mode() & 0o777, 0o600);

    // The next session has both, the second one whole: Up brings it back
    // and Enter sends it again.
    let mut prompt = Prompt::open(api(server.port, d));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    server.take();
    prompt.send(b"\x1b[A");
    prompt.pump(Duration::from_millis(200));
    prompt.send(b"\r");
    let start = Instant::now();
    while server.seen() == 0 && start.elapsed() < Duration::from_secs(5) {
        prompt.pump(Duration::from_millis(50));
    }
    assert_eq!(server.take(), ["PUT /two {\n  \"a\": 1\n}"]);
}

/// Stdin is the body of a one-shot request that takes a body and was given
/// none. A GET leaves it alone, and so can be answered a `-p` from it; a PUT
/// under `-p` with no terminal would need stdin twice and says so.
#[cfg(unix)]
#[test]
fn a_one_shot_reads_stdin_only_as_a_body_it_needs() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();

    let put = ask(&server, dir.path(), &["PUT", "/a"], Some(r#"{"x":1}"#));
    assert_eq!((put.code, &put.sent[..]), (Some(0), &[r#"PUT /a {"x":1}"#.to_string()][..]), "{}", put.stderr);

    // A GET sends no piped body.
    let get = ask(&server, dir.path(), &["GET", "/a"], Some("not a body"));
    assert_eq!((get.code, &get.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{}", get.stderr);
    let delete = ask(&server, dir.path(), &["DELETE", "/a"], Some("not a body"));
    assert_eq!((delete.code, &delete.sent[..]), (Some(0), &["DELETE /a".to_string()][..]), "{}", delete.stderr);

    // `-p` on a GET is answered from the pipe.
    let yes = ask(&server, dir.path(), &["-p", "GET", "/a"], Some("y\n"));
    assert_eq!((yes.code, &yes.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{}", yes.stderr);
    assert!(yes.stderr.contains("  GET /a\n"), "{}", yes.stderr);
    let no = ask(&server, dir.path(), &["-p", "GET", "/a"], Some("n\n"));
    assert_eq!((no.code, no.sent.len()), (Some(0), 0), "{}", no.stderr);
    let unanswered = ask(&server, dir.path(), &["-p", "GET", "/a"], Some(""));
    assert_eq!((unanswered.code, unanswered.sent.len()), (Some(1), 0), "{}", unanswered.stderr);
    assert!(unanswered.stderr.contains(UNANSWERED), "{}", unanswered.stderr);

    // A PUT under `-p`: stdin can't be the body and the answer.
    let both = ask(&server, dir.path(), &["-p", "PUT", "/a"], Some(r#"{"x":1}"#));
    assert_eq!((both.code, both.sent.len()), (Some(1), 0), "{}", both.stderr);
    assert!(both.stderr.contains("the body can't come from stdin too"), "{}", both.stderr);
    // With the body as an argument, the pipe is the answer.
    let split = ask(&server, dir.path(), &["-p", "PUT", "/a", r#"{"x":1}"#], Some("y\n"));
    assert_eq!((split.code, &split.sent[..]), (Some(0), &[r#"PUT /a {"x":1}"#.to_string()][..]), "{}", split.stderr);
}

/// A GET does not wait for a stdin that stays open, and leaves it for
/// whoever reads next (a `while read` loop around the client).
#[test]
fn a_get_does_not_wait_for_an_open_stdin() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    server.take();
    let mut child = api(server.port, dir.path())
        .args(["GET", "/a"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn api");
    // The pipe is held open and nothing is written to it.
    let held = child.stdin.take().unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if start.elapsed() > Duration::from_secs(10) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if status.is_none() {
        let _ = child.kill();
    }
    drop(held);
    assert!(status.is_some_and(|s| s.success()), "the client waited for stdin");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    assert_eq!(server.take(), ["GET /a"]);
}

/// A file saved by an editor that puts a byte order mark in front of it
/// (Windows Notepad), with CRLF line ends, runs as the same file without.
#[test]
fn a_file_with_a_byte_order_mark_and_crlf_runs() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("inc.api"), "\u{feff}GET /inc\r\n").unwrap();
    std::fs::write(dir.path().join("bom.api"), "\u{feff}GET /a\r\ninc.api\r\nPUT /b {\"x\":1}\r\n").unwrap();
    let (got, shown) = run_cli(&server, dir.path(), &["-sa".to_string(), "bom.api".to_string()]);
    assert!(got.exit_ok, "{shown}");
    assert_eq!(got.sent, ["GET /a", "GET /inc", r#"PUT /b {"x":1}"#], "{shown}");

    // The same file on stdin.
    server.take();
    let out = api(server.port, dir.path())
        .args(["-sa", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all("\u{feff}GET /a\r\n".as_bytes())?;
            child.wait_with_output()
        })
        .expect("spawn api");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    assert!(out.status.success());
    assert_eq!(server.take(), ["GET /a"]);
}

/// A reader that stops reading (`api -sa seed.api | head -1`) does not stop
/// the batch: every request is still sent, and the exit code is the one the
/// requests earned.
#[test]
fn a_batch_keeps_running_when_its_stdout_is_closed() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let lines: String = (1..=6).map(|i| format!("GET /six{i}\n")).collect();
    std::fs::write(dir.path().join("six.api"), lines).unwrap();

    for args in [&["-sa", "six.api"][..], &["-a", "six.api"][..]] {
        server.take();
        let mut child = api(server.port, dir.path())
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn api");
        // Read one byte and hang up, as `head` does once it has its lines.
        let mut stdout = child.stdout.take().unwrap();
        let mut one = [0u8; 1];
        let _ = stdout.read(&mut one);
        drop(stdout);
        let out = child.wait_with_output().expect("wait");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
        assert_eq!(out.status.code(), Some(0), "{args:?}: {stderr}");
        assert_eq!(
            server.take(),
            ["GET /six1", "GET /six2", "GET /six3", "GET /six4", "GET /six5", "GET /six6"],
            "{args:?}: {stderr}"
        );
    }

    // One request whose reader is already gone: sent, and no panic.
    server.take();
    let mut child = api(server.port, dir.path())
        .args(["GET", "/alone"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn api");
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("wait");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(server.take(), ["GET /alone"]);

    // `-f` still ends a run with exit 1 when nobody reads the body it prints.
    std::fs::write(dir.path().join("fails.api"), "GET /a\nGET /missing\nGET /never\n").unwrap();
    server.take();
    let mut child = api(server.port, dir.path())
        .args(["-sfa", "fails.api"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn api");
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("wait");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(server.take(), ["GET /a", "GET /missing"]);
}

/// A value an option can't take is reported with the option it was for.
#[test]
fn a_bad_option_value_names_its_option() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let args: Vec<String> = ["--timeout", "abc", "GET", "/a"].iter().map(|s| s.to_string()).collect();
    let (got, shown) = run_cli(&server, dir.path(), &args);
    assert!(!got.exit_ok);
    assert!(got.sent.is_empty());
    assert!(shown.contains("error: invalid value for --timeout: abc"), "{shown}");
    assert!(!shown.contains("unexpected option"), "{shown}");
}

/// What a confirmation run did: what the server received, the exit code, stderr.
#[cfg(unix)]
struct Asked {
    sent: Vec<String>,
    code: Option<i32>,
    stderr: String,
}

/// Run the client where a question can only be answered from stdin: in a
/// session of its own (`setsid`), so `/dev/tty` does not open even when
/// `cargo test` was started in a terminal. `stdin` is what the question finds
/// there; `None` is nothing at all (`/dev/null`).
#[cfg(unix)]
fn ask(server: &RecordingServer, dir: &Path, args: &[&str], stdin: Option<&str>) -> Asked {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    server.take();
    let mut cmd = api(server.port, dir);
    cmd.args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn api");
    if let Some(text) = stdin {
        child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().expect("api runs");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    Asked {
        sent: server.take(),
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

#[cfg(unix)]
const UNANSWERED: &str = "aborted (could not read confirmation)";

/// `-p` asks before sending. End of input is nobody answering, not Enter:
/// nothing is sent and the run fails. An empty line still accepts.
#[cfg(unix)]
#[test]
fn a_preview_nobody_answered_sends_nothing() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("p.api"), "GET /a\n").unwrap();
    let none: [&str; 0] = [];

    // A file and a single request, with nothing on stdin and with an empty pipe.
    for args in [&["-spa", "p.api"][..], &["-sp", "GET", "/a"]] {
        for stdin in [None, Some("")] {
            let ran = ask(&server, dir.path(), args, stdin);
            assert_eq!(ran.sent, none, "{args:?} {stdin:?}");
            assert!(ran.stderr.contains(UNANSWERED), "{args:?} {stdin:?}: {}", ran.stderr);
            assert_eq!(ran.code, Some(1), "{args:?} {stdin:?}: {}", ran.stderr);
        }
    }

    // A person declining is not a failure.
    let ran = ask(&server, dir.path(), &["-spa", "p.api"], Some("n\n"));
    assert_eq!(ran.sent, none);
    assert!(ran.stderr.contains("aborted") && !ran.stderr.contains(UNANSWERED), "{}", ran.stderr);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);

    // Enter, `y` and `yes` accept.
    for answer in ["\n", "y\n", "yes\n"] {
        let ran = ask(&server, dir.path(), &["-spa", "p.api"], Some(answer));
        assert_eq!(ran.sent, ["GET /a"], "{answer:?}: {}", ran.stderr);
        assert_eq!(ran.code, Some(0), "{answer:?}: {}", ran.stderr);
    }
}

/// The `confirm` directive is the same question in the middle of a file.
#[cfg(unix)]
#[test]
fn a_confirm_nobody_answered_stops_the_batch() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    const PROGRAM: &str = "GET /before\nconfirm Really?\nGET /after\n";
    std::fs::write(dir.path().join("c.api"), PROGRAM).unwrap();

    for stdin in [None, Some("")] {
        let ran = ask(&server, dir.path(), &["-sa", "c.api"], stdin);
        assert_eq!(ran.sent, ["GET /before"], "{stdin:?}");
        assert!(ran.stderr.contains(UNANSWERED), "{stdin:?}: {}", ran.stderr);
        assert_eq!(ran.code, Some(1), "{stdin:?}: {}", ran.stderr);
    }

    let ran = ask(&server, dir.path(), &["-sa", "c.api"], Some("n\n"));
    assert_eq!(ran.sent, ["GET /before"]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);

    let ran = ask(&server, dir.path(), &["-sa", "c.api"], Some("\n"));
    assert_eq!(ran.sent, ["GET /before", "GET /after"], "{}", ran.stderr);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);

    // The program itself on stdin: it was read to its end, so its `confirm`
    // finds end of input and can't be answered.
    let ran = ask(&server, dir.path(), &["-sa", "-"], Some(PROGRAM));
    assert_eq!(ran.sent, ["GET /before"]);
    assert!(ran.stderr.contains(UNANSWERED), "{}", ran.stderr);
    assert_eq!(ran.code, Some(1), "{}", ran.stderr);
}

/// A run asks as often as it has questions, and each answer is one line of
/// stdin: `yes |` answers them all, and a run that is given fewer answers
/// than it has questions stops at the first one left open.
#[cfg(unix)]
#[test]
fn every_question_of_a_run_takes_its_own_answer() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("q.api"), "GET /a\nconfirm One\nGET /b\nconfirm Two\nGET /c\n").unwrap();

    // The preview and both confirms, answered.
    let ran = ask(&server, dir.path(), &["-spa", "q.api"], Some("y\n\nyes\n"));
    assert_eq!(ran.sent, ["GET /a", "GET /b", "GET /c"], "{}", ran.stderr);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);

    // What `yes |` writes: more answers than questions.
    let ran = ask(&server, dir.path(), &["-spa", "q.api"], Some(&"y\n".repeat(50)));
    assert_eq!(ran.sent, ["GET /a", "GET /b", "GET /c"], "{}", ran.stderr);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);

    // One answer short: the second confirm finds end of input.
    let ran = ask(&server, dir.path(), &["-spa", "q.api"], Some("y\ny\n"));
    assert_eq!(ran.sent, ["GET /a", "GET /b"], "{}", ran.stderr);
    assert!(ran.stderr.contains(UNANSWERED), "{}", ran.stderr);
    assert_eq!(ran.code, Some(1), "{}", ran.stderr);

    // A "no" at the second question: what ran before it stays run, exit 0.
    let ran = ask(&server, dir.path(), &["-spa", "q.api"], Some("y\nn\n"));
    assert_eq!(ran.sent, ["GET /a"], "{}", ran.stderr);
    assert!(!ran.stderr.contains(UNANSWERED), "{}", ran.stderr);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);

    // Anything that is not Enter, `y` or `yes` declines, in any case.
    for answer in ["no\n", "x\n", "yess\n", "  N  \n"] {
        let ran = ask(&server, dir.path(), &["-spa", "q.api"], Some(answer));
        assert_eq!(ran.sent, Vec::<String>::new(), "{answer:?}");
        assert_eq!(ran.code, Some(0), "{answer:?}: {}", ran.stderr);
    }
    for answer in ["Y\n", "YES\n", " y \n", "y"] {
        let ran = ask(&server, dir.path(), &["-sa", "q.api"], Some(&format!("{answer}\ny\n")));
        assert_eq!(ran.sent, ["GET /a", "GET /b", "GET /c"], "{answer:?}: {}", ran.stderr);
    }
}

/// The question is the same without `-s`, and with stdin closed outright.
#[cfg(unix)]
#[test]
fn an_unanswered_question_stops_a_plain_batch_and_one_with_stdin_closed() {
    use std::os::unix::process::CommandExt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("p.api"), "GET /a\n").unwrap();
    std::fs::write(dir.path().join("c.api"), "GET /before\nconfirm\nGET /after\n").unwrap();

    for (args, sent) in [(&["-pa", "p.api"][..], &[][..]), (&["-a", "c.api"], &["GET /before"]), (&["-p", "GET", "/a"], &[])] {
        let ran = ask(&server, dir.path(), args, None);
        assert_eq!(ran.sent, sent, "{args:?}");
        assert!(ran.stderr.contains(UNANSWERED), "{args:?}: {}", ran.stderr);
        assert_eq!(ran.code, Some(1), "{args:?}: {}", ran.stderr);
    }
    // The default prompt of a bare `confirm`.
    let ran = ask(&server, dir.path(), &["-sa", "c.api"], Some("n\n"));
    assert!(ran.stderr.contains("Continue? [Y/n]"), "{}", ran.stderr);

    // `<&-`: no descriptor 0 at all.
    for (args, sent) in [(&["-spa", "p.api"][..], &[][..]), (&["-sa", "c.api"], &["GET /before"])] {
        server.take();
        let mut cmd = api(server.port, dir.path());
        cmd.args(args).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                libc::close(0);
                Ok(())
            });
        }
        let out = cmd.output().expect("spawn api");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(server.take(), sent, "{args:?}: {stderr}");
        assert!(stderr.contains(UNANSWERED), "{args:?}: {stderr}");
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
    }
}

/// The preview lists every step of the program as it will run, counts only
/// the requests among them, and sends none of it when declined.
#[cfg(unix)]
#[test]
fn the_preview_lists_directives_and_chains_and_counts_only_requests() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("d.api"),
        "GET /a && PUT /b {\"x\":1} || GET /c\nsleep 1.5s\nsleep 2 while not GET /d~count\nassert not GET /e\nconfirm Go on\nconfirm\nDELETE /f\n",
    )
    .unwrap();
    let ran = ask(&server, dir.path(), &["-spa", "d.api"], Some("n\n"));
    assert_eq!(ran.sent, Vec::<String>::new());
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    let lines: Vec<&str> = ran.stderr.lines().map(str::trim_end).collect();
    assert_eq!(
        &lines[..9],
        [
            &format!("Preview — 4 requests | GET PUT DELETE [http://127.0.0.1:{}]", server.port)[..],
            "  GET /a",
            "  && PUT /b {\"x\":1}",
            "  || GET /c",
            "  sleep 1.5s",
            "  sleep 2s while not GET /d~count",
            "  assert not GET /e",
            "  confirm Go on",
            "  confirm",
        ],
        "{}",
        ran.stderr
    );
    assert!(lines[9..].iter().any(|l| l.trim() == "DELETE /f"), "{}", ran.stderr);

    // A program with no request in it says so and still asks.
    std::fs::write(dir.path().join("s.api"), "sleep 10ms\n").unwrap();
    let ran = ask(&server, dir.path(), &["-spa", "s.api"], Some("n\n"));
    assert!(ran.stderr.starts_with("Preview — 0 requests ["), "{}", ran.stderr);
    assert!(ran.stderr.contains("  sleep 10ms") && ran.stderr.contains("Run? [Y/n]"), "{}", ran.stderr);

    // One request, singular.
    let ran = ask(&server, dir.path(), &["-sp", "PUT", "/x", "{\"a\":1}"], Some("n\n"));
    assert!(ran.stderr.starts_with("Preview — 1 request | PUT ["), "{}", ran.stderr);
    assert_eq!(ran.sent, Vec::<String>::new());

    // An outfile is shown where it is written, behind the body, in the
    // preview and in the log of the run: as the prompt logs it.
    std::fs::write(dir.path().join("o.api"), "PUT /f {\"y\": 2} > out.json\nGET /a && PUT /b {\"x\":1} >> more.json\n").unwrap();
    let ran = ask(&server, dir.path(), &["-spa", "o.api"], Some("n\n"));
    for line in ["  PUT /f {\"y\":2} > out.json\n", "  GET /a\n", "  && PUT /b {\"x\":1} >> more.json\n"] {
        assert!(ran.stderr.contains(line), "{line:?} not in\n{}", ran.stderr);
    }
    let ran = ask(&server, dir.path(), &["-sp", "PUT", "/f", "{\"y\":2}", ">", "out.json"], Some("n\n"));
    assert!(ran.stderr.contains("  PUT /f {\"y\":2} > out.json\n"), "{}", ran.stderr);
    let out = api(server.port, dir.path()).args(["-sa", "o.api"]).output().expect("spawn api");
    let log = String::from_utf8_lossy(&out.stdout);
    for line in ["\nPUT /f {\"y\":2} > out.json\n", "\nPUT /b {\"x\":1} >> more.json\n"] {
        assert!(log.contains(line), "{line:?} not in\n{log}");
    }
    assert!(dir.path().join("out.json").is_file() && dir.path().join("more.json").is_file());

    // Accepted once, the preview is not asked again per request.
    std::fs::write(dir.path().join("two.api"), "GET /a\nGET /b\n").unwrap();
    let ran = ask(&server, dir.path(), &["-spa", "two.api"], Some("y\n"));
    assert_eq!(ran.sent, ["GET /a", "GET /b"], "{}", ran.stderr);
    assert_eq!(ran.stderr.matches("Run? [Y/n]").count(), 1, "{}", ran.stderr);
}

/// A batch run in a terminal, to its end. Returns what the terminal showed
/// and whether the client ended well.
#[cfg(unix)]
fn batch_in_a_terminal(cmd: std::process::Command, wait_for: &str, keys: &[u8]) -> (String, Option<bool>) {
    let mut term = pty::Prompt::open(cmd);
    if !wait_for.is_empty() {
        term.wait_for(wait_for, Duration::from_secs(15));
        term.send(keys);
    }
    let start = Instant::now();
    let mut ended = None;
    while ended.is_none() && start.elapsed() < Duration::from_secs(15) {
        term.pump(Duration::from_millis(50));
        ended = term.exited();
    }
    term.pump(Duration::from_millis(100));
    (pty::plain(&term.screen), ended)
}

/// At a terminal the answer comes from the terminal: Enter accepts, `n`
/// declines, and ctrl+D, which ends the input without a line, is nobody
/// answering.
#[cfg(unix)]
#[test]
fn at_a_terminal_ctrl_d_is_no_answer_and_enter_still_accepts() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("p.api"), "GET /a\n").unwrap();
    std::fs::write(dir.path().join("c.api"), "GET /before\nconfirm Really?\nGET /after\n").unwrap();

    let run = |args: &[&str], question: &str, keys: &[u8]| {
        server.take();
        let mut cmd = api(server.port, dir.path());
        cmd.args(args);
        let (shown, ended) = batch_in_a_terminal(cmd, question, keys);
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        (server.take(), ended, shown)
    };
    let none: [&str; 0] = [];

    let (sent, ended, shown) = run(&["-spa", "p.api"], "Run? [Y/n]", b"\x04");
    assert_eq!(sent, none, "{shown}");
    assert!(shown.contains(UNANSWERED), "{shown}");
    assert_eq!(ended, Some(false), "{shown}");

    let (sent, ended, shown) = run(&["-spa", "p.api"], "Run? [Y/n]", b"\r");
    assert_eq!(sent, ["GET /a"], "{shown}");
    assert_eq!(ended, Some(true), "{shown}");

    let (sent, ended, shown) = run(&["-spa", "p.api"], "Run? [Y/n]", b"n\r");
    assert_eq!(sent, none, "{shown}");
    assert!(shown.contains("aborted") && !shown.contains(UNANSWERED), "{shown}");
    assert_eq!(ended, Some(true), "{shown}");

    let (sent, ended, shown) = run(&["-sa", "c.api"], "Really? [Y/n]", b"\x04");
    assert_eq!(sent, ["GET /before"], "{shown}");
    assert!(shown.contains(UNANSWERED), "{shown}");
    assert_eq!(ended, Some(false), "{shown}");

    let (sent, ended, shown) = run(&["-sa", "c.api"], "Really? [Y/n]", b"y\r");
    assert_eq!(sent, ["GET /before", "GET /after"], "{shown}");
    assert_eq!(ended, Some(true), "{shown}");
}

/// Colour is for a terminal. Whether there is one is asked of the standard
/// library (`IsTerminal`) since `atty` went: a run at a terminal is coloured
/// and does not wait on the terminal for a body, a captured one is plain.
#[cfg(unix)]
#[test]
fn output_is_coloured_at_a_terminal_and_plain_when_captured() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("p.api"), "GET /a\nPUT /b {\"x\":1}\n").unwrap();

    for args in [&["GET", "/a"][..], &["-a", "p.api"], &["-sa", "p.api"]] {
        // Captured, and nothing in the environment asking for colour or against it.
        server.take();
        let out = api(server.port, dir.path())
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR_FORCE")
            .args(args)
            .output()
            .expect("spawn api");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        assert!(out.status.success(), "{args:?}");
        assert!(!server.take().is_empty(), "{args:?}");
        let captured = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(captured.contains("200 OK"), "{args:?}: {captured}");
        assert!(!captured.contains('\x1b'), "{args:?}: escape sequences in captured output:\n{captured:?}");

        // At a terminal: the same lines, coloured. It ends by itself, so it
        // did not sit reading the terminal for a request body.
        server.take();
        let mut cmd = api(server.port, dir.path());
        cmd.args(args);
        let mut term = pty::Prompt::open(cmd);
        let start = Instant::now();
        let mut ended = None;
        while ended.is_none() && start.elapsed() < Duration::from_secs(15) {
            term.pump(Duration::from_millis(50));
            ended = term.exited();
        }
        term.pump(Duration::from_millis(100));
        assert_eq!(ended, Some(true), "{args:?}:\n{}", term.screen);
        assert!(!server.take().is_empty(), "{args:?}");
        assert!(pty::plain(&term.screen).contains("200 OK"), "{args:?}:\n{}", term.screen);
        assert!(term.screen.contains("\x1b["), "{args:?}: no colour at a terminal:\n{:?}", term.screen);
    }
}

/// The terminal is asked even when stdin is the program: with a terminal a
/// `confirm` in a program read from stdin can be answered.
#[cfg(unix)]
#[test]
fn a_program_on_stdin_asks_the_terminal() {
    use std::os::unix::process::CommandExt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("c.api");
    std::fs::write(&program, "GET /before\nconfirm Really?\nGET /after\n").unwrap();

    // A terminal of its own to be the controlling one, and the file on stdin.
    let (mut master, mut slave) = (0, 0);
    assert_eq!(unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) }, 0);
    let mut cmd = api(server.port, dir.path());
    cmd.args(["-sa", "-"])
        .stdin(std::fs::File::open(&program).unwrap())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            libc::ioctl(slave, libc::TIOCSCTTY as _, 0);
            libc::close(slave);
            libc::close(master);
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn api");
    // Answer once the question is on stderr: what is typed into a terminal
    // before the client has opened it is dropped.
    let mut errors = child.stderr.take().unwrap();
    let mut stderr = String::new();
    let mut buf = [0u8; 1024];
    while !stderr.contains("Really? [Y/n]") {
        let n = errors.read(&mut buf).expect("read stderr");
        assert!(n > 0, "the client ended without asking: {stderr}");
        stderr.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    assert_eq!(unsafe { libc::write(master, b"y\n".as_ptr() as *const _, 2) }, 2);
    // And read the echo back: on macOS the line is not handed to the reader
    // while its echo sits unread in the terminal.
    let mut echo = [0u8; 16];
    assert!(unsafe { libc::read(master, echo.as_mut_ptr() as *mut _, echo.len()) } > 0, "no echo");
    errors.read_to_string(&mut stderr).expect("read stderr");
    let status = child.wait().expect("api runs");
    unsafe {
        libc::close(slave);
        libc::close(master);
    }
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    assert_eq!(server.take(), ["GET /before", "GET /after"], "{stderr}");
    assert!(status.success(), "{stderr}");
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
        /// The bytes of a character that a read ended in the middle of.
        partial: Vec<u8>,
    }

    impl Prompt {
        pub fn open(cmd: std::process::Command) -> Self {
            Self::open_sized(cmd, 200)
        }

        /// The prompt in a terminal `cols` wide.
        pub fn open_sized(cmd: std::process::Command, cols: u16) -> Self {
            Self::open_with(cmd, cols, 50)
        }

        /// The prompt in a terminal `cols` wide and `rows` high.
        pub fn open_with(mut cmd: std::process::Command, cols: u16, rows: u16) -> Self {
            let (mut master, mut slave) = (0, 0);
            let mut size = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
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
            Prompt { master, child, screen: String::new(), partial: Vec::new() }
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
                // A read can end inside a character (`─` is three bytes).
                // Keep such a tail for the next read: decoded on its own it
                // would be three replacement characters where one `─` stood.
                self.partial.extend_from_slice(chunk);
                let whole = match std::str::from_utf8(&self.partial) {
                    Ok(_) => self.partial.len(),
                    Err(e) if e.error_len().is_none() => e.valid_up_to(),
                    Err(_) => self.partial.len(),
                };
                let rest = self.partial.split_off(whole);
                self.screen.push_str(&String::from_utf8_lossy(&self.partial));
                self.partial = rest;
            }
        }

        /// Whether the client has ended, and if so whether it ended well.
        pub fn exited(&mut self) -> Option<bool> {
            self.child.try_wait().expect("wait for api").map(|status| status.success())
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
            // A process can't finish exiting while its terminal still holds
            // output that nobody read (macOS waits for it to drain). So the
            // output is read away until the client is gone, and the terminal
            // is closed before the last wait.
            let start = Instant::now();
            while matches!(self.child.try_wait(), Ok(None)) && start.elapsed() < Duration::from_secs(5) {
                self.pump(Duration::from_millis(20));
            }
            unsafe { libc::close(self.master) };
            let _ = self.child.wait();
        }
    }

    /// What a terminal `cols` wide shows after `output`: one string per row,
    /// without trailing blanks. `plain` gives the text that was written;
    /// this gives where it ended up, which is what a layout has to be judged
    /// on. It is as much of a terminal as the client uses: text, CR and LF,
    /// relative cursor moves, erase in line and in display, saved cursor
    /// positions, and auto-wrap switched on and off. Colours are dropped.
    pub fn rows(output: &str, cols: usize) -> Vec<String> {
        let mut grid: Vec<Vec<char>> = vec![Vec::new()];
        let (mut row, mut col) = (0usize, 0usize);
        let mut saved = (0usize, 0usize);
        let mut wrap = true;
        let mut chars = output.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\x1b' => match chars.next() {
                    Some('[') => {
                        let mut params = String::new();
                        let mut last = ' ';
                        for d in chars.by_ref() {
                            if ('\x40'..='\x7e').contains(&d) {
                                last = d;
                                break;
                            }
                            params.push(d);
                        }
                        let given: Option<usize> = params.split(';').next().and_then(|p| p.parse().ok());
                        let count = given.unwrap_or(1).max(1);
                        match last {
                            'A' => row = row.saturating_sub(count),
                            'B' => row += count,
                            'C' => col = (col + count).min(cols.saturating_sub(1)),
                            'D' => col = col.saturating_sub(count),
                            'G' => col = count - 1,
                            'J' if given.unwrap_or(0) == 0 => {
                                grid[row].truncate(col);
                                grid.truncate(row + 1);
                            }
                            'K' if given.unwrap_or(0) == 2 => grid[row].clear(),
                            'K' => grid[row].truncate(col),
                            'h' | 'l' if params == "?7" => wrap = last == 'h',
                            _ => {}
                        }
                    }
                    // An operating system command runs to a BEL or to ESC \.
                    Some(']') => {
                        while let Some(d) = chars.next() {
                            if d == '\x07' || (d == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                                break;
                            }
                        }
                    }
                    Some('7') => saved = (row, col),
                    Some('8') => (row, col) = saved,
                    _ => {}
                },
                '\r' => col = 0,
                '\n' => row += 1,
                c if c.is_control() => {}
                c => {
                    if col >= cols {
                        if wrap {
                            row += 1;
                            col = 0;
                        } else {
                            col = cols.saturating_sub(1);
                        }
                    }
                    while grid.len() <= row {
                        grid.push(Vec::new());
                    }
                    while grid[row].len() < col {
                        grid[row].push(' ');
                    }
                    if col < grid[row].len() {
                        grid[row][col] = c;
                    } else {
                        grid[row].push(c);
                    }
                    col += 1;
                }
            }
            while grid.len() <= row {
                grid.push(Vec::new());
            }
        }
        let mut rows: Vec<String> =
            grid.iter().map(|cells| cells.iter().collect::<String>().trim_end().to_string()).collect();
        while rows.last().is_some_and(|last| last.is_empty()) {
            rows.pop();
        }
        rows
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

/// `--export` rewrites a response the same way whichever door the request
/// came in through.
#[test]
fn export_rewrites_the_same_way_in_a_file_from_stdin_and_as_arguments() {
    const EXPORTED: &str = "{\n  \"identifiers\": {\n    \"key?\": \"k1\",\n    \"com.heads.seedID\": \"k1\"\n  },\n  \"name\": \"Ann\",\n  \"secret\": null\n}\n";
    const WARNING: &str = "Response had masked data, now null at secret";
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let run = |args: &[&str], stdin: Option<&str>| {
        server.take();
        let mut cmd = api(server.port, dir.path());
        // In front of the request, unless the case puts the flag elsewhere.
        if !args.contains(&"--export") {
            cmd.args(["--export", "com.heads.seedID"]);
        }
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
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(server.take(), ["GET /keyed"], "{args:?}");
        (String::from_utf8_lossy(&out.stdout).to_string(), String::from_utf8_lossy(&out.stderr).to_string())
    };

    std::fs::write(dir.path().join("case.api"), "GET /keyed\n").unwrap();
    let doors: [(&str, (String, String)); 5] = [
        ("file", run(&["-a", "case.api"], None)),
        ("stdin", run(&["-a"], Some("GET /keyed\n"))),
        ("split arguments", run(&["GET", "/keyed"], None)),
        ("one quoted argument", run(&["GET /keyed"], None)),
        ("the flag last", run(&["GET", "/keyed", "--export", "com.heads.seedID"], None)),
    ];
    for (door, (stdout, stderr)) in &doors {
        assert_eq!(stdout, EXPORTED, "{door}");
        assert_eq!(stderr.matches(WARNING).count(), 1, "{door}: {stderr}");
    }

    // To a file, the same bytes without the final newline, from each door.
    for args in [&["-a", "case.api"][..], &["GET", "/keyed", ">", "out.json"], &["GET /keyed > out.json"]] {
        if args[0] == "-a" {
            std::fs::write(dir.path().join("case.api"), "GET /keyed > out.json\n").unwrap();
        }
        let (stdout, _) = run(args, None);
        assert_eq!(stdout, "", "{args:?}");
        assert_eq!(std::fs::read_to_string(dir.path().join("out.json")).unwrap(), EXPORTED.trim_end(), "{args:?}");
        std::fs::remove_file(dir.path().join("out.json")).unwrap();
    }
}

/// At the prompt the response shown is the seed data, and the hint line says
/// what was masked.
#[cfg(unix)]
#[test]
fn export_at_the_prompt_shows_the_seed_data() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let mut cmd = api(server.port, dir.path());
    cmd.args(["--export", "com.heads.seedID"]);
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

    let (sent, shown) = run("GET /keyed");
    assert_eq!(sent, ["GET /keyed"]);
    assert!(shown.contains("\"key?\": \"k1\""), "{shown}");
    assert!(shown.contains("\"com.heads.seedID\": \"k1\""), "{shown}");
    assert!(shown.contains("\"secret\": null"), "{shown}");
    assert!(!shown.contains("\"key\"") && !shown.contains("********"), "{shown}");
    assert!(shown.contains("Response had masked data, now null at secret"), "{shown}");
    assert!(!shown.contains("WARNING"), "{shown}");

    // Written to a file from the prompt, it is the seed data too.
    let (sent, _) = run("GET /keyed > prompt-out.json");
    assert_eq!(sent, ["GET /keyed"]);
    let written = std::fs::read_to_string(dir.path().join("prompt-out.json")).unwrap();
    let written: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(
        written,
        serde_json::json!({ "identifiers": { "key?": "k1", "com.heads.seedID": "k1" }, "name": "Ann", "secret": null })
    );

    // A response without a key is shown as it came.
    let (_, shown) = run("GET /a");
    assert!(shown.contains("\"ok\""), "{shown}");
}

/// ctrl+r turns export mode on and off in a running session. The name is
/// asked for the first time, has to be a namespaced key, and is remembered.
#[cfg(unix)]
#[test]
fn ctrl_r_toggles_export_at_the_prompt_and_asks_for_the_name_once() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    // Started without `--export`.
    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));

    // Type `keys` (ctrl+r is \x12), and give the screen what it showed.
    fn keys(prompt: &mut pty::Prompt, keys: &[u8]) -> String {
        let mark = prompt.screen.len();
        prompt.send(keys);
        prompt.pump(Duration::from_millis(500));
        pty::plain(&prompt.screen[mark..])
    }
    // Send `GET /keyed` and give what was shown for it.
    fn get_keyed(prompt: &mut pty::Prompt, server: &RecordingServer) -> String {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        prompt.paste("GET /keyed");
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
        assert_eq!(server.take(), ["GET /keyed"]);
        pty::plain(&prompt.screen[mark..])
    }

    // Off: the response is what the server sent.
    let shown = get_keyed(&mut prompt, &server);
    assert!(shown.contains("\"key\": \"k1\"") && shown.contains("********"), "{shown}");

    // ctrl+r asks for the name. There is no default to accept.
    let shown = keys(&mut prompt, b"\x12");
    assert!(shown.contains("Export with external identifier:"), "{shown}");
    assert!(shown.contains("enter to turn export on, esc to cancel"), "{shown}");
    // Esc leaves export off, and so does an empty answer.
    let shown = keys(&mut prompt, b"\x1b");
    assert!(shown.contains("cancelled"), "{shown}");
    keys(&mut prompt, b"\x12");
    let shown = keys(&mut prompt, b"\r");
    assert!(shown.contains("cancelled"), "{shown}");
    let shown = get_keyed(&mut prompt, &server);
    assert!(shown.contains("\"key\": \"k1\""), "{shown}");

    // A name that is no namespaced key is refused with the prompt's notice,
    // and the dialog stays open with what was typed left to correct.
    keys(&mut prompt, b"\x12");
    let shown = keys(&mut prompt, b"seedID\r");
    assert!(shown.contains("export needs a namespaced key, like com.heads.seedID"), "{shown}");
    assert!(shown.contains("Export with external identifier: seedID"), "{shown}");
    assert!(!shown.contains("cancelled") && !shown.contains("GET /"), "the dialog closed:\n{shown}");
    // Refused a second time, it is still there.
    let shown = keys(&mut prompt, b"2\r");
    assert!(shown.contains("Export with external identifier: seedID2"), "{shown}");
    keys(&mut prompt, b"\x7f");
    // Six backspaces, then a good one.
    let shown = keys(&mut prompt, b"\x7f\x7f\x7f\x7f\x7f\x7fcom.example.exportID\r");
    assert!(shown.contains("export on: com.example.exportID"), "{shown}");

    // On: the response is the seed data, under that name.
    let shown = get_keyed(&mut prompt, &server);
    assert!(shown.contains("\"key?\": \"k1\"") && shown.contains("\"com.example.exportID\": \"k1\""), "{shown}");
    assert!(shown.contains("\"secret\": null") && !shown.contains("\"key\""), "{shown}");
    // The marker sits at the right of the hint line while it is on.
    let shown = keys(&mut prompt, b"\x15");
    assert!(shown.trim_end().ends_with("export"), "{shown:?}");

    // ctrl+r again turns it off, and the next response is plain again.
    let shown = keys(&mut prompt, b"\x12");
    assert!(shown.contains("export off"), "{shown}");
    let shown = get_keyed(&mut prompt, &server);
    assert!(shown.contains("\"key\": \"k1\"") && !shown.contains("key?"), "{shown}");

    // And on once more: the name is remembered, nothing is asked.
    let shown = keys(&mut prompt, b"\x12");
    assert!(shown.contains("export on: com.example.exportID"), "{shown}");
    assert!(!shown.contains("Export with external identifier"), "{shown}");
    let shown = get_keyed(&mut prompt, &server);
    assert!(shown.contains("\"com.example.exportID\": \"k1\""), "{shown}");
}

/// The dialog ctrl+r opens is drawn in the command area and nowhere else:
/// the top ruler stays, the prompt takes the input line's place, the bottom
/// ruler and a hint follow, and closing it gives the command area back as it
/// was. In a terminal narrower than its texts, nothing may wrap: a wrapped
/// line pushes the dialog down a row, and every close then leaves a ruler
/// behind.
#[cfg(unix)]
#[test]
fn the_export_name_dialog_stays_in_the_command_area_at_any_width() {
    use pty::Prompt;

    for cols in [200u16, 84, 60, 44] {
        let server = RecordingServer::start();
        let dir = tempfile::tempdir().unwrap();
        prepare(dir.path());
        let mut prompt = Prompt::open_sized(api(server.port, dir.path()), cols);
        prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
        prompt.pump(Duration::from_millis(600));

        const HINT: &str = "  enter to turn export on, esc to cancel";
        const NOTICE: &str = "  export needs a namespaced key, like com.heads.seedID";
        let width = cols as usize;
        let ruler = "─".repeat(width);
        let keys = |prompt: &mut Prompt, keys: &[u8]| {
            prompt.send(keys);
            prompt.pump(Duration::from_millis(450));
            pty::rows(&prompt.screen, width)
        };

        // The command area is the last four rows: the top ruler with the
        // host in it, the input line, the bottom ruler and the hint.
        let before = pty::rows(&prompt.screen, width);
        let top = before.len() - 4;
        let shown = before.join("\n");
        assert!(before[top].starts_with('─') && before[top].contains("127.0.0.1"), "{cols}:\n{shown}");
        assert!(before[top + 1].starts_with("GET /"), "{cols}:\n{shown}");
        assert_eq!(before[top + 2], ruler, "{cols}:\n{shown}");
        assert!(before[top + 3].starts_with("  ctrl+h for shortcuts"), "{cols}:\n{shown}");

        // What every state of the dialog has to look like.
        let dialog = |now: &[String], what: &str| {
            let shown = now.join("\n");
            assert_eq!(now.len(), before.len(), "{cols}, {what}: the command area moved\n{shown}");
            assert_eq!(now[..=top], before[..=top], "{cols}, {what}: the rows above changed\n{shown}");
            assert!(now[top + 1].starts_with("› Export with external identifier:"), "{cols}, {what}:\n{shown}");
            assert_eq!(now[top + 2], ruler, "{cols}, {what}: no bottom ruler under the prompt\n{shown}");
            assert!(now[top + 3].starts_with("  ") && now[top + 3].len() > 2, "{cols}, {what}: no hint\n{shown}");
            assert!(now[top + 1].chars().count() < width, "{cols}, {what}: the prompt reaches the margin\n{shown}");
        };
        // And the command area once it is closed again.
        let closed = |now: &[String], hint: &str, what: &str| {
            let shown = now.join("\n");
            assert_eq!(now.len(), before.len(), "{cols}, {what}: the command area moved\n{shown}");
            assert_eq!(now[..top + 3], before[..top + 3], "{cols}, {what}: not what it was\n{shown}");
            assert!(now[top + 3].starts_with(hint), "{cols}, {what}: {:?}\n{shown}", now[top + 3]);
        };

        let now = keys(&mut prompt, b"\x12");
        dialog(&now, "opened");
        // The hint is the one every dialog of the prompt has.
        assert_eq!(now[top + 3], HINT, "{cols}");

        // A name that is refused: the dialog stays, in place, with the name
        // there to correct, and the reason is in the hint line as any notice
        // is (cut at the margin where the terminal is narrower than it).
        let refused = |now: &[String], what: &str| {
            dialog(now, what);
            let notice: String = NOTICE.chars().take(width).collect();
            assert_eq!(now[top + 3], notice, "{cols}, {what}");
        };
        let now = keys(&mut prompt, b"seedID\r");
        refused(&now, "refused");
        assert!(now[top + 1].ends_with(": seedID"), "{cols}: {:?}", now[top + 1]);

        // More than the line holds: the end of what is typed stays in view.
        let long = "x".repeat(150);
        let now = keys(&mut prompt, format!("{long}Z").as_bytes());
        dialog(&now, "a long name");
        assert!(now[top + 1].ends_with("xZ"), "{cols}: {:?}", now[top + 1]);
        // 35 columns of prompt, `seedID`, and the 151 typed now.
        assert_eq!(now[top + 1].contains('…'), width < 35 + 6 + 151 + 2, "{cols}: {:?}", now[top + 1]);
        let now = keys(&mut prompt, b"\r");
        refused(&now, "a long name refused");
        assert!(now[top + 1].ends_with("xZ"), "{cols}: {:?}", now[top + 1]);

        // The notice goes when a status message would, and the hint is back.
        if cols == 84 {
            prompt.pump(Duration::from_millis(3200));
            let now = pty::rows(&prompt.screen, width);
            dialog(&now, "after the notice");
            assert_eq!(now[top + 3], HINT, "{cols}");
        }

        // Cancelled, and opened and cancelled again: nothing is left behind,
        // and esc discards what was typed.
        let now = keys(&mut prompt, b"\x1b");
        closed(&now, "  cancelled", "cancelled");
        for round in 0..3 {
            let now = keys(&mut prompt, b"\x12");
            dialog(&now, &format!("opened again, {round}"));
            assert!(now[top + 1].ends_with("identifier:"), "{cols}, {round}: {:?}", now[top + 1]);
            assert_eq!(now[top + 3], HINT, "{cols}, {round}");
            let now = keys(&mut prompt, b"\x1b");
            closed(&now, "  cancelled", &format!("cancelled, {round}"));
        }

        // Answered: the command area is back, with export on.
        keys(&mut prompt, b"\x12");
        let now = keys(&mut prompt, b"com.example.exportID\r");
        closed(&now, "  export on: com.example.exportID", "answered");
        assert!(now[top + 3].ends_with("export"), "{cols}: {:?}", now[top + 3]);
    }
}

/// ctrl+c in a name dialog ends the session, and ends it the way ctrl+c
/// twice at the prompt does: the command area is cleared with its top ruler,
/// an unused session takes its splash with it, a used one keeps its history,
/// and the terminal gets its paste mode back.
#[cfg(unix)]
#[test]
fn ctrl_c_in_a_name_dialog_leaves_what_quitting_at_the_prompt_leaves() {
    use pty::Prompt;

    const COLS: usize = 84;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());

    // (what is pressed to leave, whether a request was sent first)
    let ways: [(&str, &[u8], bool); 6] = [
        ("ctrl+c twice at the prompt", b"\x03\x03", false),
        ("ctrl+c in the export dialog", b"\x12\x03", false),
        ("ctrl+c in the save dialog", b"\x13\x03", false),
        ("ctrl+c twice at the prompt, after a request", b"\x03\x03", true),
        ("ctrl+c in the export dialog, after a request", b"\x12\x03", true),
        ("ctrl+c in the save dialog, after a request", b"\x13\x03", true),
    ];
    for (way, keys, used) in ways {
        let mut prompt = Prompt::open_sized(api(server.port, dir.path()), COLS as u16);
        prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
        prompt.pump(Duration::from_millis(600));
        if used {
            prompt.send(b"\x15");
            prompt.pump(Duration::from_millis(60));
            prompt.paste("GET /a");
            prompt.pump(Duration::from_millis(80));
            prompt.send(b"\r");
            prompt.wait_for("\"ok\"", Duration::from_secs(5));
            prompt.pump(Duration::from_millis(500));
        }

        // The command area is the last four rows; the rest is what a used
        // session leaves in the scrollback.
        let before = pty::rows(&prompt.screen, COLS);
        let top = before.len() - 4;
        assert!(before[top].starts_with('─') && before[top].contains("127.0.0.1"), "{way}:\n{}", before.join("\n"));
        let mut kept: Vec<String> = if used { before[..top].to_vec() } else { Vec::new() };
        while kept.last().is_some_and(|row| row.is_empty()) {
            kept.pop();
        }

        for key in keys {
            prompt.send(&[*key]);
            prompt.pump(Duration::from_millis(450));
        }
        let start = Instant::now();
        while prompt.exited().is_none() && start.elapsed() < Duration::from_secs(5) {
            prompt.pump(Duration::from_millis(100));
        }
        assert_eq!(prompt.exited(), Some(true), "{way}: the client did not end");

        let after = pty::rows(&prompt.screen, COLS);
        let shown = after.join("\n");
        assert_eq!(after, kept, "{way}: left on the screen\n{shown}");
        assert!(!after.iter().any(|row| row.starts_with('─')), "{way}: a ruler is left\n{shown}");
        assert_eq!(after.iter().any(|row| row.contains("CommerceOS API Client")), used, "{way}:\n{shown}");
        // Bracketed paste is switched off again, and the cursor shown.
        assert!(
            prompt.screen.rfind("\x1b[?2004l") > prompt.screen.rfind("\x1b[?2004h"),
            "{way}: paste mode is left on"
        );
        assert!(prompt.screen.rfind("\x1b[?25h") > prompt.screen.rfind("\x1b[?25l"), "{way}: the cursor is left hidden");
    }
}

/// Leaving from the connection dialog (ctrl+q, then ctrl+c) ends the process
/// from inside the prompt. The terminal is handed back as any other way out
/// hands it back: bracketed paste off, the cursor shown.
#[cfg(unix)]
#[test]
fn ctrl_c_in_the_connection_dialog_restores_the_terminal() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    // ctrl+q needs a saved connection to offer.
    std::fs::write(
        dir.path().join(".api-credentials.json"),
        format!(
            r#"{{"connections":[{{"name":"other","url":"http://127.0.0.1:{}","auth_type":"key","credential":"k2","client_id":""}}],"default":""}}"#,
            server.port
        ),
    )
    .unwrap();
    let mut prompt = Prompt::open_sized(api(server.port, dir.path()), 84);
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    prompt.send(b"\x11");
    prompt.wait_for("other", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\x03");
    let start = Instant::now();
    while prompt.exited().is_none() && start.elapsed() < Duration::from_secs(5) {
        prompt.pump(Duration::from_millis(100));
    }
    assert_eq!(prompt.exited(), Some(true), "the client did not end");
    assert!(
        prompt.screen.rfind("\x1b[?2004l") > prompt.screen.rfind("\x1b[?2004h"),
        "paste mode is left on"
    );
    assert!(prompt.screen.rfind("\x1b[?25h") > prompt.screen.rfind("\x1b[?25l"), "the cursor is left hidden");
}

/// Up and Down in a multi-line input that holds å/ä/ö move the cursor; they
/// used to end the session with a panic and the terminal in raw mode.
#[cfg(unix)]
#[test]
fn up_and_down_over_multi_byte_text_keep_the_session() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    prompt.send("ååå".as_bytes());
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"\x0e"); // ctrl+n: a new line
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"a");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"\x1b[A\x1b[B\x1b[A");
    prompt.pump(Duration::from_millis(400));
    assert_eq!(prompt.exited(), None, "the session ended:\n{}", plain(&prompt.screen));
    assert!(!plain(&prompt.screen).contains("panicked"), "{}", plain(&prompt.screen));
}

/// A body typed or pasted in the body editor is the body that is sent.
#[cfg(unix)]
#[test]
fn the_body_editor_sends_what_was_typed_or_pasted() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));

    let mut edit = |prompt: &mut Prompt, line: &str, body: &[&[u8]], end: &[u8]| -> Vec<String> {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        prompt.send(line.as_bytes());
        prompt.pump(Duration::from_millis(100));
        prompt.send(b"\r");
        prompt.wait_for("Enter body, ctrl+d when done", Duration::from_secs(5));
        for part in body {
            prompt.send(part);
            prompt.pump(Duration::from_millis(120));
        }
        prompt.send(end);
        let start = Instant::now();
        while server.seen() == 0 && start.elapsed() < Duration::from_millis(1500) {
            prompt.pump(Duration::from_millis(50));
        }
        prompt.pump(Duration::from_millis(200));
        server.take()
    };

    // Typed.
    assert_eq!(edit(&mut prompt, "PUT /typed", &[br#"{"a":1}"#], b"\x04"), [r#"PUT /typed {"a":1}"#]);
    // Pasted: the paste is the body, not something for the line underneath.
    assert_eq!(
        edit(&mut prompt, "PUT /pasted", &[b"\x1b[200~{\"a\":1}\x1b[201~"], b"\x04"),
        [r#"PUT /pasted {"a":1}"#],
        "{}",
        plain(&prompt.screen)
    );
    // Typed and pasted together, over several lines.
    assert_eq!(
        edit(&mut prompt, "POST /both", &[b"{", b"\x1b[200~\r  \"a\": 1,\r  \"b\": \"GET /x\"\r\x1b[201~", b"}"], b"\x04"),
        ["POST /both {\n  \"a\": 1,\n  \"b\": \"GET /x\"\n}"],
        "{}",
        plain(&prompt.screen)
    );
    // Esc sends nothing.
    assert!(edit(&mut prompt, "PUT /never", &[b"\x1b[200~{\"a\":1}\x1b[201~"], b"\x1b").is_empty());
}

/// ctrl+g GETs the URI on the line, whatever was sent before and whatever
/// method, body or outfile the line has, and leaves the line as it was.
#[cfg(unix)]
#[test]
fn ctrl_g_gets_the_uri_on_the_line() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));

    let mut on_line = |prompt: &mut Prompt, line: &str, key: &[u8]| -> (Vec<String>, String) {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        if !line.is_empty() {
            prompt.send(line.as_bytes());
            prompt.pump(Duration::from_millis(150));
        }
        let mark = prompt.screen.len();
        prompt.send(key);
        let start = Instant::now();
        while server.seen() == 0 && start.elapsed() < Duration::from_millis(1200) {
            prompt.pump(Duration::from_millis(50));
        }
        prompt.pump(Duration::from_millis(250));
        (server.take(), plain(&prompt.screen[mark..]))
    };

    assert_eq!(on_line(&mut prompt, "GET /first", b"\r").0, ["GET /first"]);
    // The line, not the last request.
    assert_eq!(on_line(&mut prompt, "GET /second", b"\x07").0, ["GET /second"]);
    // A line that is a PUT with a body and an outfile: its URI, as a GET,
    // and no file.
    let (sent, shown) = on_line(&mut prompt, r#"PUT /third {"x":1} > never.json"#, b"\x07");
    assert_eq!(sent, ["GET /third"], "{shown}");
    assert!(!dir.path().join("never.json").exists());
    // The line is still the PUT that was being written.
    let rows = pty::rows(&prompt.screen, 200);
    assert!(rows.iter().any(|row| row.starts_with(r#"PUT /third {"x":1} > never.json"#)), "{}", rows.join("\n"));
    // An empty line is `GET /`.
    assert_eq!(on_line(&mut prompt, "", b"\x07").0, ["GET /"]);
    // A chain has no one URI.
    let (sent, shown) = on_line(&mut prompt, "GET /a && GET /b", b"\x07");
    assert!(sent.is_empty(), "{shown}");
    assert!(shown.contains("not a request"), "{shown}");
}

/// A paste into a name dialog fills its input.
#[cfg(unix)]
#[test]
fn a_paste_fills_a_name_dialog() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));

    prompt.send(b"\x13");
    prompt.wait_for("Save connection as", Duration::from_secs(5));
    prompt.paste("pasted-name\r");
    prompt.pump(Duration::from_millis(200));
    prompt.send(b"\r");
    prompt.wait_for("connection pasted-name saved", Duration::from_secs(5));
    let saved = std::fs::read_to_string(dir.path().join(".api-credentials.json")).unwrap();
    assert!(saved.contains(r#""name":"pasted-name""#), "{saved}");

    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\x12");
    prompt.wait_for("Export with external identifier", Duration::from_secs(5));
    prompt.paste("com.heads.seedID");
    prompt.pump(Duration::from_millis(200));
    let mark = prompt.screen.len();
    prompt.send(b"\r");
    prompt.pump(Duration::from_millis(600));
    let shown = plain(&prompt.screen[mark..]);
    assert!(!shown.contains("cancelled"), "{shown}");
    assert!(pty::rows(&prompt.screen, 200).last().unwrap().ends_with("export"), "{shown}");
}

/// On a terminal narrower than its text, the save dialog keeps to its rows
/// however long it stands, and a status message is still said.
#[cfg(unix)]
#[test]
fn a_narrow_terminal_keeps_the_save_dialog_and_the_status_line() {
    use pty::Prompt;

    const COLS: usize = 20;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = Prompt::open_sized(api(server.port, dir.path()), COLS as u16);
    // Too narrow for the splash and for the standing hint: wait for the ruler.
    prompt.wait_for("─", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(1200));

    // ctrl+c once: the notice must show, cut to the width.
    prompt.send(b"\x03");
    prompt.pump(Duration::from_millis(400));
    let rows = pty::rows(&prompt.screen, COLS);
    assert!(rows.iter().any(|row| row.contains("ctrl+c again")), "{}", rows.join("\n"));
    assert!(rows.iter().all(|row| row.chars().count() <= COLS), "{}", rows.join("\n"));
    // Any other key takes the notice back.
    prompt.send(b" ");
    prompt.pump(Duration::from_millis(300));

    let before = pty::rows(&prompt.screen, COLS).len();
    prompt.send(b"\x13");
    prompt.pump(Duration::from_millis(400));
    let opened = pty::rows(&prompt.screen, COLS);
    // It stands for a while, redrawn many times over.
    prompt.pump(Duration::from_millis(1500));
    let stood = pty::rows(&prompt.screen, COLS);
    assert_eq!(stood.len(), opened.len(), "the dialog grew:\n{}", stood.join("\n"));
    assert!(stood.len() <= before + 1, "the dialog took more rows than the command area:\n{}", stood.join("\n"));
    assert!(stood.iter().all(|row| row.chars().count() <= COLS), "{}", stood.join("\n"));
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(400));
    assert_eq!(prompt.exited(), None);
}

/// Help on a terminal too short for it is cut to what the closing clear can
/// reach, and says how much is missing; on a tall one it is all there.
#[cfg(unix)]
#[test]
fn help_is_cut_to_a_short_terminal() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();

    let mut short = Prompt::open_with(api(server.port, dir.path()), 80, 24);
    short.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    short.pump(Duration::from_millis(500));
    let mark = short.screen.len();
    short.send(b"\x08");
    short.pump(Duration::from_millis(500));
    let shown = plain(&short.screen[mark..]);
    assert!(shown.contains("more rows: enlarge the window. ctrl+h or esc to close"), "{shown}");
    assert!(shown.contains("enter      Send request"), "{shown}");
    assert!(!shown.contains("ctrl+c     Quit"), "{shown}");
    // Ruler, rows and the cursor's row: no more than the screen holds.
    let drawn = shown.matches("\r\n").count().max(shown.lines().count());
    assert!(drawn <= 24, "{drawn} rows drawn on 24:\n{shown}");
    // Closing brings the prompt back.
    let mark = short.screen.len();
    short.send(b"\x1b");
    short.pump(Duration::from_millis(500));
    assert!(plain(&short.screen[mark..]).contains("ctrl+h for shortcuts"));

    let mut tall = Prompt::open_with(api(server.port, dir.path()), 80, 50);
    tall.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));
    tall.pump(Duration::from_millis(500));
    let mark = tall.screen.len();
    tall.send(b"\x08");
    tall.pump(Duration::from_millis(500));
    let shown = plain(&tall.screen[mark..]);
    assert!(shown.contains("ctrl+c     Quit") && shown.contains("GET the URI on the line"), "{shown}");
    assert!(!shown.contains("more rows"), "{shown}");
}

/// A session started with `--export <name>` has its name: ctrl+r turns
/// export off and on again without asking.
#[cfg(unix)]
#[test]
fn ctrl_r_in_a_session_started_with_export_does_not_ask() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let mut cmd = api(server.port, dir.path());
    cmd.args(["--export", "com.heads.seedID"]);
    let mut prompt = Prompt::open(cmd);
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));

    let press = |prompt: &mut Prompt| {
        let mark = prompt.screen.len();
        prompt.send(b"\x12");
        prompt.pump(Duration::from_millis(500));
        plain(&prompt.screen[mark..])
    };
    let shown = press(&mut prompt);
    assert!(shown.contains("export off"), "{shown}");
    let shown = press(&mut prompt);
    assert!(shown.contains("export on: com.heads.seedID"), "{shown}");
    assert!(!shown.contains("Export with external identifier"), "{shown}");

    // The help lists the key.
    let mark = prompt.screen.len();
    prompt.send(b"\x08");
    prompt.pump(Duration::from_millis(400));
    let shown = plain(&prompt.screen[mark..]);
    assert!(shown.contains("ctrl+r     Toggle export mode"), "{shown}");
}

/// `export <name>` typed at the prompt is the line a file would have: it
/// holds for what is typed after it, until `export off`, and a file run from
/// the prompt is kept out of it as an included file is.
#[cfg(unix)]
#[test]
fn an_export_line_at_the_prompt_holds_for_the_lines_typed_after_it() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    std::fs::write(dir.path().join("plain.api"), "GET /keyed > from-file.json\n").unwrap();
    std::fs::write(dir.path().join("own.api"), "export other.name.id\nGET /keyed > from-own.json\n").unwrap();
    let mut prompt = Prompt::open(api(server.port, dir.path()));
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
    // The name a written record was exported under, `None` when it wasn't.
    let exported = |file: &str| -> Option<String> {
        let text = std::fs::read_to_string(dir.path().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let identifiers = value["identifiers"].as_object().unwrap();
        identifiers.keys().find(|k| *k != "key?" && *k != "key").cloned()
    };
    let seed = Some("com.heads.seedID".to_string());

    // Before the line, the response is the server's.
    let (_, shown) = run("GET /keyed");
    assert!(shown.contains("\"key\": \"k1\"") && !shown.contains("key?"), "{shown}");

    // The line sends nothing, is logged, and says what it did.
    let (sent, shown) = run("export com.heads.seedID");
    assert_eq!(sent, Vec::<String>::new());
    assert!(shown.contains("export on: com.heads.seedID"), "{shown}");
    let (_, shown) = run("GET /keyed");
    assert!(shown.contains("\"key?\": \"k1\"") && shown.contains("\"com.heads.seedID\": \"k1\""), "{shown}");

    // A file run from here is another file: not exported, unless it says so
    // itself, and then under its own name. Neither changes the prompt's.
    let (sent, _) = run("plain.api");
    assert_eq!(sent, ["GET /keyed"]);
    assert_eq!(exported("from-file.json"), None);
    let (sent, _) = run("own.api");
    assert_eq!(sent, ["GET /keyed"]);
    assert_eq!(exported("from-own.json"), Some("other.name.id".to_string()));
    run("GET /keyed > typed.json");
    assert_eq!(exported("typed.json"), seed);

    // A name that can't be one is refused, and the mode stays.
    let (sent, shown) = run("export nope");
    assert_eq!(sent, Vec::<String>::new());
    assert!(shown.contains("invalid export identifier: nope"), "{shown}");
    run("GET /keyed > still.json");
    assert_eq!(exported("still.json"), seed);

    let (sent, shown) = run("export off");
    assert_eq!(sent, Vec::<String>::new());
    assert!(shown.contains("export off"), "{shown}");
    run("GET /keyed > off.json");
    assert_eq!(exported("off.json"), None);

    // In a pasted block the line holds for the rest of the block, and after it.
    let (sent, _) = run("GET /keyed > block-before.json\nexport com.heads.seedID\nGET /keyed > block-after.json");
    assert_eq!(sent.len(), 2);
    assert_eq!(exported("block-before.json"), None);
    assert_eq!(exported("block-after.json"), seed);
    run("GET /keyed > later.json");
    assert_eq!(exported("later.json"), seed);

    // ctrl+r turns it off, as it turns off any export mode.
    let mark = prompt.screen.len();
    prompt.send(b"\x12");
    prompt.pump(Duration::from_millis(500));
    assert!(plain(&prompt.screen[mark..]).contains("export off"), "{}", plain(&prompt.screen[mark..]));
}

/// A session's own export mode (`--export`, ctrl+r) is the command line's,
/// and overrides an `export` line typed in it or read from a file.
#[cfg(unix)]
#[test]
fn an_export_line_does_not_change_a_sessions_own_export_mode() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    std::fs::write(dir.path().join("own.api"), "export other.name.id\nGET /keyed > from-own.json\n").unwrap();
    let mut cmd = api(server.port, dir.path());
    cmd.args(["--export", "com.heads.seedID"]);
    let mut prompt = Prompt::open(cmd);
    prompt.wait_for("ctrl+h for shortcuts", Duration::from_secs(15));

    let run = |prompt: &mut Prompt, paste: &str| {
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
        plain(&prompt.screen[mark..])
    };
    let name_in = |file: &str| -> String {
        let text = std::fs::read_to_string(dir.path().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["identifiers"].as_object().unwrap().keys().find(|k| *k != "key?").unwrap().clone()
    };

    for line in ["export off", "export other.name.id"] {
        let shown = run(&mut prompt, line);
        assert!(shown.contains("export stays com.heads.seedID"), "{line}: {shown}");
        run(&mut prompt, "GET /keyed > typed.json");
        assert_eq!(name_in("typed.json"), "com.heads.seedID", "{line}");
    }
    // A file's line is overridden the same way.
    run(&mut prompt, "own.api");
    assert_eq!(name_in("from-own.json"), "com.heads.seedID");

    // With the session's mode off (ctrl+r), a line is taken again.
    prompt.send(b"\x12");
    prompt.pump(Duration::from_millis(500));
    let shown = run(&mut prompt, "export other.name.id");
    assert!(shown.contains("export on: other.name.id"), "{shown}");
    run(&mut prompt, "GET /keyed > typed.json");
    assert_eq!(name_in("typed.json"), "other.name.id");
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
