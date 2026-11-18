//! One grammar, three doors. A line can be handed to the client in a `.api`
//! file, as one-shot arguments (split by the shell or quoted whole), or typed
//! at the interactive prompt, and it must mean the same request each way.
//!
//! Every case in `cases` is run through all of them against a recording
//! server, and what reached the server is compared — first between the
//! entry points, then against what the case says it should be.
//!
//! The rest of the suite is what the client sends, prints, writes and exits
//! with, from a batch and at the prompt, shown on that same recording server.
//!
//! What it needs: this machine only. Every request goes to a server the test
//! starts on a free port of 127.0.0.1; no local CommerceOS, no credentials
//! file (a test that wants one writes its own in a temporary directory), no
//! keychain, no network and no clipboard. `git` must be on the `PATH`, for
//! the import rows, which use a repository built in a temporary directory.
//! The tests that drive the prompt do it through a pseudo-terminal and are
//! compiled on unix only.
//!
//! Run with: `cargo test --test parity`, under a time limit (a pty test that
//! hangs takes the suite with it): `perl -e 'alarm 900; exec @ARGV' cargo
//! test --test parity`.

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
    if path.contains("/late") {
        // Two seconds of nothing, then an answer like any other.
        std::thread::sleep(Duration::from_secs(2));
    }
    if path.contains("/slow") {
        // A whole body, in pieces over three seconds.
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n[\r\n");
        for _ in 0..15 {
            std::thread::sleep(Duration::from_millis(200));
            if stream.write_all(b"2\r\n1,\r\n").and_then(|()| stream.flush()).is_err() {
                return;
            }
        }
        let _ = stream.write_all(b"2\r\n1]\r\n0\r\n\r\n");
        let _ = stream.flush();
        return;
    }
    if path.contains("/loop") || path.contains("/moved") {
        // `/loop` is sent on to itself, for ever; `/moved` to `/landed`, as
        // the request it was (307).
        let (status, to) = match path.contains("/loop") {
            true => ("302 Found", path.clone()),
            false => ("307 Temporary Redirect", "/api/v1/landed".to_string()),
        };
        let _ = stream.write_all(
            format!("HTTP/1.1 {status}\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        let _ = stream.flush();
        return;
    }
    if let Some(status) = ["301 Moved Permanently", "302 Found", "303 See Other"]
        .into_iter()
        .find(|status| path.contains(&format!("/old{}", &status[..3])))
    {
        // `/old301`, `/old302` and `/old303` are sent on to `/landed` the old way.
        let _ = stream.write_all(
            format!("HTTP/1.1 {status}\r\nLocation: /api/v1/landed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        let _ = stream.flush();
        return;
    }
    if path.contains("/notutf8") {
        // A JSON string with one byte that is Latin-1, not UTF-8.
        let body = b"\"caf\xe9 x\"";
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(body));
        let _ = stream.flush();
        return;
    }
    if let Some((rest, hold)) = broken {
        let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{rest}").as_bytes());
        let _ = stream.flush();
        std::thread::sleep(hold);
        return;
    }

    if path.contains("/oauth2/v1/token") && body.contains("client_id=moved") {
        // A token endpoint that sends the request, and the secret in it, on.
        let _ = stream.write_all(
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /api/v1/landed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let _ = stream.flush();
        return;
    }

    let (status, payload) = if path.contains("/oauth2/v1/token") {
        // The first token handed out has already run out by the time it is
        // used; every later one is good. The client `once` gets no second.
        let nth = tokens.fetch_add(1, Ordering::SeqCst);
        let token = if nth == 0 { "stale" } else { "fresh" };
        if body.contains("client_id=tokenless") {
            // An answer that is no token.
            ("200 OK", "{}".to_string())
        } else if body.contains("client_id=refused") {
            // A client the server does not know.
            ("401 Unauthorized", r#"{"error":"invalid_client"}"#.to_string())
        } else if body.contains("client_id=nokey") {
            // A client whose token is let in nowhere.
            ("200 OK", r#"{"access_token":"nokey","expires_in":3600}"#.to_string())
        } else if nth > 0 && body.contains("client_id=once") {
            ("500 Internal Server Error", "{}".to_string())
        } else {
            ("200 OK", format!(r#"{{"access_token":"{token}","expires_in":3600}}"#))
        }
    } else if path.contains("/denied") {
        // Nobody is let in here, whatever they carry.
        ("401 Unauthorized", r#"{"error":"denied"}"#.to_string())
    } else if path.contains("/expired") && header("authorization") != Some("Bearer fresh") {
        // Only the token the token endpoint hands out is let in.
        ("401 Unauthorized", r#"{"error":"token expired"}"#.to_string())
    } else if path.contains("/missing") {
        ("404 Not Found", "{}".to_string())
    } else if let Some((_, zero)) = path.split_once("/zero/") {
        // A zero as the path spells it: `/zero/0e0` answers `0e0`.
        ("200 OK", zero.to_string())
    } else if path.contains("/zero") {
        ("200 OK", "0".to_string())
    } else if path.contains("/gone") {
        // An error whose body has lines of its own, and is not laid out the
        // way the client lays JSON out.
        ("404 Not Found", GONE.to_string())
    } else if path.contains("/numbers") {
        ("200 OK", format!("[{NUMBERS}]"))
    } else if path.contains("/boom") {
        ("500 Internal Server Error", "{}".to_string())
    } else if path.contains("/conflict") {
        ("409 Conflict", r#"{"error":"conflict"}"#.to_string())
    } else if path.contains("/barred") {
        ("403 Forbidden", r#"{"error":"barred"}"#.to_string())
    } else if path.ends_with("/assert") && method == "PUT" {
        // Every assertion holds: `200` with `null`, as the API answers.
        ("200 OK", "null".to_string())
    } else if path.contains("/keyed") {
        // A record with only a database key and a masked value, for `--export`.
        ("200 OK", r#"{"name":"Ann","identifiers":{"key":"k1"},"secret":"********"}"#.to_string())
    } else if header("authorization") == Some("Basic Om5va2V5") || header("authorization") == Some("Bearer nokey") {
        // The key `nokey` is no key here.
        ("401 Unauthorized", r#"{"error":"no such key"}"#.to_string())
    } else if header("authorization") == Some("Basic OmZvcmJpZGRlbg==") {
        // The key `forbidden` is known, and let in nowhere.
        ("403 Forbidden", r#"{"error":"forbidden"}"#.to_string())
    } else if path.contains("/about") && header("authorization") == Some("Basic OnNwZWM=") {
        // For a session with the key `spec`: a server with a spec to complete from.
        ("200 OK", r#"{"feature-flags":[],"openapi-metadata-version":"1.2"}"#.to_string())
    } else if path.contains("/openapi") && header("authorization") == Some("Basic OnNwZWM=") {
        ("200 OK", PROMPT_SPEC.to_string())
    } else if path.contains("/mapped-types") && method != "GET" {
        ("200 OK", "null".to_string())
    } else if path.contains("/mapped-types") && header("authorization") == Some("Basic OnNwZWM=") {
        // The list follows the last of two requests the session has sent:
        // after `/more-types` there is one more type, after `/break-types`
        // the list can't be had.
        let log = log.lock().unwrap();
        let last = log.iter().rev().find(|line| line.contains("-types"));
        let base = r#"{"identifiers":{"mappedTypeName":"com.heads.sql"}},{"name":"unnamed"},{"identifiers":{"mappedTypeName":"com.heads.csv"}}"#;
        match last {
            Some(line) if line.contains("/break-types") => ("500 Internal Server Error", "{}".to_string()),
            Some(line) if line.contains("/more-types") => {
                ("200 OK", format!(r#"[{base},{{"identifiers":{{"mappedTypeName":"com.heads.xml"}}}}]"#))
            }
            _ => ("200 OK", format!("[{base}]")),
        }
    } else if path.contains("/about") && header("authorization") == Some("Basic OnNsb3dhYm91dA==") {
        // For a session with the key `slowabout`: a server slow to answer at all.
        std::thread::sleep(Duration::from_secs(4));
        ("200 OK", r#"{"feature-flags":[]}"#.to_string())
    } else if path.contains("/openapi") && header("authorization") == Some("Basic OnNsb3dzcGVj") {
        // For a session with the key `slowspec`: the spec takes its time.
        std::thread::sleep(Duration::from_secs(8));
        ("200 OK", PROMPT_SPEC.to_string())
    } else if path.contains("/about") && header("authorization") == Some("Basic OnNsb3dzcGVj") {
        ("200 OK", r#"{"feature-flags":[],"openapi-metadata-version":"1.2"}"#.to_string())
    } else if path.contains("/openapi") && header("authorization") == Some("Basic OmJhZHNwZWM=") {
        // For a session with the key `badspec`: an answer that is no spec.
        ("200 OK", r#""not a spec""#.to_string())
    } else if path.contains("/about") && header("authorization") == Some("Basic OmJhZHNwZWM=") {
        // …from a server that says it has one.
        ("200 OK", r#"{"feature-flags":[],"openapi-metadata-version":"1.1"}"#.to_string())
    } else if path.contains("/openapi") && header("authorization") == Some("Basic Om5vc3BlYw==") {
        // For a session with the key `nospec`: a server that says it has a
        // spec and has none.
        ("404 Not Found", "{}".to_string())
    } else if path.contains("/about") && header("authorization") == Some("Basic Om5vc3BlYw==") {
        ("200 OK", r#"{"feature-flags":[],"openapi-metadata-version":"1.2"}"#.to_string())
    } else if path.contains("/openapi") && header("authorization") == Some("Basic OmZhaWxzcGVj") {
        // For a session with the key `failspec`: the spec request fails.
        ("500 Internal Server Error", "{}".to_string())
    } else if path.contains("/about") && header("authorization") == Some("Basic OmZhaWxzcGVj") {
        ("200 OK", r#"{"feature-flags":[],"openapi-metadata-version":"1.2"}"#.to_string())
    } else if path.contains("/about") && header("authorization") == Some("Basic OnN0cmVhbWVy") {
        // For a session with the key `streamer`: a server that can stream.
        ("200 OK", r#"{"feature-flags":["response:streaming"]}"#.to_string())
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

/// What `/gone` answers, with its 404.
const GONE: &str = "{\"error\":\n\"gone\",\n\"n\":1}";
/// `GONE` as the client writes a buffered JSON body to a file.
const GONE_INDENTED: &str = "{\n  \"error\": \"gone\",\n  \"n\": 1\n}";

/// The one record `/numbers` answers with, in a list: numbers that no `f64`
/// holds as they are written.
const NUMBERS: &str = r#"{"big":12345678901234567890123,"frac":0.3333333333333333333333,"exp":1e+2,"neg":-0.10}"#;

/// The spec the server has for a session with the key `spec`, in the shape
/// the real one has: properties by `$ref`, collections with an `x-indexer`.
const PROMPT_SPEC: &str = r##"{
  "tags": [{ "name": "People", "x-type": "people" }, { "name": "Agents", "x-type": "agents" }],
  "paths": {
    "/about": { "get": { "responses": {} } },
    "/agents": { "get": { "tags": ["Agents"], "responses": { "200": { "content": { "application/json": {
      "schema": { "type": "array", "items": { "$ref": "#/components/schemas/agent" } } } } } } } },
    "/people": { "get": { "tags": ["People"], "responses": { "200": { "content": { "application/json": {
      "schema": { "type": "array", "items": { "$ref": "#/components/schemas/person" } } } } } } } },
    "/people/find": { "get": { "responses": {} } },
    "/people/{index}": { "get": { "responses": { "200": { "content": { "application/json": {
      "schema": { "$ref": "#/components/schemas/person" } } } } } } },
    "/pets": { "get": { "responses": {} } }
  },
  "components": { "schemas": {
    "people": { "type": "array",
      "x-indexer": { "indexType": "COS database key or common identifiers", "returnType": "person?" },
      "x-array-members": { "count": { "$ref": "#/components/schemas/number" } } },
    "agents": { "type": "array",
      "x-indexer": { "indexType": "COS database key or common identifiers", "returnType": "agent?" } },
    "agent": { "type": "object", "x-child-types": ["person", "company"],
      "properties": {
        "@type": { "type": "string" },
        "identifiers": { "$ref": "#/components/schemas/common identifiers" },
        "name": { "$ref": "#/components/schemas/strict string" } } },
    "person": { "type": "object",
      "properties": {
        "@type": { "type": "string" },
        "identifiers": { "$ref": "#/components/schemas/common identifiers" },
        "name": { "$ref": "#/components/schemas/strict string" },
        "givenName": { "$ref": "#/components/schemas/strict string" },
        "active": { "$ref": "#/components/schemas/boolean" } } },
    "common identifiers": { "type": "object",
      "properties": { "key?": {}, "com.mi6.id": { "$ref": "#/components/schemas/strict string" } },
      "additionalProperties": { "x-additionalPropertiesName": "[namespaced key]" } },
    "strict string": { "type": "string" },
    "boolean": { "type": "boolean" },
    "number": { "type": "number" }
  } }
}"##;

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
    /// A file the line must have written, and the path of the request whose
    /// answer it must hold.
    writes: Option<(PathBuf, &'static str)>,
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
    fn writes(mut self, path: PathBuf, answer_of: &'static str) -> Self {
        self.writes = Some((path, answer_of));
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
    let out6 = out("out6.json").display().to_string();
    let out7 = out("out7.json").display().to_string();
    let commented_redirect = format!("GET /a > {out6}   # as the server answers");
    let implied_redirect = format!("/a > {out7}");
    let out8 = out("out8.json").display().to_string();
    let tab_redirect8 = format!("\t> {out8}");
    let tab_append8 = format!("\t>> {out8}");
    let chain_out_b = out("chain-b.json").display().to_string();
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
        case("> outfile", &format!("GET /a > {out1}"), Some(&["GET", "/a", ">", &out1]), &["GET /a"]).writes(out("out1.json"), "/a"),
        case("> outfile as one argument", &format!("GET /a > {out2}"), Some(&["GET", "/a", &redirect2]), &["GET /a"])
            .writes(out("out2.json"), "/a"),
        case(
            "body then > outfile",
            &format!(r#"PUT /a {{"x":1}} > {out3}"#),
            Some(&["PUT", "/a", r#"{"x":1}"#, &redirect3]),
            &[r#"PUT /a {"x":1}"#],
        )
        .writes(out("out3.json"), "/a"),
        case(">> append", &format!("GET /a >> {out4}"), Some(&["GET", "/a", &append4]), &["GET /a"]).writes(out("out4.json"), "/a"),
        // The redirect in the URI argument and the body after it — the shape
        // the one-shot form has always taken.
        case(
            "> outfile in the URI argument, body after",
            &format!(r#"PUT /a {{"x":1}} > {out1}"#),
            Some(&["PUT", &uri_with_redirect1, r#"{"x":1}"#]),
            &[r#"PUT /a {"x":1}"#],
        )
        .writes(out("out1.json"), "/a"),
        case(
            ">> append in the URI argument, body after",
            &format!(r#"PUT /a {{"x":1}} >> {out2}"#),
            Some(&["PUT", &uri_with_append2, r#"{"x":1}"#]),
            &[r#"PUT /a {"x":1}"#],
        )
        .writes(out("out2.json"), "/a"),
        // A tab is a blank before `>` too
        case("a tab before > outfile", &format!("GET /a\t> {out8}"), Some(&["GET", "/a", &tab_redirect8]), &["GET /a"])
            .writes(out("out8.json"), "/a"),
        case("a tab before >> append", &format!("GET /a\t>> {out8}"), Some(&["GET", "/a", &tab_append8]), &["GET /a"])
            .writes(out("out8.json"), "/a"),
        // A redirect that names no file is a mistake, not a body of `>`
        case("> with no path", "GET /c >", Some(&["GET", "/c", ">"]), &[]).fails("needs a path"),
        case(">> with no path", "GET /c >>", Some(&["GET", "/c", ">>"]), &[]).fails("needs a path"),
        case("> with no path behind a body", r#"PUT /c {"x":1} >"#, Some(&["PUT", "/c", r#"{"x":1}"#, ">"]), &[])
            .fails("needs a path"),
        case("> with no path in a chain", "GET /a && GET /c >", Some(&["GET", "/a", "&&", "GET", "/c", ">"]), &[])
            .fails("needs a path"),
        case("> with no path in the first of a chain", "GET /c >> || GET /a", Some(&["GET", "/c", ">>", "||", "GET", "/a"]), &[])
            .fails("needs a path"),
        case("assert with a > and no path", "assert GET /c >", Some(&["assert", "GET", "/c", ">"]), &[]).fails("needs a path"),
        case(
            "sleep while with a >> and no path",
            "sleep 100ms while not GET /c >>",
            Some(&["sleep", "100ms", "while", "not", "GET", "/c", ">>"]),
            &[],
        )
        .fails("needs a path"),
        // A `#` in a URI is part of it, not a fragment that is never sent.
        case("a # in a path", "DELETE /people/com.x.id=A#1", Some(&["DELETE", "/people/com.x.id=A#1"]), &["DELETE /people/com.x.id=A%231"]),
        case(
            "a # in a quoted value",
            r#"GET /a~where(n="x #y")"#,
            Some(&["GET", r#"/a~where(n="x #y")"#]),
            &["GET /a~where(n=%22x%20%23y%22)"],
        ),
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
        .writes(out("out1.json"), "/a"),
        // The outfile of a segment holds that segment's answer
        case(
            "chain with an outfile on the last segment",
            &format!("GET /a && GET /b > {chain_out_b}"),
            Some(&["GET", "/a", "&&", "GET", "/b", ">", &chain_out_b]),
            &["GET /a", "GET /b"],
        )
        .writes(out("chain-b.json"), "/b"),
        // A body may span lines in any segment, not only the last
        case(
            "chain with a multi-line body in its first segment",
            "PUT /a {\n  \"x\": 1 // one\n} && GET /b",
            Some(&["PUT", "/a", "{\n  \"x\": 1 // one\n}", "&&", "GET", "/b"]),
            &["PUT /a {\n  \"x\": 1 \n}", "GET /b"],
        ),
        case(
            "chain with multi-line bodies in the middle",
            "GET /zero || PUT /b [\n  1,\n  2\n] && PUT /c {\n  \"y\": \"a\nb\"\n} && GET /d",
            Some(&["GET", "/zero", "||", "PUT", "/b", "[\n  1,\n  2\n]", "&&", "PUT", "/c", "{\n  \"y\": \"a\nb\"\n}", "&&", "GET", "/d"]),
            &["GET /zero", "PUT /b [\n  1,\n  2\n]", "PUT /c {\n  \"y\": \"a\\nb\"\n}", "GET /d"],
        ),
        case("directive in a chain", "GET /a && sleep 100ms", Some(&["GET", "/a", "&&", "sleep", "100ms"]), &[])
            .fails("chain segment is not a request: `sleep 100ms`"),
        case("typo in a chain", "GET /a && peple", Some(&["GET", "/a", "&&", "peple"]), &[])
            .fails("chain segment is not a request: `peple`"),
        // A method names nothing to send without a URI: not a request to `/`
        case("a method alone", "DELETE", Some(&["DELETE"]), &[]).fails("DELETE needs a URI"),
        case("a method alone in a chain", "GET /a && PUT", Some(&["GET", "/a", "&&", "PUT"]), &[]).fails("PUT needs a URI"),
        // A function an @file body does not have is not dropped
        case("an unknown body function", "PUT /x @body.json~old(1)", Some(&["PUT", "/x", "@body.json~old(1)"]), &[])
            .fails("unknown body function ~old(1)"),
        // A gate is a line of its own
        case("url in a chain", r#"url has 127.0.0.1 && PUT /x {"a":1}"#, Some(&["url", "has", "127.0.0.1", "&&", "PUT", "/x", r#"{"a":1}"#]), &[])
            .fails("can't be part of a `&&`/`||` chain"),
        // A setting is a line of its own
        case("set in a chain", "set include-nulls && GET /a", Some(&["set", "include-nulls", "&&", "GET", "/a"]), &[])
            .fails("can't be part of a `&&`/`||` chain"),
        case("set behind a chain", "GET /a && set include-nulls", Some(&["GET", "/a", "&&", "set", "include-nulls"]), &[])
            .fails("chain segment is not a request"),
        case("set, then a request", "set include-nulls\nGET /a", None, &["GET /a"]),
        case("SET in capitals, switched off again", "SET Include-Nulls ON\nset include-nulls off\nGET /a", None, &["GET /a"]),
        case("a setting that is none", "set nulls\nGET /a", None, &[]).fails("unknown setting `nulls`"),
        case("a setting with a value it does not take", "set fail-fast soon\nGET /a", None, &[])
            .fails("set fail-fast takes `on` or `off`, not `soon`"),
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
        // A condition that breaks off at a separator is refused like a plain line
        case("assert that breaks off at ||", "assert GET /a ||", Some(&["assert", "GET", "/a", "||"]), &[])
            .fails("needs a request on both sides"),
        case("assert not that breaks off at &&", "assert not GET /c &&", Some(&["assert", "not", "GET", "/c", "&&"]), &[])
            .fails("needs a request on both sides"),
        case(
            "sleep while that breaks off at &&",
            "sleep 100ms while GET /a &&",
            Some(&["sleep", "100ms", "while", "GET", "/a", "&&"]),
            &[],
        )
        .fails("needs a request on both sides"),
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
        case("import of an unknown kind", r#"import svn x {"url":"https://example.invalid/r"}"#, None, &[])
            .fails("unknown import kind `svn`"),
        case("import of a missing ref", &import_missing_ref, None, &[]).fails("import ref not found: 9.9"),
        case("import without a ref", r#"import git cl {"url":"https://example.invalid/r"}"#, None, &[])
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
        .writes(out("out5.json"), "/a"),
        case(
            "> inside a URI operator",
            r#"GET /a~where(n="x > y")"#,
            Some(&["GET", r#"/a~where(n="x > y")"#]),
            &["GET /a~where(n=%22x%20%3E%20y%22)"],
        ),
        // A `\` is a character of the URI, not another way to write `/`
        case(
            "an escaped quote inside a URI operator",
            r#"GET /a~where(n="a \" b")"#,
            Some(&["GET", r#"/a~where(n="a \" b")"#]),
            &["GET /a~where(n=%22a%20%5C%22%20b%22)"],
        ),
        case(
            "what is percent-encoded already stays as written",
            "GET /a~where(n=%22x%5Cy%2Fz%22)/b%20c",
            Some(&["GET", "/a~where(n=%22x%5Cy%2Fz%22)/b%20c"]),
            &["GET /a~where(n=%22x%5Cy%2Fz%22)/b%20c"],
        ),
        case(r"a \ in a query is left as it is", r"GET /a?x=b\c", Some(&["GET", r"/a?x=b\c"]), &[r"GET /a?x=b\c"]),
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
        // A ` # …` behind a line is a comment, as the documentation writes them
        case("comment behind a request", "GET /a # note", Some(&["GET", "/a", "#", "note"]), &["GET /a"]),
        case(
            "comment behind a body",
            r#"PUT /a {"x":"a # b"} # note"#,
            Some(&["PUT", "/a", r#"{"x":"a # b"}"#, "#", "note"]),
            &[r#"PUT /a {"x":"a # b"}"#],
        ),
        case("comment behind an outfile", &commented_redirect, Some(&["GET", "/a", ">", &out6, "#", "as the server answers"]), &["GET /a"])
            .writes(out("out6.json"), "/a"),
        case(
            "comment behind directives and an include",
            "url has 127.0.0.1 # here\nsleep 100ms # wait\nseed.api # the seeds\nassert not GET /missing # gone",
            None,
            &["GET /inc1", "GET /inc2", "GET /missing"],
        ),
        case("comment behind a chain", "GET /a && GET /b # both", Some(&["GET", "/a", "&&", "GET", "/b", "#", "both"]), &["GET /a", "GET /b"]),
        // Without a method, the arguments after the URI are still the line's
        case("implied GET to an outfile", &implied_redirect, Some(&["/a", ">", &out7]), &["GET /a"]).writes(out("out7.json"), "/a"),
        // A separator with nothing behind it is a mistake, not a body
        case("a chain that breaks off", "GET /a ||\nPUT /b {\"x\":1}", None, &[])
            .fails("needs a request on both sides"),
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
    check_shown_and_written(case, how, shown);
}

/// The half of `check` that does not depend on how the run ended: what the
/// user was told and what the line wrote.
fn check_shown_and_written(case: &Case, how: &str, shown: &str) {
    if let Some(phrase) = case.says {
        assert!(shown.contains(phrase), "[{}] {how}: expected {phrase:?} to be shown, got:\n{shown}", case.label);
    }
    if let Some((path, answer_of)) = &case.writes {
        assert!(path.is_file(), "[{}] {how}: {} was not written", case.label, path.display());
        // The file is removed after every run, so what it holds is this
        // run's: the answer of the request the redirect belongs to, once.
        let written = std::fs::read_to_string(path).unwrap();
        let holds: Option<serde_json::Value> = serde_json::from_str(&written).ok();
        assert_eq!(
            holds,
            Some(serde_json::json!({ "ok": format!("/api/v1{answer_of}") })),
            "[{}] {how}: {} holds:\n{written}",
            case.label,
            path.display()
        );
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
        // The extension of a file body is read in any case, like an outfile's.
        (&[], "PUT /h @more.njson", NDJSON, NDJSON, "-"),
        (&[], "PUT /h @LOUD.NDJSON", NDJSON, NDJSON, "-"),
        (&[], "PUT /h @Mixed.NJson", NDJSON, NDJSON, "-"),
        (&[], "PUT /h @UP.CSV", JSON, "text/csv", "-"),
        (&[], "PUT /h @UP.CSV~map(com.heads.t)", JSON, "text/csv", "com.heads.t"),
        (&[], "PUT /h @streams/*", NDJSON, NDJSON, "-"),
        // Files put together as one JSON array are sent as JSON, and what is
        // asked for stays what the run asked for.
        (&[], "PUT /h @parts/*.json", JSON, JSON, "-"),
        (&["--ndjson"], "PUT /h @parts/*.json", NDJSON, JSON, "-"),
        (&["--ndjson"], "PUT /h @data.csv", NDJSON, "text/csv", "-"),
        (&[], r#"PUT /h {"x":1}"#, JSON, JSON, "-"),
    ]
}

#[cfg(unix)]
fn header_fixtures(dir: &Path) {
    std::fs::write(dir.join("data.csv"), "a,b\n1,2\n").unwrap();
    std::fs::write(dir.join("rows.ndjson"), "{\"a\":1}\n{\"a\":2}\n").unwrap();
    for name in ["more.njson", "LOUD.NDJSON", "Mixed.NJson"] {
        std::fs::write(dir.join(name), "{\"a\":1}\n{\"a\":2}\n").unwrap();
    }
    std::fs::write(dir.join("UP.CSV"), "a,b\n1,2\n").unwrap();
    std::fs::create_dir_all(dir.join("streams")).unwrap();
    std::fs::write(dir.join("streams/a.NDJSON"), "{\"a\":1}\n").unwrap();
    std::fs::write(dir.join("streams/b.njson"), "{\"a\":2}\n").unwrap();
    std::fs::create_dir_all(dir.join("parts")).unwrap();
    std::fs::write(dir.join("parts/a.json"), "{\"a\":1}").unwrap();
    std::fs::write(dir.join("parts/b.json"), "[{\"a\":2}]").unwrap();
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
        prompt.wait_ready(Duration::from_secs(15));
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

/// The timeout is how long nothing may arrive, not how long a response may
/// take. A body that keeps coming for three seconds is whole under a timeout
/// of one, buffered and streamed, by the option and by a `set` line. (From
/// the change to one HTTP client until 3.3.2 was released it was a deadline
/// for the whole transfer, which ended any export longer than `--timeout`.)
#[test]
fn a_timeout_is_for_silence_not_for_the_whole_transfer() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let whole = |name: &str| {
        let text = std::fs::read_to_string(d.join(name)).unwrap_or_default();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}: {text:?}"));
        assert_eq!(value.as_array().map(Vec::len), Some(16), "{text}");
    };

    let buffered = run_in(&server, d, &["--timeout", "1", "GET", "/slow", ">", "b.json"]);
    assert_eq!((buffered.code, &buffered.sent[..]), (Some(0), &["GET /slow".to_string()][..]), "{}", buffered.stderr);
    whole("b.json");
    let streamed = run_in(&server, d, &["--stream", "--timeout", "1", "GET", "/slow", ">", "s.json"]);
    assert_eq!(streamed.code, Some(0), "{}", streamed.stderr);
    whole("s.json");
    std::fs::write(d.join("t.api"), "set timeout 1\nGET /slow > f.json\nGET /after\n").unwrap();
    let by_line = run_in(&server, d, &["-sa", "t.api"]);
    assert_eq!((by_line.code, by_line.sent.len()), (Some(0), 2), "{}", by_line.stderr);
    whole("f.json");

    // Silence is what it is for: an answer that is two seconds in coming.
    let late = run_in(&server, d, &["--timeout", "1", "GET", "/late"]);
    assert_eq!(late.code, Some(1), "{}", late.stderr);
    assert!(late.stderr.contains("Timed out after 1s"), "{}", late.stderr);
    // `0` waits for as long as it takes, and is not the default under
    // another name: it holds against a `set timeout 1` of the file.
    let never = run_in(&server, d, &["--timeout", "0", "GET", "/late"]);
    assert_eq!(never.code, Some(0), "{}", never.stderr);
    std::fs::write(d.join("t.api"), "set timeout 1\nGET /late\n").unwrap();
    let over_line = run_in(&server, d, &["--timeout", "0", "-sa", "t.api"]);
    assert_eq!(over_line.code, Some(0), "{}", over_line.stderr);
    assert!(over_line.stdout.contains("↳ ignored: --timeout 0 is set"), "{}", over_line.stdout);
    // `set timeout 0` and `set timeout off` both end a `set timeout 1`.
    for back in ["0", "off"] {
        std::fs::write(d.join("t.api"), format!("set timeout 1\nset timeout {back}\nGET /late\nGET /after\n")).unwrap();
        let got = run_in(&server, d, &["-sa", "t.api"]);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /late", "GET /after"].map(String::from)[..]), "{back}: {}", got.stderr);
    }
}

/// What sends nothing is not passed off as a run. A `set` line alone is an
/// error with a comment behind it as without one, and a document option
/// (`--imports`, `--describe`, `--assert`) does not drop the file or the
/// request that stands beside it without a word.
#[test]
fn what_would_send_nothing_or_drop_a_request_is_an_error() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("a.api"), "GET /a\n").unwrap();

    for line in ["set include-nulls", "set include-nulls # note", "set timeout 5   # five", "set export a.b.c # as seed data"] {
        let got = run_in(&server, d, &[line]);
        assert_eq!((got.code, got.sent.len(), got.stdout.as_str()), (Some(1), 0, ""), "{line}: {}", got.stderr);
        assert!(got.stderr.contains("`set` alone sends nothing"), "{line}: {}", got.stderr);
    }
    // With a request under it, the line is a line of a program.
    let got = run_in(&server, d, &["set include-nulls # note\nGET /a"]);
    assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{}", got.stderr);

    for option in ["--imports", "--describe", "--assert"] {
        let got = run_in(&server, d, &[option, "a.api", "GET", "/people"]);
        assert_eq!((got.code, got.sent.len(), got.stdout.as_str()), (Some(1), 0, ""), "{option}: {}", got.stderr);
        assert_eq!(
            got.stderr.trim_end(),
            format!("error: {option} a.api prints a document and GET /people is a request: give one of the two")
        );
        let got = run_in(&server, d, &[option, "a.api", "-sa", "a.api"]);
        assert_eq!((got.code, got.sent.len(), got.stdout.as_str()), (Some(1), 0, ""), "{option}: {}", got.stderr);
        assert_eq!(
            got.stderr.trim_end(),
            format!("error: {option} a.api prints a document and -a a.api runs a file: give one of the two")
        );
        // Alone, and with an option that is about how it prints, it prints.
        let got = run_in(&server, d, &["-r", option, "a.api"]);
        let document = if option == "--describe" { "null" } else { "[]" };
        assert_eq!((got.code, got.sent.len(), got.stdout.trim_end()), (Some(0), 0, document), "{option}: {}", got.stderr);
    }
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
    // The partial file is `part.json.<pid>.part`, so it is the directory
    // that is looked at, not a name.
    assert_eq!(left_in(d), Vec::<String>::new(), "a partial outfile or its .part file is left");

    // What the file held before is still there.
    std::fs::write(d.join("kept.json"), "[\"before\"]").unwrap();
    std::fs::write(d.join("stream.api"), "GET /midfail > kept.json\nGET /never\n").unwrap();
    for flags in ["-sa", "-sfa"] {
        let batch = run_in(&server, d, &["--stream", flags, "stream.api"]);
        assert_eq!(batch.code, Some(1), "{flags}: {}", batch.stderr);
        assert_eq!(batch.sent, ["GET /midfail"], "{flags}");
        assert_eq!(std::fs::read_to_string(d.join("kept.json")).unwrap(), "[\"before\"]", "{flags}");
        assert_eq!(left_in(d), ["kept.json", "stream.api"], "{flags}");
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
    assert_eq!(left_in(d), ["drain.api", "good.json", "kept.json", "stream.api"]);
}

/// What a directory holds, dot-files (the history, the credentials) aside.
fn left_in(dir: &Path) -> Vec<String> {
    let mut left: Vec<String> =
        std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    left.retain(|name| !name.starts_with('.'));
    left.sort();
    left
}

/// A streamed run that is sent `signal` once its partial file is there: how
/// it ended. `ignored` starts it the way a shell starts a background job of
/// a script, with the signal ignored.
#[cfg(unix)]
fn interrupted_mid_stream(mut cmd: std::process::Command, dir: &Path, signal: libc::c_int, ignored: bool) -> std::process::ExitStatus {
    use std::os::unix::process::CommandExt;

    unsafe {
        cmd.pre_exec(move || {
            // Not whatever the test run itself was started with.
            libc::signal(signal, if ignored { libc::SIG_IGN } else { libc::SIG_DFL });
            Ok(())
        });
    }
    let mut child = cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().expect("spawn api");
    let start = Instant::now();
    while !left_in(dir).iter().any(|name| name.ends_with(".part")) {
        assert!(start.elapsed() < Duration::from_secs(10), "no partial file appeared: {:?}", left_in(dir));
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    unsafe { libc::kill(child.id() as libc::pid_t, signal) };
    child.wait().expect("wait")
}

/// ctrl+c, or a `kill`, during a streamed `> file` leaves the target as it
/// was and no partial file, and the run still ends the way an interrupted
/// program does, so a shell reports 130.
#[cfg(unix)]
#[test]
fn an_interrupted_stream_leaves_no_partial_file() {
    use std::os::unix::process::ExitStatusExt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("kept.json"), "[\"before\"]").unwrap();
    let streamed = |args: &[&str]| {
        let mut cmd = api(server.port, d);
        cmd.arg("--stream").args(args);
        cmd
    };

    for signal in [libc::SIGINT, libc::SIGTERM] {
        let status = interrupted_mid_stream(streamed(&["GET", "/slow", ">", "new.json"]), d, signal, false);
        assert_eq!(status.signal(), Some(signal), "{status:?}");
        assert_eq!(left_in(d), ["kept.json"], "signal {signal}");

        let status = interrupted_mid_stream(streamed(&["GET", "/slow", ">", "kept.json"]), d, signal, false);
        assert_eq!(status.signal(), Some(signal), "{status:?}");
        assert_eq!(left_in(d), ["kept.json"], "signal {signal}");
        assert_eq!(std::fs::read_to_string(d.join("kept.json")).unwrap(), "[\"before\"]", "signal {signal}");
    }

    // In a batch the lines after it are not sent, and an interrupt during a
    // later line (a `sleep`) still ends the run at once.
    std::fs::write(d.join("then.api"), "GET /slow > new.json\nGET /never\n").unwrap();
    server.take();
    let status = interrupted_mid_stream(streamed(&["-sa", "then.api"]), d, libc::SIGINT, false);
    assert_eq!(status.signal(), Some(libc::SIGINT), "{status:?}");
    assert_eq!(left_in(d), ["kept.json", "then.api"]);
    server.settle(Duration::from_millis(150), Duration::from_secs(2));
    assert_eq!(server.take(), ["GET /slow"]);

    std::fs::write(d.join("sleeps.api"), "GET /a > first.json\nsleep 30\nGET /never\n").unwrap();
    let mut sleeping = streamed(&["-sa", "sleeps.api"]);
    unsafe {
        use std::os::unix::process::CommandExt;
        // Not whatever the test run itself was started with: a suite run as
        // a background job has the interrupt ignored, and so would this.
        sleeping.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            Ok(())
        });
    }
    let mut child = sleeping.stdout(std::process::Stdio::null()).spawn().expect("spawn api");
    let start = Instant::now();
    while !d.join("first.json").exists() && start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    let sent_at = Instant::now();
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };
    let status = child.wait().expect("wait");
    assert_eq!(status.signal(), Some(libc::SIGINT), "{status:?}");
    assert!(sent_at.elapsed() < Duration::from_secs(5), "the sleep was not interrupted");
    std::fs::remove_file(d.join("first.json")).unwrap();
    std::fs::remove_file(d.join("sleeps.api")).unwrap();

    // A run started with the interrupt ignored still ignores it: the
    // transfer goes on to its end.
    let status = interrupted_mid_stream(streamed(&["GET", "/slow", ">", "whole.json"]), d, libc::SIGINT, true);
    assert_eq!(status.code(), Some(0), "{status:?}");
    assert_eq!(left_in(d), ["kept.json", "then.api", "whole.json"]);
    assert!(std::fs::read_to_string(d.join("whole.json")).unwrap().ends_with("1]"));
}

/// A streamed outfile is the file a buffered one would be: `/dev/null` takes
/// it, a link stays a link, a private file stays private, and a file that
/// happens to be named `<outfile>.part` is not touched.
#[cfg(unix)]
#[test]
fn a_streamed_outfile_keeps_what_its_target_is() {
    use std::os::unix::fs::PermissionsExt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let body = r#"{"ok":"/api/v1/a"}"#;
    let mode = |name: &str| std::fs::metadata(d.join(name)).unwrap().permissions().mode() & 0o777;
    let names = || {
        let mut names: Vec<String> =
            std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
        names.retain(|n| !n.starts_with('.'));
        names.sort();
        names
    };

    for stream in [false, true] {
        let with = |args: &[&'static str]| -> Vec<&'static str> {
            let mut all = if stream { vec!["--stream", "-r"] } else { vec!["-r"] };
            all.extend_from_slice(args);
            all
        };
        let null = run_in(&server, d, &with(&["GET", "/a", ">", "/dev/null"]));
        assert_eq!(null.code, Some(0), "stream={stream}: {}", null.stderr);

        std::fs::write(d.join("real.json"), "old").unwrap();
        std::fs::write(d.join("keep.json"), "old").unwrap();
        std::fs::write(d.join("keep.json.part"), "mine").unwrap();
        std::fs::set_permissions(d.join("keep.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let _ = std::fs::remove_file(d.join("link.json"));
        std::os::unix::fs::symlink("real.json", d.join("link.json")).unwrap();

        let linked = run_in(&server, d, &with(&["GET", "/a", ">", "link.json"]));
        assert_eq!(linked.code, Some(0), "stream={stream}: {}", linked.stderr);
        assert!(std::fs::symlink_metadata(d.join("link.json")).unwrap().file_type().is_symlink(), "stream={stream}");
        assert_eq!(std::fs::read_to_string(d.join("real.json")).unwrap(), body, "stream={stream}");

        let kept = run_in(&server, d, &with(&["GET", "/a", ">", "keep.json"]));
        assert_eq!(kept.code, Some(0), "stream={stream}: {}", kept.stderr);
        assert_eq!((mode("keep.json"), std::fs::read_to_string(d.join("keep.json")).unwrap()), (0o600, body.to_string()), "stream={stream}");
        assert_eq!(std::fs::read_to_string(d.join("keep.json.part")).unwrap(), "mine", "stream={stream}");
        assert_eq!(names(), ["keep.json", "keep.json.part", "link.json", "real.json"], "stream={stream}");
    }

    // A stream that never ends is a timeout, and leaves nothing behind.
    let stalled = run_in(&server, d, &["--stream", "--timeout", "1", "GET", "/stall", ">", "s.json"]);
    assert_eq!(stalled.code, Some(1), "{}", stalled.stderr);
    assert!(stalled.stderr.contains("Timed out after"), "{}", stalled.stderr);
    assert_eq!(names(), ["keep.json", "keep.json.part", "link.json", "real.json"]);
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
        // However the one request is quoted, it is one request.
        for quoted in [&["GET /a > no-such-dir/x.json"][..], &["GET", "/a > no-such-dir/x.json"], &["/a > no-such-dir/x.json"]] {
            let one = run_in(&server, d, &with(quoted));
            assert_eq!((one.code, one.sent.len()), (Some(1), 1), "stream={stream} {quoted:?}: {}", one.stderr);
            assert!(one.stderr.contains("Error writing to no-such-dir/x.json"), "stream={stream} {quoted:?}: {}", one.stderr);
        }
        // A file named as the argument is a batch, with one request or more.
        file("one.api", "GET /a > no-such-dir/x.json\n");
        for named in [&["one.api"][..], &["-a", "one.api"]] {
            let batch = run_in(&server, d, &with(named));
            assert_eq!((batch.code, batch.sent.len()), (Some(0), 1), "stream={stream} {named:?}: {}", batch.stderr);
        }
        // And so are two lines in one argument.
        let two = run_in(&server, d, &with(&["GET /a > no-such-dir/x.json\nGET /b"]));
        assert_eq!((two.code, two.sent.len()), (Some(0), 2), "stream={stream}: {}", two.stderr);

        file("w.api", "GET /a > no-such-dir/x.json\nGET /b\n");
        let plain = run_in(&server, d, &with(&["-sa", "w.api"]));
        assert_eq!((plain.code, plain.sent.len()), (Some(0), 2), "stream={stream}: {}", plain.stderr);
        assert!(plain.stderr.contains("Error writing to no-such-dir/x.json"), "stream={stream}: {}", plain.stderr);
        let fail_fast = run_in(&server, d, &with(&["-sfa", "w.api"]));
        assert_eq!((fail_fast.code, &fail_fast.sent[..]), (Some(1), &["GET /a".to_string()][..]), "stream={stream}: {}", fail_fast.stderr);

        file("wc.api", "GET /a > no-such-dir/x.json && GET /never\n");
        let chain = run_in(&server, d, &with(&["-sa", "wc.api"]));
        assert_eq!((chain.code, &chain.sent[..]), (Some(1), &["GET /a".to_string()][..]), "stream={stream}: {}", chain.stderr);

        // A file that is there and may not be written is not replaced.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file("ro.json", "old");
            std::fs::set_permissions(d.join("ro.json"), std::fs::Permissions::from_mode(0o444)).unwrap();
            // Whoever may write anything (root) is not told no.
            if std::fs::OpenOptions::new().write(true).open(d.join("ro.json")).is_err() {
                let one = run_in(&server, d, &with(&["GET", "/a", ">", "ro.json"]));
                assert_eq!(one.code, Some(1), "stream={stream}: {}", one.stderr);
                assert!(one.stderr.contains("Error writing to ro.json"), "stream={stream}: {}", one.stderr);
                assert_eq!(std::fs::read_to_string(d.join("ro.json")).unwrap(), "old", "stream={stream}");
            }
            std::fs::remove_file(d.join("ro.json")).unwrap();
        }
    }
}

/// A number is written with the digits it came with, wherever a body is read
/// as JSON on its way: `> file.json`, `> file.ndjson`, what `>>` adds,
/// `--export`, and a glob body. None of them is an `f64` on the way.
#[test]
fn a_number_is_written_with_the_digits_it_came_with() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let read = |name: &str| std::fs::read_to_string(d.join(name)).unwrap();
    let compact = |text: &str| text.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    let list = format!("[{NUMBERS}]");

    // Stdout has them as they came, and always had.
    let shown = run_in(&server, d, &["GET", "/numbers"]);
    assert_eq!(shown.stdout.trim(), list, "{}", shown.stderr);

    for flags in [&[][..], &["-r"]] {
        let with = |args: &[&'static str]| [flags, args].concat();
        let one = run_in(&server, d, &with(&["GET", "/numbers", ">", "n.json"]));
        assert_eq!(one.code, Some(0), "{}", one.stderr);
        assert_eq!(compact(&read("n.json")), list, "{flags:?}");

        run_in(&server, d, &with(&["GET", "/numbers", ">", "n.ndjson"]));
        assert_eq!(read("n.ndjson"), format!("{NUMBERS}\n"), "{flags:?}");

        // What `>>` adds: to a file that is not there, and to one that is.
        for name in ["a.json", "a.ndjson"] {
            let _ = std::fs::remove_file(d.join(name));
            run_in(&server, d, &with(&["GET", "/numbers", ">>", name]));
            run_in(&server, d, &with(&["GET", "/numbers", ">>", name]));
        }
        assert_eq!(compact(&read("a.json")), format!("[{NUMBERS},{NUMBERS}]"), "{flags:?}");
        assert_eq!(read("a.ndjson"), format!("{NUMBERS}\n{NUMBERS}\n"), "{flags:?}");

        // `--export`: to stdout, a file and an NDJSON file.
        let export = |args: &[&'static str]| with(&[&["--export", "com.heads.seedID"], args].concat());
        let exported = run_in(&server, d, &export(&["GET", "/numbers"]));
        assert_eq!(compact(&exported.stdout), list, "{flags:?}: {}", exported.stderr);
        run_in(&server, d, &export(&["GET", "/numbers", ">", "e.json"]));
        assert_eq!(compact(&read("e.json")), list, "{flags:?}");
        run_in(&server, d, &export(&["GET", "/numbers", ">", "e.ndjson"]));
        assert_eq!(read("e.ndjson").trim_end(), NUMBERS, "{flags:?}");
    }

    // A glob body is the files as one array: a single record and a list.
    std::fs::create_dir(d.join("g")).unwrap();
    std::fs::write(d.join("g/a.json"), NUMBERS).unwrap();
    std::fs::write(d.join("g/b.json"), &list).unwrap();
    let put = run_in(&server, d, &["PUT", "/x", "@g/*.json"]);
    assert_eq!(put.sent, [format!("PUT /x [{NUMBERS},{NUMBERS}]")], "{}", put.stderr);
    // And one file is sent as it is.
    let put = run_in(&server, d, &["PUT", "/x", "@g/a.json"]);
    assert_eq!(put.sent, [format!("PUT /x {NUMBERS}")], "{}", put.stderr);
}

/// Zero is falsy however the server spells it, to a chain, an `assert` and a
/// `sleep while`; a number that only rounds to zero is not zero.
#[test]
fn zero_is_falsy_however_it_is_spelled() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for zero in ["0", "-0", "0.0", "0e0", "0E0", "0.00e-3", "-0.0"] {
        let chain = run_in(&server, d, &[&format!("GET /zero/{zero} && GET /never")]);
        assert_eq!((chain.code, &chain.sent[..]), (Some(0), &[format!("GET /zero/{zero}")][..]), "{zero}: {}", chain.stderr);
        let or = run_in(&server, d, &[&format!("GET /zero/{zero} || GET /then")]);
        assert_eq!(or.sent, [format!("GET /zero/{zero}"), "GET /then".to_string()], "{zero}: {}", or.stderr);
        let asserted = run_in(&server, d, &[&format!("assert GET /zero/{zero}")]);
        assert_eq!(asserted.code, Some(1), "{zero}: {}", asserted.stderr);
        assert!(asserted.stderr.contains(&format!("assertion failed: assert GET /zero/{zero} ({zero})")), "{zero}: {}", asserted.stderr);
        let not = run_in(&server, d, &[&format!("assert not GET /zero/{zero}")]);
        assert_eq!(not.code, Some(0), "{zero}: {}", not.stderr);
        // The poll ends at once: there is nothing to wait for.
        let polled = run_in(&server, d, &[&format!("sleep 100ms while GET /zero/{zero}\nGET /after")]);
        assert_eq!(polled.sent, [format!("GET /zero/{zero}"), "GET /after".to_string()], "{zero}: {}", polled.stderr);
    }
    for other in ["1", "0.1", "1e-9", "0.0000000000000000000001", "12345678901234567890123"] {
        let chain = run_in(&server, d, &[&format!("GET /zero/{other} && GET /then")]);
        assert_eq!(chain.sent, [format!("GET /zero/{other}"), "GET /then".to_string()], "{other}: {}", chain.stderr);
    }
}

/// Without `-f` a `> file` takes whatever was answered, an error too. A
/// `>> file` collects answers, and an error is not one: it is shown where it
/// would have been without the redirect, and the file is left as it was,
/// whatever it holds.
#[test]
fn an_error_replaces_an_outfile_and_is_never_appended_to_one() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let read = |name: &str| std::fs::read_to_string(d.join(name)).unwrap();

    for stream in [false, true] {
        let with = |args: &[&'static str]| -> Vec<&'static str> {
            let mut all = if stream { vec!["--stream"] } else { Vec::new() };
            all.extend_from_slice(args);
            all
        };
        // `>`: the error is what the file holds, buffered even under
        // `--stream` (so indented, where a streamed 200 is as it came).
        let replaced = run_in(&server, d, &with(&["GET", "/gone", ">", "e.json"]));
        assert_eq!(replaced.code, Some(0), "stream={stream}: {}", replaced.stderr);
        assert_eq!(read("e.json"), GONE_INDENTED, "stream={stream}");
        assert_eq!(replaced.stdout, "", "stream={stream}");

        // `>>`: every kind of target is left as it was.
        let targets = [
            ("list.json", "[{\"a\":1}]"),
            ("one.json", "{\"a\":1}\n"),
            ("rows.ndjson", "{\"a\":1}\n"),
            ("table.csv", "a,b\n1,2\n"),
            ("notes.txt", "a note\n"),
            ("empty.json", ""),
        ];
        for (name, held) in targets {
            std::fs::write(d.join(name), held).unwrap();
            let appended = run_in(&server, d, &with(&["GET", "/gone", ">>", name]));
            assert_eq!(appended.code, Some(0), "stream={stream} {name}: {}", appended.stderr);
            assert_eq!(read(name), held, "stream={stream}: the error was appended to {name}");
            // The body goes where it would have gone, and a line says why
            // the file did not get it.
            assert_eq!(appended.stdout.trim_end(), GONE, "stream={stream} {name}");
            assert!(appended.stderr.contains("404 Not Found"), "stream={stream} {name}: {}", appended.stderr);
            assert!(appended.stderr.contains(&format!(">> {name} (not appended)")), "stream={stream} {name}: {}", appended.stderr);
        }
        // A file that is not there is not made for it.
        let fresh = run_in(&server, d, &with(&["GET", "/gone", ">>", "fresh.json"]));
        assert_eq!(fresh.code, Some(0), "stream={stream}: {}", fresh.stderr);
        assert!(!d.join("fresh.json").exists(), "stream={stream}: an error made the file");
        // `-s` leaves the line out, as it leaves the size line out.
        let silent = run_in(&server, d, &with(&["-s", "GET", "/gone", ">>", "fresh.json"]));
        assert_eq!((silent.stderr.as_str(), silent.stdout.trim_end()), ("", GONE), "stream={stream}");

        // In a batch the next line runs, and an answer is still appended:
        // under `--stream` too, where `>>` splices as it does buffered.
        std::fs::write(d.join("list.json"), "[{\"a\":1}]").unwrap();
        std::fs::write(d.join("b.api"), "GET /gone >> list.json\nGET /a >> list.json\nGET /b >> list.json\n").unwrap();
        let batch = run_in(&server, d, &with(&["-sa", "b.api"]));
        assert_eq!((batch.code, batch.sent.len()), (Some(0), 3), "stream={stream}: {}", batch.stderr);
        // `-sa` shows no body, with or without a redirect.
        assert!(!batch.stdout.contains("\"error\""), "stream={stream}: {}", batch.stdout);
        let list: serde_json::Value = serde_json::from_str(&read("list.json")).unwrap();
        assert_eq!(
            list,
            serde_json::json!([{ "a": 1 }, { "ok": "/api/v1/a" }, { "ok": "/api/v1/b" }]),
            "stream={stream}"
        );

        // A chain's condition answered "no" leaves its `>>` target alone and
        // goes on to the other half.
        std::fs::write(d.join("list.json"), "[{\"a\":1}]").unwrap();
        let chain = run_in(&server, d, &with(&["GET /gone >> list.json || GET /a >> list.json"]));
        assert_eq!((chain.code, chain.sent.len()), (Some(0), 2), "stream={stream}: {}", chain.stderr);
        let list: serde_json::Value = serde_json::from_str(&read("list.json")).unwrap();
        assert_eq!(list, serde_json::json!([{ "a": 1 }, { "ok": "/api/v1/a" }]), "stream={stream}");

        // Under `-f` neither redirect gets the error, as before.
        std::fs::remove_file(d.join("e.json")).unwrap();
        for redirect in [">", ">>"] {
            let stopped = run_in(&server, d, &with(&["-f", "GET", "/gone", redirect, "e.json"]));
            assert_eq!((stopped.code, stopped.stdout.trim_end()), (Some(1), GONE), "stream={stream} {redirect}");
            assert!(!d.join("e.json").exists(), "stream={stream} {redirect}");
        }
    }

    // A streamed `> file` holds the server's bytes; a streamed `>>` is
    // buffered, and laid out as a buffered one is.
    run_in(&server, d, &["--stream", "GET", "/a", ">", "s.json"]);
    assert_eq!(read("s.json"), r#"{"ok":"/api/v1/a"}"#);
    run_in(&server, d, &["--stream", "GET", "/a", ">>", "s2.json"]);
    run_in(&server, d, &["GET", "/a", ">>", "b2.json"]);
    assert_eq!(read("s2.json"), "{\n  \"ok\": \"/api/v1/a\"\n}");
    assert_eq!(read("s2.json"), read("b2.json"));
}

/// The prompt does with an error and a `>>` what a batch does.
#[cfg(unix)]
#[test]
fn the_prompt_does_not_append_an_error_either() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let read = |name: &str| std::fs::read_to_string(d.join(name)).unwrap();
    std::fs::write(d.join("list.json"), "[{\"a\":1}]").unwrap();

    let mut prompt = open_prompt(&server, d, &[]);
    let shown = enter_line(&mut prompt, "GET /gone >> list.json", "404");
    assert_eq!(read("list.json"), "[{\"a\":1}]", "{shown}");
    assert!(shown.contains(">> list.json (not appended)"), "{shown}");
    assert!(shown.contains("\"error\": \"gone\""), "{shown}");
    let shown = enter_line(&mut prompt, "GET /gone >> fresh.json", "404");
    assert!(!d.join("fresh.json").exists(), "{shown}");
    // A `>` takes it, and an answer is appended as ever.
    enter_line(&mut prompt, "GET /gone > e.json", "404");
    assert_eq!(read("e.json"), GONE_INDENTED);
    enter_line(&mut prompt, "GET /a >> list.json", "200 OK");
    let list: serde_json::Value = serde_json::from_str(&read("list.json")).unwrap();
    assert_eq!(list, serde_json::json!([{ "a": 1 }, { "ok": "/api/v1/a" }]));
}

/// The outfile of a chain's segment holds the answer of that segment, and a
/// segment that did not run writes nothing.
#[test]
fn an_outfile_in_a_chain_holds_the_answer_of_its_own_segment() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let holds = |name: &str| -> Option<serde_json::Value> {
        std::fs::read_to_string(d.join(name)).ok().map(|text| serde_json::from_str(&text).unwrap())
    };
    let answer = |path: &str| Some(serde_json::json!({ "ok": format!("/api/v1{path}") }));
    let line = "GET /a > a.json && GET /b > b.json || GET /c > c.json";
    std::fs::write(d.join("chain.api"), format!("{line}\n")).unwrap();

    let runs: [&[&str]; 3] = [
        &["-sa", "chain.api"],
        &[line],
        &["GET", "/a", ">", "a.json", "&&", "GET", "/b", ">", "b.json", "||", "GET", "/c", ">", "c.json"],
    ];
    for args in runs {
        for name in ["a.json", "b.json", "c.json"] {
            let _ = std::fs::remove_file(d.join(name));
        }
        let chain = run_in(&server, d, args);
        assert_eq!((chain.code, &chain.sent[..]), (Some(0), &["GET /a".to_string(), "GET /b".to_string()][..]), "{args:?}: {}", chain.stderr);
        assert_eq!((holds("a.json"), holds("b.json"), holds("c.json")), (answer("/a"), answer("/b"), None), "{args:?}");
    }

    // The condition's own "no" is what its file holds, and the other half's
    // answer is in the other half's file.
    let or = run_in(&server, d, &["GET /zero > zero.json || GET /b >> or.json"]);
    assert_eq!(or.code, Some(0), "{}", or.stderr);
    assert_eq!((holds("zero.json"), holds("or.json")), (Some(serde_json::json!(0)), answer("/b")));
}

/// `PUT /x @dir/*.json` with one file that is not JSON: the file is named,
/// the run fails, and nothing is sent, not that request and not a later one.
#[test]
fn a_glob_body_with_a_malformed_file_names_it_and_sends_nothing() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::create_dir(d.join("rows")).unwrap();
    std::fs::write(d.join("rows/a.json"), r#"{"a":1}"#).unwrap();
    std::fs::write(d.join("rows/b.json"), r#"{"b":2,}"#).unwrap();
    std::fs::write(d.join("rows/c.json"), r#"{"c":3}"#).unwrap();
    std::fs::write(d.join("glob.api"), "PUT /x @rows/*.json\nGET /never\n").unwrap();

    let runs: [&[&str]; 4] = [&["PUT", "/x", "@rows/*.json"], &["PUT /x @rows/*.json"], &["-sa", "glob.api"], &["-sfa", "glob.api"]];
    for args in runs {
        let bad = run_in(&server, d, args);
        assert_eq!((bad.code, bad.sent.len()), (Some(1), 0), "{args:?}: {}", bad.stderr);
        assert!(bad.stderr.contains("invalid JSON in rows/b.json: "), "{args:?}: {}", bad.stderr);
        assert!(bad.stderr.contains("line 1 column 8"), "{args:?}: {}", bad.stderr);
    }
    // With the file mended the three are one array, in sorted order.
    std::fs::write(d.join("rows/b.json"), r#"[{"b":2}]"#).unwrap();
    let good = run_in(&server, d, &["-sa", "glob.api"]);
    assert_eq!(good.sent, [r#"PUT /x [{"a":1},{"b":2},{"c":3}]"#, "GET /never"], "{}", good.stderr);
}

/// A file body that is NDJSON is sent as it is, as NDJSON, whichever of the
/// two extensions it has; a glob of them is one stream, in sorted order, with
/// a line break between two files where the first had none.
#[test]
fn an_ndjson_file_body_is_sent_as_ndjson_and_a_glob_of_them_as_one_stream() {
    const HEAD: &str = "accept=application/x-ndjson; content-type=application/x-ndjson; authorization=Basic Oms=; x-request-map=-";
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("rows.njson"), "{\"a\":1}\n{\"a\":2}\n").unwrap();
    std::fs::create_dir(d.join("ev")).unwrap();
    std::fs::write(d.join("ev/b.ndjson"), "{\"b\":1}\n{\"b\":2}").unwrap();
    std::fs::write(d.join("ev/a.ndjson"), "{\"a\":1}\n").unwrap();
    std::fs::write(d.join("ev/c.njson"), "{\"c\":1}\n").unwrap();
    std::fs::write(d.join(".DS_Store"), "junk").unwrap();
    std::fs::write(d.join("nd.api"), "PUT /rows @rows.njson\nPUT /events @ev/*\n").unwrap();

    let sent = ["PUT /rows {\"a\":1}\n{\"a\":2}\n", "PUT /events {\"a\":1}\n{\"b\":1}\n{\"b\":2}\n{\"c\":1}\n"];
    let batch = api(server.port, d).args(["-sa", "nd.api"]).output().expect("spawn api");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    assert_eq!(server.heads(), [HEAD, HEAD], "{}", String::from_utf8_lossy(&batch.stderr));
    assert_eq!(server.take(), sent);

    for (line, sent) in [(&["PUT", "/rows", "@rows.njson"], sent[0]), (&["PUT", "/events", "@ev/*"], sent[1])] {
        api(server.port, d).args(line).output().expect("spawn api");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        assert_eq!(server.heads(), [HEAD], "{line:?}");
        assert_eq!(server.take(), [sent], "{line:?}");
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
    prompt.wait_ready(Duration::from_secs(15));
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

/// How often each of `paths` was requested, by what the server recorded.
fn counts(sent: &[String], paths: &[&str]) -> Vec<usize> {
    paths.iter().map(|p| sent.iter().filter(|line| line.split(' ').nth(1) == Some(p)).count()).collect()
}

/// Renewal has an end: the answer to the request sent again is the answer,
/// a token endpoint that fails leaves the first 401 standing, and a
/// connection without client credentials never asks for a token.
#[test]
fn a_token_is_renewed_once_and_only_for_an_oauth2_connection() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let token = "/oauth2/v1/token";
    let run = |connection: (&str, &str, &str), args: &[&str]| {
        let server = RecordingServer::start();
        let url = format!("http://127.0.0.1:{}", server.port);
        write_credentials(d, &[("c", url, connection.0, connection.1, connection.2)], "c");
        let got = run_bare(&server, d, args);
        (got.code, got.sent, got.stderr)
    };

    // A 401 that stays: two requests, two tokens, and no third of either.
    let (_, sent, stderr) = run(("oauth2", "secret", "id"), &["GET", "/denied"]);
    assert_eq!(counts(&sent, &[token, "/denied"]), [2, 2], "{sent:?}\n{stderr}");
    assert!(stderr.contains("401"), "{stderr}");
    let (code, sent, stderr) = run(("oauth2", "secret", "id"), &["-f", "GET", "/denied"]);
    assert_eq!((code, counts(&sent, &[token, "/denied"])), (Some(1), vec![2, 2]), "{sent:?}\n{stderr}");

    // The token endpoint fails the second time: the 401 is the answer.
    let (_, sent, stderr) = run(("oauth2", "secret", "once"), &["GET", "/expired"]);
    assert_eq!(counts(&sent, &[token, "/expired"]), [2, 1], "{sent:?}\n{stderr}");
    assert!(stderr.contains("401"), "{stderr}");

    // A key and a plain token have nothing to renew with.
    for kind in ["key", "token"] {
        let (_, sent, stderr) = run((kind, "secret", ""), &["GET", "/denied"]);
        assert_eq!(counts(&sent, &[token, "/denied"]), [0, 1], "{kind}: {sent:?}\n{stderr}");
    }
    // Nor has an OAuth2 connection with `-k` in the place of its secret.
    let (_, sent, _) = run(("oauth2", "secret", "id"), &["-k", "CLIKEY", "GET", "/denied"]);
    assert_eq!(counts(&sent, &[token, "/denied"]), [0, 1], "{sent:?}");

    // A check, a poll and a chain are renewed for like any request, and
    // judge the answer the renewed token got.
    std::fs::write(d.join("assert.api"), "assert GET /expired\nGET /after\n").unwrap();
    std::fs::write(d.join("poll.api"), "sleep 0 while not GET /expired\nGET /after\n").unwrap();
    std::fs::write(d.join("chain.api"), "GET /expired && GET /after\n").unwrap();
    for file in ["assert.api", "poll.api", "chain.api"] {
        let (code, sent, stderr) = run(("oauth2", "secret", "id"), &["-sfa", file]);
        assert_eq!(code, Some(0), "{file}: {stderr}");
        assert_eq!(counts(&sent, &[token, "/expired", "/after"]), [2, 2, 1], "{file}: {sent:?}");
    }
}

/// A token renewed at the prompt is the session's from then on: the next
/// request carries it, and nothing more is asked of the token endpoint.
#[cfg(unix)]
#[test]
fn a_renewed_token_is_kept_for_the_session() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    write_credentials(d, &[("o", url, "oauth2", "secret", "id")], "o");
    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));

    for (line, expired_requests) in [("GET /expired/x", 2), ("GET /expired/y", 1)] {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        let before = server.seen();
        let mark = prompt.screen.len();
        prompt.paste(line);
        prompt.pump(Duration::from_millis(60));
        prompt.send(b"\r");
        let answered = pump_until(&mut prompt, Duration::from_secs(8), |p| pty::plain(&p.screen[mark..]).contains("200 OK"));
        assert!(answered, "{line}: {}", screen_tail(&prompt));
        prompt.pump(Duration::from_millis(300));
        let sent = server.log.lock().unwrap()[before..].to_vec();
        let path = line.trim_start_matches("GET ");
        assert_eq!(counts(&sent, &[path]), [expired_requests], "{line}: {sent:?}");
    }
    // The startup exchange and the one renewal.
    let sent = server.log.lock().unwrap().clone();
    assert_eq!(counts(&sent, &["/oauth2/v1/token"]), [2], "{sent:?}");
    assert!(server.heads().last().unwrap().contains("authorization=Bearer fresh;"), "{:?}", server.heads());
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
    prompt.wait_ready(Duration::from_secs(15));
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
    // Nor is it appended to one.
    let shown = enter(&mut prompt, "GET /missing >> error2.json", "404");
    assert!(!d.join("error2.json").exists(), "the error was appended to the outfile\n{shown}");

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

/// Type `line` at a prompt in the place of what is there, press Enter, and
/// wait for `wait_for` to show. Returns what the screen showed from then on.
#[cfg(unix)]
fn enter_line(prompt: &mut pty::Prompt, line: &str, wait_for: &str) -> String {
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    let mark = prompt.screen.len();
    prompt.paste(line);
    prompt.pump(Duration::from_millis(60));
    prompt.send(b"\r");
    pump_until(prompt, Duration::from_secs(6), |p| pty::plain(&p.screen[mark..]).contains(wait_for));
    prompt.pump(Duration::from_millis(250));
    pty::plain(&prompt.screen[mark..])
}

/// With streaming on, the prompt writes an outfile as a streamed batch does:
/// whole when the body ends, not at all when it breaks off, and a path that
/// can't be written is said to be that.
#[cfg(unix)]
#[test]
fn the_prompt_streams_an_outfile_as_a_batch_does() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    let mut cmd = api_bare(d);
    cmd.args(["-b", &url, "-k", "streamer", "--stream"]);
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    assert!(pty::rows(&prompt.screen, 200).last().unwrap().ends_with("streaming"), "{}", screen_tail(&prompt));

    let shown = enter_line(&mut prompt, "GET /a > s.json", "200 OK");
    assert!(shown.contains("> s.json"), "{shown}");
    // The server's bytes as they came, which is what a stream writes.
    assert_eq!(std::fs::read_to_string(d.join("s.json")).unwrap(), r#"{"ok":"/api/v1/a"}"#);
    assert!(server.heads().last().unwrap().contains("accept=application/json;stream=true;"), "{:?}", server.heads());

    std::fs::write(d.join("kept.json"), "[\"before\"]").unwrap();
    let shown = enter_line(&mut prompt, "GET /midfail > kept.json", "The response was cut short");
    assert!(shown.contains("The response was cut short"), "{shown}");
    assert_eq!(std::fs::read_to_string(d.join("kept.json")).unwrap(), "[\"before\"]");

    let shown = enter_line(&mut prompt, "GET /a > no-such-dir/x.json", "Error writing");
    assert!(shown.contains("Error writing to no-such-dir/x.json"), "{shown}");

    let mut left: Vec<String> =
        std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    left.retain(|name| !name.starts_with('.'));
    left.sort();
    assert_eq!(left, ["kept.json", "s.json"]);
}

/// esc during a request says `request aborted` and the session goes on. A
/// streamed `> file` that is aborted is really given up: the target is as
/// it was and no partial file is left, then, when the body would have
/// ended, or after quitting at once.
#[cfg(unix)]
#[test]
fn an_aborted_stream_at_the_prompt_is_given_up() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    std::fs::write(d.join("kept.json"), "[\"before\"]").unwrap();
    let open = || {
        let mut cmd = api_bare(d);
        cmd.args(["-b", &url, "-k", "streamer", "--stream"]);
        let mut prompt = pty::Prompt::open(cmd);
        prompt.wait_ready(Duration::from_secs(15));
        prompt.pump(Duration::from_millis(500));
        prompt
    };
    // Send `line` and press esc once its partial file is there (or, for a
    // line with no outfile, once the server has the request).
    let aborted = |prompt: &mut pty::Prompt, line: &str| -> String {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        let mark = prompt.screen.len();
        prompt.paste(line);
        prompt.pump(Duration::from_millis(60));
        prompt.send(b"\r");
        let to_file = line.contains('>');
        let under_way = pump_until(prompt, Duration::from_secs(6), |_| match to_file {
            true => left_in(d).iter().any(|name| name.ends_with(".part")),
            false => server.seen() > 0,
        });
        assert!(under_way, "{line}: {:?}\n{}", left_in(d), screen_tail(prompt));
        prompt.pump(Duration::from_millis(400));
        prompt.send(b"\x1b");
        assert!(
            pump_until(prompt, Duration::from_secs(3), |p| pty::plain(&p.screen[mark..]).contains("request aborted")),
            "{line}: {}",
            screen_tail(prompt)
        );
        pty::plain(&prompt.screen[mark..])
    };

    let mut prompt = open();
    aborted(&mut prompt, "GET /slow");
    for target in ["new.json", "kept.json"] {
        aborted(&mut prompt, &format!("GET /slow > {target}"));
        assert_eq!(left_in(d), ["kept.json"], "{target}, at once");
        // The body ends three seconds after it began.
        prompt.pump(Duration::from_millis(3500));
        assert_eq!(left_in(d), ["kept.json"], "{target}, when the body has ended");
        assert_eq!(std::fs::read_to_string(d.join("kept.json")).unwrap(), "[\"before\"]", "{target}");
    }
    // The session is still there, and still streams to a file.
    let shown = enter_line(&mut prompt, "GET /a > s.json", "200 OK");
    assert!(shown.contains("> s.json"), "{shown}");
    assert_eq!(left_in(d), ["kept.json", "s.json"]);

    // Quitting right behind an abort.
    aborted(&mut prompt, "GET /slow > new.json");
    quit(&mut prompt);
    assert_eq!(ended(&mut prompt), Some(true));
    assert_eq!(left_in(d), ["kept.json", "s.json"]);

    // A `kill` while the prompt streams: no partial file, and the terminal
    // is given back as the shell had it.
    let mut prompt = open();
    prompt.paste("GET /slow > new.json");
    prompt.pump(Duration::from_millis(60));
    prompt.send(b"\r");
    assert!(pump_until(&mut prompt, Duration::from_secs(6), |_| left_in(d).iter().any(|name| name.ends_with(".part"))));
    prompt.pump(Duration::from_millis(300));
    let mark = prompt.screen.len();
    prompt.signal(libc::SIGTERM);
    assert_eq!(ended(&mut prompt), Some(false));
    assert_eq!(left_in(d), ["kept.json", "s.json"]);
    assert!(prompt.is_cooked(), "the terminal is left in raw mode");
    assert!(prompt.screen[mark..].contains("\x1b[?2004l"), "bracketed paste is left on: {:?}", &prompt.screen[mark..]);
}

/// A request ended with esc has no status. Under `-f` the 404 of the line
/// before is not reported as what stopped the block, and the rest of the
/// block is not sent.
#[cfg(unix)]
#[test]
fn an_aborted_request_under_fail_fast_stops_the_block_without_a_status() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &["-f"]);
    let shown = enter_line(&mut prompt, "GET /missing", "404");
    assert!(shown.contains("404"), "{shown}");

    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    server.take();
    let mark = prompt.screen.len();
    prompt.paste("GET /stall\rGET /never");
    prompt.pump(Duration::from_millis(60));
    prompt.send(b"\r");
    assert!(pump_until(&mut prompt, Duration::from_secs(5), |_| server.seen() > 0), "{}", screen_tail(&prompt));
    prompt.pump(Duration::from_millis(400));
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(1500));
    let shown = pty::plain(&prompt.screen[mark..]);
    assert!(!shown.contains("stopped at 404"), "{shown}");
    assert_eq!(server.log.lock().unwrap().clone(), ["GET /stall"], "{shown}");
    // The session is still there.
    let shown = enter_line(&mut prompt, "GET /after", "200 OK");
    assert!(shown.contains("200 OK"), "{shown}");
}

/// An outfile written at the prompt is the file a batch writes: the
/// server's bytes under `-r`, and one array after two appends.
#[cfg(unix)]
#[test]
fn the_prompt_writes_a_raw_and_an_appended_outfile_as_a_batch_does() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("twice.api"), "GET /a >> batch.json\nGET /a >> batch.json\nGET /a > batch-raw.json\n").unwrap();
    let batch = run_in(&server, d, &["-r", "-sa", "twice.api"]);
    assert_eq!(batch.code, Some(0), "{}", batch.stderr);

    let mut prompt = open_prompt(&server, d, &["-r"]);
    enter_line(&mut prompt, "GET /a >> prompt.json", "200 OK");
    enter_line(&mut prompt, "GET /a >> prompt.json", "200 OK");
    enter_line(&mut prompt, "GET /a > prompt-raw.json", "200 OK");
    let read = |name: &str| std::fs::read_to_string(d.join(name)).unwrap();
    assert_eq!(read("prompt-raw.json"), r#"{"ok":"/api/v1/a"}"#);
    assert_eq!(read("prompt-raw.json"), read("batch-raw.json"));
    assert_eq!(read("prompt.json"), read("batch.json"));
    let appended: serde_json::Value = serde_json::from_str(&read("prompt.json")).unwrap();
    assert_eq!(appended.as_array().map(Vec::len), Some(2), "{appended}");
}

/// On a terminal too narrow for the splash box nothing of a box is drawn,
/// not when the session starts and not when the connection has loaded.
#[cfg(unix)]
#[test]
fn a_narrow_terminal_gets_no_piece_of_the_splash_box() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("a", url.clone(), "key", "k", "")], "a");
    for args in [&["-c", "a"][..], &["-b", &url, "-k", "k"]] {
        let mut cmd = api_bare(d);
        cmd.args(args);
        let mut prompt = pty::Prompt::open_sized(cmd, 30);
        prompt.wait_for("ctrl+h", Duration::from_secs(15));
        prompt.pump(Duration::from_millis(1500));
        let rows = pty::rows(&prompt.screen, 30);
        assert!(!rows.iter().any(|row| row.contains('│') || row.contains('╭') || row.contains('╰')), "{args:?}:\n{}", rows.join("\n"));
        // The command area is there and keeps to the width.
        assert!(rows.iter().any(|row| row.starts_with("GET /")), "{args:?}:\n{}", rows.join("\n"));
        assert!(rows.iter().all(|row| row.chars().count() <= 30), "{args:?}:\n{}", rows.join("\n"));
    }
}

/// `-m` at a terminal wraps the description to the terminal's width.
#[cfg(unix)]
#[test]
fn describe_first_wraps_to_the_width_of_the_terminal() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let words = "Innehåller x y z och andra intressanta saker, se till att köra bananer också. ".repeat(3);
    std::fs::write(
        d.join("cat.api"),
        format!("{{ \"title\": {{ \"en\": \"Catalog\" }}, \"description\": {{ \"en\": \"{}\" }} }}\nGET /a\n", words.trim()),
    )
    .unwrap();
    let mut cmd = api(server.port, d);
    cmd.args(["-spma", "cat.api"]).env("LANG", "en_GB.UTF-8").env_remove("LC_ALL").env_remove("LC_MESSAGES");
    let mut prompt = pty::Prompt::open_sized(cmd, 40);
    prompt.wait_for("Run?", Duration::from_secs(10));
    let shown = pty::plain(&prompt.screen);
    let described: Vec<&str> = shown.split("Preview").next().unwrap().lines().map(str::trim_end).collect();
    assert!(described.iter().any(|line| *line == "Catalog"), "{shown}");
    assert!(described.len() > 6, "the description was not wrapped:\n{shown}");
    assert!(described.iter().all(|line| line.chars().count() <= 40), "{shown}");
    // Every word is still there, in order.
    let joined = described.join(" ").split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(joined.contains(words.trim()), "{shown}");
    prompt.send(b"n");
    prompt.pump(Duration::from_millis(500));
    assert_eq!(server.seen(), 0);
}

/// The form for a new connection reads its URL as `-b` does: a scheme is
/// added and the API path is cut, and it says that it cut something.
#[cfg(unix)]
#[test]
fn the_connection_form_trims_its_url_to_the_base() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    assert!(
        pump_until(&mut prompt, Duration::from_secs(10), |p| pty::plain(&p.screen).contains("URL")),
        "{}",
        pty::plain(&prompt.screen)
    );
    prompt.pump(Duration::from_millis(400));
    let typed = format!("127.0.0.1:{}/api/v1", server.port);
    prompt.send(typed.as_bytes());
    prompt.pump(Duration::from_millis(300));
    let mark = prompt.screen.len();
    prompt.send(b"\r");
    let said = pump_until(&mut prompt, Duration::from_secs(4), |p| pty::plain(&p.screen[mark..]).contains("trimmed to base URL"));
    let shown = pty::plain(&prompt.screen[mark..]);
    assert!(said, "{shown}");
    assert!(shown.contains(&format!("http://127.0.0.1:{}", server.port)), "{shown}");
    assert!(!shown.contains("/api/v1"), "{shown}");
}

/// A file that opens with a describe block runs from a paste as it would
/// from disk: the block is read, checked, and not sent. A describe block
/// alone sends nothing and says so.
#[cfg(unix)]
#[test]
fn a_describe_block_at_the_prompt_is_read_and_not_sent() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);

    server.take();
    let shown = enter_line(&mut prompt, "{ \"title\": \"Katalog\" }\rGET /d1\rPUT /d2 {\"a\":1}", "PUT /d2");
    pump_until(&mut prompt, Duration::from_secs(5), |_| server.seen() >= 2);
    assert_eq!(server.take(), ["GET /d1", "PUT /d2 {\"a\":1}"], "{shown}");
    let shown = pty::plain(&prompt.screen);
    assert!(shown.contains("describe block: title is not an object of texts by locale"), "{}", screen_tail(&prompt));

    // Alone, typed or pasted, it is a program that sends nothing. (ctrl+f
    // clears the block of several lines that is still on the input.)
    prompt.send(b"\x06\x15");
    prompt.pump(Duration::from_millis(100));
    let mark = prompt.screen.len();
    prompt.send(b"{\"title\":{}}");
    prompt.pump(Duration::from_millis(200));
    prompt.send(b"\r");
    let said = pump_until(&mut prompt, Duration::from_secs(4), |p| {
        pty::plain(&p.screen[mark..]).contains("a describe block alone sends nothing")
    });
    assert!(said, "{}", screen_tail(&prompt));
    assert_eq!(server.seen(), 0);
}

/// Keys the prompt reads in more than one spelling: alt+← as the CSI
/// sequence some terminals send, a modified letter in a name dialog, and
/// ctrl+g on a line that is no request.
#[cfg(unix)]
#[test]
fn the_prompt_reads_modified_keys_as_what_they_are() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("seed.api"), "GET /inc1\nGET /inc2\n").unwrap();
    let mut prompt = open_prompt(&server, d, &[]);
    let mut type_line = |prompt: &mut pty::Prompt, line: &str| {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        prompt.send(line.as_bytes());
        prompt.pump(Duration::from_millis(200));
    };

    // alt+← (CSI 1;3D) goes a word back, alt+→ (CSI 1;3C) a word on.
    server.take();
    type_line(&mut prompt, "GET /aaa~where(b=1)~take(2)");
    prompt.send(b"\x1b[1;3D");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"\x1b[1;3D");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"\x1b[1;3C");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"\x1b[1;3C");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"~count\r");
    pump_until(&mut prompt, Duration::from_secs(5), |_| server.seen() > 0);
    assert_eq!(server.take(), ["GET /aaa~where(b=1)~take(2)~count"], "{}", screen_tail(&prompt));
    prompt.pump(Duration::from_millis(300));

    // ctrl+g on a directive or an include has no URI to GET.
    for line in ["assert /x", "seed.api"] {
        type_line(&mut prompt, line);
        let mark = prompt.screen.len();
        prompt.send(b"\x07");
        let said = pump_until(&mut prompt, Duration::from_secs(3), |p| pty::plain(&p.screen[mark..]).contains("not a request"));
        assert!(said, "{line}: {}", screen_tail(&prompt));
        assert_eq!(server.seen(), 0, "{line}");
    }
    // On a request it GETs the URI and leaves the line: Enter then sends it.
    type_line(&mut prompt, "PUT /x {\"a\":1}");
    prompt.send(b"\x07");
    pump_until(&mut prompt, Duration::from_secs(5), |_| server.seen() > 0);
    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\r");
    pump_until(&mut prompt, Duration::from_secs(5), |_| server.seen() > 1);
    assert_eq!(server.take(), ["GET /x", "PUT /x {\"a\":1}"], "{}", screen_tail(&prompt));
    prompt.pump(Duration::from_millis(300));

    // In a name dialog a letter typed with alt or ctrl is not a letter.
    prompt.send(EXPORT_ROW);
    prompt.wait_for("Export with external identifier", Duration::from_secs(5));
    prompt.send(b"\x1bb");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"\x01");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"com.heads.seedID");
    prompt.pump(Duration::from_millis(200));
    let mark = prompt.screen.len();
    prompt.send(b"\r");
    prompt.pump(Duration::from_millis(600));
    let shown = pty::plain(&prompt.screen[mark..]);
    assert!(!shown.contains("export needs a namespaced key"), "{shown}");
    prompt.send(CLOSE_MENU);
    prompt.pump(Duration::from_millis(400));
    assert!(pty::rows(&prompt.screen, 200).last().unwrap().ends_with("export"), "{}", screen_tail(&prompt));
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
            // As a file written by hand may have it.
            ("shout", format!("HTTP://127.0.0.1:{}/api/v1/", other.port), "key", "STOREDKEY", ""),
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
        // Flags over the default connection…
        (&["-k", "CLIKEY", "GET", "/a"][..], cli),
        (&["--token", "T", "GET", "/a"][..], "Bearer T"),
        // …and over one chosen with -c, whatever kind it is.
        (&["-c", "local", "-k", "CLIKEY", "GET", "/a"][..], cli),
        (&["-c", "local", "--token", "T", "GET", "/a"][..], "Bearer T"),
        (&["-c", "tok", "-k", "CLIKEY", "GET", "/a"][..], cli),
        (&["-c", "tok", "--token", "T", "GET", "/a"][..], "Bearer T"),
        (&["-c", "oauth", "-k", "CLIKEY", "GET", "/a"][..], cli),
        // A token over an OAuth2 connection: used as it is, nothing exchanged.
        (&["-c", "oauth", "--token", "T", "GET", "/a"][..], "Bearer T"),
        // Both given: the token wins.
        (&["-k", "CLIKEY", "--token", "T", "GET", "/a"][..], "Bearer T"),
        (&["-c", "oauth", "-k", "CLIKEY", "--token", "T", "GET", "/a"][..], "Bearer T"),
    ] {
        let got = run_bare(&server, d, args);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{args:?}: {}", got.stderr);
        assert_eq!(authorization(&server), authorization_sent, "{args:?}");
    }

    // The same in a batch.
    std::fs::write(d.join("one.api"), "GET /from-file\n").unwrap();
    let got = run_bare(&server, d, &["-c", "local", "-k", "CLIKEY", "-sa", "one.api"]);
    assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /from-file".to_string()][..]), "{}", got.stderr);
    assert_eq!(authorization(&server), cli);

    // `-b` over an OAuth2 connection: the exchange goes to the other host too.
    other.take();
    let got = run_bare(&server, d, &["-c", "oauth", "-b", &other_url, "GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 0), "{}", got.stderr);
    let there = other.log.lock().unwrap().clone();
    assert_eq!(there.len(), 2, "{there:?}");
    assert!(there[0].starts_with("POST /oauth2/v1/token"), "{there:?}");
    assert_eq!(there[1], "GET /a");

    // A stored URL is read as `-b` is: its scheme in any case, its API path
    // dropped. And the connection is chosen by that URL in any spelling.
    let bare_other = other_url.trim_start_matches("http://").to_string();
    for selector in ["shout", &other_url, &bare_other, &format!("{other_url}/api/v1")] {
        other.take();
        let got = run_bare(&server, d, &["-c", selector, "GET", "/a"]);
        assert_eq!((got.code, got.sent.len()), (Some(0), 0), "{selector}: {}", got.stderr);
        assert_eq!(other.log.lock().unwrap().clone(), ["GET /a"], "{selector}");
        assert_eq!(authorization(&other), stored, "{selector}");
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
    assert!(missing.stderr.contains("Connection \"nope\" not found. Saved connections: local, tok, oauth, shout"), "{}", missing.stderr);

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

/// `-c <url>` names a connection only when one saved connection has that
/// URL. With several, which credential to send is not guessed: the aliases
/// are listed and nothing is sent. An alias is still an alias.
#[test]
fn a_url_that_fits_several_connections_is_not_guessed() {
    let server = RecordingServer::start();
    let other = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    let bare = url.trim_start_matches("http://").to_string();
    let other_url = format!("http://127.0.0.1:{}", other.port);
    write_credentials(
        d,
        &[
            ("a1", url.clone(), "key", "STOREDKEY", ""),
            ("a2", format!("HTTP://{bare}/api/v1"), "token", "STOREDTOKEN", ""),
            ("alone", other_url.clone(), "key", "STOREDKEY", ""),
            // A connection named as another one's URL is written.
            (&bare, other_url.clone(), "token", "NAMED", ""),
        ],
        "a2",
    );
    std::fs::write(d.join("one.api"), "GET /a\n").unwrap();

    for selector in [url.clone(), format!("{url}/api/v1")] {
        for args in [&["GET", "/a"][..], &["-sa", "one.api"][..], &["-k", "CLIKEY", "GET", "/a"][..]] {
            let mut all = vec!["-c", selector.as_str()];
            all.extend_from_slice(args);
            let got = run_bare(&server, d, &all);
            assert_eq!((got.code, got.sent.len(), other.seen()), (Some(1), 0, 0), "{all:?}: {}", got.stderr);
            assert_eq!(
                got.stderr.trim(),
                format!("Connection \"{selector}\" fits several saved connections: a1, a2. Name one of them."),
                "{all:?}"
            );
            assert_eq!(got.stdout, "", "{all:?}");
        }
    }

    // An exact alias wins over a URL, and one match is the connection.
    other.take();
    let got = run_bare(&server, d, &["-c", &bare, "GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 0), "{}", got.stderr);
    assert_eq!(authorization(&other), "Bearer NAMED");
    for (selector, sent) in [("a1", "Basic OlNUT1JFREtFWQ=="), ("a2", "Bearer STOREDTOKEN")] {
        let got = run_bare(&server, d, &["-c", selector, "GET", "/a"]);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{selector}: {}", got.stderr);
        assert_eq!(authorization(&server), sent, "{selector}");
    }
    std::fs::write(
        d.join(".api-credentials.json"),
        format!(r#"{{"connections":[{{"name":"only","url":"{url}","auth_type":"key","credential":"STOREDKEY"}}],"default":""}}"#),
    )
    .unwrap();
    for selector in [&url, &bare] {
        let got = run_bare(&server, d, &["-c", selector, "GET", "/a"]);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{selector}: {}", got.stderr);
        assert_eq!(authorization(&server), "Basic OlNUT1JFREtFWQ==", "{selector}");
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

    // A connection asked for by name is not found in it, and the reason is
    // said first.
    let named = run_bare(&server, d, &["-c", "keep", "GET", "/a"]);
    assert_eq!((named.code, named.sent.len()), (Some(1), 0));
    assert!(named.stderr.contains("WARNING: could not read"), "{}", named.stderr);
    assert!(named.stderr.contains("Connection \"keep\" not found. Saved connections: none"), "{}", named.stderr);

    // A file that may not be read is reported the same way, and one with
    // nothing in it is a store with nothing saved: no warning.
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = tempfile::tempdir().unwrap();
        let path = locked.path().join(".api-credentials.json");
        write_credentials(locked.path(), &[("keep", format!("http://127.0.0.1:{}", server.port), "key", "k", "")], "keep");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let got = run_bare(&server, locked.path(), &["GET", "/a"]);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{}", got.stderr);
        assert!(got.stderr.contains("WARNING: could not read"), "{}", got.stderr);
        assert!(got.stderr.contains("no base URL specified"), "{}", got.stderr);

        std::fs::write(&path, "").unwrap();
        let got = run_bare(&server, locked.path(), &["GET", "/a"]);
        assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{}", got.stderr);
        assert!(!got.stderr.contains("WARNING"), "{}", got.stderr);
        assert!(got.stderr.contains("no base URL specified"), "{}", got.stderr);
        // And it can be written to.
        let url = format!("http://127.0.0.1:{}", server.port);
        let got = run_bare(&server, locked.path(), &["-b", &url, "-k", "k", "GET", "/a"]);
        assert_eq!((got.code, got.sent.len()), (Some(0), 1), "{}", got.stderr);
    }

    // At the prompt, saving the connection in use does not replace the file.
    let mut prompt = Prompt::open(api(server.port, d));
    prompt.wait_ready(Duration::from_secs(15));
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
    prompt.wait_ready(Duration::from_secs(15));
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
    prompt.wait_ready(Duration::from_secs(15));
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

/// The saved connections as `name=credential`, and the default.
#[cfg(unix)]
fn stored(dir: &Path) -> (Vec<String>, String) {
    let text = std::fs::read_to_string(dir.join(".api-credentials.json")).unwrap();
    let data: serde_json::Value = serde_json::from_str(&text).unwrap();
    let connections = data["connections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| format!("{}={}", c["name"].as_str().unwrap(), c["credential"].as_str().unwrap()))
        .collect();
    (connections, data["default"].as_str().unwrap_or("").to_string())
}

/// `ctrl+s` at a prompt, answered with `name` in the place of the name the
/// dialog proposes. Returns what the screen showed from then on.
#[cfg(unix)]
fn save_as(prompt: &mut pty::Prompt, name: &str, then: &str) -> String {
    prompt.pump(Duration::from_millis(300));
    let mark = prompt.screen.len();
    prompt.send(b"\x13");
    prompt.wait_for("Save connection as", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(150));
    prompt.send(&[0x7f; 24]);
    prompt.pump(Duration::from_millis(150));
    prompt.send(name.as_bytes());
    prompt.pump(Duration::from_millis(150));
    prompt.send(b"\r");
    let start = Instant::now();
    while !pty::plain(&prompt.screen[mark..]).contains(then) {
        assert!(start.elapsed() < Duration::from_secs(6), "{then:?} never appeared:\n{}", pty::plain(&prompt.screen[mark..]));
        prompt.pump(Duration::from_millis(50));
    }
    pty::plain(&prompt.screen[mark..])
}

/// Saved under a new name, the connection a session runs is renamed, and the
/// default follows. Not when a flag stands in the place of what that
/// connection has stored: the session then holds something else, which is
/// saved as a new connection, and the stored one keeps its secret.
#[cfg(unix)]
#[test]
fn saving_under_a_new_name_renames_the_connection_unless_a_flag_overrides_it() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let open = |d: &Path, args: &[&str]| {
        let mut cmd = api_bare(d);
        cmd.args(args);
        let mut prompt = Prompt::open(cmd);
        prompt.wait_ready(Duration::from_secs(15));
        prompt.pump(Duration::from_millis(500));
        prompt
    };
    let strs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    // No override: a rename, and the default moves with it.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("a", url.clone(), "key", "SECRET", "")], "a");
    let mut prompt = open(d, &["-c", "a"]);
    save_as(&mut prompt, "b", "connection b saved");
    assert_eq!(stored(d), (strs(&["b=SECRET"]), "b".to_string()));
    drop(prompt);

    // `-k` over the connection: a new name is a new connection.
    for flags in [&["-k", "OTHERKEY"][..], &["--token", "OTHERKEY"], &["-b", &url]] {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write_credentials(d, &[("staging", url.clone(), "key", "SECRET", "")], "staging");
        let mut args = vec!["-c", "staging"];
        args.extend_from_slice(flags);
        let held = if flags[0] == "-b" { "SECRET" } else { "OTHERKEY" };
        let mut prompt = open(d, &args);
        save_as(&mut prompt, "mine", "connection mine saved");
        assert_eq!(stored(d), (strs(&["staging=SECRET", &format!("mine={held}")]), "staging".to_string()), "{flags:?}");
        // The override ended with the save: the session now runs `mine`,
        // and saving that under a new name renames it.
        save_as(&mut prompt, "mine2", "connection mine2 saved");
        assert_eq!(stored(d), (strs(&["staging=SECRET", &format!("mine2={held}")]), "staging".to_string()), "{flags:?}");
    }

    // Under the same name the override is what is saved, without a question.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("staging", url.clone(), "key", "SECRET", "")], "staging");
    let mut prompt = open(d, &["-c", "staging", "-k", "OTHERKEY"]);
    let shown = save_as(&mut prompt, "staging", "connection staging saved");
    assert!(!shown.contains("already exists"), "{shown}");
    assert_eq!(stored(d), (strs(&["staging=OTHERKEY"]), "staging".to_string()));
    drop(prompt);

    // A name another connection has is asked about, with or without a flag.
    for flags in [&[][..], &["-k", "OTHERKEY"]] {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write_credentials(d, &[("a", url.clone(), "key", "SECRET", ""), ("x", url.clone(), "key", "XKEY", "")], "a");
        let mut args = vec!["-c", "a"];
        args.extend_from_slice(flags);
        let mut prompt = open(d, &args);
        save_as(&mut prompt, "x", "\"x\" already exists. Overwrite?");
        prompt.send(b"n");
        prompt.wait_for("cancelled", Duration::from_secs(5));
        assert_eq!(stored(d), (strs(&["a=SECRET", "x=XKEY"]), "a".to_string()), "{flags:?}");
        save_as(&mut prompt, "x", "\"x\" already exists. Overwrite?");
        prompt.send(b"y");
        prompt.wait_for("connection x saved", Duration::from_secs(5));
        let expected = match flags.is_empty() {
            // Renamed over `x`: `a` is gone and the default is `x`.
            true => (strs(&["x=SECRET"]), "x".to_string()),
            false => (strs(&["a=SECRET", "x=OTHERKEY"]), "a".to_string()),
        };
        assert_eq!(stored(d), expected, "{flags:?}");
    }
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
    prompt.wait_ready(Duration::from_secs(15));
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

/// The token exchange follows no redirect: the client secret is in its body,
/// and a 307 would carry it to wherever the answer points.
#[test]
fn the_client_secret_does_not_follow_a_redirect() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("c", format!("http://127.0.0.1:{}", server.port), "oauth2", "s3cret", "moved")], "c");
    let got = run_bare(&server, d, &["GET", "/a"]);
    assert_eq!(got.code, Some(1), "{}", got.stdout);
    assert!(got.stderr.contains("OAuth2 token exchange failed") && got.stderr.contains("307"), "{}", got.stderr);
    // Sent once, to the token endpoint, and nothing after it.
    assert_eq!(got.sent, ["POST /oauth2/v1/token grant_type=client_credentials&client_id=moved&client_secret=s3cret"]);
}

/// The same when the connection is the default one, or is named with `-c`
/// for a prompt: a batch ends with the reason, a prompt says it and opens.
#[cfg(unix)]
#[test]
fn a_failed_token_exchange_at_startup_is_said_and_sends_nothing() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    write_credentials(d, &[("gone", format!("http://127.0.0.1:{dead}"), "oauth2", "secret", "id")], "gone");
    std::fs::write(d.join("one.api"), "GET /from-file\n").unwrap();

    for args in [&["GET", "/a"][..], &["-sa", "one.api"], &["-c", "gone", "-sa", "one.api"]] {
        let batch = run_bare(&server, d, args);
        assert_eq!((batch.code, batch.sent.len()), (Some(1), 0), "{args:?}");
        assert!(batch.stderr.contains("OAuth2 token exchange failed"), "{args:?}: {}", batch.stderr);
    }

    for args in [&[][..], &["-c", "gone"]] {
        let mut cmd = api_bare(d);
        cmd.args(args);
        let mut prompt = Prompt::open(cmd);
        let said = pump_until(&mut prompt, Duration::from_secs(15), |p| plain(&p.screen).contains("OAuth2 token exchange failed"));
        assert!(said, "{args:?}: {}", plain(&prompt.screen));
        prompt.pump(Duration::from_millis(500));
        assert!(!plain(&prompt.screen).contains("panicked"), "{args:?}: {}", plain(&prompt.screen));
        assert!(server.log.lock().unwrap().is_empty(), "{args:?}");
    }
}

/// A batch at a terminal with nowhere to send to says so and ends: it does
/// not open the connection form, which is the prompt's.
#[cfg(unix)]
#[test]
fn a_batch_with_no_base_url_says_so_at_a_terminal() {
    use pty::{plain, Prompt};

    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("one.api"), "GET /from-file\n").unwrap();
    for args in [&["-sa", "one.api"][..], &["-a", "one.api"], &["GET /x && GET /y"], &["one.api"]] {
        let mut cmd = api_bare(d);
        cmd.args(args);
        let mut prompt = Prompt::open(cmd);
        let start = Instant::now();
        while prompt.exited().is_none() && start.elapsed() < Duration::from_secs(8) {
            prompt.pump(Duration::from_millis(100));
        }
        let shown = plain(&prompt.screen);
        assert_eq!(prompt.exited(), Some(false), "{args:?}: {shown}");
        assert!(shown.contains("no base URL specified"), "{args:?}: {shown}");
        assert!(!shown.contains("API key:") && !shown.contains("New connection"), "{args:?}: the form was opened\n{shown}");
    }
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
        prompt.wait_ready(Duration::from_secs(15));
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
    prompt.wait_ready(Duration::from_secs(15));
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

/// One plain request is the same single request whether the shell split it
/// (`api GET /x`) or it came in one quoted argument (`api "GET /x"`): the
/// same stdout, the same stderr, the same exit code and the same request,
/// under no flags, `-s`, `-sf` and `-f`, and with the body piped in.
#[cfg(unix)]
#[test]
fn one_request_is_the_same_single_request_quoted_or_split() {
    use std::process::Stdio;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();

    // The time a request took is the one thing that differs between two runs.
    fn timeless(text: &str) -> String {
        text.lines()
            .map(|l| match l.rsplit_once(' ') {
                Some((head, took)) if l.contains("HTTP/1.1") && took.ends_with('s') => format!("{head} <time>"),
                _ => l.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    let run = |flags: &[&str], request: &[&str], stdin: Option<&str>| {
        let mut cmd = api(server.port, dir.path());
        cmd.args(flags).args(request).stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        server.take();
        let mut child = cmd.spawn().expect("spawn api");
        if let Some(text) = stdin {
            child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        }
        let out = child.wait_with_output().expect("api runs");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            timeless(&String::from_utf8_lossy(&out.stderr)),
            out.status.code(),
            server.take(),
        )
    };

    let rows: [(&[&str], &str, Option<&str>); 9] = [
        (&["GET", "/a"], "GET /a", None),
        (&["/a"], "/a", None),
        (&["GET", "/gone"], "GET /gone", None),
        (&["PUT", "/a", r#"{"x":1}"#], r#"PUT /a {"x":1}"#, None),
        (&["PUT", "/a", "{\"x\": 1, // one\n}"], "PUT /a {\"x\": 1, // one\n}", None),
        (&["GET", "/a", ">", "out.json"], "GET /a > out.json", None),
        (&["PUT", "/a"], "PUT /a", Some(r#"{"x":1}"#)),
        (&["POST", "/gone"], "POST /gone", Some(r#"{"x":1}"#)),
        (&["GET", "/a"], "GET /a", Some("not a body")),
    ];
    let flag_sets: [&[&str]; 4] = [&[], &["-s"], &["-sf"], &["-f"]];
    for (split, quoted, stdin) in rows {
        for flags in flag_sets {
            let as_split = run(flags, split, stdin);
            let as_quoted = run(flags, &[quoted], stdin);
            assert_eq!(as_quoted, as_split, "{flags:?} {quoted:?} (left: quoted, right: split)");
        }
    }

    // What the split form is known to do, so the two are not alike in being wrong.
    let (stdout, stderr, code, sent) = run(&["-s"], &["GET /a"], None);
    assert_eq!((stdout.as_str(), stderr.as_str(), code), ("{\"ok\":\"/api/v1/a\"}\n", "", Some(0)));
    assert_eq!(sent, ["GET /a"]);
    let (stdout, stderr, code, _) = run(&["-sf"], &["GET /gone"], None);
    assert_eq!((stdout.trim_end(), code), (GONE, Some(1)), "{stderr}");
    let (stdout, stderr, code, _) = run(&["-f"], &["GET /gone"], None);
    assert_eq!((stdout.trim_end(), code), (GONE, Some(1)), "{stderr}");
    assert!(stderr.contains("HTTP/1.1 404"), "{stderr}");
    let (_, stderr, code, sent) = run(&[], &["PUT /a"], Some(r#"{"x":1}"#));
    assert_eq!((code, &sent[..]), (Some(0), &[r#"PUT /a {"x":1}"#.to_string()][..]), "{stderr}");

    // What is not one plain request still runs as a batch, and logs like one.
    for line in ["GET /a && GET /b", "GET /a\nGET /b", "assert GET /a"] {
        let (stdout, stderr, code, _) = run(&["-s"], &[line], None);
        assert!(stdout.starts_with("[http://127.0.0.1:"), "{line:?}: {stdout}\n{stderr}");
        assert_eq!(code, Some(0), "{line:?}: {stderr}");
    }
    std::fs::write(dir.path().join("one.api"), "GET /a\n").unwrap();
    let (stdout, stderr, _, sent) = run(&["-s"], &["one.api"], None);
    assert!(stdout.starts_with("[http://127.0.0.1:"), "{stdout}\n{stderr}");
    assert_eq!(sent, ["GET /a"]);
}

/// At a terminal a quoted `PUT /x` with no body asks for one, as the split
/// form does, and sends what is typed.
#[cfg(unix)]
#[test]
fn a_quoted_request_without_a_body_reads_one_at_a_terminal() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    for request in [&["PUT", "/a"][..], &["PUT /a"][..]] {
        server.take();
        let mut cmd = api(server.port, dir.path());
        cmd.args(request);
        let (shown, ended) = batch_in_a_terminal(cmd, "Reading body from stdin", b"{\"x\":1}\r\x04");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        assert_eq!(server.take(), [r#"PUT /a {"x":1}"#], "{request:?}\n{shown}");
        assert_eq!(ended, Some(true), "{request:?}\n{shown}");
    }
}

/// A file whose last body is never closed is not run in part: the error names
/// the unclosed body, the exit code is 1, and the requests above it are not
/// sent either.
#[test]
fn a_file_that_ends_in_an_unclosed_body_sends_nothing() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    for (name, text) in [
        ("object.api", "GET /a\nPUT /x {\n"),
        ("deep.api", "GET /a\nPUT /x {\n  \"a\": [1,\n"),
        ("array.api", "PUT /a {\"x\":1}\nPOST /x ["),
    ] {
        std::fs::write(dir.path().join(name), text).unwrap();
        for flags in ["-a", "-sa", "-sfa"] {
            let ran = run_in(&server, dir.path(), &[flags, name]);
            assert_eq!((ran.code, ran.sent.len()), (Some(1), 0), "{flags} {name}: {}", ran.stderr);
            assert!(ran.stderr.contains("error: unclosed body at end of bulk file"), "{flags} {name}: {}", ran.stderr);
            assert_eq!(ran.stdout, "", "{flags} {name}");
        }
        // From stdin it is the same file.
        let mut cmd = api(server.port, dir.path());
        cmd.args(["-sa", "-"]).stdin(std::fs::File::open(dir.path().join(name)).unwrap());
        let ran = ran(&server, cmd);
        assert_eq!((ran.code, ran.sent.len()), (Some(1), 0), "stdin {name}: {}", ran.stderr);
        assert!(ran.stderr.contains("unclosed body at end of bulk file"), "stdin {name}: {}", ran.stderr);
    }
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

/// A run whose stdout, stderr or both are pipes that nobody reads and that
/// are closed as soon as it has started: its exit code and what it sent.
fn run_unheard(server: &RecordingServer, dir: &Path, args: &[&str], out: bool, err: bool) -> (Option<i32>, Vec<String>) {
    use std::process::Stdio;
    server.take();
    let mut child = api(server.port, dir)
        .args(args)
        .stdout(if out { Stdio::piped() } else { Stdio::null() })
        .stderr(if err { Stdio::piped() } else { Stdio::null() })
        .spawn()
        .expect("spawn api");
    drop(child.stdout.take());
    drop(child.stderr.take());
    let status = child.wait().expect("wait");
    server.settle(Duration::from_millis(150), Duration::from_secs(3));
    (status.code(), server.take())
}

/// The same holds for stderr, where `-a` writes its status lines, and for
/// every kind of line a batch has: a closed pipe changes neither what is
/// sent nor the exit code.
#[test]
fn a_batch_keeps_running_when_nobody_reads_what_it_says() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = |name: &str, text: &str| std::fs::write(d.join(name), text).unwrap();
    let lines: String = (1..=6).map(|i| format!("GET /six{i}\n")).collect();
    file("six.api", &lines);
    file("inner.api", "GET /inner\n");
    file("fails.api", "GET /a\nassert GET /missing\nGET /never\n");
    file(
        "mixed.api",
        "import dir d {\"path\":\"libdir\"}\nGET /a > out.json\nsleep 0 while GET /zero\nGET /missing && GET /never\nassert not GET /missing\ninner.api\nGET /last\n",
    );
    std::fs::create_dir(d.join("libdir")).unwrap();
    let six: Vec<String> = (1..=6).map(|i| format!("GET /six{i}")).collect();
    let mixed = ["GET /a", "GET /zero", "GET /missing", "GET /missing", "GET /inner", "GET /last"];

    for (out, err) in [(false, true), (true, true), (true, false)] {
        for flags in ["-a", "-sa", "-sfa"] {
            let how = format!("{flags} stdout closed={out} stderr closed={err}");
            assert_eq!(run_unheard(&server, d, &[flags, "six.api"], out, err), (Some(0), six.clone()), "{how}");
            let (code, sent) = run_unheard(&server, d, &[flags, "fails.api"], out, err);
            assert_eq!((code, &sent[..]), (Some(1), &["GET /a".to_string(), "GET /missing".to_string()][..]), "{how}");
        }
        for flags in ["-a", "-sa"] {
            let how = format!("{flags} stdout closed={out} stderr closed={err}");
            let (code, sent) = run_unheard(&server, d, &[flags, "mixed.api"], out, err);
            assert_eq!((code, &sent[..]), (Some(0), &mixed.map(String::from)[..]), "{how}");
        }
        let how = format!("stdout closed={out} stderr closed={err}");
        assert_eq!(run_unheard(&server, d, &["GET", "/alone"], out, err), (Some(0), vec!["GET /alone".to_string()]), "{how}");
        assert_eq!(
            run_unheard(&server, d, &["--stream", "GET", "/alone"], out, err),
            (Some(0), vec!["GET /alone".to_string()]),
            "{how}"
        );
        // An error is still an error.
        assert_eq!(run_unheard(&server, d, &["-f", "GET", "/missing"], out, err).0, Some(1), "{how}");
        assert_eq!(run_unheard(&server, d, &["-a", "nofile.api"], out, err), (Some(1), Vec::new()), "{how}");
    }
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

/// A run whose stdout (or stderr, with `to_stderr`) is a pipe that takes
/// nothing more once it is full, with a reader that starts late: everything
/// that came through it, what the other stream said, and the exit code.
#[cfg(unix)]
fn run_into_a_slow_pipe(mut cmd: std::process::Command, to_stderr: bool) -> (Vec<u8>, String, Option<i32>) {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::process::Stdio;

    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (mut reader, writer) = unsafe { (std::fs::File::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // The mode belongs to the pipe, so the client's end has it too.
    unsafe {
        let flags = libc::fcntl(fds[1], libc::F_GETFL);
        assert_eq!(libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
    }
    if to_stderr {
        cmd.stdout(Stdio::piped()).stderr(Stdio::from(writer));
    } else {
        cmd.stdout(Stdio::from(writer)).stderr(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn api");
    // The command holds the other copy of the write end.
    drop(cmd);
    let other = std::thread::spawn({
        let mut out = child.stdout.take();
        let mut err = child.stderr.take();
        move || {
            let mut text = String::new();
            if let Some(pipe) = out.as_mut() {
                let _ = pipe.read_to_string(&mut text);
            }
            if let Some(pipe) = err.as_mut() {
                let _ = pipe.read_to_string(&mut text);
            }
            text
        }
    });
    std::thread::sleep(Duration::from_millis(400));
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let status = child.wait().expect("wait");
    (got, other.join().unwrap(), status.code())
}

/// A pipe that is full for the moment has not lost its reader: what is
/// printed arrives whole, on stdout and on stderr. And a stdout that fails
/// for good is an error, not a short output with exit 0.
#[cfg(unix)]
#[test]
fn output_arrives_whole_through_a_pipe_that_is_full_for_a_while() {
    use std::os::unix::process::CommandExt;

    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // A describe block of some 250 KB, and one with 4,000 members to warn about.
    let texts: Vec<String> = (0..500usize)
        .map(|i| format!(r#""{}{}-SE": "{}""#, (b'a' + (i / 26) as u8) as char, (b'a' + (i % 26) as u8) as char, "d".repeat(480)))
        .collect();
    std::fs::write(d.join("big.api"), format!("{{\n\"description\": {{\n{}\n}}\n}}\nGET /a\n", texts.join(",\n"))).unwrap();
    let members: Vec<String> = (0..4000).map(|i| format!(r#""member{i:04}": 1"#)).collect();
    std::fs::write(d.join("odd.api"), format!("{{\n{}\n}}\nGET /a\n", members.join(",\n"))).unwrap();

    let mut cmd = api_bare(d);
    cmd.args(["--describe", "big.api"]);
    let (stdout, stderr, code) = run_into_a_slow_pipe(cmd, false);
    assert_eq!(code, Some(0), "{stderr}");
    let block: serde_json::Value = serde_json::from_slice(&stdout)
        .unwrap_or_else(|e| panic!("{} bytes of stdout are not the block: {e}\n{stderr}", stdout.len()));
    assert_eq!(block["description"].as_object().unwrap().len(), 500);

    let mut cmd = api_bare(d);
    cmd.args(["-r", "--describe", "odd.api"]);
    let (stderr, _, code) = run_into_a_slow_pipe(cmd, true);
    assert_eq!(code, Some(0));
    let stderr = String::from_utf8_lossy(&stderr);
    assert_eq!(stderr.lines().count(), 4000, "{} bytes of stderr", stderr.len());
    assert!(stderr.lines().last().unwrap().contains("member3999 is not a member"), "{:?}", stderr.lines().last());

    // A file that may hold 1,000 bytes and no more.
    let mut cmd = api_bare(d);
    cmd.args(["--describe", "big.api"]).stdout(std::fs::File::create(d.join("full.json")).unwrap()).stderr(std::process::Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let limit = libc::rlimit { rlim_cur: 1000, rlim_max: 1000 };
            match libc::setrlimit(libc::RLIMIT_FSIZE, &limit) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        });
    }
    let out = cmd.output().expect("spawn api");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Error writing to stdout: "), "{stderr}");
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

    // A negative number is a value too, and not one the option takes.
    let args: Vec<String> = ["--timeout", "-1", "GET", "/a"].iter().map(|s| s.to_string()).collect();
    let (got, shown) = run_cli(&server, dir.path(), &args);
    assert!(!got.exit_ok && got.sent.is_empty());
    assert!(shown.contains("error: invalid value for --timeout: -1"), "{shown}");
    assert!(!shown.contains("unexpected option"), "{shown}");

    // An empty `-b` is no base URL, not a host that does not answer.
    let empty = run_bare(&server, dir.path(), &["-b", "", "-k", "k", "GET", "/a"]);
    assert_eq!((empty.code, empty.sent.len()), (Some(1), 0), "{}", empty.stderr);
    assert!(empty.stderr.contains("no base URL specified"), "{}", empty.stderr);
    assert!(!empty.stderr.contains("Is COS running"), "{}", empty.stderr);
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

/// Lines the documentation promises and nothing else pinned: a `confirm`
/// whose message holds `&&`, stdin as the body of every method that takes
/// one, `>> clipboard` refused however it is spelled, a file with a byte
/// order mark named as the argument, and the `url` gate in capitals.
#[cfg(unix)]
#[test]
fn documented_lines_mean_what_the_documentation_says() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = |name: &str, text: &str| std::fs::write(d.join(name), text).unwrap();
    let sent = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    // Everything after `confirm` is the message: it is not a chain.
    file("confirm.api", "confirm Seed a && b?\nGET /after\n");
    let asked = ask(&server, d, &["-sa", "confirm.api"], Some("y\n"));
    assert_eq!((asked.code, asked.sent), (Some(0), sent(&["GET /after"])), "{}", asked.stderr);
    assert!(asked.stderr.contains("Seed a && b?"), "{}", asked.stderr);
    let declined = ask(&server, d, &["-sa", "confirm.api"], Some("n\n"));
    assert_eq!((declined.code, declined.sent.len()), (Some(0), 0), "{}", declined.stderr);
    let typed = ask(&server, d, &["confirm Seed a && b?"], Some("y\n"));
    assert_eq!((typed.code, typed.sent.len()), (Some(0), 0), "{}", typed.stderr);
    assert!(typed.stderr.contains("Seed a && b?"), "{}", typed.stderr);

    // Stdin is the body of a POST, a PATCH and a `put`, and of a request
    // whose outfile is in the same argument as its URI.
    let body = r#"{"x":1}"#;
    for (args, request) in [
        (&["POST", "/a"][..], r#"POST /a {"x":1}"#),
        (&["PATCH", "/a"][..], r#"PATCH /a {"x":1}"#),
        (&["put", "/a"][..], r#"PUT /a {"x":1}"#),
        (&["PUT", "/a > piped.json"][..], r#"PUT /a {"x":1}"#),
    ] {
        let got = ask(&server, d, args, Some(body));
        assert_eq!((got.code, got.sent), (Some(0), sent(&[request])), "{args:?}: {}", got.stderr);
    }
    assert!(d.join("piped.json").exists());
    // A check is not a request that reads a body from stdin.
    let check = ask(&server, d, &["assert", "PUT", "/x"], Some(body));
    assert_eq!((check.code, check.sent), (Some(0), sent(&["PUT /x"])), "{}", check.stderr);

    // `>> clipboard` is refused when the line is read, before anything is sent.
    file("clip.api", "GET /first\nGET /a && GET /b >> clipboard\n");
    for args in [&["GET", "/a", ">>clipboard"][..], &["GET", "/a", ">>", "Clipboard"], &["GET /a >> clipboard"], &["-sa", "clip.api"]] {
        let got = run_in(&server, d, args);
        assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{args:?}: {}", got.stderr);
        assert!(got.stderr.contains("cannot append to clipboard"), "{args:?}: {}", got.stderr);
    }

    // A byte order mark, in a file named as the argument and in an include.
    file("bom.api", "\u{feff}GET /bom1\r\nGET /bom2\r\n");
    file("includes-bom.api", "GET /own\nbom.api\n");
    let named = run_in(&server, d, &["bom.api"]);
    assert_eq!((named.code, named.sent), (Some(0), sent(&["GET /bom1", "GET /bom2"])), "{}", named.stderr);
    let included = run_in(&server, d, &["-sa", "includes-bom.api"]);
    assert_eq!((included.code, included.sent), (Some(0), sent(&["GET /own", "GET /bom1", "GET /bom2"])), "{}", included.stderr);

    // The gate is read in any case and with any blanks, as an argument too.
    let open = run_in(&server, d, &[&format!("URL  HAS {}\nGET /gated", server.port)]);
    assert_eq!((open.code, open.sent), (Some(0), sent(&["GET /gated"])), "{}", open.stderr);
    let shut = run_in(&server, d, &["URL  HAS nomatch.example\nGET /gated"]);
    assert_eq!((shut.code, shut.sent.len()), (Some(1), 0), "{}", shut.stderr);
    let exact = run_in(&server, d, &[&format!("Url Is http://127.0.0.1:{}\nGET /gated", server.port)]);
    assert_eq!((exact.code, exact.sent), (Some(0), sent(&["GET /gated"])), "{}", exact.stderr);
}

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
            // The request of a poll and of an assert are requests too.
            &format!("Preview — 6 requests | GET PUT DELETE [http://127.0.0.1:{}]", server.port)[..],
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

    // A file of checks alone is not a file of no requests, and their
    // methods are listed.
    std::fs::write(dir.path().join("checks.api"), "assert GET /x\nsleep 1 while not POST /q {\"a\":1}\nassert not /implied\n").unwrap();
    let ran = ask(&server, dir.path(), &["-spa", "checks.api"], Some("n\n"));
    assert!(ran.stderr.starts_with("Preview — 3 requests | GET POST ["), "{}", ran.stderr);
    std::fs::write(dir.path().join("check.api"), "assert GET /x\nconfirm assert GET /y?\n").unwrap();
    let ran = ask(&server, dir.path(), &["-spa", "check.api"], Some("n\n"));
    assert!(ran.stderr.starts_with("Preview — 1 request | GET ["), "{}", ran.stderr);

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
        ///
        /// It never stops in the middle of a frame. The client draws its
        /// command area in several writes, between switching auto-wrap off
        /// and on again, and while a notice is up it draws ten times a
        /// second: a screen looked at after a fixed time could be one with
        /// half a command area on it. So while a frame is open the reading
        /// goes on until it is closed (or, for a client that is gone or
        /// stuck, two seconds have passed).
        pub fn pump(&mut self, d: Duration) {
            if !self.read_until(Instant::now() + d) {
                return;
            }
            let limit = Instant::now() + Duration::from_secs(2);
            while self.frame_is_open() && Instant::now() < limit {
                if !self.read_until(Instant::now() + Duration::from_millis(5)) {
                    return;
                }
            }
        }

        /// Whether the client is in the middle of drawing: auto-wrap is
        /// off, or a character has arrived in part.
        fn frame_is_open(&self) -> bool {
            let last = |mode: &str| self.screen.rfind(mode);
            !self.partial.is_empty() || last("\x1b[?7l") > last("\x1b[?7h")
        }

        /// Read what arrives until `end`. False when the terminal is closed.
        fn read_until(&mut self, end: Instant) -> bool {
            loop {
                let left = end.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return true;
                }
                let mut pfd = libc::pollfd { fd: self.master, events: libc::POLLIN, revents: 0 };
                let rc = unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(50) as i32) };
                if rc <= 0 {
                    continue;
                }
                if pfd.revents & libc::POLLIN == 0 {
                    return false;
                }
                let mut buf = [0u8; 65536];
                let n = unsafe { libc::read(self.master, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n <= 0 {
                    return false;
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

        /// Whether the terminal is as a shell expects it: lines are read
        /// whole and what is typed is echoed. A prompt has both off.
        pub fn is_cooked(&self) -> bool {
            let mut modes: libc::termios = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::tcgetattr(self.master, &mut modes) };
            assert_eq!(rc, 0, "tcgetattr");
            modes.c_lflag & libc::ICANON != 0 && modes.c_lflag & libc::ECHO != 0
        }

        /// Give the terminal a new size, as dragging its window does.
        pub fn resize(&mut self, cols: u16, rows: u16) {
            let size = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
            let rc = unsafe { libc::ioctl(self.master, libc::TIOCSWINSZ as _, &size) };
            assert_eq!(rc, 0, "TIOCSWINSZ");
        }

        /// Whether the client has ended, and if so whether it ended well.
        /// Send the client a signal, as `kill` does.
        pub fn signal(&mut self, signal: libc::c_int) {
            unsafe { libc::kill(self.child.id() as libc::pid_t, signal) };
        }

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

        /// Wait until the prompt takes what is typed. The hint line alone
        /// does not say so: with `-c` the command area is drawn while the
        /// connection is still being loaded, with a spinner where the input
        /// line goes, and until that has ended every key and paste is
        /// dropped. The input line with its cursor block is drawn when the
        /// wait is over, so that is what is waited for, not a length of time.
        pub fn wait_ready(&mut self, timeout: Duration) {
            self.wait_for("ctrl+h for shortcuts", timeout);
            self.wait_for("GET /\x1b[48;5;24", timeout);
        }
    }

    impl Drop for Prompt {
        fn drop(&mut self) {
            // A killed process writes no coverage profile, so under
            // `cargo llvm-cov` the session is first asked to leave the way a
            // user would: esc out of whatever is open, then ctrl+c until it
            // is gone. The wait is bounded, and the kill below still follows,
            // so a prompt that does not leave can't hang the suite.
            if std::env::var_os("LLVM_PROFILE_FILE").is_some() {
                let start = Instant::now();
                let mut keys: &[u8] = b"\x1b";
                while matches!(self.child.try_wait(), Ok(None)) && start.elapsed() < Duration::from_secs(3) {
                    // Not `send`: it asserts, and a panic in a drop aborts.
                    unsafe { libc::write(self.master, keys.as_ptr() as *const _, keys.len()) };
                    keys = b"\x03";
                    self.pump(Duration::from_millis(150));
                }
            }
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

    /// The columns a character takes on a terminal: two for a wide one (CJK,
    /// emoji), none for a combining mark. A table of the test's own, so that
    /// the screen is not measured with the function the client lays out by.
    pub fn columns(c: char) -> usize {
        match c as u32 {
            0x0300..=0x036F | 0x200B..=0x200F | 0xFE00..=0xFE0F => 0,
            0x1100..=0x115F
            | 0x2E80..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE30..=0xFE4F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1F64F
            | 0x1F900..=0x1F9FF
            | 0x20000..=0x3FFFD => 2,
            _ => 1,
        }
    }

    /// What a terminal `cols` wide shows after `output`: one string per row,
    /// without trailing blanks. `plain` gives the text that was written;
    /// this gives where it ended up, which is what a layout has to be judged
    /// on. It is as much of a terminal as the client uses: text, CR and LF,
    /// relative cursor moves, erase in line and in display, saved cursor
    /// positions, and auto-wrap switched on and off. Colours are dropped.
    ///
    /// A cell is a column. A wide character takes two (with auto-wrap on it
    /// goes to the next row whole when one is left; with it off it is not
    /// drawn there), a combining mark joins the cell before it, and a tab
    /// moves to the next multiple of eight without drawing anything.
    pub fn rows(output: &str, cols: usize) -> Vec<String> {
        let mut grid: Vec<Vec<String>> = vec![Vec::new()];
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
                '\t' => col = ((col / 8 + 1) * 8).min(cols.saturating_sub(1)),
                c if c.is_control() => {}
                c if columns(c) == 0 => {
                    // Joins what stands before the cursor, if anything does.
                    if let Some(cell) = col.checked_sub(1).and_then(|at| grid.get_mut(row)?.get_mut(at)) {
                        cell.push(c);
                    }
                }
                c => {
                    let wide = columns(c);
                    let mut draw = true;
                    if col + wide > cols {
                        if wrap {
                            row += 1;
                            col = 0;
                        } else if wide > 1 {
                            // No room for it at the margin, and no wrapping.
                            draw = false;
                        } else {
                            col = cols.saturating_sub(1);
                        }
                    }
                    while grid.len() <= row {
                        grid.push(Vec::new());
                    }
                    if draw {
                        while grid[row].len() < col + wide {
                            grid[row].push(" ".to_string());
                        }
                        grid[row][col] = c.to_string();
                        // The second column of a wide character holds nothing of its own.
                        for cell in &mut grid[row][col + 1..col + wide] {
                            cell.clear();
                        }
                        col += wide;
                    }
                }
            }
            while grid.len() <= row {
                grid.push(Vec::new());
            }
        }
        let mut rows: Vec<String> = grid.iter().map(|cells| cells.concat().trim_end().to_string()).collect();
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
    prompt.wait_ready(Duration::from_secs(15));

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

        let sent = server.take();
        let shown = plain(&prompt.screen[mark..]);
        let expected = case.prompt_sent.clone().unwrap_or_else(|| case.sent.clone());
        assert_eq!(sent, expected, "[{}] prompt: `{}`\nshown:\n{shown}", case.label, case.line);
        // A prompt has no exit code to compare: a line that fails says so
        // (`says`, below) and the session stays open.
        assert_eq!(prompt.exited(), None, "[{}] prompt: `{}` ended the session\n{shown}", case.label, case.line);
        check_shown_and_written(&case, "prompt", &shown);
    }
}

/// `--export` rewrites a response the same way whichever door the request
/// came in through.
#[test]
fn export_rewrites_the_same_way_in_a_file_from_stdin_and_as_arguments() {
    const EXPORTED: &str = "{\n  \"identifiers\": {\n    \"key?\": \"k1\",\n    \"com.heads.seedID\": \"k1\"\n  },\n  \"name\": \"Ann\"\n}\n";
    const WARNING: &str = "warning: response had masked data, left out at secret";
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
        // A batch says it once more where it ends; one request has said it.
        let batch = matches!(*door, "file" | "stdin");
        assert_eq!(stderr.contains("warning: 1 response had masked data left out of the export"), batch, "{door}: {stderr}");
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
    prompt.wait_ready(Duration::from_secs(15));

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
    assert!(!shown.contains("\"secret\""), "{shown}");
    assert!(!shown.contains("\"key\"") && !shown.contains("********"), "{shown}");
    assert!(shown.contains("warning: response had masked data, left out at secret"), "{shown}");
    // A session is no batch: nothing is counted up at its end.
    assert!(!shown.contains("responses had") && !shown.contains("1 response had"), "{shown}");
    assert!(!shown.contains("WARNING"), "{shown}");

    // Written to a file from the prompt, it is the seed data too.
    let (sent, _) = run("GET /keyed > prompt-out.json");
    assert_eq!(sent, ["GET /keyed"]);
    let written = std::fs::read_to_string(dir.path().join("prompt-out.json")).unwrap();
    let written: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(
        written,
        serde_json::json!({ "identifiers": { "key?": "k1", "com.heads.seedID": "k1" }, "name": "Ann" })
    );

    // A response without a key is shown as it came.
    let (_, shown) = run("GET /a");
    assert!(shown.contains("\"ok\""), "{shown}");
}

/// The export row of the settings menu turns export mode on and off in a
/// running session. The name is asked for the first time, has to be a
/// namespaced key, and is remembered.
#[cfg(unix)]
#[test]
fn the_export_row_toggles_export_at_the_prompt_and_asks_for_the_name_once() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    // Started without `--export`.
    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_ready(Duration::from_secs(15));

    // Type `keys`, and give the screen what it showed.
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

    // The row asks for the name. There is no default to accept.
    let shown = keys(&mut prompt, EXPORT_ROW);
    assert!(shown.contains("Export with external identifier:"), "{shown}");
    assert!(shown.contains("enter to turn export on, esc to cancel"), "{shown}");
    // Esc leaves export off, and the menu is back on the row it was on,
    // with what happened said in its last row.
    let shown = keys(&mut prompt, b"\x1b");
    assert!(shown.contains("cancelled"), "{shown}");
    assert!(shown.contains("› Export mode (responses as seed data)  off"), "{shown}");
    // Enter on the row asks again, and an empty answer leaves it off too.
    let shown = keys(&mut prompt, b"\r");
    assert!(shown.contains("Export with external identifier:"), "{shown}");
    let shown = keys(&mut prompt, b"\r");
    assert!(shown.contains("cancelled"), "{shown}");
    let shown = get_keyed(&mut prompt, &server);
    assert!(shown.contains("\"key\": \"k1\""), "{shown}");

    // A name that is no namespaced key is refused with the prompt's notice,
    // and the dialog stays open with what was typed left to correct.
    keys(&mut prompt, EXPORT_ROW);
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
    // The menu is back and shows the name as the row's value.
    assert!(shown.contains("› Export mode (responses as seed data)  com.example.exportID"), "{shown}");

    // On: the response is the seed data, under that name.
    let shown = get_keyed(&mut prompt, &server);
    assert!(shown.contains("\"key?\": \"k1\"") && shown.contains("\"com.example.exportID\": \"k1\""), "{shown}");
    assert!(!shown.contains("\"secret\"") && !shown.contains("\"key\""), "{shown}");
    // The marker sits at the right of the hint line while it is on.
    let shown = keys(&mut prompt, b"\x15");
    assert!(shown.trim_end().ends_with("export"), "{shown:?}");

    // The row again turns it off, and the next response is plain again.
    let shown = keys(&mut prompt, EXPORT_ROW);
    assert!(shown.contains("export off"), "{shown}");
    let shown = get_keyed(&mut prompt, &server);
    assert!(shown.contains("\"key\": \"k1\"") && !shown.contains("key?"), "{shown}");

    // And on once more: the name is remembered, nothing is asked.
    let shown = keys(&mut prompt, EXPORT_ROW);
    assert!(shown.contains("export on: com.example.exportID"), "{shown}");
    assert!(!shown.contains("Export with external identifier"), "{shown}");
    let shown = get_keyed(&mut prompt, &server);
    assert!(shown.contains("\"com.example.exportID\": \"k1\""), "{shown}");
}

/// The dialog the export row opens is drawn in the command area and nowhere else:
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
        prompt.wait_ready(Duration::from_secs(15));
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

        let now = keys(&mut prompt, EXPORT_ROW);
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

        // The settings menu, which is back when the dialog ends: under the
        // top ruler, a blank row, a row per setting with the cursor on the
        // export row, a blank row and its hint row, where `said` stands.
        // Nothing of it reaches the margin, so nothing wraps.
        let menu = |now: &[String], said: &str, what: &str| {
            let shown = now.join("\n");
            assert_eq!(now[..=top], before[..=top], "{cols}, {what}: the rows above changed\n{shown}");
            assert_eq!(now.len(), top + 11, "{cols}, {what}: not the menu's rows\n{shown}");
            assert_eq!(now[top + 1], "", "{cols}, {what}:\n{shown}");
            assert!(now[top + 2].starts_with("  Response streaming"), "{cols}, {what}:\n{shown}");
            assert!(now[top + 3].starts_with("› Export mode"), "{cols}, {what}:\n{shown}");
            assert!(now[top + 8].starts_with("  Timeout"), "{cols}, {what}:\n{shown}");
            assert_eq!(now[top + 9], "", "{cols}, {what}:\n{shown}");
            let said: String = format!("  {said}").chars().take(width - 1).collect();
            assert_eq!(now[top + 10], said.trim_end(), "{cols}, {what}:\n{shown}");
            assert!(now[top + 1..].iter().all(|row| row.chars().count() < width), "{cols}, {what}:\n{shown}");
            assert_eq!(ruler_rows(now).len(), 1, "{cols}, {what}: a ruler was left behind\n{shown}");
        };

        // Cancelled, and opened and cancelled again: nothing is left behind,
        // and esc discards what was typed. The menu is back each time, and
        // closing it gives the command area as it was.
        let now = keys(&mut prompt, b"\x1b");
        menu(&now, "cancelled", "cancelled");
        let now = keys(&mut prompt, CLOSE_MENU);
        closed(&now, "  cancelled", "cancelled, the menu closed");
        for round in 0..3 {
            let now = keys(&mut prompt, EXPORT_ROW);
            dialog(&now, &format!("opened again, {round}"));
            assert!(now[top + 1].ends_with("identifier:"), "{cols}, {round}: {:?}", now[top + 1]);
            assert_eq!(now[top + 3], HINT, "{cols}, {round}");
            let now = keys(&mut prompt, b"\x1b");
            menu(&now, "cancelled", &format!("cancelled, {round}"));
            let now = keys(&mut prompt, CLOSE_MENU);
            closed(&now, "  cancelled", &format!("cancelled, {round}, the menu closed"));
        }

        // Answered: the menu says so, and closed, the command area is back
        // with export on.
        keys(&mut prompt, EXPORT_ROW);
        let now = keys(&mut prompt, b"com.example.exportID\r");
        menu(&now, "export on: com.example.exportID", "answered");
        assert!(now[top + 3].ends_with("com.example.exportID") || width < 62, "{cols}: {:?}", now[top + 3]);
        let now = keys(&mut prompt, CLOSE_MENU);
        closed(&now, "  export on: com.example.exportID", "answered, the menu closed");
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
    // The timeout is the last row of the settings menu: up from the first.
    let ways: [(&str, &[&[u8]], bool); 8] = [
        ("ctrl+c twice at the prompt", &[b"\x03", b"\x03"], false),
        ("ctrl+c in the export dialog", &[b"\x14", b"\x1b[B", b"\r", b"\x03"], false),
        ("ctrl+c in the timeout dialog", &[b"\x14", b"\x1b[A", b"\r", b"\x03"], false),
        ("ctrl+c in the save dialog", &[b"\x13", b"\x03"], false),
        ("ctrl+c twice at the prompt, after a request", &[b"\x03", b"\x03"], true),
        ("ctrl+c in the export dialog, after a request", &[b"\x14", b"\x1b[B", b"\r", b"\x03"], true),
        ("ctrl+c in the timeout dialog, after a request", &[b"\x14", b"\x1b[A", b"\r", b"\x03"], true),
        ("ctrl+c in the save dialog, after a request", &[b"\x13", b"\x03"], true),
    ];
    for (way, keys, used) in ways {
        let mut prompt = Prompt::open_sized(api(server.port, dir.path()), COLS as u16);
        prompt.wait_ready(Duration::from_secs(15));
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
            prompt.send(key);
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
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    assert!(!prompt.is_cooked(), "a prompt reads keys, not lines");
    prompt.send(b"\x11");
    prompt.wait_for("other", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\x03");
    let start = Instant::now();
    while prompt.exited().is_none() && start.elapsed() < Duration::from_secs(5) {
        prompt.pump(Duration::from_millis(100));
    }
    assert_eq!(prompt.exited(), Some(true), "the client did not end");
    assert!(prompt.is_cooked(), "the terminal is left in raw mode");
    // Keyboard flags that were pushed are popped again.
    assert_eq!(prompt.screen.matches("\x1b[>1u").count(), prompt.screen.matches("\x1b[<1u").count());
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
    prompt.wait_ready(Duration::from_secs(15));
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
    prompt.wait_ready(Duration::from_secs(15));
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

/// A body that is not closed is refused by the body editor as the input line
/// refuses it: nothing is sent and nothing written, the reason is in the hint
/// line, and the editor stays open with the text there to finish. A ` > `
/// inside a string of a body that is closed is the body's own.
#[cfg(unix)]
#[test]
fn the_body_editor_refuses_an_unclosed_body_and_stays_open() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    let files = |dir: &Path| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|name| name != ".api_history")
            .collect();
        names.sort();
        names
    };
    let before = files(dir.path());

    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    prompt.send(b"PUT /note");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"\r");
    prompt.wait_for("Enter body, ctrl+d when done", Duration::from_secs(5));
    server.take();
    prompt.send(br#"{"note": "a > b""#);
    let shown = keys_then(&mut prompt, "\x04", "unclosed body");
    prompt.pump(Duration::from_millis(300));
    assert_eq!(server.take(), Vec::<String>::new(), "{shown}");
    assert_eq!(files(dir.path()), before, "a file was written");
    // Still the editor, with what was typed: the reason is under its ruler.
    let rows = pty::rows(&prompt.screen, 200);
    let tail = rows[rows.len().saturating_sub(6)..].join("\n");
    let at = |text: &str| rows.iter().rposition(|row| row.contains(text)).unwrap_or_else(|| panic!("{text:?}:\n{tail}"));
    assert_eq!(at("PUT /note") + 1, at("Enter body, ctrl+d when done"), "{tail}");
    assert_eq!(at("Enter body, ctrl+d when done") + 1, at(r#"{"note": "a > b""#), "{tail}");
    assert_eq!(at(r#"{"note": "a > b""#) + 2, at("unclosed body"), "{tail}");
    assert_eq!(ruler_rows(&rows).len(), 2, "{tail}");

    // Closed, it is sent whole, and the ` > ` in its string names no file.
    prompt.send(b"}");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"\x04");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    prompt.pump(Duration::from_millis(200));
    assert_eq!(server.take(), [r#"PUT /note {"note": "a > b"}"#], "{}", screen_tail(&prompt));
    assert_eq!(files(dir.path()), before, "a file was written");
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
    prompt.wait_ready(Duration::from_secs(15));
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
    prompt.wait_ready(Duration::from_secs(15));
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
    prompt.send(EXPORT_ROW);
    prompt.wait_for("Export with external identifier", Duration::from_secs(5));
    prompt.paste("com.heads.seedID");
    prompt.pump(Duration::from_millis(200));
    let mark = prompt.screen.len();
    prompt.send(b"\r");
    prompt.pump(Duration::from_millis(600));
    let shown = plain(&prompt.screen[mark..]);
    assert!(!shown.contains("cancelled"), "{shown}");
    prompt.send(CLOSE_MENU);
    prompt.pump(Duration::from_millis(400));
    assert!(pty::rows(&prompt.screen, 200).last().unwrap().ends_with("export"), "{shown}");
}

/// A prompt on `server` with the test's own key, waited for until it is up.
#[cfg(unix)]
fn open_prompt(server: &RecordingServer, dir: &Path, args: &[&str]) -> pty::Prompt {
    let mut cmd = api(server.port, dir);
    cmd.args(args);
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    prompt
}

/// Pump until `done` holds or `timeout` has passed.
#[cfg(unix)]
fn pump_until(prompt: &mut pty::Prompt, timeout: Duration, mut done: impl FnMut(&pty::Prompt) -> bool) -> bool {
    let start = Instant::now();
    while !done(prompt) {
        if start.elapsed() > timeout {
            return false;
        }
        prompt.pump(Duration::from_millis(50));
    }
    true
}

/// The last rows of the screen, for a failure message.
#[cfg(unix)]
fn screen_tail(prompt: &pty::Prompt) -> String {
    let rows = pty::rows(&prompt.screen, 200);
    rows[rows.len().saturating_sub(14)..].join("\n")
}

/// An identifier pasted onto a URI is one segment of it, whatever its value
/// holds: a blank, `/`, `?`, `#` and `%` arrive percent-encoded, once, and
/// nothing of the value is sent as a body or read as a query.
#[cfg(unix)]
#[test]
fn a_pasted_identifier_is_one_segment_of_the_uri() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    let mut paste_on = |line: &str, pasted: &str| -> (Vec<String>, String) {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        prompt.send(line.as_bytes());
        prompt.pump(Duration::from_millis(150));
        server.take();
        prompt.paste(pasted);
        prompt.pump(Duration::from_millis(200));
        let rows = pty::rows(&prompt.screen, 200);
        let line = rows[rows.len().saturating_sub(3)].clone();
        prompt.send(b"\r");
        pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
        prompt.pump(Duration::from_millis(200));
        (server.take(), line)
    };

    let (sent, line) = paste_on("GET /people", r#"{"identifiers":{"com.x.name":"A B"}}"#);
    assert_eq!(sent, ["GET /people/com.x.name=A%20B"], "{line}");
    assert_eq!(line.trim_end(), "GET /people/com.x.name=A%20B");
    let (sent, line) = paste_on("DELETE /people/", r#"{"com.x.name":"a/b?c#d 50%"}"#);
    assert_eq!(sent, ["DELETE /people/com.x.name=a%2Fb%3Fc%23d%2050%25"], "{line}");
    // A value with nothing of the kind is pasted as it is.
    let (sent, line) = paste_on("GET /people", r#"{"identifiers":{"com.x.id":"007-a_b.c"}}"#);
    assert_eq!(sent, ["GET /people/com.x.id=007-a_b.c"], "{line}");
}

/// A paste of several lines into a dialog that takes one fills it with the
/// first, however the terminal wrote the line breaks.
#[cfg(unix)]
#[test]
fn a_paste_of_several_lines_gives_a_name_dialog_its_first() {
    let server = RecordingServer::start();
    for (pasted, name) in [("first\rsecond", "first"), ("one\r\ntwo\r\n", "one"), ("  uno\ndos", "uno")] {
        let dir = tempfile::tempdir().unwrap();
        let mut prompt = open_prompt(&server, dir.path(), &[]);
        prompt.send(b"\x13");
        prompt.wait_for("Save connection as", Duration::from_secs(5));
        prompt.paste(pasted);
        prompt.pump(Duration::from_millis(200));
        prompt.send(b"\r");
        prompt.wait_for(&format!("connection {name} saved"), Duration::from_secs(5));
        assert_eq!(stored(dir.path()).0, [format!("{name}=k")], "{pasted:?}");

        // In the export dialog the first line is the name, where the whole
        // paste would be refused.
        prompt.pump(Duration::from_millis(300));
        prompt.send(EXPORT_ROW);
        prompt.wait_for("Export with external identifier", Duration::from_secs(5));
        prompt.paste("com.heads.seedID\rcom.heads.other");
        prompt.pump(Duration::from_millis(200));
        let mark = prompt.screen.len();
        prompt.send(b"\r");
        prompt.pump(Duration::from_millis(600));
        let shown = pty::plain(&prompt.screen[mark..]);
        assert!(!shown.contains("export needs a namespaced key"), "{shown}");
        prompt.send(CLOSE_MENU);
        prompt.pump(Duration::from_millis(400));
        assert!(pty::rows(&prompt.screen, 200).last().unwrap().ends_with("export"), "{shown}");
    }
}

/// Lines of NDJSON pasted behind a typed request go in as its body. They are
/// not a file that opens with a describe block, which would take the
/// request's place on the line.
#[cfg(unix)]
#[test]
fn pasted_ndjson_is_the_body_of_the_request_being_typed() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    prompt.send(b"PUT /events ");
    prompt.pump(Duration::from_millis(150));
    server.take();
    prompt.paste("{\"a\":1}\r{\"a\":2}");
    prompt.pump(Duration::from_millis(200));
    let typed = pty::rows(&prompt.screen, 200).join("\n");
    assert!(typed.contains("PUT /events {\"a\":1}"), "{typed}");
    assert!(typed.contains("\n{\"a\":2}"), "{typed}");
    // Nothing was run by the paste itself.
    assert_eq!(server.seen(), 0);
}

/// A response whose body stops before its end is said to be that at the
/// prompt too, not taken for a server that is not there.
#[cfg(unix)]
#[test]
fn the_prompt_says_a_response_was_cut_short() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &["--timeout", "2"]);
    for (line, says) in [
        ("GET /trunc", "The response was cut short"),
        ("GET /midfail > f.json", "The response was cut short"),
        ("GET /stall", "Timed out after 2s"),
    ] {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        let mark = prompt.screen.len();
        prompt.paste(line);
        prompt.pump(Duration::from_millis(60));
        prompt.send(b"\r");
        let said = pump_until(&mut prompt, Duration::from_secs(8), |p| pty::plain(&p.screen[mark..]).contains(says));
        let shown = pty::plain(&prompt.screen[mark..]);
        assert!(said, "{line}: {shown}");
        assert!(!shown.contains("Is COS running"), "{line}: {shown}");
        prompt.pump(Duration::from_millis(200));
    }
    assert!(!dir.path().join("f.json").exists());
}

/// A server whose spec can't be read is said so once, in the hint line,
/// however the session was started: with `-c` the notice takes the place of
/// `connected to: <name>`.
#[cfg(unix)]
#[test]
fn a_spec_that_cannot_be_read_is_said_with_b_and_with_c() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let notice = "completion unavailable: the API spec could not be read";
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("bad", url.clone(), "key", "badspec", ""), ("good", url.clone(), "key", "k", "")], "");
    for (args, said) in [
        (&["-b", &url, "-k", "badspec"][..], true),
        // A spec request that fails is no more a spec than an answer that is none.
        (&["-b", &url, "-k", "failspec"][..], true),
        // A server without a spec (a 404) simply has none: nothing is said.
        (&["-b", &url, "-k", "nospec"][..], false),
        (&["-c", "bad"][..], true),
        (&["-c", "good"][..], false),
    ] {
        let mut cmd = api_bare(d);
        cmd.args(args);
        let mut prompt = pty::Prompt::open(cmd);
        prompt.wait_ready(Duration::from_secs(15));
        let seen = pump_until(&mut prompt, Duration::from_secs(4), |p| pty::plain(&p.screen).contains(notice));
        assert_eq!(seen, said, "{args:?}: {}", pty::plain(&prompt.screen));
    }
}

/// A save reads the store afresh: a connection another session saved since
/// this one started is still there afterwards.
#[cfg(unix)]
#[test]
fn a_save_keeps_what_was_saved_from_outside_in_the_meantime() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("a", url.clone(), "key", "AKEY", ""), ("b", url.clone(), "key", "BKEY", "")], "a");
    let mut cmd = api_bare(d);
    cmd.args(["-c", "a"]);
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));

    write_credentials(
        d,
        &[("a", url.clone(), "key", "AKEY", ""), ("b", url.clone(), "key", "BKEY", ""), ("third", url.clone(), "key", "CKEY", "")],
        "b",
    );
    save_as(&mut prompt, "a", "connection a saved");
    assert_eq!(
        stored(d),
        (vec!["a=AKEY".to_string(), "b=BKEY".to_string(), "third=CKEY".to_string()], "b".to_string())
    );
}

/// `ctrl+q` shows what is saved now. A file that was broken when the session
/// started and has been fixed since is read; one that broke since is not
/// picked from, and is left as it is.
#[cfg(unix)]
#[test]
fn the_connection_picker_reads_the_store_afresh() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = d.join(".api-credentials.json");
    let broken = r#"{"connections":[],"default":"",}"#;

    std::fs::write(&file, broken).unwrap();
    let mut prompt = open_prompt(&server, d, &[]);
    prompt.send(b"\x11");
    prompt.wait_for("could not read", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(300));

    // Fixed from outside: the next ctrl+q lists it.
    write_credentials(d, &[("fixed-one", url.clone(), "key", "k", "")], "");
    let mark = prompt.screen.len();
    prompt.send(b"\x11");
    let listed = pump_until(&mut prompt, Duration::from_secs(5), |p| pty::plain(&p.screen[mark..]).contains("fixed-one"));
    assert!(listed, "{}", pty::plain(&prompt.screen[mark..]));
    // In the picker, that is: the notice of the first ctrl+q may still be
    // drawn in the hint line until the picker takes its place.
    let shown = pty::plain(&prompt.screen[mark..]);
    let picker = shown.rsplit("Choose a connection").next().unwrap();
    assert!(!picker.contains("could not read"), "{shown}");
    // Wait until the picker is gone: an esc the client has not read yet
    // when the next key arrives would be read together with it, as one key.
    let mark = prompt.screen.len();
    prompt.send(b"\x1b");
    let closed = pump_until(&mut prompt, Duration::from_secs(5), |p| pty::plain(&p.screen[mark..]).contains("ctrl+h for shortcuts"));
    assert!(closed, "{}", pty::plain(&prompt.screen[mark..]));
    prompt.pump(Duration::from_millis(400));

    // Broken from outside: nothing to pick from, and nothing written.
    std::fs::write(&file, broken).unwrap();
    let mark = prompt.screen.len();
    prompt.send(b"\x11");
    let told = pump_until(&mut prompt, Duration::from_secs(5), |p| pty::plain(&p.screen[mark..]).contains("could not read"));
    assert!(told, "{}", pty::plain(&prompt.screen[mark..]));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), broken);
}

/// The width of the last ruler drawn in `output`.
#[cfg(unix)]
fn last_ruler(output: &str) -> usize {
    pty::plain(output)
        .split(|c: char| c != '─')
        .filter(|run| !run.is_empty())
        .last()
        .map_or(0, |run| run.chars().count())
}

/// A terminal resized while the prompt is busy with something else (a wait,
/// a name dialog, a yes or no) is drawn at its new size when that ends.
#[cfg(unix)]
#[test]
fn a_resize_during_a_wait_or_a_dialog_is_drawn_when_it_ends() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("a", url.clone(), "key", "k", ""), ("x", url.clone(), "key", "k", "")], "a");
    let mut cmd = api_bare(d);
    cmd.args(["-c", "a"]);
    let mut prompt = Prompt::open_with(cmd, 100, 40);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    assert_eq!(last_ruler(&prompt.screen), 100);

    // During a `sleep`.
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    prompt.paste("sleep 1");
    prompt.pump(Duration::from_millis(60));
    prompt.send(b"\r");
    prompt.pump(Duration::from_millis(300));
    let mark = prompt.screen.len();
    prompt.resize(60, 40);
    prompt.pump(Duration::from_millis(1800));
    assert_eq!(last_ruler(&prompt.screen[mark..]), 60, "{}", pty::plain(&prompt.screen[mark..]));

    // In the save dialog, left with esc.
    prompt.send(b"\x13");
    prompt.wait_for("Save connection as", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(200));
    let mark = prompt.screen.len();
    prompt.resize(80, 40);
    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(600));
    assert_eq!(last_ruler(&prompt.screen[mark..]), 80, "{}", pty::plain(&prompt.screen[mark..]));

    // In the export dialog.
    prompt.send(EXPORT_ROW);
    prompt.wait_for("Export with external identifier", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(200));
    let mark = prompt.screen.len();
    prompt.resize(70, 40);
    prompt.pump(Duration::from_millis(300));
    // The input keeps to the new width from here on.
    prompt.send("com.heads.".repeat(9).as_bytes());
    prompt.pump(Duration::from_millis(300));
    let asks = "› Export with external identifier: ";
    let drawn = pty::plain(&prompt.screen[mark..]);
    let input = drawn.rsplit(asks).next().unwrap().trim_end();
    assert!(input.starts_with('…') && asks.chars().count() + input.chars().count() < 70, "{input:?}");
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(600));
    // The settings menu is back, at the new width; closed, so is the prompt.
    prompt.send(CLOSE_MENU);
    prompt.pump(Duration::from_millis(400));
    assert_eq!(last_ruler(&prompt.screen[mark..]), 70, "{}", pty::plain(&prompt.screen[mark..]));

    // At the question whether to write over a saved connection.
    prompt.send(b"\x13");
    prompt.wait_for("Save connection as", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(150));
    prompt.send(&[0x7f; 8]);
    prompt.send(b"x\r");
    let mark = prompt.screen.len();
    prompt.wait_for("\"x\" already exists. Overwrite?", Duration::from_secs(5));
    prompt.resize(90, 40);
    prompt.pump(Duration::from_millis(300));
    prompt.send(b"n");
    prompt.pump(Duration::from_millis(600));
    assert_eq!(last_ruler(&prompt.screen[mark..]), 90, "{}", pty::plain(&prompt.screen[mark..]));
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
    // And nothing of the help is left on the screen.
    let rows = pty::rows(&short.screen, 80);
    assert!(!rows.iter().any(|row| row.contains("more rows") || row.contains("Send request")), "{}", rows.join("\n"));

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

/// ctrl+t opens the settings menu in the command area's place: a row per
/// setting, the arrows to move, Enter or the space bar to change the row the
/// cursor is on. It stays open until ctrl+t or esc, and what it changed
/// holds for the requests sent after it, as a typed `set` line does.
#[cfg(unix)]
#[test]
fn the_settings_menu_changes_what_the_session_has_set() {
    use pty::Prompt;

    const COLS: usize = 100;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let mut prompt = Prompt::open_sized(api(server.port, dir.path()), COLS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    let keys = |prompt: &mut Prompt, keys: &[u8]| {
        prompt.send(keys);
        prompt.pump(Duration::from_millis(400));
        pty::rows(&prompt.screen, COLS)
    };

    let mut before = pty::rows(&prompt.screen, COLS);
    let mut top = before.len() - 4;
    assert!(before[top + 3].starts_with("  ctrl+h for shortcuts"), "{}", before.join("\n"));
    const HINT: &str = "  ↑/↓ to move, enter to change, ctrl+t or esc to close";
    // The menu as it stands under the rows of `before`: the row the cursor
    // is on, and each value.
    let menu = |now: &[String], before: &[String], cursor: usize, values: [&str; 7], said: &str, what: &str| {
        let top = before.len() - 4;
        let shown = now.join("\n");
        assert_eq!(now[..=top], before[..=top], "{what}: the rows above changed\n{shown}");
        assert_eq!(now.len(), top + 11, "{what}: not the menu's rows\n{shown}");
        let labels = [
            "Response streaming                  ",
            "Export mode (responses as seed data)",
            "Include nulls                       ",
            "Fail fast                           ",
            "NDJSON                              ",
            "Raw JSON (no pretty printing)       ",
            "Timeout                             ",
        ];
        let rows: Vec<String> = (0..7)
            .map(|at| format!("{} {}  {}", if at == cursor { "›" } else { " " }, labels[at], values[at]))
            .collect();
        assert_eq!(now[top + 1], "", "{what}\n{shown}");
        assert_eq!(now[top + 2..top + 9], rows[..], "{what}\n{shown}");
        assert_eq!(now[top + 9], "", "{what}\n{shown}");
        assert_eq!(now[top + 10], said, "{what}\n{shown}");
        assert_eq!(ruler_rows(now), [top], "{what}: a ruler too many\n{shown}");
    };
    let closed = |now: &[String], before: &[String], hint: &str, what: &str| {
        let top = before.len() - 4;
        let shown = now.join("\n");
        assert_eq!(now.len(), before.len(), "{what}: the command area moved\n{shown}");
        assert_eq!(now[..top + 3], before[..top + 3], "{what}: not what it was\n{shown}");
        assert_eq!(now[top + 3], hint, "{what}\n{shown}");
        assert_eq!(ruler_rows(now), [top, top + 2], "{what}\n{shown}");
    };
    let off = ["off", "off", "off", "off", "off", "off", "600s"];

    // Opened on its first row, whatever row it was left on.
    let now = keys(&mut prompt, b"\x14");
    menu(&now, &before, 0, off, HINT, "opened");
    // The arrows go round.
    let now = keys(&mut prompt, b"\x1b[A");
    menu(&now, &before, 6, off, HINT, "up from the first row");
    let now = keys(&mut prompt, b"\x1b[B");
    menu(&now, &before, 0, off, HINT, "down from the last row");
    let now = keys(&mut prompt, b"\x1b[B\x1b[B");
    menu(&now, &before, 2, off, HINT, "two down");

    // Enter changes the row and says so in the last row, where the hint is
    // back once the notice has had its time. The menu stays open.
    let now = keys(&mut prompt, b"\r");
    menu(&now, &before, 2, ["off", "off", "on", "off", "off", "off", "600s"], "  include-nulls on", "nulls on");
    // The space bar does what Enter does.
    let now = keys(&mut prompt, b"\x1b[B ");
    menu(&now, &before, 3, ["off", "off", "on", "on", "off", "off", "600s"], "  fail-fast on", "fail fast on");
    prompt.pump(Duration::from_millis(3200));
    menu(&pty::rows(&prompt.screen, COLS), &before, 3, ["off", "off", "on", "on", "off", "off", "600s"], HINT, "the notice has gone");

    // ctrl+t closes it. The command area is back, with what is on marked
    // at the right of the hint line.
    let now = keys(&mut prompt, b"\x14");
    closed(&now, &before, &format!("  ctrl+h for shortcuts{}nulls · fail-fast", " ".repeat(COLS - 22 - 17 - 2)), "closed");

    // What it set is what the session has set: the next request has it, a
    // block stops at its first failure, and a typed line changes it again.
    let (sent, shown, accepts) = run_pasted_accepts(&mut prompt, &server, "GET /missing\nGET /never");
    assert_eq!(sent, ["GET /missing"], "{shown}");
    assert_eq!(accepts, ["application/json;skipNulls=false"]);
    assert!(shown.contains("stopped at 404 (--fail-fast)"), "{shown}");
    run_pasted(&mut prompt, &server, "set fail-fast off");
    prompt.pump(Duration::from_millis(3200));
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(200));
    // The requests are in the scrollback now, and the command area under them.
    before = pty::rows(&prompt.screen, COLS);
    top = before.len() - 4;

    // Opened again it is on its first row, and shows what a typed line did.
    let now = keys(&mut prompt, b"\x14");
    menu(&now, &before, 0, ["off", "off", "on", "off", "off", "off", "600s"], HINT, "opened again");
    // esc closes it too.
    let now = keys(&mut prompt, b"\x1b");
    assert_eq!(now.len(), before.len(), "{}", now.join("\n"));
    assert!(now[top + 3].ends_with("nulls"), "{:?}", now[top + 3]);

    // The timeout is asked for in the command area, and the menu is back
    // when it is answered. What is no number of seconds is refused there.
    let now = keys(&mut prompt, b"\x14");
    menu(&now, &before, 0, ["off", "off", "on", "off", "off", "off", "600s"], HINT, "opened for the timeout");
    let now = keys(&mut prompt, b"\x1b[A\r");
    assert_eq!(now.len(), before.len(), "{}", now.join("\n"));
    assert_eq!(now[top + 1], "› Timeout in seconds:", "{}", now.join("\n"));
    assert_eq!(now[top + 3], "  enter to set the timeout, esc to cancel", "{}", now.join("\n"));
    let now = keys(&mut prompt, b"soon\r");
    assert_eq!(now[top + 1], "› Timeout in seconds: soon", "{}", now.join("\n"));
    assert_eq!(now[top + 3], "  a timeout is whole seconds, 0 for none", "{}", now.join("\n"));
    let now = keys(&mut prompt, b"\x7f\x7f\x7f\x7f45\r");
    menu(&now, &before, 6, ["off", "off", "on", "off", "off", "off", "45s"], "  timeout 45s", "a timeout");
    let now = keys(&mut prompt, b"\r");
    assert_eq!(now[top + 1], "› Timeout in seconds:", "{}", now.join("\n"));
    let now = keys(&mut prompt, b"0\r");
    menu(&now, &before, 6, ["off", "off", "on", "off", "off", "off", "no timeout"], "  no timeout", "no timeout");

    // From the menu ctrl+h goes to the shortcuts and ctrl+t back, each
    // clearing the other: one ruler above, none left behind.
    let now = keys(&mut prompt, b"\x08");
    assert_eq!(ruler_rows(&now), [top], "{}", now.join("\n"));
    assert!(now.iter().any(|row| row.starts_with("  ctrl+t     Settings")), "{}", now.join("\n"));
    assert!(!now.iter().any(|row| row.contains("Response streaming")), "{}", now.join("\n"));
    let now = keys(&mut prompt, b"\x14");
    // What the menu last said still has its time, and is said again.
    menu(&now, &before, 0, ["off", "off", "on", "off", "off", "off", "no timeout"], "  no timeout", "back from the shortcuts");

    // A key that is not the menu's closes it and does what it does at the
    // prompt: here a letter, which is typed.
    prompt.pump(Duration::from_millis(3200));
    let now = keys(&mut prompt, b"x");
    assert_eq!(now.len(), before.len(), "{}", now.join("\n"));
    assert!(now[top + 1].ends_with('x'), "{:?}", now[top + 1]);
    assert_eq!(ruler_rows(&now), [top, top + 2], "{}", now.join("\n"));
    assert!(now[top + 3].ends_with("nulls · no timeout"), "{:?}", now[top + 3]);
    assert_eq!(server.take(), Vec::<String>::new());
}

/// The menu keeps to the width of the terminal, and to its height: a row
/// that wrapped, or one that scrolled off the top, could not be cleared
/// again when the menu closes.
#[cfg(unix)]
#[test]
fn the_settings_menu_keeps_to_a_small_terminal() {
    use pty::Prompt;

    for (cols, rows) in [(44u16, 40u16), (30, 40), (22, 40), (80, 12), (80, 8), (40, 10), (30, 8)] {
        let server = RecordingServer::start();
        let dir = tempfile::tempdir().unwrap();
        prepare(dir.path());
        let mut prompt = Prompt::open_with(api(server.port, dir.path()), cols, rows);
        prompt.wait_ready(Duration::from_secs(15));
        prompt.pump(Duration::from_millis(600));
        let width = cols as usize;
        let before = pty::rows(&prompt.screen, width);
        let keys = |prompt: &mut Prompt, keys: &[u8]| {
            prompt.send(keys);
            prompt.pump(Duration::from_millis(400));
            pty::rows(&prompt.screen, width)
        };
        for round in 0..3 {
            let open = keys(&mut prompt, b"\x14");
            let shown = open.join("\n");
            assert!(open.iter().all(|row| row.chars().count() <= width), "{cols}x{rows}, {round}: a row is too wide\n{shown}");
            assert!(open.len() > before.len(), "{cols}x{rows}, {round}:\n{shown}");
            // The ruler and ten rows: a screen of twelve rows holds them. A
            // shorter one shows the settings it has rows for, the one the
            // cursor is on among them, and still says how to close it.
            let tall = |now: &[String]| now.len() - ruler_rows(now).last().copied().unwrap_or(0);
            assert!(tall(&open) < rows as usize, "{cols}x{rows}, {round}: taller than the screen\n{shown}");
            assert!(!shown.contains("more rows"), "{cols}x{rows}, {round}:\n{shown}");
            assert_eq!(open.iter().filter(|row| row.starts_with("› ")).count(), 1, "{cols}x{rows}, {round}:\n{shown}");
            // (Later rounds open on what the last one changed, still said.)
            let said = if round == 0 { "  ↑/↓ to move" } else { "  include-nulls o" };
            assert!(open.last().unwrap().starts_with(&said[..said.len().min(cols as usize - 2)]), "{cols}x{rows}, {round}:\n{shown}");
            // A row of the menu ends in its value, however narrow it is.
            if cols >= 30 {
                let streaming = open.iter().find(|row| row.starts_with("› ")).unwrap();
                assert!(streaming.ends_with("  off"), "{cols}x{rows}, {round}:\n{shown}");
            }
            // The cursor stays in sight on its way down and round.
            for _ in 0..(if round == 0 { 7 } else { 0 }) {
                let moved = keys(&mut prompt, b"\x1b[B");
                let shown = moved.join("\n");
                assert!(tall(&moved) < rows as usize, "{cols}x{rows}, {round}:\n{shown}");
                assert_eq!(moved.iter().filter(|row| row.starts_with("› ")).count(), 1, "{cols}x{rows}, {round}:\n{shown}");
            }
            // A row changed, so the menu is drawn once more before it closes.
            keys(&mut prompt, b"\x1b[B\x1b[B\r");
            let closed = keys(&mut prompt, b"\x14");
            let shown = closed.join("\n");
            assert_eq!(closed.len(), before.len(), "{cols}x{rows}, {round}: the command area moved\n{shown}");
            assert_eq!(closed[..closed.len() - 1], before[..before.len() - 1], "{cols}x{rows}, {round}:\n{shown}");
            assert_eq!(ruler_rows(&closed).len(), ruler_rows(&before).len(), "{cols}x{rows}, {round}: a ruler was left\n{shown}");
        }
    }
}

/// A key of the menu between two ctrl+c takes the question back, as a key
/// at the prompt does: the second ctrl+c asks again and does not leave.
#[cfg(unix)]
#[test]
fn a_menu_key_takes_ctrl_c_back_in_the_settings_menu() {
    use pty::Prompt;

    const COLS: usize = 100;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let mut prompt = Prompt::open_sized(api(server.port, dir.path()), COLS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    let mut keys = |prompt: &mut Prompt, keys: &[u8]| {
        prompt.send(keys);
        prompt.pump(Duration::from_millis(400));
        pty::rows(&prompt.screen, COLS).last().unwrap().clone()
    };
    const ASKED: &str = "  ctrl+c again to exit";

    // The question is asked in the menu's last row.
    keys(&mut prompt, b"\x14");
    assert_eq!(keys(&mut prompt, b"\x03"), ASKED);
    // An arrow takes it back, and the row says how the menu works again.
    assert_eq!(keys(&mut prompt, b"\x1b[B\x1b[B"), "  ↑/↓ to move, enter to change, ctrl+t or esc to close");
    assert_eq!(keys(&mut prompt, b"\x03"), ASKED);
    assert_eq!(prompt.exited(), None, "an arrow between two ctrl+c");
    // So does Enter, which changes the row.
    assert_eq!(keys(&mut prompt, b"\r"), "  include-nulls on");
    assert_eq!(keys(&mut prompt, b"\x03"), ASKED);
    assert_eq!(prompt.exited(), None, "Enter between two ctrl+c");
    // And the space bar.
    assert_eq!(keys(&mut prompt, b" "), "  include-nulls off");
    assert_eq!(keys(&mut prompt, b"\x03"), ASKED);
    assert_eq!(prompt.exited(), None, "the space bar between two ctrl+c");
    // Twice in a row still leaves.
    prompt.send(b"\x03");
    let start = Instant::now();
    while prompt.exited().is_none() && start.elapsed() < Duration::from_secs(5) {
        prompt.pump(Duration::from_millis(100));
    }
    assert!(prompt.exited().is_some(), "ctrl+c twice did not leave:\n{}", screen_tail(&prompt));
}

/// `--no-streaming` keeps streaming off for the session too. The menu's row
/// and a typed `set stream` say that, not that streaming is on, and a file's
/// `set stream` is passed over by the option's name: the session set nothing.
#[cfg(unix)]
#[test]
fn a_session_started_with_no_streaming_says_that_streaming_stays_off() {
    use pty::Prompt;

    const COLS: usize = 100;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    std::fs::write(dir.path().join("stream.api"), "set stream\nGET /keyed > from-file.json\n").unwrap();
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("api"));
    cmd.args(["--no-keychain", "-b", &format!("http://127.0.0.1:{}", server.port), "-k", "streamer", "--no-streaming"])
        .current_dir(dir.path())
        .env("NO_COLOR", "1")
        .env("HOME", dir.path())
        .env_remove("API_STREAMING")
        .env_remove("API_CREDENTIALS_FILE");
    let mut prompt = Prompt::open_sized(cmd, COLS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    const REFUSED: &str = "streaming is off: the session was started with --no-streaming";

    // The first row of the menu: refused in its last row, and still `off`.
    prompt.send(b"\x14");
    prompt.pump(Duration::from_millis(400));
    prompt.send(b"\r");
    prompt.pump(Duration::from_millis(400));
    let rows = pty::rows(&prompt.screen, COLS);
    let shown = rows.join("\n");
    assert_eq!(rows.last().unwrap(), &format!("  {REFUSED}"), "{shown}");
    let row = rows.iter().find(|row| row.starts_with("› Response streaming")).unwrap_or_else(|| panic!("{shown}"));
    assert!(row.ends_with("  off"), "{shown}");
    prompt.send(CLOSE_MENU);
    prompt.pump(Duration::from_millis(400));
    let rows = pty::rows(&prompt.screen, COLS);
    assert!(!rows.last().unwrap().trim_end().ends_with(" streaming"), "a marker for what is off:\n{}", rows.join("\n"));

    // Typed, it is the same line.
    let (sent, shown) = run_pasted(&mut prompt, &server, "set stream");
    assert!(sent.is_empty() && shown.contains(REFUSED), "{shown}");
    // A request is not asked to stream.
    let (_, _, accepts) = run_pasted_accepts(&mut prompt, &server, "GET /keyed > typed.json");
    assert_eq!(accepts, ["application/json"]);

    // A file's line is kept off by the option, and the log names it.
    let (sent, shown, accepts) = run_pasted_accepts(&mut prompt, &server, "stream.api");
    assert_eq!(sent, ["GET /keyed"], "{shown}");
    assert_eq!(accepts, ["application/json"]);
    assert!(shown.contains("↳ ignored: --no-streaming is set"), "{shown}");
    assert!(!shown.contains("the session has"), "{shown}");
}

/// A session started with `--export <name>` has its name: the export row
/// turns export off and on again without asking.
#[cfg(unix)]
#[test]
fn the_export_row_in_a_session_started_with_export_does_not_ask() {
    use pty::{plain, Prompt};

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let mut cmd = api(server.port, dir.path());
    cmd.args(["--export", "com.heads.seedID"]);
    let mut prompt = Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));

    let press = |prompt: &mut Prompt, keys: &[u8]| {
        let mark = prompt.screen.len();
        prompt.send(keys);
        prompt.pump(Duration::from_millis(500));
        plain(&prompt.screen[mark..])
    };
    // The menu shows the name the session was started with.
    let shown = press(&mut prompt, b"\x14");
    assert!(shown.contains("Export mode (responses as seed data)  com.heads.seedID"), "{shown}");
    // What the screen holds now, not what went past: the row the cursor is
    // on and the menu's last row.
    let stands = |prompt: &Prompt| {
        let rows = pty::rows(&prompt.screen, 200);
        let chosen = rows.iter().find(|row| row.starts_with("› ")).unwrap_or_else(|| panic!("{}", rows.join("\n"))).clone();
        (chosen, rows.last().unwrap().clone())
    };
    let shown = press(&mut prompt, b"\x1b[B\r");
    assert!(shown.contains("export off"), "{shown}");
    assert_eq!(stands(&prompt), ("› Export mode (responses as seed data)  off".to_string(), "  export off".to_string()));
    // It stays open: Enter on the row again turns it back on.
    let shown = press(&mut prompt, b"\r");
    assert!(shown.contains("export on: com.heads.seedID"), "{shown}");
    assert!(!shown.contains("Export with external identifier"), "{shown}");
    assert_eq!(
        stands(&prompt),
        ("› Export mode (responses as seed data)  com.heads.seedID".to_string(), "  export on: com.heads.seedID".to_string())
    );

    // From the menu, ctrl+h goes to the shortcuts, which list the menu's key
    // and no longer one for export.
    let shown = press(&mut prompt, b"\x08");
    assert!(shown.contains("ctrl+t     Settings"), "{shown}");
    assert!(!shown.contains("ctrl+r"), "{shown}");
}

/// Paste a line or a block at the prompt and press Enter, as `run_pasted`
/// does: what was sent, what the screen showed, and the `Accept` header of
/// each request.
#[cfg(unix)]
fn run_pasted_accepts(prompt: &mut pty::Prompt, server: &RecordingServer, paste: &str) -> (Vec<String>, String, Vec<String>) {
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
    let accepts = server.heads().iter().map(|head| accept_of(head)).collect();
    (server.take(), pty::plain(&prompt.screen[mark..]), accepts)
}

/// The `Accept` header in a line of `RecordingServer::heads`.
fn accept_of(head: &str) -> String {
    let from = head.find("accept=").map_or(0, |at| at + "accept=".len());
    head[from..].split("; content-type=").next().unwrap_or("").to_string()
}

/// The name a written record was exported under, `None` when it was written
/// as the server sent it.
fn exported_under(dir: &Path, file: &str) -> Option<String> {
    let text = std::fs::read_to_string(dir.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file}: {e}: {text}"));
    value["identifiers"].as_object().unwrap().keys().find(|k| *k != "key?" && *k != "key").cloned()
}

/// `set <name>` typed at the prompt changes what the session has set: it
/// holds for what is typed after it, until it is changed again, and for a
/// file run from the prompt, as an option does for a batch.
#[cfg(unix)]
#[test]
fn a_set_line_at_the_prompt_holds_for_the_session() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    std::fs::write(dir.path().join("plain.api"), "GET /keyed > from-file.json\n").unwrap();
    std::fs::write(dir.path().join("own.api"), "set export other.name.id\nGET /keyed > from-own.json\n").unwrap();
    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_ready(Duration::from_secs(15));
    let mut run = |paste: &str| run_pasted_accepts(&mut prompt, &server, paste);
    let exported = |file: &str| exported_under(dir.path(), file);
    let seed = Some("com.heads.seedID".to_string());

    // Before the line, the response is the server's.
    let (_, shown, _) = run("GET /keyed");
    assert!(shown.contains("\"key\": \"k1\"") && !shown.contains("key?"), "{shown}");

    // The line sends nothing, is logged, and says what it did.
    let (sent, shown, _) = run("set export com.heads.seedID");
    assert_eq!(sent, Vec::<String>::new());
    assert!(shown.contains("set export com.heads.seedID") && shown.contains("export on: com.heads.seedID"), "{shown}");
    let (_, shown, _) = run("GET /keyed");
    assert!(shown.contains("\"key?\": \"k1\"") && shown.contains("\"com.heads.seedID\": \"k1\""), "{shown}");

    // A file run from here runs in the session: exported, and a line of its
    // own does not change what the session has on.
    let (sent, _, _) = run("plain.api");
    assert_eq!(sent, ["GET /keyed"]);
    assert_eq!(exported("from-file.json"), seed);
    let (sent, shown, _) = run("own.api");
    assert_eq!(sent, ["GET /keyed"]);
    assert_eq!(exported("from-own.json"), seed);
    assert!(shown.contains("↳ ignored: the session has set export com.heads.seedID"), "{shown}");
    run("GET /keyed > typed.json");
    assert_eq!(exported("typed.json"), seed);

    // A name that can't be one is refused, and the setting stays.
    let (sent, shown, _) = run("set export nope");
    assert_eq!(sent, Vec::<String>::new());
    assert!(shown.contains("invalid export identifier: nope"), "{shown}");
    run("GET /keyed > still.json");
    assert_eq!(exported("still.json"), seed);

    let (sent, shown, _) = run("set export off");
    assert_eq!(sent, Vec::<String>::new());
    assert!(shown.contains("export off"), "{shown}");
    run("GET /keyed > off.json");
    assert_eq!(exported("off.json"), None);

    // With it off, a file's own line holds in that file and ends with it.
    let (_, shown, _) = run("own.api");
    assert_eq!(exported("from-own.json"), Some("other.name.id".to_string()));
    assert!(!shown.contains("ignored"), "{shown}");
    run("GET /keyed > after-own.json");
    assert_eq!(exported("after-own.json"), None);

    // In a pasted block the line holds for the rest of the block, and after it.
    let (sent, _, _) = run("GET /keyed > block-before.json\nset export com.heads.seedID\nGET /keyed > block-after.json");
    assert_eq!(sent.len(), 2);
    assert_eq!(exported("block-before.json"), None);
    assert_eq!(exported("block-after.json"), seed);
    run("GET /keyed > later.json");
    assert_eq!(exported("later.json"), seed);
    run("set export off");

    // The other settings, each by what it does to a request.
    let (sent, shown, _) = run("set include-nulls");
    assert_eq!(sent, Vec::<String>::new());
    assert!(shown.contains("include-nulls on"), "{shown}");
    let (_, _, accepts) = run("GET /a");
    assert_eq!(accepts, ["application/json;skipNulls=false"]);
    let (_, _, accepts) = run("seed.api");
    assert_eq!(accepts, ["application/json;skipNulls=false", "application/json;skipNulls=false"], "a file run from here");
    let (_, shown, _) = run("set ndjson on");
    assert!(shown.contains("ndjson on"), "{shown}");
    let (_, _, accepts) = run("GET /a");
    assert_eq!(accepts, ["application/x-ndjson;skipNulls=false"]);
    let (_, shown, _) = run("set include-nulls off\nset ndjson off");
    assert!(shown.contains("ndjson off"), "{shown}");
    let (_, _, accepts) = run("GET /a");
    assert_eq!(accepts, ["application/json"]);

    // Fail fast: a block stops at the first failed request, until it is off.
    run("set fail-fast");
    let (sent, shown, _) = run("GET /missing\nGET /never");
    assert_eq!(sent, ["GET /missing"]);
    assert!(shown.contains("stopped at 404 (--fail-fast)"), "{shown}");
    run("set fail-fast off");
    let (sent, _, _) = run("GET /missing\nGET /after");
    assert_eq!(sent, ["GET /missing", "GET /after"]);

    // A timeout says what it is now, and `off` is the default again.
    let (_, shown, _) = run("set timeout 30");
    assert!(shown.contains("timeout 30s"), "{shown}");
    let (_, shown, _) = run("set timeout 0");
    assert!(shown.contains("no timeout"), "{shown}");
    let (_, shown, _) = run("set timeout off");
    assert!(shown.contains("timeout 600s"), "{shown}");

    // A setting that is none is said to be none, and nothing is sent.
    let (sent, shown, _) = run("set nulls");
    assert_eq!(sent, Vec::<String>::new());
    assert!(shown.contains("unknown setting `nulls`"), "{shown}");
}

/// What a session was started with is what it has set, no more: a line
/// typed in it changes it, as it changes a setting typed earlier.
#[cfg(unix)]
#[test]
fn a_set_line_changes_what_the_session_was_started_with() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    std::fs::write(dir.path().join("own.api"), "set export other.name.id\nset include-nulls off\nGET /keyed > from-own.json\n").unwrap();
    let mut cmd = api(server.port, dir.path());
    cmd.args(["--export", "com.heads.seedID", "-i"]);
    let mut prompt = Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));
    let mut run = |paste: &str| run_pasted_accepts(&mut prompt, &server, paste);
    let exported = |file: &str| exported_under(dir.path(), file);

    let (_, _, accepts) = run("GET /keyed > typed.json");
    assert_eq!(exported("typed.json"), Some("com.heads.seedID".to_string()));
    assert_eq!(accepts, ["application/json;skipNulls=false"]);

    // A file's lines are overridden by what the session has on, each named.
    let (_, shown, accepts) = run("own.api");
    assert_eq!(exported("from-own.json"), Some("com.heads.seedID".to_string()));
    assert_eq!(accepts, ["application/json;skipNulls=false"]);
    assert!(shown.contains("↳ ignored: the session has set export com.heads.seedID"), "{shown}");
    assert!(shown.contains("↳ ignored: the session has set include-nulls"), "{shown}");

    // A typed line is the session's own, and the last one wins.
    let (_, shown, _) = run("set export other.name.id");
    assert!(shown.contains("export on: other.name.id"), "{shown}");
    run("GET /keyed > typed.json");
    assert_eq!(exported("typed.json"), Some("other.name.id".to_string()));
    let (_, shown, _) = run("set export off\nset include-nulls off");
    assert!(shown.contains("include-nulls off"), "{shown}");
    let (_, _, accepts) = run("GET /keyed > typed.json");
    assert_eq!(exported("typed.json"), None);
    assert_eq!(accepts, ["application/json"]);

    // And now the file's own lines hold, in the file.
    let (_, shown, _) = run("own.api");
    assert_eq!(exported("from-own.json"), Some("other.name.id".to_string()));
    assert!(!shown.contains("ignored"), "{shown}");
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
        (server.take(), out.status.code() == Some(0), String::from_utf8_lossy(&out.stdout).to_string(), out.status.code())
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
            assert_eq!(got.3, Some(if ok { 0 } else { 1 }), "{how}: {lines:?}");
            // The failing body, `{}` from this server, ends stdout.
            assert_eq!(got.2.ends_with("\n{}\n"), !ok, "{how}: {lines:?}\n{}", got.2);
        }
        // Without the flag every line is sent and the run succeeds.
        // Every case ends in `GET /b`, the line `-f` did not get to.
        let unflagged = run(&["-sa", "case.api"], None);
        let mut all: Vec<&str> = sent.to_vec();
        if !ok {
            all.push("GET /b");
        }
        assert_eq!((unflagged.3, &unflagged.0), (Some(0), &all.iter().map(|s| s.to_string()).collect::<Vec<_>>()), "{lines:?}: {unflagged:?}");
        assert!(!unflagged.2.ends_with("\n{}\n"), "{lines:?}: {}", unflagged.2);
    }

    // One request, split by the shell or not.
    for args in [&["-f", "GET", "/missing"][..], &["-f", "GET /missing"], &["GET", "/missing", "-f"]] {
        let got = run(args, None);
        assert_eq!((got.0, got.3, got.2.as_str()), (vec!["GET /missing".to_string()], Some(1), "{}\n"), "{args:?}");
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
    prompt.wait_ready(Duration::from_secs(15));

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

/// A plain line whose outfile can't be written is said to be so and the next
/// line runs, in a pasted block and in a file run from the prompt, as in a
/// batch. A chain stops there, a request that got no answer stops the
/// program, and so does a failed write under `-f`.
#[cfg(unix)]
#[test]
fn an_outfile_that_cannot_be_written_does_not_stop_a_block_at_the_prompt() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);

    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /a > nodir/x.json\rGET /b\r");
    assert_eq!(sent, ["GET /a", "GET /b"], "{shown}");
    assert!(shown.contains("Error writing to nodir/x.json"), "{shown}");

    std::fs::write(dir.path().join("unwritable.api"), "GET /a > nodir/x.json\nGET /b\n").unwrap();
    let (sent, shown) = run_pasted(&mut prompt, &server, "unwritable.api");
    assert_eq!(sent, ["GET /a", "GET /b"], "{shown}");
    assert!(shown.contains("Error writing to nodir/x.json"), "{shown}");

    // A chain stops where its write failed, and the block with it, as a batch does.
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /a > nodir/x.json && GET /never\rGET /b\r");
    assert_eq!(sent, ["GET /a"], "{shown}");
    assert!(shown.contains("Error writing to nodir/x.json"), "{shown}");

    // A response that stops before its end is no answer: the program stops.
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /trunc\rGET /b\r");
    assert_eq!(sent, ["GET /trunc"], "{shown}");
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /trunc > t.json\rGET /b\r");
    assert_eq!(sent, ["GET /trunc"], "{shown}");
    assert!(!dir.path().join("t.json").exists());
    drop(prompt);

    // Streamed, the two are told apart the same way.
    let mut prompt = open_prompt(&server, dir.path(), &["--stream"]);
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /a > nodir/x.json\rGET /b\r");
    assert_eq!(sent, ["GET /a", "GET /b"], "{shown}");
    assert!(shown.contains("Error writing to nodir/x.json"), "{shown}");
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /trunc > t.json\rGET /b\r");
    assert_eq!(sent, ["GET /trunc"], "{shown}");
    drop(prompt);

    // Under `-f` a write that failed ends the program, as it ends a batch.
    let mut prompt = open_prompt(&server, dir.path(), &["-f"]);
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /a > nodir/x.json\rGET /b\r");
    assert_eq!(sent, ["GET /a"], "{shown}");
    assert!(shown.contains("Error writing to nodir/x.json"), "{shown}");
    let (sent, _) = run_pasted(&mut prompt, &server, "GET /b");
    assert_eq!(sent, ["GET /b"]);
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
    prompt.wait_ready(Duration::from_secs(15));

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
    prompt.wait_ready(Duration::from_secs(15));

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
    prompt.wait_ready(Duration::from_secs(15));

    // Each entry is typed key by key; `\t` is Tab. `body.json` also starts
    // with a letter of its own but is never offered, not being a `.api` file.
    let lines: [(&[&str], &str, &[&str]); 4] = [
        (&["se", "\t"], "seed.api", &["GET /inc1", "GET /inc2"]),
        (&["in", "\t", "b", "\t"], "inc/b.api", &["GET /g2"]),
        // Tab on the one directory that matched goes into it, as its ghost
        // shows, and the next Tab goes on to the file after.
        (&["./in", "\t", "\t"], "./inc/a.api", &["GET /g1"]),
        (&["./in", "\t", "\t", "\t"], "./inc/b.api", &["GET /g2"]),
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
    prompt.wait_ready(Duration::from_secs(15));
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
    prompt.wait_ready(Duration::from_secs(15));

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

/// The prompt of a session with the key `spec`, once it has read the spec
/// the server has for it: Tab completes from then on.
#[cfg(unix)]
fn open_completing(server: &RecordingServer, dir: &Path, flags: &[&str]) -> pty::Prompt {
    let url = format!("http://127.0.0.1:{}", server.port);
    let mut cmd = api_bare(dir);
    cmd.args(["-b", &url, "-k", "spec"]).args(flags);
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));
    let start = Instant::now();
    loop {
        let mark = prompt.screen.len();
        prompt.send(b"\x15GET /pe\t");
        prompt.pump(Duration::from_millis(250));
        if pty::plain(&prompt.screen[mark..]).contains("GET /people") {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(15), "the spec was never read:\n{}", screen_tail(&prompt));
    }
    server.take();
    prompt
}

/// The prompt opens when the server has answered `/about`. The API spec is
/// read behind it: meanwhile a request is sent as typed and `GET /` offers
/// `/about`, and Tab completes from the spec once it is there.
#[cfg(unix)]
#[test]
fn the_prompt_is_open_while_the_spec_is_on_its_way() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let url = format!("http://127.0.0.1:{}", server.port);
    let mut cmd = api_bare(dir.path());
    // The spec of the key `slowspec` takes eight seconds: long enough for
    // what is checked before it arrives, with every other test running.
    cmd.args(["-b", &url, "-k", "slowspec"]);
    let start = Instant::now();
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(300));

    // The first frame offers `/about`, and Tab writes it.
    let rows = pty::rows(&prompt.screen, 200);
    assert!(rows.iter().any(|row| row.trim_end() == "GET /about"), "{}", rows.join("\n"));
    assert!(press(&mut prompt, &["GET /", "\t", "?"]).contains("GET /about?"), "{}", screen_tail(&prompt));
    // Nothing else is known yet.
    assert!(!press(&mut prompt, &["GET /pe", "\t"]).contains("GET /people"), "{}", screen_tail(&prompt));
    // A request does not wait for the spec.
    press(&mut prompt, &["GET /early"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /early"], "{}", screen_tail(&prompt));
    assert!(start.elapsed() < Duration::from_secs(7), "the prompt waited for the spec: {:?}", start.elapsed());

    // When the spec is there, Tab completes from it.
    let arrived = pump_until(&mut prompt, Duration::from_secs(15), |_| start.elapsed() > Duration::from_secs(8));
    assert!(arrived);
    let start = Instant::now();
    while !press(&mut prompt, &["GET /pe", "\t"]).contains("GET /people") {
        assert!(start.elapsed() < Duration::from_secs(10), "the spec was never read:\n{}", screen_tail(&prompt));
    }
}

/// The requests of a run that follow each other are sent over one
/// connection: a batch does not open one per line.
#[test]
fn a_batch_sends_its_requests_over_one_connection() {
    use std::io::{Read, Write};
    use std::sync::atomic::AtomicUsize;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (connections, requests) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (connections2, requests2) = (Arc::clone(&connections), Arc::clone(&requests));
    // A server that keeps a connection open for the next request, as COS does.
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            connections2.fetch_add(1, Ordering::SeqCst);
            let requests = Arc::clone(&requests2);
            std::thread::spawn(move || {
                let mut pending: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    // The requests here have no body: a head ends one.
                    while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                        pending.drain(..end + 4);
                        requests.fetch_add(1, Ordering::SeqCst);
                        let reply = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\ntrue";
                        if stream.write_all(reply).is_err() {
                            return;
                        }
                    }
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => pending.extend_from_slice(&chunk[..n]),
                    }
                }
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("lines.api"), "GET /one\nGET /two && GET /three\nassert GET /four\nGET /five\n").unwrap();
    let mut cmd = api_bare(dir.path());
    cmd.args(["-b", &url, "-k", "k", "-sa", "lines.api"]);
    let out = cmd.output().expect("spawn api");
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(requests.load(Ordering::SeqCst), 5, "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

/// Clear the line and press `keys`, one after the other. Returns what the
/// screen showed meanwhile.
#[cfg(unix)]
fn press(prompt: &mut pty::Prompt, keys: &[&str]) -> String {
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    let mark = prompt.screen.len();
    for key in keys {
        prompt.send(key.as_bytes());
        prompt.pump(Duration::from_millis(90));
    }
    pty::plain(&prompt.screen[mark..])
}

/// Press Enter and return what the server was sent for it.
#[cfg(unix)]
fn entered(prompt: &mut pty::Prompt, server: &RecordingServer) -> Vec<String> {
    server.take();
    prompt.send(b"\r");
    pump_until(prompt, Duration::from_secs(4), |_| server.seen() > 0);
    prompt.pump(Duration::from_millis(250));
    let sent = server.log.lock().unwrap().clone();
    sent
}

const LEFT: &str = "\x1b[D";
const HOME: &str = "\x1b[H";
const END: &str = "\x1b[F";
const SHIFT_TAB: &str = "\x1b[Z";

/// Tab at the prompt completes the URI from the spec the server has, and
/// Shift+Tab goes back through what Tab offered.
#[cfg(unix)]
#[test]
fn tab_completes_the_uri_from_the_servers_spec() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("data.csv"), "a,b\n1,2\n").unwrap();
    let mut prompt = open_completing(&server, d, &[]);

    let lines: &[(&[&str], &str)] = &[
        (&["GET /pe", "\t"], "GET /people"),
        (&["GET /pe", "\t", "\t"], "GET /people/find"),
        (&["GET /pe", "\t", "\t", "\t", "\t"], "GET /people"),
        (&["GET /pe", "\t", "\t", SHIFT_TAB], "GET /people"),
        (&["GET /pe", "\t", SHIFT_TAB], "GET /pets"),
        (&["/pet", "\t"], "GET /pets"),
        (&["GET /people~wi", "\t", "na", "\t", ")"], "GET /people~with(name)"),
        // In an operator that follows another, and in one inside another.
        (&["GET /people~take(5)~with(gi", "\t", ")"], "GET /people~take(5)~with(givenName)"),
        (&["GET /people~with(name,identifiers~just(com", "\t", "))"], "GET /people~with(name,identifiers~just(com.mi6.id))"),
        (&["GET /people~with(n:na", "\t", ")"], "GET /people~with(n:name)"),
        (&["GET /people/", "\t", "007/gi", "\t"], "GET /people/com.mi6.id=007/givenName"),
        // In front of the URI Tab does nothing; at its end it completes.
        (&["GET /pe", HOME, "\t", END, "\t"], "GET /people"),
        (&["GET /pe", LEFT, LEFT, LEFT, "\t", END, "\t"], "GET /people"),
    ];
    for (keys, sent) in lines {
        let shown = press(&mut prompt, keys);
        assert_eq!(entered(&mut prompt, &server), [*sent], "{keys:?}: {shown}");
        prompt.pump(Duration::from_millis(150));
    }

    // With an outfile on the line, Tab and Shift+Tab in the URI leave it.
    let mut keys = vec!["GET /pe > out.json"];
    keys.extend(std::iter::repeat(LEFT).take(11));
    keys.extend(["\t", SHIFT_TAB]);
    let shown = press(&mut prompt, &keys);
    assert_eq!(entered(&mut prompt, &server), ["GET /pets"], "{shown}");
    assert!(d.join("out.json").is_file(), "{shown}");
    assert_eq!(std::fs::read_dir(d).unwrap().count(), 3, "data.csv, out.json and the history file");

    // A body file takes `~map(`, with the mapped types the server lists.
    let shown = press(&mut prompt, &["PUT /people @data.csv~", "\t", "\t"]);
    let sent = entered(&mut prompt, &server);
    assert_eq!(sent, ["PUT /people a,b\n1,2\n"], "{shown}");
    assert!(server.heads()[0].ends_with("x-request-map=com.heads.csv"), "{:?}", server.heads());
    // And `~` after `>` is the home directory.
    let shown = press(&mut prompt, &["GET /people > ~", "\t"]);
    assert!(shown.contains("GET /people > ~/"), "{shown}");

    // What Tab would add is shown ahead of the cursor, with the count of
    // what it can be once it has been pressed, and the index a collection takes.
    let shown = press(&mut prompt, &["GET /pe"]);
    assert!(shown.contains("GET /people"), "{shown}");
    let shown = press(&mut prompt, &["GET /pe", "\t"]);
    assert!(shown.contains("(1/3)"), "{shown}");
    let shown = press(&mut prompt, &["GET /people/"]);
    assert!(shown.contains("index: COS database key or common identifiers"), "{shown}");
    // Esc ends the cycling: Tab then starts from what the line has.
    press(&mut prompt, &["GET /pe", "\t", "\t", "\x1b"]);
    prompt.pump(Duration::from_millis(200));
    prompt.send(b"\t");
    prompt.pump(Duration::from_millis(100));
    assert_eq!(entered(&mut prompt, &server), ["GET /people/find"], "{}", screen_tail(&prompt));
}

/// A ghost is drawn where Tab then writes it: at the cursor, with the rest of
/// the line left as it is, and on the row it will stand on. Where no ghost
/// is drawn, Tab writes nothing.
#[cfg(unix)]
#[test]
fn a_ghost_is_drawn_where_tab_writes_it() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_completing(&server, dir.path(), &["-x"]);
    // The rows of the input, between the two rulers.
    let input_rows = |prompt: &mut pty::Prompt, keys: &[&str]| {
        press(prompt, keys);
        prompt.pump(Duration::from_millis(300));
        let rows = pty::rows(&prompt.screen, 200);
        let rulers = ruler_rows(&rows);
        rows[rulers[rulers.len() - 2] + 1..rulers[rulers.len() - 1]].to_vec()
    };

    // What Enter sends, with the prompt back before the next keys.
    let sent = |prompt: &mut pty::Prompt| {
        let sent = entered(prompt, &server);
        prompt.pump(Duration::from_millis(300));
        sent
    };

    // At the end of a segment with more of the line behind it. The ghost
    // used to be drawn behind the blank: `GET /peo ple&& GET /pets`.
    let mut keys = vec!["GET /peo && GET /pets"];
    keys.extend(std::iter::repeat(LEFT).take(13));
    assert_eq!(input_rows(&mut prompt, &keys), ["GET /people && GET /pets"]);
    keys.push("\t");
    let rows = input_rows(&mut prompt, &keys);
    assert!(rows[0].starts_with("GET /people && GET /pets  ") && rows[0].ends_with("(1/2)"), "{rows:?}");
    assert_eq!(sent(&mut prompt), ["GET /people", "GET /pets"]);
    // In the blank behind the segment there is none, and Tab leaves the line.
    let mut keys = vec!["GET /peo && GET /pets"];
    keys.extend(std::iter::repeat(LEFT).take(12));
    assert_eq!(input_rows(&mut prompt, &keys), ["GET /peo && GET /pets"]);
    keys.push("\t");
    assert_eq!(input_rows(&mut prompt, &keys), ["GET /peo && GET /pets"]);

    // Behind an operator that was the only one: what is inside it, and the
    // next Tab writes that. Tab was dead there.
    assert_eq!(input_rows(&mut prompt, &["GET /people~wh", "\t"]), ["GET /people~where(active"]);
    press(&mut prompt, &["GET /people~wh", "\t", "\t", ")"]);
    assert_eq!(sent(&mut prompt), ["GET /people~where(active)"]);
    // Behind one of several Tab goes on to the next, so nothing is shown.
    let rows = input_rows(&mut prompt, &["GET /people~wi", "\t"]);
    assert!(rows[0].starts_with("GET /people~with(  ") && rows[0].ends_with("(1/2)"), "{rows:?}");
    press(&mut prompt, &["GET /people~wi", "\t", "\t", "name)"]);
    assert_eq!(sent(&mut prompt), ["GET /people~without(name)"]);
    // Nothing starts so: nothing is written.
    assert_eq!(input_rows(&mut prompt, &["GET /people~zz", "\t"]), ["GET /people~zz"]);
    assert_eq!(input_rows(&mut prompt, &["GET /find", "\t"]), ["GET /find"]);

    // The index hint is that of the request the cursor is in.
    let rows = input_rows(&mut prompt, &["GET /about && GET /people/"]);
    assert!(rows[0].ends_with("index: COS database key or common identifiers"), "{rows:?}");
    assert_eq!(input_rows(&mut prompt, &["GET /people/ && GET /about"]), ["GET /people/ && GET /about"]);
    assert_eq!(input_rows(&mut prompt, &["GET /people~"])[0].trim_end(), "GET /people~with(");

    // A bracket that closes on a line of its own: the cursor keeps its
    // cell, and the ghost is on the row Tab writes it on.
    let body: &[&str] = &["PUT /people [{", "\r", "\"name\": \"x\""];
    let mark = prompt.screen.len();
    assert_eq!(input_rows(&mut prompt, body), ["PUT /people [{", "    \"name\": \"x\"", "  }"]);
    let drawn = &prompt.screen[mark..];
    assert!(drawn.contains("\x1b[48;5;247m\x1b[38;5;0m \x1b[0m\x1b[38;5;240m\r\n  }\x1b[0m"), "{drawn:?}");
    let closed = [body, &["\t"]].concat();
    assert_eq!(input_rows(&mut prompt, &closed), ["PUT /people [{", "    \"name\": \"x\"", "  }", "]"]);
    press(&mut prompt, &[body, &["\t", "\t"]].concat());
    assert_eq!(sent(&mut prompt), ["PUT /people [{\n    \"name\": \"x\"\n  }\n]"]);
    // A literal ends a value as a string does. (The `[` is the prompt's,
    // for an endpoint that takes a list.)
    assert_eq!(input_rows(&mut prompt, &["PUT /agents {\"name\": null"]), ["PUT /agents [{\"name\": null}"]);
    assert_eq!(input_rows(&mut prompt, &["PUT /agents {\"name\": null", "\t"]), ["PUT /agents [{\"name\": null}]"]);
    press(&mut prompt, &["PUT /agents {\"name\": null", "\t", "\t"]);
    assert_eq!(sent(&mut prompt), ["PUT /agents [{\"name\": null}]"]);
}

/// Under `-x` the body completes from the spec too: keys, values, the
/// subtypes of a type and the brackets that close it.
#[cfg(unix)]
#[test]
fn tab_completes_a_body_from_the_servers_spec_under_x() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_completing(&server, dir.path(), &["-x"]);
    // The body the server was sent, as the JSON it is.
    let body_of = |sent: &[String], line: &str| -> serde_json::Value {
        assert_eq!(sent.len(), 1, "{line}: {sent:?}");
        let body = sent[0].strip_prefix(line).unwrap_or_else(|| panic!("{sent:?} does not start with {line}"));
        serde_json::from_str(body).unwrap_or_else(|e| panic!("{body:?} is not JSON: {e}"))
    };

    // A key by its start, a closing bracket after each complete value.
    let shown = press(&mut prompt, &["PUT /people [{\"gi", "\t", " \"Ann\"", "\t", "\t"]);
    let sent = entered(&mut prompt, &server);
    assert_eq!(sent, ["PUT /people [{\"givenName\": \"Ann\"}]"], "{shown}");
    // The ghost showed the rest of the key before Tab wrote it.
    let shown = press(&mut prompt, &["PUT /people [{\"gi"]);
    assert!(shown.contains("[{\"givenName\":"), "{shown}");

    // A value after its colon, and the other one on the next Tab.
    let shown = press(&mut prompt, &["PUT /people [{\"active\":", "\t", "\t", "}]"]);
    assert_eq!(entered(&mut prompt, &server), ["PUT /people [{\"active\": false}]"], "{shown}");
    let shown = press(&mut prompt, &["PUT /people [{\"name\": \"x\", ac", "\t", "\t", "}]"]);
    assert_eq!(entered(&mut prompt, &server), ["PUT /people [{\"name\": \"x\", \"active\": true}]"], "{shown}");

    // The subtypes of a type, forward and back.
    let shown = press(&mut prompt, &["POST /agents {", "\t", "\t", SHIFT_TAB, "}"]);
    assert_eq!(entered(&mut prompt, &server), ["POST /agents { \"@type\": \"person\"}"], "{shown}");
    let shown = press(&mut prompt, &["POST /agents {", "\t", "\t", ",", "\"na", "\t", "\"Acme\"", "\t"]);
    let sent = entered(&mut prompt, &server);
    assert_eq!(sent.len(), 1, "{shown}\n{}", screen_tail(&prompt));
    assert_eq!(body_of(&sent, "POST /agents "), serde_json::json!({"@type": "company", "name": "Acme"}), "{shown}");

    // Tab before a body opens the brackets the endpoint takes, on lines of
    // their own; the object's first key is its identifiers.
    let shown = press(&mut prompt, &["PUT /people ", "\t", "\t", "\t", " \"007\"", END]);
    let sent = entered(&mut prompt, &server);
    assert_eq!(sent.len(), 1, "{shown}\n{}", screen_tail(&prompt));
    assert_eq!(
        body_of(&sent, "PUT /people "),
        serde_json::json!([{"identifiers": {"com.mi6.id": "007"}}]),
        "{shown}"
    );

    // Enter inside the brackets lays the body out on lines and goes on.
    let shown = press(&mut prompt, &["PUT /people [{\"name\": \"x\",", "\r", "\"gi", "\t", " \"y\"", "\t", "\t"]);
    let sent = entered(&mut prompt, &server);
    assert_eq!(sent.len(), 1, "{shown}\n{}", screen_tail(&prompt));
    assert_eq!(body_of(&sent, "PUT /people "), serde_json::json!([{"name": "x", "givenName": "y"}]), "{shown}");

    // A closing bracket typed after a comma takes the comma away, and on a
    // line of its own takes the indent of what it closes.
    let shown = press(&mut prompt, &["PUT /people [{\"name\": \"x\",", "\r", "}", "]"]);
    let sent = entered(&mut prompt, &server);
    assert_eq!(sent, ["PUT /people [{\n    \"name\": \"x\"\n  }]"], "{shown}");
    // In a body that has lines, Enter goes to a new one: indented after a
    // comma, between a pair of brackets, and out again after a closing one.
    let shown = press(&mut prompt, &["PUT /people ", "\t", "\"name\": \"x\",", "\r", "\"givenName\": \"y\"", END]);
    let sent = entered(&mut prompt, &server);
    assert_eq!(sent.len(), 1, "{shown}\n{}", screen_tail(&prompt));
    assert_eq!(body_of(&sent, "PUT /people "), serde_json::json!([{"name": "x", "givenName": "y"}]), "{shown}");
    let shown = press(&mut prompt, &["PUT /people ", "\t", "\"identifiers\": {}", LEFT, "\r", "\"com.mi6.id\": \"7\"", END]);
    let sent = entered(&mut prompt, &server);
    assert_eq!(sent.len(), 1, "{shown}\n{}", screen_tail(&prompt));
    assert_eq!(body_of(&sent, "PUT /people "), serde_json::json!([{"identifiers": {"com.mi6.id": "7"}}]), "{shown}");
    let shown = press(&mut prompt, &["PUT /people ", "\t", "\"identifiers\": {}", "\r", END]);
    let sent = entered(&mut prompt, &server);
    assert_eq!(sent.len(), 1, "{shown}\n{}", screen_tail(&prompt));
    assert_eq!(body_of(&sent, "PUT /people "), serde_json::json!([{"identifiers": {}}]), "{shown}");

    // Keys are coloured as keys and strings in a list as values.
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    let mark = prompt.screen.len();
    prompt.send(b"PUT /pets [\"a\", \"b\", {\"k\": 1}] > out-1.json");
    prompt.pump(Duration::from_millis(300));
    let drawn = &prompt.screen[mark..];
    assert!(drawn.contains("\x1b[38;5;114m\"b\"\x1b[0m"), "{drawn:?}");
    assert!(drawn.contains("\x1b[38;5;110m\"k\"\x1b[0m"), "{drawn:?}");
    assert!(!drawn.contains("\x1b[38;5;110m\"b\""), "{drawn:?}");
    assert!(drawn.contains("> out-1.json"), "{drawn:?}");
}

/// Send `keys` and wait until the screen has shown `text` since then.
#[cfg(unix)]
fn keys_then(prompt: &mut pty::Prompt, keys: &str, text: &str) -> String {
    prompt.pump(Duration::from_millis(150));
    let mark = prompt.screen.len();
    prompt.send(keys.as_bytes());
    let seen = pump_until(prompt, Duration::from_secs(8), |p| pty::plain(&p.screen[mark..]).contains(text));
    let shown = pty::plain(&prompt.screen[mark..]);
    assert!(seen, "{text:?} never appeared after {keys:?}:\n{shown}");
    shown
}

/// The keys that move in the line and take text out of it do so where the
/// cursor is, and history comes back with Up and Down.
#[cfg(unix)]
#[test]
fn the_prompt_edits_its_line_with_the_usual_keys() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    const DELETE: &str = "\x1b[3~";

    let lines: &[(&[&str], &str)] = &[
        // ← ←, backspace, delete.
        (&["GET /abcd", LEFT, LEFT, "\x7f", DELETE], "GET /ad"),
        (&["GET /abc", LEFT, "\x1b[C", "\x1b[C", "d"], "GET /abcd"),
        // Home and End, and ctrl+a and ctrl+e.
        (&["ET /x", HOME, "G", END, "y"], "GET /xy"),
        (&["ET /x", "\x01", "G", "\x05", "z"], "GET /xz"),
        // At either end there is nothing more to take.
        (&["GET /edge", HOME, "\x7f", LEFT, END, DELETE, "\x0b", "\x1bd", "\x1b[C", "s"], "GET /edges"),
        // ctrl+k takes the rest of the line.
        (&["GET /keep/drop", LEFT, LEFT, LEFT, LEFT, LEFT, "\x0b"], "GET /keep"),
        // ctrl+w and alt+backspace take the word before the cursor, alt+d the one after.
        (&["GET /one two", "\x17"], "GET /one"),
        (&["GET /one three", "\x1b\x7f"], "GET /one"),
        (&["GET /aaa~bbb", HOME, "\x1bf", "\x1bd"], "GET /bbb"),
        // alt+b and alt+f, and ctrl+← and ctrl+→, go by words.
        (&["GET /aaa~bbb", "\x1bb", "\x1bb", "X", "\x1bf", "Y"], "GET /Xaaa~Ybbb"),
        (&["GET /aaa~bbb", "\x1b[1;5D", "Q", HOME, "\x1b[1;5C", "\x1b[1;5C", "R"], "GET /aaa~RQbbb"),
        // ctrl+x takes the body, ctrl+f the whole request.
        (&["PUT /x {\"a\":1}", "\x18", " {\"c\":3}"], "PUT /x {\"c\":3}"),
        (&["PUT /junk {\"a\":1}", "\x06", "full"], "GET /full"),
        // ctrl+space goes round the methods: first back to GET, which puts
        // the body aside, then on to PUT and PATCH with the body again.
        (&["PUT /m {\"a\":1}", "\x00", "\x00", "\x00"], "PATCH /m {\"a\":1}"),
        (&["/m", "\x00", "\x00", "\x00", "\x00"], "GET /m"),
        // ctrl+n starts a new line in the body.
        (&["PUT /n {\"a\":", "\x0e", "1}"], "PUT /n {\"a\":\n1}"),
        // So do alt+enter, and shift+enter where the terminal tells it
        // from Enter.
        (&["PUT /n {\"a\":", "\x1b\r", "2}"], "PUT /n {\"a\":\n2}"),
        (&["PUT /n {\"a\":", "\x1b[13;2u", "3}"], "PUT /n {\"a\":\n3}"),
        // Non-ASCII text is edited by the character.
        (&["GET /åäö", LEFT, "\x7f", "x", END, "\x7f", "y"], "GET /%C3%A5xy"),
    ];
    for (keys, sent) in lines {
        let shown = press(&mut prompt, keys);
        assert_eq!(entered(&mut prompt, &server), [*sent], "{keys:?}: {shown}");
        prompt.pump(Duration::from_millis(120));
    }

    // Up goes back through what was sent, Down forward again and at last
    // to what was being typed.
    for line in ["GET /h1", "GET /h2"] {
        press(&mut prompt, &[line]);
        entered(&mut prompt, &server);
    }
    let shown = press(&mut prompt, &["GET /dra", "\x1b[A", "\x1b[A", "\x1b[B", "\x1b[B", "ft"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /draft"], "{shown}");
    let shown = press(&mut prompt, &["\x1b[A", "\x1b[A", "\x1b[A"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /h1"], "{shown}");
    let shown = press(&mut prompt, &["\x1b[A", "\x1b[A", "\x1b[A", "\x1b[B", "\x1b[B", "\x1b[B", "\x1b[B", "\x1b[B", "GET /last"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /last"], "{shown}");

    // The body editor a body-less PUT opens: Enter starts a line, backspace
    // takes a character, and ctrl+d sends. With nothing typed, no body is sent.
    press(&mut prompt, &["PUT /ed"]);
    keys_then(&mut prompt, "\r", "Enter body, ctrl+d when done");
    for key in ["{\"a\":", "\r", "12", "\x7f", "}", "\x1b[A"] {
        prompt.send(key.as_bytes());
        prompt.pump(Duration::from_millis(90));
    }
    server.take();
    prompt.send(b"\x04");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    assert_eq!(server.take(), ["PUT /ed {\"a\":\n1}"], "{}", screen_tail(&prompt));
    prompt.pump(Duration::from_millis(300));
    press(&mut prompt, &["PUT /empty"]);
    keys_then(&mut prompt, "\r", "Enter body, ctrl+d when done");
    prompt.send(b"\x04");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    assert_eq!(server.take(), ["PUT /empty"], "{}", screen_tail(&prompt));
    prompt.pump(Duration::from_millis(300));

    // ctrl+h shows the shortcuts and takes them away again, as Esc does,
    // and any other key does while doing what it does.
    keys_then(&mut prompt, "\x15\x08", "ctrl+space");
    prompt.send(b"\x08");
    prompt.pump(Duration::from_millis(200));
    keys_then(&mut prompt, "\x08", "ctrl+space");
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(300));
    keys_then(&mut prompt, "\x08", "ctrl+space");
    prompt.send(b"GET /helped");
    prompt.pump(Duration::from_millis(200));
    assert_eq!(entered(&mut prompt, &server), ["GET /helped"], "{}", screen_tail(&prompt));

    // Streaming, the first row of the settings menu, says on a server that
    // can't stream that it can't, in the menu's last row.
    let shown = press(&mut prompt, &["\x14", "\r"]);
    assert!(shown.contains("streaming not available on this server"), "{shown}");
    assert!(shown.contains("› Response streaming                    off"), "{shown}");
    // On the screen as it stands: the row still off, the notice in the
    // menu's last row.
    let rows = pty::rows(&prompt.screen, 200);
    assert_eq!(rows.last().unwrap(), "  streaming not available on this server", "{}", rows.join("\n"));
    assert!(rows.contains(&"› Response streaming                    off".to_string()), "{}", rows.join("\n"));
    press(&mut prompt, &["\x14"]);
    // One ctrl+c asks for another, and any other key takes the question back.
    let shown = press(&mut prompt, &["\x03"]);
    assert!(shown.contains("ctrl+c again to exit"), "{shown}");
    press(&mut prompt, &["GET /still-here"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /still-here"]);
    assert_eq!(prompt.exited(), None);

    // ctrl+j takes the last response's body off the screen and keeps its
    // request and status; ctrl+l takes everything but the splash.
    prompt.pump(Duration::from_millis(300));
    let mark = prompt.screen.len();
    prompt.send(b"\x0a");
    prompt.pump(Duration::from_millis(500));
    let redrawn = pty::plain(&prompt.screen[mark..]);
    assert!(redrawn.contains("GET /still-here") && redrawn.contains("200 OK"), "{redrawn}");
    assert!(!redrawn.contains("\"ok\": \"/api/v1/still-here\""), "{redrawn}");
    assert!(redrawn.contains("\"ok\": \"/api/v1/last\""), "{redrawn}");
    let mark = prompt.screen.len();
    prompt.send(b"\x0c");
    prompt.pump(Duration::from_millis(500));
    let redrawn = pty::plain(&prompt.screen[mark..]);
    assert!(redrawn.contains("CommerceOS API"), "{redrawn}");
    assert!(!redrawn.contains("200 OK") && !redrawn.contains("/api/v1/last"), "{redrawn}");
    // With nothing to take they do nothing, and the session goes on.
    prompt.send(b"\x0c\x0a");
    prompt.pump(Duration::from_millis(200));
    press(&mut prompt, &["GET /after"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /after"]);
}

/// Wait for the client to end. Returns whether it ended well, or `None`
/// when it is still running after five seconds.
#[cfg(unix)]
fn ended(prompt: &mut pty::Prompt) -> Option<bool> {
    let start = Instant::now();
    while prompt.exited().is_none() && start.elapsed() < Duration::from_secs(5) {
        prompt.pump(Duration::from_millis(50));
    }
    prompt.exited()
}

/// The row of the picker that is selected, as the screen has it now.
#[cfg(unix)]
fn selected_row(prompt: &pty::Prompt) -> String {
    pty::rows(&prompt.screen, 200).into_iter().rev().find(|row| row.contains('›')).unwrap_or_default()
}

/// The picker a session starts with when connections are saved and none is
/// the default: it filters as one types, marks a default, deletes, says
/// when a connection is refused, and connects.
#[cfg(unix)]
#[test]
fn the_startup_picker_filters_marks_deletes_and_connects() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(
        d,
        &[
            ("alpha", url.clone(), "key", "k1", ""),
            ("beta", url.clone(), "key", "nokey", ""),
            ("gamma", url.clone(), "key", "k3", ""),
            ("zeta", url.clone(), "key", "k4", ""),
        ],
        "",
    );
    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_for("+ Add new connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));
    assert!(selected_row(&prompt).contains("alpha"), "{}", selected_row(&prompt));

    // Down and Up move, and stop at the ends.
    prompt.send(b"\x1b[A\x1b[B");
    prompt.pump(Duration::from_millis(250));
    assert!(selected_row(&prompt).contains("beta"), "{}", selected_row(&prompt));
    // A connection the server refuses is said to be that, and the picker stays.
    keys_then(&mut prompt, "\r", "beta: unauthorized");

    // Typing filters: the first match is selected, and the others are gone.
    prompt.send(b"zt");
    prompt.pump(Duration::from_millis(300));
    let rows = pty::rows(&prompt.screen, 200);
    let listed: Vec<&String> = rows.iter().rev().take(8).collect();
    assert!(selected_row(&prompt).contains("zeta"), "{listed:?}");
    assert!(listed.iter().any(|row| row.contains("search: zt")), "{listed:?}");
    assert!(!listed.iter().any(|row| row.contains("alpha") || row.contains("gamma")), "{listed:?}");
    // Nothing matches: only the search is left.
    prompt.send(b"q");
    prompt.pump(Duration::from_millis(300));
    let rows = pty::rows(&prompt.screen, 200);
    assert!(rows.iter().rev().take(6).any(|row| row.contains("(no matches)")), "{rows:?}");
    prompt.send(b"\x7f\x7f\x7f\x7f");
    prompt.pump(Duration::from_millis(300));
    assert!(selected_row(&prompt).contains("alpha"), "{}", selected_row(&prompt));

    // Tab makes the selected one the default, and Tab again none.
    prompt.send(b"\x1b[B\x1b[B\t");
    prompt.pump(Duration::from_millis(300));
    assert_eq!(stored(d).1, "gamma");
    assert!(selected_row(&prompt).contains("gamma ♥"), "{}", selected_row(&prompt));
    prompt.send(b"\t");
    prompt.pump(Duration::from_millis(300));
    assert_eq!(stored(d).1, "");
    assert!(!selected_row(&prompt).contains('♥'), "{}", selected_row(&prompt));

    // Delete asks first, and any answer but y keeps the connection.
    prompt.send(b"\x1b[A");
    prompt.pump(Duration::from_millis(200));
    keys_then(&mut prompt, "\x1b[3~", "Delete? y/n");
    prompt.send(b"n");
    prompt.pump(Duration::from_millis(300));
    assert_eq!(stored(d).0.len(), 4);
    keys_then(&mut prompt, "\x1b[3~", "Delete? y/n");
    keys_then(&mut prompt, "y", "beta deleted");
    assert_eq!(stored(d).0, ["alpha=k1", "gamma=k3", "zeta=k4"]);
    // The selection stays where the deleted one was, on the one after it.
    // It used to jump to the first.
    prompt.pump(Duration::from_millis(200));
    assert!(selected_row(&prompt).contains("gamma"), "{}", selected_row(&prompt));

    // The last line opens the form for a new connection, and Esc there
    // comes back to the list.
    prompt.send(b"\x1b[B\x1b[B\x1b[B");
    prompt.pump(Duration::from_millis(200));
    keys_then(&mut prompt, "\r", "Type the API base URL");
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(400));
    assert!(selected_row(&prompt).contains("Add new connection"), "{}", selected_row(&prompt));

    // Enter on a connection opens the prompt on it.
    prompt.send(b"\x1b[A");
    prompt.pump(Duration::from_millis(200));
    keys_then(&mut prompt, "\r", "connected to: zeta");
    prompt.pump(Duration::from_millis(400));
    press(&mut prompt, &["GET /picked"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /picked"]);
    assert!(server.heads()[0].contains("authorization=Basic Oms0;"), "{:?}", server.heads());
}

/// Esc in the startup picker ends the client, with the terminal as a shell
/// expects it; deleting the last connection there opens the form.
#[cfg(unix)]
#[test]
fn the_startup_picker_is_left_with_esc_and_empties_into_the_form() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("only", url.clone(), "key", "k1", "")], "");

    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_for("+ Add new connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));
    prompt.send(b"\x1b");
    assert_eq!(ended(&mut prompt), Some(true), "the client did not end well");
    assert!(prompt.is_cooked(), "the terminal is left in raw mode");
    assert_eq!(server.seen(), 0);

    // In a narrow terminal the splash above the list is a narrow one.
    let mut prompt = pty::Prompt::open_sized(api_bare(d), 36);
    prompt.wait_for("+ Add new connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));
    let rows = pty::rows(&prompt.screen, 36);
    assert!(rows.iter().any(|row| row.contains("CommerceOS API") && !row.contains("Client")), "{rows:#?}");
    assert!(rows.iter().any(|row| row.contains("ctrl+b for docs")), "{rows:#?}");
    assert!(rows.iter().any(|row| row.contains("only") && row.contains(&url)), "{rows:#?}");
    assert!(rows.iter().all(|row| row.chars().count() <= 36), "{rows:#?}");
    prompt.send(b"\x03");
    assert_eq!(ended(&mut prompt), Some(true), "the client did not end well");

    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_for("+ Add new connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));
    // A visit to the form first, left with something typed in it.
    keys_then(&mut prompt, "\x1b[B\r", "Type the API base URL");
    prompt.send(b"stale.example.com");
    prompt.pump(Duration::from_millis(300));
    assert!(row_with(&prompt, 200, "URL:").contains("stale.example.com"));
    keys_then(&mut prompt, "\x1b", "type to search");
    prompt.send(b"\x1b[A");
    prompt.pump(Duration::from_millis(300));
    assert!(selected_row(&prompt).contains("only"), "{}", selected_row(&prompt));
    keys_then(&mut prompt, "\x1b[3~", "Delete? y/n");
    keys_then(&mut prompt, "y", "Type the API base URL");
    assert_eq!(stored(d).0, Vec::<String>::new());
    // The form the picker empties into is an empty one.
    prompt.pump(Duration::from_millis(300));
    assert_eq!(row_with(&prompt, 200, "URL:").trim(), "› URL:");
    // With no connection to go back to, Esc in the form ends the client too.
    prompt.send(b"\x1b");
    assert_eq!(ended(&mut prompt), Some(true), "the client did not end well");
    assert!(prompt.is_cooked(), "the terminal is left in raw mode");
}

/// The form for a new connection takes a URL and an API key, a bearer token
/// or OAuth2 client credentials, goes back a field with Esc, and says what
/// went wrong when the server refuses or does not answer.
#[cfg(unix)]
#[test]
fn the_connection_form_takes_a_key_a_token_or_a_client() {
    let server = RecordingServer::start();
    let host = format!("127.0.0.1:{}", server.port);
    let url = format!("http://{host}");
    let get = |prompt: &mut pty::Prompt, line: &str| -> String {
        prompt.pump(Duration::from_millis(400));
        press(prompt, &[line]);
        let sent = entered(prompt, &server);
        assert_eq!(sent, [line]);
        server.heads()[0].split("authorization=").nth(1).unwrap().split(';').next().unwrap().to_string()
    };

    // An API key. Tab in the URL completes what is typed to a known host.
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    prompt.wait_for("Type the API base URL", Duration::from_secs(15));
    keys_then(&mut prompt, "loc\t", "localhost:5000");
    prompt.send(&[0x7f; 14]);
    keys_then(&mut prompt, "acme\t", "acme.app.heads.com");
    keys_then(&mut prompt, "\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\t", "acme.app.heads.com");
    prompt.send(&[0x7f; 18]);
    // An empty URL is not one: Enter and Tab wait for it.
    prompt.send(b"\r\t");
    prompt.pump(Duration::from_millis(200));
    keys_then(&mut prompt, &format!("{host}\r"), "Use ← → to choose auth method");
    // ← and → go round the three methods.
    keys_then(&mut prompt, "\x1b[C", "Bearer token");
    keys_then(&mut prompt, "\x1b[C", "OAuth2 Client Credentials");
    keys_then(&mut prompt, "\x1b[C", "API key");
    keys_then(&mut prompt, "\x1b[D", "OAuth2 Client Credentials");
    keys_then(&mut prompt, "\x1b[C\r", "Type your API key");
    keys_then(&mut prompt, "wrong\x7f\x7f\x1b", "Use ← → to choose auth method");
    // Esc goes back a field, and from the method to the URL as it was confirmed.
    keys_then(&mut prompt, "\x1b", "Type the API base URL");
    prompt.pump(Duration::from_millis(200));
    assert_eq!(row_with(&prompt, 200, "URL:"), format!("  › {:<14}{url}", "URL:"));
    keys_then(&mut prompt, "\r\r", "Type your API key");
    // What was typed of the key is still there. A key the server refuses
    // is said to be that, and is typed again from nothing.
    keys_then(&mut prompt, "\x7f\x7f\x7fnokey\r", "authentication failed, try again");
    keys_then(&mut prompt, "k9\r", "ctrl+s to save this connection");
    assert_eq!(get(&mut prompt, "GET /with-key"), "Basic Oms5");

    // A bearer token.
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    prompt.wait_for("Type the API base URL", Duration::from_secs(15));
    keys_then(&mut prompt, &format!("{host}\r"), "Use ← → to choose auth method");
    keys_then(&mut prompt, "\x1b[C\r", "Type your bearer token");
    keys_then(&mut prompt, "tok\r", "ctrl+s to save this connection");
    assert_eq!(get(&mut prompt, "GET /with-token"), "Bearer tok");

    // OAuth2 client credentials, with `-b` given: the form starts at the method.
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = api_bare(dir.path());
    cmd.args(["-b", &url]);
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_for("Use ← → to choose auth method", Duration::from_secs(15));
    keys_then(&mut prompt, "\x1b[D\r", "Type your OAuth2 client ID");
    // An empty client ID is not one; Esc goes back to the method and on again.
    prompt.send(b"\r");
    keys_then(&mut prompt, "\x1b", "Use ← → to choose auth method");
    keys_then(&mut prompt, "\r", "Type your OAuth2 client ID");
    keys_then(&mut prompt, "cidx\x7f\r", "Type your client secret");
    keys_then(&mut prompt, "\x1b", "Type your OAuth2 client ID");
    keys_then(&mut prompt, "\r", "Type your client secret");
    // A client the server refuses is said to be that, not a server that
    // is not there, and the secret is typed again from nothing.
    keys_then(&mut prompt, "\x1b", "Type your OAuth2 client ID");
    keys_then(&mut prompt, "\x7f\x7f\x7frefused\r", "Type your client secret");
    keys_then(&mut prompt, "nope\r", "authentication failed, try again");
    keys_then(&mut prompt, "\x1b", "Type your OAuth2 client ID");
    keys_then(&mut prompt, "\x7f\x7f\x7f\x7f\x7f\x7f\x7fcid\r", "Type your client secret");
    keys_then(&mut prompt, "secret\r", "ctrl+s to save this connection");
    let authorization = get(&mut prompt, "GET /with-client");
    assert!(authorization.starts_with("Bearer "), "{authorization}");

    // A server that does not answer: said so, and after three tries the
    // URL is what to look at.
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    prompt.wait_for("Type the API base URL", Duration::from_secs(15));
    keys_then(&mut prompt, "127.0.0.1:1\r", "Use ← → to choose auth method");
    keys_then(&mut prompt, "\r", "Type your API key");
    keys_then(&mut prompt, "k\r", "connection could not be established, try again");
    keys_then(&mut prompt, "\r", "connection could not be established, try again");
    keys_then(&mut prompt, "\r", "connection could not be established, check URL");
    // The same for a client whose token the server does not give.
    keys_then(&mut prompt, "\x1b", "Use ← → to choose auth method");
    keys_then(&mut prompt, "\x1b[D\r", "Type your OAuth2 client ID");
    keys_then(&mut prompt, "c\r", "Type your client secret");
    keys_then(&mut prompt, "s\r", "connection could not be established");
}

/// Run the client in a terminal until it ends. Returns what it printed and
/// whether it ended well.
#[cfg(unix)]
fn ends_in_a_terminal(cmd: std::process::Command) -> (String, Option<bool>) {
    batch_in_a_terminal(cmd, "", b"")
}

/// A session that can't be opened says why and ends; one opened on a saved
/// connection that fails stays open and says which one failed.
#[cfg(unix)]
#[test]
fn a_session_that_cannot_connect_says_why() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let with = |args: &[&str]| {
        let mut cmd = api_bare(d);
        cmd.args(args);
        cmd
    };

    // A key and nowhere to send it.
    let (shown, ended) = ends_in_a_terminal(with(&["-k", "k"]));
    assert!(shown.contains("Error: no base URL specified. Use -b <url> or -c <connection>."), "{shown}");
    assert_eq!(ended, Some(false));
    // A key the server refuses, and a server that is not there.
    let (shown, ended) = ends_in_a_terminal(with(&["-b", &url, "-k", "nokey"]));
    assert!(shown.contains("HTTP/1.1 401 Unauthorized"), "{shown}");
    assert_eq!(ended, Some(false));
    let (shown, ended) = ends_in_a_terminal(with(&["-b", "http://127.0.0.1:1", "-k", "k"]));
    assert!(shown.contains("Could not connect to 127.0.0.1:1"), "{shown}");
    assert_eq!(ended, Some(false));
    assert_eq!(server.seen(), 0);

    // The same two as saved connections: the default one ends the session
    // before it starts, and one asked for with -c opens it and says so there.
    write_credentials(
        d,
        &[
            ("down", "http://127.0.0.1:1".to_string(), "key", "k", ""),
            ("refused", url.clone(), "key", "nokey", ""),
            ("good", url.clone(), "key", "k", ""),
        ],
        "down",
    );
    let (shown, ended) = ends_in_a_terminal(with(&[]));
    assert!(shown.contains("Could not connect to 127.0.0.1:1"), "{shown}");
    assert_eq!(ended, Some(false));
    for (name, said) in [("down", "down: connection failed"), ("refused", "refused: unauthorized"), ("good", "connected to: good")] {
        let mut prompt = pty::Prompt::open(with(&["-c", name]));
        prompt.wait_ready(Duration::from_secs(15));
        let seen = pump_until(&mut prompt, Duration::from_secs(8), |p| pty::plain(&p.screen).contains(said));
        assert!(seen, "{name}: {}", pty::plain(&prompt.screen));
        assert_eq!(prompt.exited(), None, "{name}");
        // From there another one can be picked.
        if name == "down" {
            prompt.pump(Duration::from_millis(300));
            keys_then(&mut prompt, "\x11", "good");
            keys_then(&mut prompt, "\x1b[B\x1b[B\r", "connected to: good");
            prompt.pump(Duration::from_millis(400));
            press(&mut prompt, &["GET /switched"]);
            assert_eq!(entered(&mut prompt, &server), ["GET /switched"]);
        }
    }
}

/// A saved connection whose key a server elsewhere refuses opens the form
/// on that server, to take another key. (Against a local server, as with a
/// key given on the command line, the session just ends: see above.)
#[cfg(unix)]
#[test]
fn a_refused_default_connection_asks_for_another_key() {
    let server = RecordingServer::start();
    // The loopback address, written so that it does not read as local.
    let url = format!("http://127.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("far", url.clone(), "key", "nokey", "")], "far");

    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_for("Use ← → to choose auth method", Duration::from_secs(15));
    assert!(pty::plain(&prompt.screen).contains(&url), "{}", pty::plain(&prompt.screen));
    keys_then(&mut prompt, "\r", "Type your API key");
    keys_then(&mut prompt, "k\r", "ctrl+h for shortcuts");
    prompt.pump(Duration::from_millis(500));
    press(&mut prompt, &["GET /let-in"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /let-in"], "{}", screen_tail(&prompt));
    assert!(server.heads()[0].contains("authorization=Basic Oms=;"), "{:?}", server.heads());
    // The stored connection is as it was: nothing was saved over it.
    assert_eq!(stored(d), (vec!["far=nokey".to_string()], "far".to_string()));

    // ctrl+c there ends the client.
    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_for("Use ← → to choose auth method", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\x03");
    assert_eq!(ended(&mut prompt), Some(true), "the client did not end well");
    assert!(prompt.is_cooked(), "the terminal is left in raw mode");
}

/// Nothing of a refused default connection is kept by the session that
/// follows it: not its name, and not its client secret, which would
/// otherwise answer the next 401 on whatever was connected to instead.
#[cfg(unix)]
#[test]
fn a_refused_default_connection_leaves_nothing_in_the_session() {
    let server = RecordingServer::start();
    let url = format!("http://127.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let connections =
        [("far", url.clone(), "oauth2", "REFUSEDSECRET", "nokey"), ("good", url.clone(), "key", "k", "")];
    let refused = |d: &Path| {
        write_credentials(d, &connections, "far");
        let mut prompt = pty::Prompt::open(api_bare(d));
        prompt.wait_for("Use ← → to choose auth method", Duration::from_secs(15));
        prompt
    };

    // Another key, typed into the form.
    let mut prompt = refused(d);
    keys_then(&mut prompt, "\r", "Type your API key");
    keys_then(&mut prompt, "k\r", "ctrl+h for shortcuts");
    prompt.pump(Duration::from_millis(600));
    assert!(!pty::plain(&prompt.screen).contains("connected to: far"), "{}", screen_tail(&prompt));
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /denied");
    // A 401, and not one that is answered with the refused connection's secret.
    assert_eq!(sent, ["GET /denied"], "{shown}");
    // Saved, it is a connection of its own: the refused one is as it was.
    let shown = save_as(&mut prompt, "mine", "saved");
    assert!(!shown.contains("far"), "{shown}");
    let (saved, default) = stored(d);
    assert_eq!((saved, default.as_str()), (vec!["far=REFUSEDSECRET".to_string(), "good=k".to_string(), "mine=k".to_string()], "far"));
    drop(prompt);

    // Another saved connection, from the picker behind the form.
    let mut prompt = refused(d);
    keys_then(&mut prompt, "\x1b", "Type the API base URL");
    keys_then(&mut prompt, "\x1b", "good");
    prompt.pump(Duration::from_millis(200));
    let down = if selected_row(&prompt).contains("good") { "" } else { "\x1b[B" };
    keys_then(&mut prompt, &format!("{down}\r"), "connected to: good");
    assert!(!pty::plain(&prompt.screen).contains("connected to: far"), "{}", screen_tail(&prompt));
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /denied");
    // A 401, and not one that is answered with the refused connection's secret.
    assert_eq!(sent, ["GET /denied"], "{shown}");
    // ctrl+s proposes the name of the connection in use.
    prompt.pump(Duration::from_millis(300));
    keys_then(&mut prompt, "\x13", "Save connection as");
    prompt.pump(Duration::from_millis(200));
    let rows = pty::rows(&prompt.screen, 200);
    assert!(rows.iter().any(|row| row.contains("Save connection as") && row.contains("good")), "{rows:#?}");
    assert!(rows.iter().all(|row| !(row.contains("Save connection as") && row.contains("far"))), "{rows:#?}");
}

/// `--me` sends to the API of the signed-in user, a bearer token after `-t`
/// is told where it goes now, an option that is none is named, and a
/// body-less PUT at a terminal reads its body from there.
#[cfg(unix)]
#[test]
fn one_shot_corners_of_the_command_line() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    let ran = run_in(&server, d, &["--me", "GET", "/x"]);
    assert_eq!(ran.sent, ["GET /api/me/v1/x"], "{}", ran.stderr);

    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl";
    let ran = run_in(&server, d, &["-t", token, "GET", "/x"]);
    assert_eq!(ran.code, Some(1));
    assert!(ran.stderr.contains("error: -t is now --stream. Use --token <TOKEN> for a bearer token."), "{}", ran.stderr);
    assert!(ran.sent.is_empty());

    let ran = run_in(&server, d, &["--no-such-option", "GET", "/x"]);
    assert_eq!(ran.code, Some(1));
    assert_eq!(ran.stderr.trim(), "error: unexpected option --no-such-option");
    assert!(ran.sent.is_empty());

    let mut cmd = api(server.port, d);
    cmd.args(["PUT", "/typed"]);
    let (shown, ended) = batch_in_a_terminal(cmd, "Reading body from stdin (ctrl+d to finish):", b"{\"a\":1}\n\x04");
    assert_eq!(ended, Some(true), "{shown}");
    assert_eq!(server.take(), ["PUT /typed {\"a\":1}"], "{shown}");
}

/// The first row of the settings menu turns streaming off and on again on a
/// server that can stream.
#[cfg(unix)]
#[test]
fn the_streaming_row_toggles_streaming_on_a_server_that_streams() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = api_bare(dir.path());
    cmd.args(["-b", &url, "-k", "streamer", "--stream"]);
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));
    let on = |prompt: &pty::Prompt| pty::rows(&prompt.screen, 200).last().is_some_and(|row| row.trim_end().ends_with("streaming"));
    assert!(pump_until(&mut prompt, Duration::from_secs(5), |p| on(p)), "{}", screen_tail(&prompt));
    // Open the menu, change the row, close the menu.
    prompt.send(b"\x14\r");
    prompt.pump(Duration::from_millis(400));
    assert!(screen_tail(&prompt).contains("streaming off"), "{}", screen_tail(&prompt));
    let rows = pty::rows(&prompt.screen, 200);
    assert_eq!(rows.last().unwrap(), "  streaming off", "{}", rows.join("\n"));
    assert!(rows.contains(&"› Response streaming                    off".to_string()), "{}", rows.join("\n"));
    prompt.send(CLOSE_MENU);
    prompt.pump(Duration::from_millis(400));
    assert!(!on(&prompt), "{}", screen_tail(&prompt));
    prompt.send(b"\x14\r");
    prompt.pump(Duration::from_millis(400));
    let rows = pty::rows(&prompt.screen, 200);
    assert!(rows.contains(&"› Response streaming                    on".to_string()), "{}", rows.join("\n"));
    prompt.send(CLOSE_MENU);
    prompt.pump(Duration::from_millis(400));
    assert!(on(&prompt), "{}", screen_tail(&prompt));
}

/// A body on stdin that can't be read is not an empty body: nothing is sent.
#[cfg(unix)]
#[test]
fn a_piped_body_that_cannot_be_read_sends_nothing() {
    use std::process::Stdio;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    server.take();
    let mut child = api(server.port, dir.path())
        .args(["PUT", "/a"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn api");
    // Latin-1, which is not UTF-8.
    child.stdin.take().unwrap().write_all(b"{\"name\":\"Bj\xf6rn\"}").unwrap();
    let out = child.wait_with_output().expect("api runs");
    server.settle(Duration::from_millis(150), Duration::from_secs(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("could not read the body from stdin"), "{stderr}");
    assert_eq!(server.take(), Vec::<String>::new());
}

/// What turns export mode on or off from the prompt: ctrl+t opens the
/// settings menu, down goes to its export row, Enter changes it. The menu
/// stays open; the first time a dialog asks for the name before it is back.
#[cfg(unix)]
const EXPORT_ROW: &[u8] = b"\x14\x1b[B\r";
/// ctrl+t again closes the settings menu.
#[cfg(unix)]
const CLOSE_MENU: &[u8] = b"\x14";

/// Paste a line or a block at the prompt, press Enter, and wait until the
/// server has been quiet: what was sent, and what the screen showed.
#[cfg(unix)]
fn run_pasted(prompt: &mut pty::Prompt, server: &RecordingServer, paste: &str) -> (Vec<String>, String) {
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
    (server.take(), pty::plain(&prompt.screen[mark..]))
}

/// A file that stops midway (a failed assert) is still only a file: what it
/// set is not the session's afterwards, and what the session has set stays.
#[cfg(unix)]
#[test]
fn a_file_that_stops_at_the_prompt_leaves_the_sessions_settings_as_they_were() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("own.api"), "set export other.name.id\nassert GET /missing\nGET /never\n").unwrap();
    std::fs::write(dir.path().join("plain.api"), "assert GET /missing\nGET /never\n").unwrap();
    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_ready(Duration::from_secs(15));

    let exported = |file: &str| -> Option<String> {
        let text = std::fs::read_to_string(dir.path().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["identifiers"].as_object().unwrap().keys().find(|k| *k != "key?" && *k != "key").cloned()
    };

    // The file turned export on and stopped: the session has it off.
    let (sent, shown) = run_pasted(&mut prompt, &server, "own.api");
    assert_eq!(sent, ["GET /missing"], "{shown}");
    run_pasted(&mut prompt, &server, "GET /keyed > after-own.json");
    assert_eq!(exported("after-own.json"), None);

    // The session has it on, and a file run in it stops: still on.
    run_pasted(&mut prompt, &server, "set export com.heads.seedID");
    let (sent, shown) = run_pasted(&mut prompt, &server, "plain.api");
    assert_eq!(sent, ["GET /missing"], "{shown}");
    run_pasted(&mut prompt, &server, "GET /keyed > after-plain.json");
    assert_eq!(exported("after-plain.json"), Some("com.heads.seedID".to_string()));
    // And after a file with a line of its own.
    run_pasted(&mut prompt, &server, "own.api");
    run_pasted(&mut prompt, &server, "GET /keyed > after-both.json");
    assert_eq!(exported("after-both.json"), Some("com.heads.seedID".to_string()));
}

/// Without `-f` a block at the prompt runs on past a line that was answered
/// with an error status, as a batch does. What got no answer stops it.
#[cfg(unix)]
#[test]
fn a_block_at_the_prompt_runs_on_past_an_error_status() {
    use pty::Prompt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("failing.api"), "GET /boom\nGET /b\n").unwrap();
    let mut prompt = Prompt::open(api(server.port, dir.path()));
    prompt.wait_ready(Duration::from_secs(15));

    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /boom\rGET /denied\rGET /missing\rGET /b\r");
    assert_eq!(sent, ["GET /boom", "GET /denied", "GET /missing", "GET /b"], "{shown}");
    let (sent, shown) = run_pasted(&mut prompt, &server, "failing.api");
    assert_eq!(sent, ["GET /boom", "GET /b"], "{shown}");

    // A body file that isn't there is no request at all, and ends the block.
    let (sent, shown) = run_pasted(&mut prompt, &server, "PUT /a @nowhere.json\rGET /b\r");
    assert_eq!(sent, Vec::<String>::new(), "{shown}");
    // In a chain an error status is still no answer to go on from.
    let (sent, _) = run_pasted(&mut prompt, &server, "GET /boom || GET /never\rGET /b\r");
    assert_eq!(sent, ["GET /boom"]);
}

/// `-b` alone names a host the stored credential was not saved for: the
/// default connection's key is not sent there. With `-c` it is asked for.
#[test]
fn a_base_url_alone_is_not_sent_the_default_connections_credential() {
    let saved = RecordingServer::start();
    let other = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("local", format!("http://127.0.0.1:{}", saved.port), "key", "STOREDKEY", "")], "local");
    let elsewhere = format!("http://127.0.0.1:{}", other.port);

    let got = run_bare(&other, d, &["-b", &elsewhere, "GET", "/a"]);
    assert_eq!(got.sent, ["GET /a"], "{}", got.stderr);
    assert_eq!(authorization(&other), "-");
    assert_eq!(saved.seen(), 0);
    // Named, the connection lends its credential to the other host.
    let got = run_bare(&other, d, &["-c", "local", "-b", &elsewhere, "GET", "/a"]);
    assert_eq!(got.sent, ["GET /a"], "{}", got.stderr);
    assert_eq!(authorization(&other), "Basic OlNUT1JFREtFWQ==");
}

/// A `default` that names no saved connection is said to be that, where it
/// used to end in a bare "no base URL specified".
#[test]
fn a_default_that_names_no_connection_is_said() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    write_credentials(d, &[("local", url.clone(), "key", "k", ""), ("stage", url, "key", "k", "")], "locl");
    let got = run_bare(&server, d, &["GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{}", got.stderr);
    assert!(
        got.stderr.contains("the default connection \"locl\" is not among the saved connections (local, stage)"),
        "{}",
        got.stderr
    );
    // By name it still works.
    let got = run_bare(&server, d, &["-c", "stage", "GET", "/a"]);
    assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{}", got.stderr);
}

/// A key given with `-k` beside `-c` is the credential of the session: a 401
/// is the answer, and is not answered by exchanging the client secret the
/// connection has stored. Saving then stores the key, not the secret.
#[cfg(unix)]
#[test]
fn a_key_beside_an_oauth2_connection_is_not_renewed_with_the_stored_secret() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("o", url, "oauth2", "STOREDSECRET", "id")], "");
    let mut cmd = api_bare(d);
    cmd.args(["-c", "o", "-k", "CLIKEY"]);
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));
    // With `-c` the prompt is drawn while the connection is still being
    // loaded, and until that has ended it takes no key and no paste.
    prompt.wait_for("connected to: o", Duration::from_secs(15));

    // Not `run_pasted`, which empties the server's log and headers when it
    // returns: they are what is looked at here.
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    server.take();
    prompt.paste("GET /denied");
    prompt.pump(Duration::from_millis(80));
    let mark = prompt.screen.len();
    prompt.send(b"\r");
    let start = Instant::now();
    let mut quiet = 0;
    while (server.seen() == 0 || quiet < 3) && start.elapsed() < Duration::from_secs(6) {
        let before = server.seen();
        prompt.pump(Duration::from_millis(120));
        quiet = if server.seen() == before { quiet + 1 } else { 0 };
    }
    let shown = pty::plain(&prompt.screen[mark..]);
    let all = server.log.lock().unwrap().clone();
    let heads = server.heads();
    // One request, with the key, and no token asked for: not now and not
    // when the session started (the count is never reset).
    assert_eq!(all, ["GET /denied"], "{shown}");
    assert_eq!(server.tokens.load(Ordering::SeqCst), 0, "a token was asked for");
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert!(heads[0].contains("authorization=Basic "), "{heads:?}");

    save_as(&mut prompt, "mine", "saved");
    let (connections, _) = stored(d);
    assert!(connections.contains(&"mine=CLIKEY".to_string()), "{connections:?}");
    assert!(connections.contains(&"o=STOREDSECRET".to_string()), "{connections:?}");
}

/// The picker shows what the store holds. When the store can't be written, a
/// connection is not shown as deleted, nor as the default.
#[cfg(unix)]
#[test]
fn the_picker_says_when_the_store_could_not_be_changed() {
    use std::os::unix::fs::PermissionsExt;

    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("alpha", url.clone(), "key", "k1", ""), ("beta", url, "key", "k2", "")], "");
    let file = d.join(".api-credentials.json");
    let lock = |locked: bool| {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(if locked { 0o444 } else { 0o644 })).unwrap();
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(if locked { 0o555 } else { 0o755 })).unwrap();
    };
    lock(true);
    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_for("+ Add new connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));

    prompt.send(b"\t");
    prompt.pump(Duration::from_millis(400));
    let after_tab = selected_row(&prompt);
    keys_then(&mut prompt, "\x1b[3~", "Delete? y/n");
    let mark = prompt.screen.len();
    prompt.send(b"y");
    prompt.pump(Duration::from_millis(500));
    let shown = pty::plain(&prompt.screen[mark..]);
    let after_delete = selected_row(&prompt);
    lock(false);

    assert!(after_tab.contains("alpha") && !after_tab.contains('♥'), "{after_tab}");
    assert!(!shown.contains("alpha deleted"), "{shown}");
    assert!(shown.to_lowercase().contains("could not") || shown.contains("denied"), "{shown}");
    assert!(after_delete.contains("alpha"), "{after_delete}");
    assert_eq!(stored(d), (vec!["alpha=k1".to_string(), "beta=k2".to_string()], String::new()));
}

/// The rows of the screen that are rulers of the command area.
#[cfg(unix)]
fn ruler_rows(rows: &[String]) -> Vec<usize> {
    rows.iter().enumerate().filter(|(_, row)| row.starts_with("──")).map(|(at, _)| at).collect()
}

/// ctrl+x takes the body of the request the cursor is in and ctrl+space
/// changes its method. Neither touches an outfile, the other requests of a
/// chain or a line that is no request, and a body put aside by ctrl+space
/// does not come back on another line.
#[cfg(unix)]
#[test]
fn clearing_a_body_and_cycling_a_method_leave_the_rest_of_the_line() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api(server.port, dir.path()));
    prompt.wait_ready(Duration::from_secs(15));

    // The outfile stays. A PUT without a body asks for one, and sent with
    // none from there the request goes out and the file is written.
    press(&mut prompt, &["PUT /x {\"a\":1} > kept.json", "\x18"]);
    server.take();
    prompt.send(b"\r");
    prompt.wait_for("Enter body", Duration::from_secs(3));
    prompt.send(b"\x04");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    prompt.pump(Duration::from_millis(250));
    assert_eq!(server.log.lock().unwrap().clone(), ["PUT /x"]);
    assert!(dir.path().join("kept.json").is_file());
    // In a chain only the request the cursor is in loses its body.
    press(&mut prompt, &["GET /a && PUT /b {\"n\":1}", "\x18"]);
    prompt.pump(Duration::from_millis(100));
    let sent = entered(&mut prompt, &server);
    prompt.pump(Duration::from_millis(400));
    assert_eq!(server.log.lock().unwrap().clone(), ["GET /a", "PUT /b"], "{sent:?}");
    // A directive is no request with a body.
    let shown = press(&mut prompt, &["confirm Ready to deploy now?", "\x18", "\r"]);
    prompt.pump(Duration::from_millis(300));
    let shown = format!("{shown}{}", screen_tail(&prompt));
    assert!(shown.contains("Ready to deploy now? (Y/n)"), "{shown}");
    prompt.send(b"n");
    prompt.pump(Duration::from_millis(300));

    // ctrl+space on a chain and before an outfile.
    press(&mut prompt, &["GET /c && PUT /d {\"n\":1} > cycled.json", "\x00", "\x00"]);
    let sent = entered(&mut prompt, &server);
    prompt.pump(Duration::from_millis(400));
    assert_eq!(server.log.lock().unwrap().clone(), ["GET /c", "PUT /d {\"n\":1}"], "{sent:?}");
    assert!(dir.path().join("cycled.json").is_file());

    // A body put aside on one line is not the body of the next.
    press(&mut prompt, &["PUT /a {\"s\":1}", "\x00"]);
    press(&mut prompt, &["GET /b", "\x00"]);
    server.take();
    prompt.send(b"\r");
    prompt.pump(Duration::from_millis(800));
    // `PUT /b` has no body: the editor opens and nothing is sent.
    assert_eq!(server.take(), Vec::<String>::new(), "{}", screen_tail(&prompt));
    assert!(screen_tail(&prompt).contains("Enter body"), "{}", screen_tail(&prompt));
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(200));
}

/// The question whether to write over a saved connection stands in the hint
/// row, and both answers leave the command area where it was: two rulers,
/// and nothing of the dialog.
#[cfg(unix)]
#[test]
fn the_overwrite_question_keeps_the_command_area_in_place() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("a", url.clone(), "key", "k", ""), ("x", url.clone(), "key", "k", "")], "a");
    for (cols, answer, says) in [(100u16, "n", "cancelled"), (100, "y", "connection x saved"), (30, "n", "cancelled")] {
        write_credentials(d, &[("a", url.clone(), "key", "k", ""), ("x", url.clone(), "key", "k", "")], "a");
        let mut cmd = api_bare(d);
        cmd.args(["-c", "a"]);
        let mut prompt = pty::Prompt::open_with(cmd, cols, 40);
        prompt.wait_ready(Duration::from_secs(15));
        prompt.pump(Duration::from_millis(500));
        let before = ruler_rows(&pty::rows(&prompt.screen, cols as usize));
        assert_eq!(before.len(), 2, "{cols}:\n{}", pty::rows(&prompt.screen, cols as usize).join("\n"));

        prompt.send(b"\x13");
        prompt.wait_for("Save connection as", Duration::from_secs(5));
        prompt.pump(Duration::from_millis(150));
        prompt.send(&[0x7f; 8]);
        prompt.send(b"x\r");
        prompt.wait_for("already", Duration::from_secs(5));
        prompt.pump(Duration::from_millis(200));
        // The question is in the hint row, under the second ruler, on one row.
        let rows = pty::rows(&prompt.screen, cols as usize);
        let asked = rows.iter().position(|row| row.contains("already")).unwrap();
        assert_eq!(asked, before[1] + 1, "{cols}:\n{}", rows.join("\n"));
        assert!(rows[asked].contains("(Y/n)") && rows.len() == asked + 1, "{cols}:\n{}", rows.join("\n"));

        prompt.send(answer.as_bytes());
        prompt.pump(Duration::from_millis(700));
        let rows = pty::rows(&prompt.screen, cols as usize);
        assert_eq!(ruler_rows(&rows), before, "{cols} {answer}:\n{}", rows.join("\n"));
        assert!(!rows.iter().any(|row| row.contains("Save connection") || row.contains("already")), "{}", rows.join("\n"));
        if cols >= 60 {
            assert!(rows.last().unwrap().contains(says), "{cols} {answer}:\n{}", rows.join("\n"));
        }
    }
}

/// A window resized while the shortcuts are open keeps the output above
/// them: the redraw moves up over the rows the shortcuts take, no further.
#[cfg(unix)]
#[test]
fn a_resize_with_the_shortcuts_open_keeps_the_output() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open_with(api(server.port, dir.path()), 100, 60);
    prompt.wait_ready(Duration::from_secs(15));
    press(&mut prompt, &["GET /kept"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /kept"]);

    prompt.send(b"\x08");
    prompt.wait_for("Send request", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(200));
    let mark = prompt.screen.len();
    prompt.resize(90, 60);
    prompt.pump(Duration::from_millis(700));
    let rows = pty::rows(&prompt.screen[mark..], 90);
    assert!(rows.iter().any(|row| row.contains("/api/v1/kept")), "{}", rows.join("\n"));
    assert!(rows.iter().any(|row| row.contains("Send request")), "{}", rows.join("\n"));

    // Closed, the command area is right under the output.
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(500));
    let rows = pty::rows(&prompt.screen[mark..], 90);
    let rulers = ruler_rows(&rows);
    let answered = rows.iter().rposition(|row| row.contains("/api/v1/kept")).expect("the response is still there");
    assert_eq!(rulers.len(), 2, "{}", rows.join("\n"));
    assert!(rulers[0] > answered && rulers[0] <= answered + 3, "{}", rows.join("\n"));
    assert!(!rows.iter().any(|row| row.contains("Send request")), "{}", rows.join("\n"));
    assert_eq!(rows.len(), rulers[1] + 2, "{}", rows.join("\n"));
}

/// A `confirm` whose question is longer than the terminal is wide is cut to
/// the hint row and keeps its `(Y/n)`. Declined, nothing after it is sent.
#[cfg(unix)]
#[test]
fn a_long_confirm_at_the_prompt_stays_on_its_row() {
    const COLS: usize = 40;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open_sized(api(server.port, dir.path()), COLS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    std::fs::write(
        dir.path().join("gate.api"),
        "confirm Ready to deploy the whole catalogue to the production environment now\nGET /never\n",
    )
    .unwrap();

    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    prompt.paste("gate.api");
    prompt.pump(Duration::from_millis(80));
    server.take();
    prompt.send(b"\r");
    prompt.wait_for("(Y/n)", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(200));
    let rows = pty::rows(&prompt.screen, COLS);
    let rulers = ruler_rows(&rows);
    assert_eq!(rulers.len(), 2, "{}", rows.join("\n"));
    let asked = rows.last().unwrap();
    assert!(asked.contains("Ready to deploy") && asked.trim_end().ends_with("(Y/n)"), "{}", rows.join("\n"));
    assert_eq!(rows.len(), rulers[1] + 2, "{}", rows.join("\n"));
    assert!(rows.iter().all(|row| row.chars().count() <= COLS), "{}", rows.join("\n"));

    prompt.send(b"n");
    prompt.pump(Duration::from_millis(600));
    assert_eq!(server.take(), Vec::<String>::new());
    let rows = pty::rows(&prompt.screen, COLS);
    assert_eq!(ruler_rows(&rows).len(), 2, "{}", rows.join("\n"));
    assert!(rows.last().unwrap().contains("aborted"), "{}", rows.join("\n"));
    // The session is still there.
    press(&mut prompt, &["GET /after"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /after"]);
}

/// esc ends a `sleep` and a `sleep while` at the prompt, says so, and nothing
/// after it is sent. The session goes on.
#[cfg(unix)]
#[test]
fn esc_ends_a_wait_at_the_prompt_and_what_follows_it() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api(server.port, dir.path()));
    prompt.wait_ready(Duration::from_secs(15));

    for (block, polls, says) in [
        ("sleep 30\rGET /never\r", 0, "sleeping cancelled"),
        ("sleep 30 while GET /a\rGET /never\r", 1, "cancelled"),
    ] {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        prompt.paste(block);
        prompt.pump(Duration::from_millis(80));
        let mark = prompt.screen.len();
        prompt.send(b"\r");
        prompt.pump(Duration::from_millis(900));
        prompt.send(b"\x1b");
        let said = pump_until(&mut prompt, Duration::from_secs(4), |p| pty::plain(&p.screen[mark..]).contains(says));
        assert!(said, "{block:?}: {}", pty::plain(&prompt.screen[mark..]));
        prompt.pump(Duration::from_millis(400));
        let sent = server.take();
        assert_eq!(sent.len(), polls, "{block:?}: {sent:?}");
        assert!(!sent.iter().any(|line| line.contains("/never")), "{sent:?}");
    }
    press(&mut prompt, &["GET /after"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /after"]);
}

/// Without `-f` an error's body is what a `>` outfile gets: the file is
/// replaced with it. A `>>` target is left as it was, and the batch goes on.
/// (Under `-f` neither file is touched, which other tests pin too.)
#[test]
fn without_fail_fast_an_error_body_replaces_an_outfile_and_is_not_appended() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("out.json"), "[{\"kept\":1}]\n").unwrap();
    std::fs::write(d.join("log.json"), "[{\"kept\":1}]\n").unwrap();
    std::fs::write(d.join("case.api"), "GET /missing > out.json\nGET /boom >> log.json\nGET /after\n").unwrap();

    let got = run_in(&server, d, &["-sa", "case.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert_eq!(got.sent, ["GET /missing", "GET /boom", "GET /after"]);
    let json = |name: &str| serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(d.join(name)).unwrap()).unwrap();
    assert_eq!(json("out.json"), serde_json::json!({}));
    assert_eq!(std::fs::read_to_string(d.join("log.json")).unwrap(), "[{\"kept\":1}]\n");

    // Under `-f` neither file is touched, and the run stops at the first.
    std::fs::write(d.join("out.json"), "[{\"kept\":1}]\n").unwrap();
    let got = run_in(&server, d, &["-sfa", "case.api"]);
    assert_eq!((got.code, &got.sent[..]), (Some(1), &["GET /missing".to_string()][..]), "{}", got.stderr);
    assert_eq!(json("out.json"), serde_json::json!([{ "kept": 1 }]));
}

/// The command area as the screen has it now: the rows from its top ruler
/// to its hint. There is one top ruler and one bottom ruler on the screen,
/// and nothing under the hint.
#[cfg(unix)]
fn command_area(prompt: &pty::Prompt, cols: usize, what: &str) -> Vec<String> {
    let rows = pty::rows(&prompt.screen, cols);
    let rulers = ruler_rows(&rows);
    assert_eq!(rulers.len(), 2, "{what}: a ruler was left behind\n{}", rows.join("\n"));
    assert_eq!(rows.len(), rulers[1] + 2, "{what}:\n{}", rows.join("\n"));
    assert!(rows.iter().all(|row| row.chars().count() <= cols), "{what}:\n{}", rows.join("\n"));
    rows[rulers[0]..].to_vec()
}

/// A line of an input of several lines that is exactly as wide as the
/// terminal takes one row, on the input line and in the body editor: the
/// rows drawn are the rows the next redraw clears. It used to draw a blank
/// row under such a line and leave a ruler behind on every key.
#[cfg(unix)]
#[test]
fn a_line_as_wide_as_the_terminal_takes_one_row() {
    const COLS: usize = 40;
    const LEFT: &str = "\x1b[D";
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open_with(api(server.port, dir.path()), COLS as u16, 40);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));

    // A first line of 40 columns, and one of 39 with the cursor at its end.
    for (first, lefts) in [(format!("GET /{}", "a".repeat(35)), 2), (format!("GET /{}", "b".repeat(34)), 7)] {
        prompt.send(b"\x06\x15");
        prompt.pump(Duration::from_millis(100));
        prompt.paste(&format!("{first}\rGET /c"));
        prompt.pump(Duration::from_millis(300));
        for _ in 0..lefts {
            prompt.send(LEFT.as_bytes());
            prompt.pump(Duration::from_millis(120));
        }
        let area = command_area(&prompt, COLS, &first);
        assert_eq!(area.len(), 5, "{first}:\n{}", area.join("\n"));
        assert_eq!(area[1], first, "{}", area.join("\n"));
        assert_eq!(area[2], "GET /c", "{}", area.join("\n"));
    }

    // The body editor: a line of 40 columns that is not the last.
    prompt.send(b"\x06\x15");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"PUT /wide\r");
    prompt.wait_for("Enter body, ctrl+d when done", Duration::from_secs(5));
    let wide = format!("{{\"k\":\"{}\",", "x".repeat(32));
    assert_eq!(wide.len(), COLS);
    prompt.send(wide.as_bytes());
    prompt.pump(Duration::from_millis(150));
    for key in ["\r", "\"", "n", "\"", ":", "1", "}"] {
        prompt.send(key.as_bytes());
        prompt.pump(Duration::from_millis(120));
    }
    let area = command_area(&prompt, COLS, "body editor");
    // The ruler, the request, the editor's own line (two rows at this
    // width), the two lines of the body, the ruler and the hint.
    assert_eq!(area.len(), 8, "{}", area.join("\n"));
    assert_eq!((area[4].as_str(), area[5].as_str()), (wide.as_str(), "\"n\":1}"), "{}", area.join("\n"));
    server.take();
    prompt.send(b"\x04");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    assert_eq!(server.take(), [format!("PUT /wide {wide}\n\"n\":1}}")]);
}

/// One line taller than the terminal (a compact body pasted as one line) is
/// shown by the rows around the cursor: the command area never takes more
/// rows than the terminal has, so nothing scrolls and no copy of it is left
/// behind, and the cursor's row is shown wherever the cursor goes.
#[cfg(unix)]
#[test]
fn a_line_taller_than_the_terminal_is_shown_around_the_cursor() {
    const COLS: usize = 80;
    const ROWS: usize = 12;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open_with(api(server.port, dir.path()), COLS as u16, ROWS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));

    let members: Vec<String> = (0..150).map(|i| format!("\"key{i:03}\":{i}")).collect();
    let line = format!("PUT /tall {{{}}}", members.join(","));
    assert!(line.len() > COLS * ROWS, "{}", line.len());
    let shown = |prompt: &mut pty::Prompt, keys: &[&str], what: &str| -> Vec<String> {
        for key in keys {
            prompt.send(key.as_bytes());
            prompt.pump(Duration::from_millis(150));
        }
        let area = command_area(prompt, COLS, what);
        assert!(area.len() <= ROWS, "{what}: {} rows on {ROWS}\n{}", area.len(), area.join("\n"));
        area
    };

    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    prompt.paste(&line);
    prompt.pump(Duration::from_millis(400));
    // Pasted, the cursor is at the end: the last rows, under a marker.
    let area = shown(&mut prompt, &[], "pasted");
    assert_eq!(area[1], "⋯", "{}", area.join("\n"));
    assert!(area[2..area.len() - 2].concat().ends_with("\"key148\":148,\"key149\":149}"), "{}", area.join("\n"));
    assert!(!area.iter().any(|row| row.contains("PUT /tall")), "{}", area.join("\n"));
    // Every key redraws it in place.
    let area = shown(&mut prompt, &[LEFT, LEFT, LEFT, "x", "\x7f"], "edited at the end");
    assert!(area[2..area.len() - 2].concat().ends_with("\"key148\":148,\"key149\":149}"), "{}", area.join("\n"));
    // At the start: the first rows, over a marker.
    let area = shown(&mut prompt, &[HOME], "at the start");
    assert!(area[1].starts_with("PUT /tall {\"key000\":0,"), "{}", area.join("\n"));
    assert_eq!(area[area.len() - 3], "⋯", "{}", area.join("\n"));
    assert!(!area.iter().any(|row| row.contains("key149")), "{}", area.join("\n"));
    // In the middle: a marker on both sides.
    let rights: Vec<&str> = std::iter::repeat("\x1b[C").take(COLS * 6).collect();
    prompt.send(rights.concat().as_bytes());
    prompt.pump(Duration::from_millis(1500));
    let area = shown(&mut prompt, &["\x1b[C"], "in the middle");
    assert_eq!((area[1].as_str(), area[area.len() - 3].as_str()), ("⋯", "⋯"), "{}", area.join("\n"));
    // It is sent whole.
    prompt.send(END.as_bytes());
    prompt.pump(Duration::from_millis(150));
    assert_eq!(entered(&mut prompt, &server), [line]);
    // The answer stands right over the command area: room is made for the
    // rows the line is shown on, not for every row it would take whole.
    prompt.pump(Duration::from_millis(400));
    let rows = pty::rows(&prompt.screen, COLS);
    let rulers = ruler_rows(&rows);
    let top = rulers[rulers.len() - 2];
    let answer = rows[..top].iter().rposition(|row| !row.trim().is_empty()).expect("an answer");
    assert!(rows[..=answer].iter().any(|row| row.contains("HTTP/1.1 200")), "{}", rows.join("\n"));
    assert_eq!(top - answer, 2, "the answer ends on row {answer}, the ruler is on row {top}\n{}", rows.join("\n"));
}

/// In a block of several lines the hint line belongs to the next request
/// within the moment, so what a request has to say about its data is also
/// a note under its status line, where it stays. One request alone says it
/// in the hint line, once.
#[cfg(unix)]
#[test]
fn a_warning_about_the_data_stays_under_its_request_in_a_block() {
    const MASKED: &str = "↳ warning: response had masked data, left out at secret";
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &["--export", "a.b.c"]);

    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /keyed > k1.json\rGET /a > k2.json\rGET /notutf8\rGET /b");
    assert_eq!(sent, ["GET /keyed", "GET /a", "GET /notutf8", "GET /b"]);
    assert_eq!(shown.matches(MASKED).count(), 1, "{shown}");
    assert_eq!(shown.matches("↳ response had bytes that are not valid").count(), 1, "{shown}");
    // Each under the status line of the request it is about.
    let rows = pty::rows(&prompt.screen, 200);
    let under = |request: &str| {
        let at = rows.iter().position(|row| row.trim_end() == request).unwrap_or_else(|| panic!("{request}\n{}", rows.join("\n")));
        let status = (at..rows.len()).find(|&row| rows[row].contains("HTTP/1.1 200")).expect("a status line");
        rows[status + 1..].iter().find(|row| row.starts_with('↳') || row.trim().is_empty()).cloned().unwrap_or_default()
    };
    assert_eq!(under("GET /keyed > k1.json").trim_end(), MASKED, "{}", rows.join("\n"));
    assert!(under("GET /notutf8").starts_with("↳ response had bytes"), "{}", rows.join("\n"));
    assert_eq!(under("GET /a > k2.json").trim(), "", "{}", rows.join("\n"));

    // In a chain too, which is a program of one line.
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /keyed > k3.json && GET /a");
    assert_eq!(sent, ["GET /keyed", "GET /a"]);
    assert_eq!(shown.matches(MASKED).count(), 1, "{shown}");
    // One request alone: the hint line, and no note.
    let (_, shown) = run_pasted(&mut prompt, &server, "GET /keyed > k4.json");
    assert!(shown.contains("warning: response had masked data") && !shown.contains('↳'), "{shown}");
}

/// ctrl+y always answers: with what it copied, or with why it copied
/// nothing. Before any request there is none, and a glob body is no one
/// command.
#[cfg(unix)]
#[test]
fn ctrl_y_says_why_it_copied_nothing() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.json"), "{}").unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);

    let mark = prompt.screen.len();
    prompt.send(b"\x19");
    let said = pump_until(&mut prompt, Duration::from_secs(4), |p| pty::plain(&p.screen[mark..]).contains("no request to copy yet"));
    assert!(said, "{}", pty::plain(&prompt.screen[mark..]));

    let (sent, _) = run_pasted(&mut prompt, &server, "PUT /x @*.json");
    assert_eq!(sent, ["PUT /x [{}]"]);
    let mark = prompt.screen.len();
    prompt.send(b"\x19");
    let said = pump_until(&mut prompt, Duration::from_secs(4), |p| {
        pty::plain(&p.screen[mark..]).contains("a glob body can't be written as a curl command")
    });
    assert!(said, "{}", pty::plain(&prompt.screen[mark..]));
    // The command area is as it was: two rulers, the hint under the second.
    let rows = pty::rows(&prompt.screen, 200);
    assert_eq!(ruler_rows(&rows).len(), 2, "{}", rows.join("\n"));
}

/// More saved connections than the terminal has rows: the picker shows the
/// ones that fit, moved along with the selection, with a `⋯` where the list
/// goes on. It is drawn in place whatever is selected, searched or deleted.
#[cfg(unix)]
#[test]
fn the_connection_picker_keeps_to_a_short_terminal() {
    const COLS: usize = 80;
    const ROWS: usize = 12;
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let names: Vec<String> = (1..=30).map(|n| format!("c{n:02}")).collect();
    let connections: Vec<(&str, String, &str, &str, &str)> =
        names.iter().map(|name| (name.as_str(), url.clone(), "key", "k", "")).collect();
    write_credentials(d, &connections, "");

    // The picker's rows, from its top ruler to its hint.
    let picker = |prompt: &pty::Prompt, what: &str| -> Vec<String> {
        let rows = pty::rows(&prompt.screen, COLS);
        let shown = rows.join("\n");
        let rulers = ruler_rows(&rows);
        assert_eq!(rulers.len(), 2, "{what}: a ruler was left behind\n{shown}");
        assert_eq!(rows.len(), rulers[1] + 2, "{what}:\n{shown}");
        let picker = rows[rulers[0]..].to_vec();
        assert!(picker.len() < ROWS, "{what}: {} rows on {ROWS}\n{shown}", picker.len());
        assert_eq!(picker.iter().filter(|row| row.starts_with("  › ")).count(), 1, "{what}: one row is selected\n{shown}");
        picker
    };
    let names_of = |picker: &[String]| -> Vec<String> {
        picker[1..].iter().take_while(|row| !row.starts_with("    ──")).map(|row| row.split_whitespace().take(2).collect::<Vec<_>>().join(" ")).collect()
    };

    let mut prompt = pty::Prompt::open_with(api_bare(d), COLS as u16, ROWS as u16);
    prompt.wait_for("+ Add new connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));
    let shown = picker(&prompt, "opened");
    assert_eq!(names_of(&shown), ["› c01", "c02 http://127.0.0.1", "c03 http://127.0.0.1", "c04 http://127.0.0.1", "c05 http://127.0.0.1", "⋯"].map(|row| row.replace("http://127.0.0.1", &url)));

    // Down the list: the selected one stays in view, between two markers.
    for _ in 0..10 {
        prompt.send(b"\x1b[B");
        prompt.pump(Duration::from_millis(120));
    }
    let shown = picker(&prompt, "ten down");
    let listed = names_of(&shown);
    assert_eq!((listed[0].as_str(), listed[5].as_str()), ("⋯", "⋯"), "{}", shown.join("\n"));
    assert!(listed.iter().any(|row| row == "› c11"), "{}", shown.join("\n"));
    // To the row under the list: the end of the list is over it.
    for _ in 0..25 {
        prompt.send(b"\x1b[B");
        prompt.pump(Duration::from_millis(80));
    }
    let shown = picker(&prompt, "at the end");
    let listed = names_of(&shown);
    assert_eq!(listed[0], "⋯", "{}", shown.join("\n"));
    assert!(listed[5].starts_with("c30 "), "{}", shown.join("\n"));
    assert!(shown.iter().any(|row| row == "  › + Add new connection"), "{}", shown.join("\n"));
    // And back up to the first.
    for _ in 0..35 {
        prompt.send(b"\x1b[A");
        prompt.pump(Duration::from_millis(80));
    }
    let shown = picker(&prompt, "back up");
    assert_eq!((names_of(&shown)[0].as_str(), names_of(&shown)[5].as_str()), ("› c01", "⋯"), "{}", shown.join("\n"));

    // A search that leaves more than fit is cut the same way; one that
    // leaves few is shown whole.
    prompt.send(b"c2");
    prompt.pump(Duration::from_millis(300));
    let shown = picker(&prompt, "searched c2");
    assert_eq!(names_of(&shown)[5], "⋯", "{}", shown.join("\n"));
    assert!(shown.iter().any(|row| row.trim() == "search: c2"), "{}", shown.join("\n"));
    prompt.send(b"7");
    prompt.pump(Duration::from_millis(300));
    let shown = picker(&prompt, "searched c27");
    assert_eq!(names_of(&shown), ["› c27"], "{}", shown.join("\n"));

    // A taller window shows more of them, a shorter one fewer.
    prompt.send(b"\x7f\x7f\x7f");
    prompt.pump(Duration::from_millis(300));
    prompt.resize(COLS as u16, 20);
    prompt.pump(Duration::from_millis(600));
    let rows = pty::rows(&prompt.screen, COLS);
    let rulers = ruler_rows(&rows);
    let top = rulers[rulers.len() - 2];
    let listed = rows[top + 1..].iter().take_while(|row| !row.starts_with("    ──")).count();
    assert_eq!(listed, 14, "{}", rows[top..].join("\n"));
    assert_eq!(rows.len() - top, 19, "{}", rows[top..].join("\n"));

    // The one that is selected is the one Enter connects to.
    prompt.send(b"c07");
    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\r");
    prompt.wait_ready(Duration::from_secs(15));
    press(&mut prompt, &["GET /through-c07"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /through-c07"]);
}

/// Under `-f` at the prompt a chain is judged as in a batch: its last
/// request is a plain request and stops the block, and a "no" that was
/// asked for (a segment with another after it) does not.
#[cfg(unix)]
#[test]
fn fail_fast_at_the_prompt_stops_at_the_last_request_of_a_chain() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &["-f"]);

    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /a && GET /missing\rGET /never");
    assert_eq!(sent, ["GET /a", "GET /missing"], "{shown}");
    assert!(shown.contains("stopped at 404 (--fail-fast)"), "{shown}");

    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /missing || GET /b\rGET /c");
    assert_eq!(sent, ["GET /missing", "GET /b", "GET /c"], "{shown}");
    assert!(!shown.contains("stopped at"), "{shown}");

    // The session is as it was.
    press(&mut prompt, &["GET /after"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /after"]);
}

/// esc and ctrl+c end the request of an `assert` and the poll of a `sleep
/// while` as they end any request: the block stops there with no verdict,
/// and the next line typed is a plain request again, logged with its body
/// and without the check's prefix.
#[cfg(unix)]
#[test]
fn a_check_that_is_aborted_at_the_prompt_stops_the_block_and_leaves_no_trace() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);

    for (block, key) in [
        ("assert GET /stall\rGET /never", "\x1b"),
        ("assert GET /stall\rGET /never", "\x03"),
        ("sleep 1 while GET /stall\rGET /never", "\x1b"),
        ("sleep 1 while not GET /stall\rGET /never", "\x03"),
    ] {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        prompt.paste(block);
        prompt.pump(Duration::from_millis(80));
        let mark = prompt.screen.len();
        prompt.send(b"\r");
        assert!(pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0), "{block:?} was not sent");
        prompt.pump(Duration::from_millis(300));
        prompt.send(key.as_bytes());
        let said = pump_until(&mut prompt, Duration::from_secs(4), |p| {
            let shown = pty::plain(&p.screen[mark..]);
            shown.contains("request aborted") || shown.contains("cancelled")
        });
        let shown = pty::plain(&prompt.screen[mark..]);
        assert!(said, "{block:?} {key:?}: {shown}");
        prompt.pump(Duration::from_millis(400));
        let shown = pty::plain(&prompt.screen[mark..]);
        assert!(!shown.contains("assertion failed") && !shown.contains("could not be evaluated"), "{block:?} {key:?}: {shown}");
        assert_eq!(server.take(), ["GET /stall"], "{block:?} {key:?}");

        // What follows is a request like any other.
        let (sent, shown) = run_pasted(&mut prompt, &server, "GET /plain");
        assert_eq!(sent, ["GET /plain"], "{block:?} {key:?}");
        assert!(shown.contains("\"ok\": \"/api/v1/plain\""), "{block:?} {key:?}: the body is shown\n{shown}");
        assert!(!shown.contains("assert GET /plain") && !shown.contains("sleep"), "{block:?} {key:?}: {shown}");
    }
}

/// A server that is gone in the middle of a session: the request says so,
/// a block stops at it, and the session stays.
#[cfg(unix)]
#[test]
fn a_server_that_went_away_stops_a_block_at_the_prompt() {
    let server = RecordingServer::start();
    let port = server.port;
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    let (sent, _) = run_pasted(&mut prompt, &server, "GET /a");
    assert_eq!(sent, ["GET /a"]);
    drop(server);

    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    prompt.paste("GET /b\rGET /c\rGET /d");
    prompt.pump(Duration::from_millis(80));
    let mark = prompt.screen.len();
    prompt.send(b"\r");
    let asked = format!("Is COS running on 127.0.0.1:{port}?");
    let said = pump_until(&mut prompt, Duration::from_secs(8), |p| pty::plain(&p.screen[mark..]).contains(&asked));
    prompt.pump(Duration::from_millis(800));
    let shown = pty::plain(&prompt.screen[mark..]);
    assert!(said, "{shown}");
    // Once: the lines behind it were not tried.
    let rows = pty::rows(&prompt.screen, 200);
    assert_eq!(rows.iter().filter(|row| row.contains(&asked)).count(), 1, "{}", rows.join("\n"));
    assert!(!shown.contains("panicked"), "{shown}");
    assert_eq!(ruler_rows(&rows).len(), 2, "{}", rows.join("\n"));
}

/// ctrl+s in a session that runs on OAuth2 client credentials saves the
/// client's id and secret, not the token they were exchanged for: a saved
/// token would work until it ran out, and then never again.
#[cfg(unix)]
#[test]
fn saving_an_oauth2_session_saves_the_client_and_not_its_token() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("o", format!("http://127.0.0.1:{}", server.port), "oauth2", "s3cret", "client-7")], "o");
    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));

    save_as(&mut prompt, "copy", "connection copy saved");
    let text = std::fs::read_to_string(d.join(".api-credentials.json")).unwrap();
    let data: serde_json::Value = serde_json::from_str(&text).unwrap();
    let saved: Vec<(&str, &str, &str, &str)> = data["connections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["name"].as_str().unwrap(), c["auth_type"].as_str().unwrap(), c["credential"].as_str().unwrap(), c["client_id"].as_str().unwrap()))
        .collect();
    assert!(saved.contains(&("copy", "oauth2", "s3cret", "client-7")), "{text}");
    assert!(!text.contains("stale") && !text.contains("fresh"), "a token was saved: {text}");
}

/// Deleting the connection that is the default leaves no default: the next
/// start does not name a connection that is gone.
#[cfg(unix)]
#[test]
fn deleting_the_default_connection_leaves_no_default() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("alpha", url.clone(), "key", "k1", ""), ("beta", url.clone(), "key", "k2", "")], "");
    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_for("+ Add new connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));

    // beta is made the default, then deleted.
    prompt.send(b"\x1b[B\t");
    prompt.pump(Duration::from_millis(300));
    assert_eq!(stored(d).1, "beta");
    keys_then(&mut prompt, "\x1b[3~", "Delete? y/n");
    keys_then(&mut prompt, "y", "beta deleted");
    assert_eq!(stored(d), (vec!["alpha=k1".to_string()], String::new()));
    drop(prompt);

    // A batch has no default to run on, and no warning about one that is gone.
    let got = run_bare(&server, d, &["GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{}", got.stderr);
    assert!(got.stderr.contains("no base URL specified") && !got.stderr.contains("WARNING"), "{}", got.stderr);
}

/// The last row of the screen that holds `text`.
#[cfg(unix)]
fn row_with(prompt: &pty::Prompt, cols: usize, text: &str) -> String {
    let rows = pty::rows(&prompt.screen, cols);
    rows.iter().rev().find(|row| row.contains(text)).cloned().unwrap_or_else(|| panic!("{text:?}:\n{}", rows.join("\n")))
}

/// A paste into the connection picker or the form for a new connection
/// fills the field that is active with its first line, as it does in the
/// other dialogs. The form a session starts with takes a paste too: it
/// switches bracketed paste on, so a pasted line break is not an Enter.
#[cfg(unix)]
#[test]
fn a_paste_fills_the_field_of_the_connection_dialog() {
    let server = RecordingServer::start();
    let host = format!("127.0.0.1:{}", server.port);
    let url = format!("http://{host}");

    // The form at startup: URL and key.
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    prompt.wait_for("Type the API base URL", Duration::from_secs(15));
    assert!(prompt.screen.contains("\x1b[?2004h"), "bracketed paste is not on in the startup form");
    prompt.pump(Duration::from_millis(300));
    prompt.paste(&format!("  {host}\rGET /second-line\r"));
    prompt.pump(Duration::from_millis(300));
    assert_eq!(row_with(&prompt, 200, "URL:"), format!("  › {:<14}{host}", "URL:"));
    keys_then(&mut prompt, "\r", "Use ← → to choose auth method");
    // The method is chosen, not typed: a paste there is nothing.
    prompt.paste("x\r");
    prompt.pump(Duration::from_millis(200));
    keys_then(&mut prompt, "\r", "Type your API key");
    prompt.paste("k9\rmore\r");
    prompt.pump(Duration::from_millis(300));
    assert_eq!(row_with(&prompt, 200, "API key:"), format!("  › {:<14}••", "API key:"));
    keys_then(&mut prompt, "\r", "ctrl+s to save this connection");
    prompt.pump(Duration::from_millis(400));
    press(&mut prompt, &["GET /pasted-key"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /pasted-key"]);
    assert!(server.heads()[0].contains("authorization=Basic Oms5;"), "{:?}", server.heads());
    drop(prompt);

    // A token, and a client with its secret.
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    prompt.wait_for("Type the API base URL", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(300));
    prompt.paste(&url);
    keys_then(&mut prompt, "\r", "Use ← → to choose auth method");
    keys_then(&mut prompt, "\x1b[C\r", "Type your bearer token");
    prompt.paste("tok\r");
    prompt.pump(Duration::from_millis(300));
    keys_then(&mut prompt, "\r", "ctrl+s to save this connection");
    prompt.pump(Duration::from_millis(400));
    press(&mut prompt, &["GET /pasted-token"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /pasted-token"]);
    assert!(server.heads()[0].contains("authorization=Bearer tok;"), "{:?}", server.heads());
    drop(prompt);

    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    prompt.wait_for("Type the API base URL", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(300));
    prompt.paste(&url);
    keys_then(&mut prompt, "\r", "Use ← → to choose auth method");
    keys_then(&mut prompt, "\x1b[D\r", "Type your OAuth2 client ID");
    prompt.paste("client-1\r");
    prompt.pump(Duration::from_millis(300));
    assert_eq!(row_with(&prompt, 200, "Client ID:"), format!("  › {:<14}client-1", "Client ID:"));
    keys_then(&mut prompt, "\r", "Type your client secret");
    prompt.paste("s3cret\r");
    prompt.pump(Duration::from_millis(300));
    assert_eq!(row_with(&prompt, 200, "Secret:"), format!("  › {:<14}••••••", "Secret:"));
    keys_then(&mut prompt, "\r", "ctrl+s to save this connection");
    drop(prompt);

    // The picker of a running session: the paste is what is searched for.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(
        d,
        &[("alpha", url.clone(), "key", "k1", ""), ("zeta", url.clone(), "key", "k4", "")],
        "alpha",
    );
    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    keys_then(&mut prompt, "\x11", "+ Add new connection");
    prompt.paste("zet\ralpha\r");
    prompt.pump(Duration::from_millis(300));
    assert_eq!(row_with(&prompt, 200, "search:"), "    search: zet");
    assert!(selected_row(&prompt).contains("zeta"), "{}", selected_row(&prompt));
    keys_then(&mut prompt, "\r", "connected to: zeta");
}

/// A saved connection whose name starts with `+` is a connection like any
/// other: listed above the line that adds one, found by a search, connected
/// to and deleted. Its name used to make it the line that adds one.
#[cfg(unix)]
#[test]
fn a_connection_named_with_a_plus_is_one_of_the_list() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("beta", url.clone(), "key", "k2", ""), ("+plus", url.clone(), "key", "k1", "")], "");
    let open = |d: &Path| {
        let mut prompt = pty::Prompt::open(api_bare(d));
        prompt.wait_for("+ Add new connection", Duration::from_secs(15));
        prompt.pump(Duration::from_millis(400));
        prompt
    };
    // The picker as the screen has it: from its top ruler to its hint.
    let picker = |prompt: &pty::Prompt, what: &str| -> Vec<String> {
        let rows = pty::rows(&prompt.screen, 200);
        let rulers = ruler_rows(&rows);
        assert_eq!(rulers.len(), 2, "{what}: a ruler was left behind\n{}", rows.join("\n"));
        assert_eq!(rows.len(), rulers[1] + 2, "{what}:\n{}", rows.join("\n"));
        rows[rulers[0]..].iter().map(|row| row.trim().to_string()).collect()
    };

    let mut prompt = open(d);
    let shown = picker(&prompt, "opened");
    assert!(shown[0].contains("Choose a connection"), "{shown:#?}");
    assert_eq!(
        shown[1..5],
        [format!("› beta      {url}"), format!("+plus     {url}"), "─".repeat(10 + url.len()), "+ Add new connection".to_string()],
        "{shown:#?}"
    );
    // Down goes through it to the line that adds one, and every redraw is in place.
    prompt.send(b"\x1b[B");
    prompt.pump(Duration::from_millis(200));
    assert!(picker(&prompt, "down").iter().any(|row| row.starts_with("› +plus")));
    prompt.send(b"\x1b[B");
    prompt.pump(Duration::from_millis(200));
    assert!(picker(&prompt, "down twice").iter().any(|row| row == "› + Add new connection"));
    // A search finds it.
    prompt.send(b"pl");
    prompt.pump(Duration::from_millis(300));
    let shown = picker(&prompt, "searched");
    assert_eq!(shown[1..4], [format!("› +plus     {url}"), "─".repeat(10 + url.len()), "search: pl".to_string()], "{shown:#?}");
    // It is connected to.
    keys_then(&mut prompt, "\r", "connected to: +plus");
    prompt.pump(Duration::from_millis(400));
    press(&mut prompt, &["GET /plus"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /plus"]);
    assert!(server.heads()[0].contains("authorization=Basic Omsx;"), "{:?}", server.heads());
    drop(prompt);

    // And deleted.
    let mut prompt = open(d);
    prompt.send(b"\x1b[B");
    prompt.pump(Duration::from_millis(200));
    keys_then(&mut prompt, "\x1b[3~", "Delete? y/n");
    keys_then(&mut prompt, "y", "+plus deleted");
    assert_eq!(stored(d).0, ["beta=k2"]);
    prompt.pump(Duration::from_millis(200));
    let shown = picker(&prompt, "deleted");
    assert_eq!(shown[1..4], [format!("› beta     {url}"), "─".repeat(9 + url.len()), "+ Add new connection".to_string()], "{shown:#?}");
}

/// The picker keeps to the terminal's width: a connection with a long URL
/// is one row, cut, and so is the line under the list. Every redraw is in
/// place. A row that wrapped left a ruler behind on every key.
#[cfg(unix)]
#[test]
fn the_connection_picker_keeps_to_a_narrow_terminal() {
    const COLS: usize = 40;
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}/a/long/path/under/the/host/that/goes/on", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(
        d,
        &[("first", url.clone(), "key", "k", ""), ("second-with-a-long-name", url.clone(), "key", "k", "")],
        "",
    );
    let picker = |prompt: &pty::Prompt, cols: usize, from: usize, what: &str| -> Vec<String> {
        let rows = pty::rows(&prompt.screen[from..], cols);
        let shown = rows.join("\n");
        let rulers = ruler_rows(&rows);
        assert_eq!(rulers.len(), 2, "{what}: a ruler was left behind\n{shown}");
        assert_eq!(rows.len(), rulers[1] + 2, "{what}:\n{shown}");
        assert!(rows.iter().all(|row| row.chars().count() <= cols), "{what}:\n{shown}");
        rows[rulers[0]..].to_vec()
    };

    let mut prompt = pty::Prompt::open_sized(api_bare(d), COLS as u16);
    prompt.wait_for("+ Add new connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));
    let shown = picker(&prompt, COLS, 0, "opened");
    assert_eq!(shown.len(), 7, "{}", shown.join("\n"));
    assert!(shown[1].starts_with("  › first") && shown[1].ends_with('…'), "{}", shown.join("\n"));
    assert!(shown[2].starts_with("    second-with-a-long-name") && shown[2].ends_with('…'), "{}", shown.join("\n"));
    assert_eq!(shown[3], format!("    {}", "─".repeat(COLS - 4)), "{}", shown.join("\n"));
    assert_eq!(shown[4], "    + Add new connection");
    assert!(shown[6].starts_with("  type to search") && shown[6].ends_with('…'), "{}", shown.join("\n"));

    // Moving, searching, asking before a delete: all in place.
    for (keys, what) in [("\x1b[B", "down"), ("\x1b[A", "up"), ("sec", "searched"), ("\x7f\x7f\x7f", "search cleared"), ("\x1b[3~", "delete?"), ("n", "kept")] {
        prompt.send(keys.as_bytes());
        prompt.pump(Duration::from_millis(300));
        let shown = picker(&prompt, COLS, 0, what);
        match what {
            "searched" => assert_eq!(shown[3], "    search: sec", "{}", shown.join("\n")),
            "delete?" => assert!(shown[1].starts_with("  › first") && shown[1].contains("Delete? y/n"), "{}", shown.join("\n")),
            _ => assert_eq!(shown.len(), 7, "{what}:\n{}", shown.join("\n")),
        }
    }
    // A connection that is being tried, and one that failed: its row has a
    // spinner behind it, and the reason is under the ruler.
    let down = "http://127.0.0.1:1/a/long/path/under/the/host/that/goes/on".to_string();
    write_credentials(d, &[("first", down, "key", "k", ""), ("second-with-a-long-name", url.clone(), "key", "k", "")], "");
    drop(prompt);
    let mut prompt = pty::Prompt::open_sized(api_bare(d), COLS as u16);
    prompt.wait_for("+ Add new connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));
    keys_then(&mut prompt, "\r", "first: connection failed");
    prompt.pump(Duration::from_millis(200));
    let shown = picker(&prompt, COLS, 0, "failed");
    assert_eq!(shown[6], "  first: connection failed", "{}", shown.join("\n"));

    // A window made narrower, and wider again, with the picker open: it is
    // drawn anew at that width, and stays in place from there.
    prompt.pump(Duration::from_millis(3200));
    for cols in [30usize, 28, 100] {
        let mark = prompt.screen.len();
        prompt.resize(cols as u16, 50);
        prompt.pump(Duration::from_millis(700));
        let shown = picker(&prompt, cols, mark, &format!("resized to {cols}"));
        assert_eq!(shown.len(), 7, "{cols}:\n{}", shown.join("\n"));
        prompt.send(b"\x1b[B");
        prompt.pump(Duration::from_millis(250));
        prompt.send(b"\x1b[A");
        prompt.pump(Duration::from_millis(250));
        let shown = picker(&prompt, cols, mark, &format!("moved at {cols}"));
        assert!(shown[1].starts_with("  › first"), "{cols}:\n{}", shown.join("\n"));
        if cols == 100 {
            assert!(shown[2].ends_with(&url), "{}", shown.join("\n"));
        }
    }
    drop(prompt);

    // The same in the picker of a running session, and the session has the
    // new width when the picker is left.
    let mut cmd = api_bare(d);
    cmd.args(["-c", "second-with-a-long-name"]);
    let mut prompt = pty::Prompt::open_sized(cmd, 60);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    keys_then(&mut prompt, "\x11", "+ Add new connection");
    let mark = prompt.screen.len();
    prompt.resize(COLS as u16, 50);
    prompt.pump(Duration::from_millis(700));
    let shown = picker(&prompt, COLS, mark, "resized in a session");
    assert_eq!(shown.len(), 7, "{}", shown.join("\n"));
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(600));
    // The session clears the screen and draws itself at the new width.
    let mark = prompt.screen.rfind("\x1b[2J").unwrap();
    assert!(mark > prompt.screen.rfind("Choose a connection").unwrap(), "the session did not draw itself again");
    let shown = picker(&prompt, COLS, mark, "back in the session");
    assert_eq!(shown.len(), 4, "{}", shown.join("\n"));
    assert_eq!(shown[2], "─".repeat(COLS), "{}", shown.join("\n"));
    // A line longer than the window is now wide takes two rows.
    let line = format!("GET /after-resize/{}", "x".repeat(30));
    press(&mut prompt, &[&line]);
    let shown = picker(&prompt, COLS, mark, "a long line in the session");
    assert_eq!(shown.len(), 5, "{}", shown.join("\n"));
    assert_eq!(format!("{}{}", shown[1], shown[2]), line, "{}", shown.join("\n"));
    let sent = entered(&mut prompt, &server);
    assert!(sent.len() == 1 && sent[0].ends_with(&line[4..]), "{sent:?}");
}

/// The URL field of the form for a new connection. Tab writes what the
/// ghost shows and nothing where there is none, a scheme is one in any
/// case, a URL that names no host is not confirmed, and Esc from the method
/// comes back to the URL as it was confirmed, its scheme included.
#[cfg(unix)]
#[test]
fn the_url_field_completes_confirms_and_keeps_what_it_shows() {
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    prompt.wait_for("Type the API base URL", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(300));
    let field = |prompt: &pty::Prompt| row_with(prompt, 200, "URL:").split_once("URL:").unwrap().1.trim().to_string();
    let typed = |prompt: &mut pty::Prompt, keys: &str| -> String {
        prompt.send(&[0x7f; 40]);
        prompt.pump(Duration::from_millis(150));
        prompt.send(keys.as_bytes());
        prompt.pump(Duration::from_millis(300));
        row_with(prompt, 200, "URL:").split_once("URL:").unwrap().1.trim().to_string()
    };

    // An address has no ghost, and Tab adds nothing to it.
    assert_eq!(typed(&mut prompt, "10.0.0.5"), "10.0.0.5");
    assert_eq!(typed(&mut prompt, "10.0.0.5\t"), "10.0.0.5");
    // A name has one, and Tab writes it.
    assert_eq!(typed(&mut prompt, "acme"), "acme.app.heads.com");
    assert_eq!(typed(&mut prompt, "acme\t\t"), "acme.app.heads.com");
    assert_eq!(typed(&mut prompt, "acme.app.h\tX"), "acme.app.heads.comX");
    assert_eq!(typed(&mut prompt, "loc\tX"), "localhost:5000X");
    // A URL with a scheme is whole, however the scheme is written.
    for url in ["https://host", "HTTPS://host", "Http://host"] {
        assert_eq!(typed(&mut prompt, url), url);
        assert_eq!(typed(&mut prompt, &format!("{url}\t")), url);
    }

    // What names no host is not a URL: Enter stays in the field.
    for none in ["http://", "HTTPS://", "/", "   ", "http:///api/v1"] {
        typed(&mut prompt, none);
        let mark = prompt.screen.len();
        prompt.send(b"\r");
        prompt.pump(Duration::from_millis(400));
        let shown = pty::plain(&prompt.screen[mark..]);
        assert!(!shown.contains("choose auth method"), "{none:?}: {shown}");
        assert!(row_with(&prompt, 200, "URL:").starts_with("  › "), "{none:?}");
    }

    // Confirmed, the URL has its scheme, and keeps it over Esc and Enter.
    for (typed_url, confirmed) in [
        ("https://127.0.0.1:18731", "https://127.0.0.1:18731"),
        ("http://example.invalid", "http://example.invalid"),
        ("example.invalid", "https://example.invalid"),
        ("127.0.0.1:18731", "http://127.0.0.1:18731"),
    ] {
        typed(&mut prompt, typed_url);
        keys_then(&mut prompt, "\r", "Use ← → to choose auth method");
        prompt.pump(Duration::from_millis(200));
        assert_eq!(field(&prompt), format!("{confirmed} ✓"), "{typed_url}");
        keys_then(&mut prompt, "\x1b", "Type the API base URL");
        prompt.pump(Duration::from_millis(200));
        assert_eq!(field(&prompt), confirmed, "{typed_url}, back from the method");
        keys_then(&mut prompt, "\r", "Use ← → to choose auth method");
        prompt.pump(Duration::from_millis(200));
        assert_eq!(field(&prompt), format!("{confirmed} ✓"), "{typed_url}, confirmed again");
        keys_then(&mut prompt, "\x1b", "Type the API base URL");
    }
}

/// `-b` with nothing in it (an empty variable, `-b http://`) names no host.
/// At the prompt it is as no `-b`: the session opens on the default
/// connection, or on the form at its URL field. It used to open the form at
/// the method, with an empty URL. With a request it is still an error:
/// what was meant for a host that was not named is not sent to another.
#[cfg(unix)]
#[test]
fn an_empty_base_url_is_no_base_url() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);

    for empty in ["", "http://", " / "] {
        // Nothing saved: the form, at the URL.
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = api_bare(dir.path());
        cmd.args(["-b", empty]);
        let mut prompt = pty::Prompt::open(cmd);
        prompt.wait_for("New connection", Duration::from_secs(15));
        prompt.pump(Duration::from_millis(500));
        let shown = pty::plain(&prompt.screen);
        assert!(shown.contains("Type the API base URL") && !shown.contains("choose auth method"), "{empty:?}: {shown}");
        drop(prompt);

        // A default connection: the session opens on it.
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write_credentials(d, &[("home", url.clone(), "key", "k", "")], "home");
        let mut cmd = api_bare(d);
        cmd.args(["-b", empty]);
        let mut prompt = pty::Prompt::open(cmd);
        prompt.wait_ready(Duration::from_secs(15));
        prompt.pump(Duration::from_millis(500));
        press(&mut prompt, &["GET /home"]);
        assert_eq!(entered(&mut prompt, &server), ["GET /home"], "{empty:?}");
        drop(prompt);

        // A request is not sent to the default connection in its place.
        let ran = run_bare(&server, d, &["-b", empty, "-k", "k", "PUT", "/x", "{}"]);
        assert_eq!((ran.code, ran.sent.len()), (Some(1), 0), "{empty:?}: {}", ran.stderr);
        assert!(ran.stderr.contains("no base URL specified"), "{empty:?}: {}", ran.stderr);
        std::fs::write(d.join("seed.api"), "PUT /x {}\n").unwrap();
        let ran = run_bare(&server, d, &["-b", empty, "-sa", "seed.api"]);
        assert_eq!((ran.code, ran.sent.len()), (Some(1), 0), "{empty:?}: {}", ran.stderr);
    }
}

/// What the picker and the form say when a connection can't be used, and
/// that the form's own request carries a key as every later request does:
/// a key shaped like a JWT is a bearer token there too.
#[cfg(unix)]
#[test]
fn the_connection_dialog_says_why_a_connection_is_refused() {
    let server = RecordingServer::start();
    let host = format!("127.0.0.1:{}", server.port);
    let url = format!("http://{host}");
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(
        d,
        &[
            ("Zulu", url.clone(), "key", "forbidden", ""),
            ("down", "http://127.0.0.1:1".to_string(), "key", "k", ""),
            ("refused", url.clone(), "key", "nokey", ""),
        ],
        "",
    );
    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_for("+ Add new connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));
    // The reason is under the ruler, and the picker stays.
    keys_then(&mut prompt, "\r", "Zulu: forbidden");
    keys_then(&mut prompt, "\x1b[B\r", "down: connection failed");
    keys_then(&mut prompt, "\x1b[B\r", "refused: unauthorized");
    prompt.pump(Duration::from_millis(200));
    assert_eq!(pty::rows(&prompt.screen, 200).last().unwrap(), "  refused: unauthorized");
    // A search takes capital letters too.
    prompt.send(b"Zu");
    prompt.pump(Duration::from_millis(300));
    assert_eq!(row_with(&prompt, 200, "search:"), "    search: Zu");
    assert!(selected_row(&prompt).contains("Zulu"), "{}", selected_row(&prompt));
    assert_eq!(server.take(), Vec::<String>::new());
    drop(prompt);

    // The form: a server that answers its request with an error of its own.
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    prompt.wait_for("Type the API base URL", Duration::from_secs(15));
    keys_then(&mut prompt, &format!("{host}/boom\r"), "Use ← → to choose auth method");
    keys_then(&mut prompt, "\r", "Type your API key");
    keys_then(&mut prompt, "k\r", "server returned 500 Internal Server Error, try again");
    // The key is still there to send again, and the form is where it was.
    keys_then(&mut prompt, "\r", "server returned 500 Internal Server Error, try again");
    keys_then(&mut prompt, "\x1b", "Use ← → to choose auth method");
    keys_then(&mut prompt, "\x1b", "Type the API base URL");
    // Back at the URL, with the host alone, a key that is shaped like a JWT
    // is tried as the bearer token it is sent as from then on.
    prompt.send(&[0x7f; 5]);
    keys_then(&mut prompt, "\r", "Use ← → to choose auth method");
    keys_then(&mut prompt, "\r", "Type your API key");
    let jwt = format!("ey{}", "A".repeat(200));
    prompt.send(&[0x7f; 2]);
    prompt.pump(Duration::from_millis(200));
    server.take();
    keys_then(&mut prompt, &format!("{jwt}\r"), "ctrl+s to save this connection");
    let tried = server.heads();
    assert!(tried[0].contains(&format!("authorization=Bearer {jwt};")), "{tried:?}");
    prompt.pump(Duration::from_millis(400));
    press(&mut prompt, &["GET /with-jwt"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /with-jwt"]);
    assert!(server.heads()[0].contains(&format!("authorization=Bearer {jwt};")), "{:?}", server.heads());
}

/// The form for a new connection keeps to the terminal's width, and a
/// window resized while it is open gets the form drawn anew at that width,
/// with what was typed, in place from there on.
#[cfg(unix)]
#[test]
fn the_connection_form_keeps_to_the_width_and_follows_a_resize() {
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open_sized(api_bare(dir.path()), 44);
    prompt.wait_for("New connection", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(400));
    let form = |prompt: &pty::Prompt, cols: usize, from: usize, what: &str| -> Vec<String> {
        let rows = pty::rows(&prompt.screen[from..], cols);
        let shown = rows.join("\n");
        let rulers = ruler_rows(&rows);
        assert_eq!(rulers.len(), 2, "{what}: a ruler was left behind\n{shown}");
        assert_eq!(rows.len(), rulers[1] + 2, "{what}:\n{shown}");
        assert!(rows.iter().all(|row| row.chars().count() <= cols), "{what}:\n{shown}");
        rows[rulers[0]..].to_vec()
    };

    // Every step of the form, each drawn several times over.
    let steps = [
        ("a-host-with-a-name-that-is-long.example.com", "url"),
        ("\r", "method"),
        ("\x1b[D", "oauth2"),
        ("\r", "client id"),
        ("a-client-id-that-is-longer-than-the-row", "client id typed"),
        ("\r", "secret"),
        ("a-secret-that-is-longer-than-the-row-too", "secret typed"),
    ];
    for (keys, what) in steps {
        prompt.send(keys.as_bytes());
        prompt.pump(Duration::from_millis(400));
        let shown = form(&prompt, 44, 0, what);
        let expected = if what == "url" || what == "method" { 6 } else { 7 };
        assert_eq!(shown.len(), expected, "{what}:\n{}", shown.join("\n"));
    }

    for cols in [30usize, 60] {
        let mark = prompt.screen.len();
        prompt.resize(cols as u16, 50);
        prompt.pump(Duration::from_millis(700));
        let shown = form(&prompt, cols, mark, &format!("resized to {cols}"));
        assert_eq!(shown.len(), 7, "{cols}:\n{}", shown.join("\n"));
        assert!(shown[1].contains("URL:") && shown[1].ends_with(".com ✓"), "{cols}:\n{}", shown.join("\n"));
        assert!(shown[4].contains("Secret:") && shown[4].contains("•••"), "{cols}:\n{}", shown.join("\n"));
        prompt.send(b"x");
        prompt.pump(Duration::from_millis(250));
        prompt.send(b"\x7f");
        prompt.pump(Duration::from_millis(250));
        form(&prompt, cols, mark, &format!("typed at {cols}"));
    }
}

/// `PUT /x > out.json` with no body opens the body editor, as `PUT /x` does,
/// and so do POST and PATCH. The redirect is kept: the body is sent and the
/// answer written where the line said, appended for `>>`. A file body is a
/// body, and is sent at once.
#[cfg(unix)]
#[test]
fn a_write_with_an_outfile_and_no_body_opens_the_body_editor() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("body.json"), r#"{"f":1}"#).unwrap();
    let mut prompt = open_prompt(&server, d, &[]);

    for (line, file) in [("PUT /x > put.json", "put.json"), ("POST /y > post.json", "post.json"), ("PATCH /z >> patch.json", "patch.json")] {
        press(&mut prompt, &[line]);
        server.take();
        prompt.send(b"\r");
        let opened = pump_until(&mut prompt, Duration::from_secs(3), |p| screen_tail(p).contains("Enter body"));
        assert!(opened, "{line}: {}", screen_tail(&prompt));
        assert_eq!(server.seen(), 0, "{line}: sent before a body was given");
        assert!(!d.join(file).exists(), "{line}");
        prompt.send(br#"{"a":1}"#);
        prompt.pump(Duration::from_millis(150));
        prompt.send(b"\x04");
        pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
        prompt.pump(Duration::from_millis(300));
        let request = line.split(" >").next().unwrap();
        assert_eq!(server.take(), [format!("{request} {{\"a\":1}}")], "{}", screen_tail(&prompt));
        let written = std::fs::read_to_string(d.join(file)).unwrap_or_else(|_| panic!("{line}: {file} not written"));
        assert!(written.contains(&request[request.find('/').unwrap()..]), "{line}: {written}");
        // The line is back as it was sent, redirect and all.
        assert!(screen_tail(&prompt).contains(&format!("{request} {{\"a\":1}} >")), "{}", screen_tail(&prompt));
    }

    // A file body is a body: nothing to ask for.
    press(&mut prompt, &["PUT /f @body.json > file.json"]);
    assert_eq!(entered(&mut prompt, &server), [r#"PUT /f {"f":1}"#]);
    assert!(d.join("file.json").is_file());
    assert!(!screen_tail(&prompt).contains("Enter body"), "{}", screen_tail(&prompt));
}

/// A chain that esc cuts short says that the request was aborted, not how
/// many requests it skipped. A chain that ran to its end with a request left
/// out says `↳ skipped`, in the hint line.
#[cfg(unix)]
#[test]
fn an_aborted_chain_says_the_abort_and_a_finished_one_what_it_skipped() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);

    for chain in ["GET /slow && GET /never", "GET /missing && GET /left-out || GET /slow && GET /never"] {
        press(&mut prompt, &[chain]);
        server.take();
        let mark = prompt.screen.len();
        prompt.send(b"\r");
        pump_until(&mut prompt, Duration::from_secs(4), |_| server.log.lock().unwrap().iter().any(|l| l.contains("/slow")));
        prompt.pump(Duration::from_millis(900));
        prompt.send(b"\x1b");
        prompt.pump(Duration::from_millis(700));
        let shown = pty::plain(&prompt.screen[mark..]);
        assert!(!shown.contains("skipped"), "{chain}: {shown}");
        let rows = pty::rows(&prompt.screen, 200);
        assert_eq!(rows.last().unwrap().trim(), "request aborted", "{chain}:\n{}", screen_tail(&prompt));
        assert!(!server.take().iter().any(|line| line.contains("/never")), "{chain}");
        // The notice goes like any other, and the session is still there.
        prompt.pump(Duration::from_millis(3200));
    }

    for (chain, sent, says) in [
        ("GET /missing && GET /left-out", vec!["GET /missing"], "↳ skipped 1 request"),
        ("GET /missing && GET /b && GET /c", vec!["GET /missing"], "↳ skipped 2 requests"),
        ("GET /a || GET /left-out", vec!["GET /a"], "↳ skipped 1 request"),
        ("GET /missing && GET /left-out || GET /c", vec!["GET /missing", "GET /c"], "↳ skipped 1 request"),
    ] {
        press(&mut prompt, &[chain]);
        server.take();
        prompt.send(b"\r");
        pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() >= sent.len());
        prompt.pump(Duration::from_millis(500));
        assert_eq!(server.take(), sent, "{chain}");
        let rows = pty::rows(&prompt.screen, 200);
        assert_eq!(rows.last().unwrap().trim(), says, "{chain}:\n{}", screen_tail(&prompt));
    }
    // A chain that sent everything has nothing to say.
    press(&mut prompt, &["GET /a && GET /b"]);
    let mark = prompt.screen.len();
    prompt.send(b"\r");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() >= 2);
    prompt.pump(Duration::from_millis(500));
    assert!(!pty::plain(&prompt.screen[mark..]).contains("skipped"), "{}", screen_tail(&prompt));
}

/// A paste is input like a typed character: it takes back a first ctrl+c,
/// so the next ctrl+c does not end the session, and it closes the shortcuts.
#[cfg(unix)]
#[test]
fn a_paste_takes_back_a_first_ctrl_c_and_closes_the_shortcuts() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);

    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(100));
    prompt.send(b"\x03");
    prompt.wait_for("ctrl+c again to exit", Duration::from_secs(3));
    prompt.paste("GET /pasted");
    prompt.pump(Duration::from_millis(300));
    assert!(!pty::rows(&prompt.screen, 200).last().unwrap().contains("ctrl+c again"), "{}", screen_tail(&prompt));
    let mark = prompt.screen.len();
    prompt.send(b"\x03");
    prompt.pump(Duration::from_millis(600));
    assert_eq!(prompt.exited(), None, "a ctrl+c after a paste ended the session");
    assert!(pty::plain(&prompt.screen[mark..]).contains("ctrl+c again to exit"), "{}", screen_tail(&prompt));
    prompt.send(b" ");
    prompt.pump(Duration::from_millis(200));

    // The shortcuts close for a paste as for a key, and the paste is taken.
    prompt.send(b"\x15\x08");
    prompt.wait_for("ctrl+q", Duration::from_secs(3));
    prompt.pump(Duration::from_millis(200));
    prompt.paste("GET /after-help");
    prompt.pump(Duration::from_millis(400));
    let rows = pty::rows(&prompt.screen, 200);
    assert_eq!(ruler_rows(&rows).len(), 2, "{}", rows.join("\n"));
    assert!(rows[rows.len() - 3].starts_with("GET /after-help"), "{}", rows.join("\n"));
    assert_eq!(entered(&mut prompt, &server), ["GET /after-help"]);
}

/// The spinner of a wait and the progress of a slow request stay on the hint
/// row of a narrow terminal: cut to its width, with nothing wrapped onto a
/// row that the next redraw does not know of.
#[cfg(unix)]
#[test]
fn a_spinner_and_a_progress_line_keep_to_a_narrow_terminal() {
    const COLS: usize = 16;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open_sized(api(server.port, dir.path()), COLS as u16);
    prompt.wait_for("─", Duration::from_secs(15));
    prompt.pump(Duration::from_millis(1200));

    for (line, during, ends_with) in [("GET /slow", "200 OK", "\x1b"), ("sleep 300", "sleep", "\x1b")] {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(100));
        prompt.paste(line);
        prompt.pump(Duration::from_millis(200));
        prompt.send(b"\r");
        prompt.pump(Duration::from_millis(1600));
        // Many frames have been drawn by now.
        let rows = pty::rows(&prompt.screen, COLS);
        let shown = rows.join("\n");
        let rulers = ruler_rows(&rows);
        assert_eq!(rulers.len(), 2, "{line}: a ruler was left behind\n{shown}");
        assert_eq!(rows.len(), rulers[1] + 2, "{line}: the hint row wrapped\n{shown}");
        assert!(rows.last().unwrap().contains(during), "{line}:\n{shown}");
        assert!(rows.iter().all(|row| row.chars().count() <= COLS), "{line}:\n{shown}");
        prompt.send(ends_with.as_bytes());
        prompt.pump(Duration::from_millis(900));
        let rows = pty::rows(&prompt.screen, COLS);
        let rulers = ruler_rows(&rows);
        assert_eq!(rulers.len(), 2, "{line}: a ruler was left behind\n{}", rows.join("\n"));
        assert_eq!(rows.len(), rulers[1] + 2, "{line}: after the wait\n{}", rows.join("\n"));
        assert!(rows.iter().all(|row| row.chars().count() <= COLS), "{line}:\n{}", rows.join("\n"));
        prompt.pump(Duration::from_millis(3200));
    }
    assert_eq!(prompt.exited(), None);
}

/// The progress line of a single slow request at a terminal is one row
/// however narrow the terminal is, and is gone when the answer is printed.
#[cfg(unix)]
#[test]
fn the_progress_line_of_a_single_request_keeps_to_a_narrow_terminal() {
    const COLS: usize = 12;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = api(server.port, dir.path());
    cmd.args(["-r", "GET", "/slow"]);
    let mut term = pty::Prompt::open_sized(cmd, COLS as u16);
    // The status line is on screen by then, and may take two rows here:
    // what counts is that the progress under it is one row, the last.
    let start = Instant::now();
    let mut heights = std::collections::BTreeSet::new();
    while term.exited().is_none() && start.elapsed() < Duration::from_secs(15) {
        term.pump(Duration::from_millis(100));
        let rows = pty::rows(&term.screen, COLS);
        if let Some(at) = rows.iter().position(|row| row.contains("receiv")) {
            heights.insert(rows.len());
            assert_eq!(at + 1, rows.len(), "the progress line wrapped:\n{}", rows.join("\n"));
            assert!(rows[at].chars().count() < COLS, "{}", rows.join("\n"));
        }
    }
    term.pump(Duration::from_millis(200));
    assert_eq!(heights.len(), 1, "the progress line moved or was never seen: {heights:?}\n{}", pty::plain(&term.screen));
    let rows = pty::rows(&term.screen, COLS);
    assert!(!rows.iter().any(|row| row.contains("receiv")), "{}", rows.join("\n"));
}

/// A line recalled from history is the line as it was sent: a PUT that was
/// typed as one stays a PUT when its body is cleared, whatever the line
/// before it on the input line had been promoted from.
#[cfg(unix)]
#[test]
fn a_recalled_line_keeps_its_method_when_its_body_is_cleared() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);

    press(&mut prompt, &["PUT /a {\"x\":1}"]);
    assert_eq!(entered(&mut prompt, &server), ["PUT /a {\"x\":1}"]);
    // A body typed on a GET makes it a PUT, which clearing the body undoes…
    let shown = press(&mut prompt, &["GET /a {"]);
    assert!(shown.contains("PUT /a {"), "{shown}");
    // …but not on the line that Up brings back.
    server.take();
    prompt.send(b"\x1b[A");
    prompt.pump(Duration::from_millis(200));
    prompt.send(b"\x18");
    prompt.pump(Duration::from_millis(200));
    prompt.send(b"\r");
    prompt.pump(Duration::from_millis(600));
    assert_eq!(server.take(), Vec::<String>::new(), "{}", screen_tail(&prompt));
    assert!(screen_tail(&prompt).contains("Enter body"), "{}", screen_tail(&prompt));
    prompt.send(b"{\"y\":2}\x04");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    assert_eq!(server.take(), ["PUT /a {\"y\":2}"], "{}", screen_tail(&prompt));
    prompt.pump(Duration::from_millis(300));

    // The same for a line that Down brings back, and for the one put aside.
    press(&mut prompt, &["GET /a {"]);
    prompt.send(b"\x1b[A\x1b[A\x1b[B");
    prompt.pump(Duration::from_millis(200));
    prompt.send(b"\x18\r");
    prompt.pump(Duration::from_millis(600));
    assert_eq!(server.take(), Vec::<String>::new(), "{}", screen_tail(&prompt));
    assert!(screen_tail(&prompt).contains("Enter body"), "{}", screen_tail(&prompt));
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(200));
}

/// ctrl+x on a block of lines takes the body of the line the cursor is on.
/// The other lines are requests of their own and stay as they are.
#[cfg(unix)]
#[test]
fn clearing_a_body_in_a_block_leaves_the_other_lines() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    let block = "GET /a\rPUT /b {\"x\":1}\rGET /c";

    // The cursor on the first line, which has no body: nothing goes.
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    prompt.paste(block);
    prompt.pump(Duration::from_millis(150));
    prompt.send(b"\x1b[A\x1b[A\x18");
    prompt.pump(Duration::from_millis(200));
    server.take();
    prompt.send(b"\r");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() >= 3);
    prompt.pump(Duration::from_millis(300));
    assert_eq!(server.take(), ["GET /a", "PUT /b {\"x\":1}", "GET /c"], "{}", screen_tail(&prompt));

    // On the second line it is that line's body, and only that.
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(60));
    prompt.paste("GET /a\rPUT /b {\"x\":1} > b.json\rPUT /c {\"y\":2}");
    prompt.pump(Duration::from_millis(150));
    prompt.send(b"\x1b[A\x18");
    prompt.pump(Duration::from_millis(200));
    let rows = pty::rows(&prompt.screen, 200);
    let area = &rows[ruler_rows(&rows)[0] + 1..];
    assert_eq!(&area[..3], ["GET /a", "PUT /b > b.json", "PUT /c {\"y\":2}"], "{}", rows.join("\n"));
}

/// A character typed with AltGr on Windows arrives as a key with ctrl and
/// alt held. It is typed, on the input line, in the body editor and in a
/// dialog; ctrl or alt alone still types nothing.
#[cfg(unix)]
#[test]
fn a_character_that_comes_with_ctrl_and_alt_is_typed() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    // `{`, `}` and `@` as a terminal that reports modifiers sends them with
    // ctrl+alt (CSI code ; 7 u); `~` with ctrl+alt+shift (; 8 u).
    let (open, close, at, tilde) = ("\x1b[123;7u", "\x1b[125;7u", "\x1b[64;7u", "\x1b[126;8u");

    press(&mut prompt, &["PUT /typed ", open, "\"a\":1", close]);
    assert_eq!(entered(&mut prompt, &server), ["PUT /typed {\"a\":1}"], "{}", screen_tail(&prompt));
    prompt.pump(Duration::from_millis(200));
    press(&mut prompt, &["GET /people", tilde, "count"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /people~count"], "{}", screen_tail(&prompt));
    prompt.pump(Duration::from_millis(200));

    // In the body editor.
    press(&mut prompt, &["PUT /edited"]);
    server.take();
    prompt.send(b"\r");
    prompt.wait_for("Enter body", Duration::from_secs(3));
    for key in [open, "\"b\":\"", at, "\"", close] {
        prompt.send(key.as_bytes());
        prompt.pump(Duration::from_millis(90));
    }
    prompt.send(b"\x04");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    assert_eq!(server.take(), ["PUT /edited {\"b\":\"@\"}"], "{}", screen_tail(&prompt));
    prompt.pump(Duration::from_millis(300));

    // In a dialog: the name a connection is saved under.
    prompt.send(b"\x13");
    prompt.wait_for("Save connection as", Duration::from_secs(3));
    for key in ["a", at, "b", "\r"] {
        prompt.send(key.as_bytes());
        prompt.pump(Duration::from_millis(90));
    }
    prompt.wait_for("connection a@b saved", Duration::from_secs(3));
    assert_eq!(stored(dir.path()).0, ["a@b=k"]);
}

/// While a connection made in the form is loading, ctrl+c leaves the client
/// with the terminal as a shell wants it. Anything else typed or pasted
/// meanwhile is not kept for the prompt that opens when the load is done.
#[cfg(unix)]
#[test]
fn ctrl_c_leaves_while_a_connection_is_loading_and_other_keys_are_dropped() {
    let server = RecordingServer::start();
    let host = format!("127.0.0.1:{}", server.port);
    let to_loading = |prompt: &mut pty::Prompt| {
        prompt.wait_for("Type the API base URL", Duration::from_secs(15));
        keys_then(prompt, &format!("{host}\r"), "Use ← → to choose auth method");
        keys_then(prompt, "\r", "Type your API key");
        keys_then(prompt, "slowabout\r", "loading...");
        prompt.pump(Duration::from_millis(300));
    };

    // ctrl+c ends it, well before the load is done.
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    to_loading(&mut prompt);
    assert!(!prompt.is_cooked());
    prompt.send(b"\x03");
    let start = Instant::now();
    while prompt.exited().is_none() && start.elapsed() < Duration::from_millis(2500) {
        prompt.pump(Duration::from_millis(50));
    }
    assert_eq!(prompt.exited(), Some(true), "ctrl+c did not end the client:\n{}", screen_tail(&prompt));
    assert!(prompt.is_cooked(), "the terminal is left in raw mode");
    assert!(prompt.screen.rfind("\x1b[?2004l") > prompt.screen.rfind("\x1b[?2004h"), "paste mode is left on");
    assert!(prompt.screen.rfind("\x1b[?25h") > prompt.screen.rfind("\x1b[?25l"), "the cursor is left hidden");
    let rows = pty::rows(&prompt.screen, 200);
    assert!(!rows.iter().any(|row| row.contains("loading") || row.starts_with("──")), "{}", rows.join("\n"));

    // Keys and a paste during the load are not the prompt's.
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    to_loading(&mut prompt);
    prompt.send(b"typed");
    prompt.pump(Duration::from_millis(200));
    prompt.paste("GET /pasted-early");
    prompt.wait_for("ctrl+s to save this connection", Duration::from_secs(10));
    prompt.pump(Duration::from_millis(500));
    let rows = pty::rows(&prompt.screen, 200);
    let shown = rows.join("\n");
    assert!(!shown.contains("typed") && !shown.contains("pasted-early"), "{shown}");
    assert_eq!(entered(&mut prompt, &server), ["GET /"], "{}", screen_tail(&prompt));
}

/// After a write to `/mapped-types`, however the path is spelled, the types
/// that `~map(` completes from are read again, without the prompt waiting
/// for it. A list that can't be had leaves the one there was.
#[cfg(unix)]
#[test]
fn the_mapped_types_are_read_again_after_one_is_written() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_completing(&server, dir.path(), &[]);
    let completes = |prompt: &mut pty::Prompt, typed: &str| -> String {
        prompt.pump(Duration::from_millis(700));
        press(prompt, &[typed, "\t"]);
        entered(prompt, &server).pop().unwrap_or_default()
    };
    let send = |prompt: &mut pty::Prompt, line: &str| {
        press(prompt, &[line]);
        prompt.send(b"\r");
        prompt.pump(Duration::from_millis(500));
    };

    assert_eq!(completes(&mut prompt, "GET /people~map(com.heads.x"), "GET /people~map(com.heads.x");
    for written in ["PUT mapped-types {\"a\":1}", "POST /api/v1/mapped-types {\"a\":1}", "PATCH v1/mapped-types/x {\"a\":1}", "PUT /mapped-types {\"a\":1}"] {
        // One type more on the server, then the write, then one fewer again.
        send(&mut prompt, "GET /more-types");
        send(&mut prompt, written);
        assert_eq!(completes(&mut prompt, "GET /people~map(com.heads.x"), "GET /people~map(com.heads.xml)", "{written}");
        send(&mut prompt, "GET /fewer-types");
        send(&mut prompt, written);
        assert_eq!(completes(&mut prompt, "GET /people~map(com.heads.x"), "GET /people~map(com.heads.x", "{written}");
    }

    // The list can't be read: the one there was stays.
    send(&mut prompt, "GET /break-types");
    send(&mut prompt, "PUT /mapped-types {\"a\":1}");
    assert_eq!(completes(&mut prompt, "GET /people~map(com.heads.c"), "GET /people~map(com.heads.csv)");
}

/// A name typed into the save dialog is trimmed, as a pasted one is, and a
/// name of blanks alone is no name: nothing is saved.
#[cfg(unix)]
#[test]
fn a_connection_name_is_trimmed_and_blanks_are_no_name() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);

    prompt.send(b"\x13");
    prompt.wait_for("Save connection as", Duration::from_secs(3));
    let mark = prompt.screen.len();
    prompt.send(b"   \r");
    let said = pump_until(&mut prompt, Duration::from_secs(3), |p| pty::plain(&p.screen[mark..]).contains("cancelled"));
    assert!(said, "{}", screen_tail(&prompt));
    assert!(!dir.path().join(".api-credentials.json").exists() || stored(dir.path()).0.is_empty());
    command_area(&prompt, 200, "after blanks");

    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\x13");
    prompt.pump(Duration::from_millis(400));
    prompt.send(b"  local dev  \r");
    prompt.wait_for("connection local dev saved", Duration::from_secs(3));
    assert_eq!(stored(dir.path()).0, ["local dev=k"]);
}

/// ctrl+o with no file written yet does nothing, and says nothing.
#[cfg(unix)]
#[test]
fn ctrl_o_with_nothing_to_open_does_nothing() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    press(&mut prompt, &["GET /a"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /a"]);
    prompt.pump(Duration::from_millis(3200));
    let before = pty::rows(&prompt.screen, 200);
    prompt.send(b"\x0f");
    prompt.pump(Duration::from_millis(500));
    assert_eq!(pty::rows(&prompt.screen, 200), before);
    assert_eq!(prompt.exited(), None);
    press(&mut prompt, &["GET /b"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /b"]);
}

/// ctrl+c in the body editor closes the editor and nothing more: nothing is
/// sent, the session stays, and it is not counted as the first of the two
/// that end it.
#[cfg(unix)]
#[test]
fn ctrl_c_in_the_body_editor_closes_only_the_editor() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    press(&mut prompt, &["PUT /x"]);
    server.take();
    prompt.send(b"\r");
    prompt.wait_for("Enter body", Duration::from_secs(3));
    prompt.send(b"{\"a\":1}");
    prompt.pump(Duration::from_millis(200));
    let mark = prompt.screen.len();
    prompt.send(b"\x03");
    prompt.pump(Duration::from_millis(500));
    assert_eq!(prompt.exited(), None);
    assert_eq!(server.seen(), 0);
    assert!(!pty::plain(&prompt.screen[mark..]).contains("ctrl+c again"), "{}", screen_tail(&prompt));
    let rows = command_area(&prompt, 200, "after ctrl+c");
    assert_eq!(rows[1], "PUT /x", "{}", rows.join("\n"));
    // One more is the first of two, not the second.
    prompt.send(b"\x03");
    prompt.pump(Duration::from_millis(400));
    assert_eq!(prompt.exited(), None, "the session ended on the first ctrl+c");
    assert!(screen_tail(&prompt).contains("ctrl+c again to exit"), "{}", screen_tail(&prompt));
    prompt.send(b" \x7f");
    prompt.pump(Duration::from_millis(200));
    assert_eq!(entered(&mut prompt, &server), Vec::<String>::new());
    prompt.wait_for("Enter body", Duration::from_secs(3));
}

/// An `assert` or a `sleep while` at the prompt whose request gets a status
/// that is no answer (5xx, 401) says that it could not be evaluated, and the
/// block it is in stops there.
#[cfg(unix)]
#[test]
fn a_check_that_gets_no_answer_at_the_prompt_stops_the_block() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);

    for (check, sent, status) in [
        ("assert GET /boom", "GET /boom", "500"),
        ("assert not GET /denied", "GET /denied", "401"),
        ("sleep 1s while GET /boom", "GET /boom", "500"),
        ("sleep 1s while not GET /denied", "GET /denied", "401"),
    ] {
        let (requests, shown) = run_pasted(&mut prompt, &server, &format!("GET /first\r{check}\rGET /never"));
        assert_eq!(requests, ["GET /first", sent], "{check}: {shown}");
        assert!(shown.contains(&format!("{check} — could not be evaluated")), "{check}: {shown}");
        assert!(shown.contains(&format!("HTTP/1.1 {status}")), "{check}: {shown}");
        prompt.pump(Duration::from_millis(300));
    }
    press(&mut prompt, &["GET /after"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /after"]);
}

/// The command area as the screen has it: its rows between the two rulers.
/// There are exactly two rulers, the top one on row `top`, the hint row is
/// the last row of the screen, and what is above the top ruler is `above`.
#[cfg(unix)]
fn input_rows_at(prompt: &pty::Prompt, cols: usize, top: usize, above: &[String], what: &str) -> Vec<String> {
    let rows = pty::rows(&prompt.screen, cols);
    let shown = rows.join("\n");
    let rulers = ruler_rows(&rows);
    assert_eq!(rulers.len(), 2, "{what}: not two rulers\n{shown}");
    assert_eq!(rulers[0], top, "{what}: the top ruler moved\n{shown}");
    assert_eq!(&rows[..top], above, "{what}: the rows above changed\n{shown}");
    assert!(rows.len() <= rulers[1] + 2, "{what}: rows under the hint line\n{shown}");
    for row in &rows[top..] {
        let columns: usize = row.chars().map(pty::columns).sum();
        assert!(columns <= cols, "{what}: a row of {columns} columns\n{shown}");
    }
    rows[top + 1..rulers[1]].to_vec()
}

/// A line of wide characters takes two columns a character: it is wrapped
/// where the row is full, a character that would straddle the margin goes
/// to the next row whole, and the rows drawn are the rows the next redraw
/// moves up by, so no key leaves a ruler or a row behind.
#[cfg(unix)]
#[test]
fn a_line_of_wide_characters_is_wrapped_by_the_columns_it_takes() {
    const COLS: usize = 40;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open_sized(api(server.port, dir.path()), COLS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(300));
    let before = pty::rows(&prompt.screen, COLS);
    let top = ruler_rows(&before)[0];
    let above = before[..top].to_vec();

    let wide = |count: usize| "日".repeat(count);
    for (count, expected) in [
        // `GET /` and 17 of them are 39 columns: with the cursor the row is full.
        (17, vec![format!("GET /{}", wide(17))]),
        // One more has a single column left, and takes the next row.
        (18, vec![format!("GET /{}", wide(17)), wide(1)]),
        // A full row of them in the middle.
        (40, vec![format!("GET /{}", wide(17)), wide(20), wide(3)]),
        // The last row is full: the cursor is on a row of its own.
        (37, vec![format!("GET /{}", wide(17)), wide(20), String::new()]),
    ] {
        let what = format!("{count} wide characters");
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(80));
        prompt.paste(&format!("GET /{}", wide(count)));
        prompt.pump(Duration::from_millis(300));
        assert_eq!(input_rows_at(&prompt, COLS, top, &above, &what), expected, "{what}");
        // Moving in the line, typing into it and taking that back again.
        for (key, name) in [
            (&b"\x1b[D"[..], "left"),
            (b"\x1b[D", "left"),
            (b"x", "a character"),
            (b"\x7f", "backspace"),
            (b"\x01", "home"),
            (b"\x1b[C", "right"),
            (b"\x05", "end"),
        ] {
            prompt.send(key);
            prompt.pump(Duration::from_millis(150));
            input_rows_at(&prompt, COLS, top, &above, &format!("{what}, after {name}"));
        }
        assert_eq!(input_rows_at(&prompt, COLS, top, &above, &what), expected, "{what}, after the keys");
    }
    // The line is sent as it was written.
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(80));
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /日本");
    assert_eq!(sent, ["GET /%E6%97%A5%E6%9C%AC"], "{shown}");
}

/// A tab in a pasted body is drawn as the blanks to the next tab stop, and
/// counted as them: a tab-indented line is wrapped where the row is full,
/// nothing is drawn over, and no key leaves a row behind. The text keeps
/// its tabs: what is sent is what was pasted.
#[cfg(unix)]
#[test]
fn a_tab_indented_body_is_drawn_by_the_columns_it_takes() {
    const COLS: usize = 30;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open_sized(api(server.port, dir.path()), COLS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(300));
    let before = pty::rows(&prompt.screen, COLS);
    let top = ruler_rows(&before)[0];
    let above = before[..top].to_vec();

    // A terminal sends the line breaks of a paste as carriage returns.
    let body = "{\r\t\"name\": \"Alec Trevelyan\",\r\t\t\"n\": 1\r}";
    let expected = [
        "PUT /x {",
        // Eight columns of tab and 22 of text fill the row.
        "        \"name\": \"Alec Trevelya",
        "n\",",
        "                \"n\": 1",
        "}",
    ];
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(80));
    prompt.paste(&format!("PUT /x {body}"));
    prompt.pump(Duration::from_millis(300));
    assert_eq!(input_rows_at(&prompt, COLS, top, &above, "pasted"), expected);
    for (key, name) in [
        (&b"\x1b[D"[..], "left"),
        (b"\x1b[D", "left"),
        (b"\x1b[D", "left"),
        (b" ", "a blank"),
        (b"\x7f", "backspace"),
        (b"\x01", "home"),
        (b"\x1b[C", "right"),
        (b"\x05", "end"),
    ] {
        prompt.send(key);
        prompt.pump(Duration::from_millis(150));
        input_rows_at(&prompt, COLS, top, &above, &format!("after {name}"));
    }
    assert_eq!(input_rows_at(&prompt, COLS, top, &above, "after the keys"), expected);

    // Sent with its tabs.
    server.take();
    prompt.send(b"\r");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    prompt.pump(Duration::from_millis(250));
    assert_eq!(server.take(), ["PUT /x {\n\t\"name\": \"Alec Trevelyan\",\n\t\t\"n\": 1\n}"]);

    // The same in the body editor, under its two heading rows.
    let rows = pty::rows(&prompt.screen, COLS);
    let top = ruler_rows(&rows)[0];
    let above = rows[..top].to_vec();
    prompt.send(b"\x15");
    prompt.pump(Duration::from_millis(80));
    prompt.paste("PUT /y");
    prompt.send(b"\r");
    prompt.wait_for("Enter body", Duration::from_secs(3));
    prompt.paste(body);
    prompt.pump(Duration::from_millis(300));
    let editor = input_rows_at(&prompt, COLS, top, &above, "the body editor");
    assert_eq!(editor[0], "PUT /y", "{editor:?}");
    assert_eq!(editor[editor.len() - 5..], ["{", expected[1], expected[2], expected[3], "}"], "{editor:?}");
    for round in 0..3 {
        prompt.send(b"x");
        prompt.pump(Duration::from_millis(120));
        prompt.send(b"\x7f");
        prompt.pump(Duration::from_millis(120));
        input_rows_at(&prompt, COLS, top, &above, &format!("the body editor, round {round}"));
    }
    server.take();
    prompt.send(b"\x04");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    prompt.pump(Duration::from_millis(250));
    assert_eq!(server.take(), ["PUT /y {\n\t\"name\": \"Alec Trevelyan\",\n\t\t\"n\": 1\n}"]);
}

/// A dialog's input line is drawn in one write. While a notice stands in
/// its hint line the dialog draws thirty times a second, and a line that was
/// cleared in one write and filled in the next could be read between the
/// two with nothing on it: by a terminal as a flicker, and by a test that
/// looks at the screen after a fixed wait as a prompt that is gone.
#[cfg(unix)]
#[test]
fn a_dialog_is_never_seen_with_its_input_line_half_drawn() {
    const COLS: usize = 84;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open_sized(api(server.port, dir.path()), COLS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    let top = ruler_rows(&pty::rows(&prompt.screen, COLS))[0];
    prompt.send(EXPORT_ROW);
    prompt.wait_for("Export with external identifier", Duration::from_secs(5));
    // Refused: the notice is up for three seconds, and drawn all the while.
    prompt.send(b"seedID\r");
    prompt.wait_for("export needs a namespaced key", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(200));
    let start = Instant::now();
    let mut frames = 0;
    while start.elapsed() < Duration::from_millis(2000) {
        let seen = prompt.screen.len();
        // As short as a read: whatever one write brought is looked at.
        prompt.pump(Duration::from_micros(200));
        if prompt.screen.len() == seen {
            continue;
        }
        frames += 1;
        let rows = pty::rows(&prompt.screen, COLS);
        assert_eq!(rows[top + 1], "› Export with external identifier: seedID", "frame {frames}:\n{}", rows.join("\n"));
    }
    assert!(frames > 20, "the dialog was not drawing: {frames} frames");
}

/// With `-c` the connection is loaded while the command area is up, and
/// until it is loaded no key and no paste is taken. So the input line is
/// not drawn before that: a line that is shown takes what is typed, at once.
#[cfg(unix)]
#[test]
fn the_input_line_of_a_saved_connection_is_drawn_when_it_takes_keys() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("a", url, "key", "k", "")], "a");
    for round in 0..3 {
        let mut cmd = api_bare(d);
        cmd.args(["-c", "a"]);
        let mut prompt = pty::Prompt::open(cmd);
        prompt.wait_ready(Duration::from_secs(15));
        // No pause: what is typed the moment the line is there is taken.
        server.take();
        prompt.paste("GET /at-once");
        prompt.send(b"\r");
        let sent = pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
        assert!(sent, "round {round}: nothing was sent\n{}", screen_tail(&prompt));
        assert_eq!(server.take(), ["GET /at-once"], "round {round}");
        // The first frame, up to its hint line, had the spinner in its place.
        let first = &prompt.screen[..prompt.screen.find("ctrl+h for shortcuts").unwrap()];
        assert!(first.contains("Connecting to a") || first.contains("from a"), "round {round}: {first:?}");
        assert!(!first.contains("GET /"), "round {round}: an input line that takes no key\n{first:?}");
    }
}

// ----- options, the store, base URLs and what a response is said to be -----

/// An option given twice is said to be given twice, and one that is the last
/// word of the command line, with no value behind it, to need one.
#[test]
fn an_option_given_twice_or_without_its_value_is_said_to_be_that() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    for (args, says) in [
        (&["-b", &url, "-k", "a", "-k", "b", "GET", "/a"][..], "error: --key was given twice"),
        (&["-b", &url, "-k", "k", "--timeout", "1", "--timeout", "2", "GET", "/a"], "error: --timeout was given twice"),
        (&["-b", &url, "-k", "k", "-s", "-s", "GET", "/a"], "error: --silent was given twice"),
        (&["-b", &url, "-k", "k", "GET", "/a", "--export"], "error: --export needs a value"),
        (&["-b", &url, "-k", "k", "GET", "/a", "--timeout"], "error: --timeout needs a value"),
        (&["-c"], "error: --connection needs a value"),
    ] {
        let got = run_bare(&server, d, args);
        assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{args:?}: {}", got.stderr);
        assert_eq!(got.stderr.trim(), says, "{args:?}");
        assert_eq!(got.stdout, "", "{args:?}");
    }
}

/// A known `auth_type` is read in any case. One the client does not know is
/// not sent as a key: the connection is not used, and that is said.
#[test]
fn a_connection_with_an_auth_type_the_client_does_not_know_is_not_used() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    write_credentials(
        d,
        &[
            ("shout", url.clone(), "Token", "STOREDTOKEN", ""),
            ("caps", url.clone(), "KEY", "STOREDKEY", ""),
            ("oauth", url.clone(), "OAuth2", "secret", "id"),
            ("odd", url.clone(), "bearer", "SECRET", ""),
        ],
        "odd",
    );
    for (name, authorization_sent) in [("shout", "Bearer STOREDTOKEN"), ("caps", "Basic OlNUT1JFREtFWQ==")] {
        let got = run_bare(&server, d, &["-c", name, "GET", "/a"]);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{name}: {}", got.stderr);
        assert_eq!(authorization(&server), authorization_sent, "{name}");
    }
    let got = run_bare(&server, d, &["-c", "oauth", "GET", "/a"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert!(got.sent[0].starts_with("POST /oauth2/v1/token"), "{:?}", got.sent);
    assert_eq!(got.sent[1], "GET /a");
    assert!(server.heads()[1].contains("authorization=Bearer "), "{:?}", server.heads());

    // The default connection, and the same one asked for by name.
    let unknown = r#"its auth_type "bearer" is not "key", "token" or "oauth2""#;
    for args in [&["GET", "/a"][..], &["-sa", "one.api"]] {
        std::fs::write(d.join("one.api"), "GET /a\n").unwrap();
        let got = run_bare(&server, d, args);
        assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{args:?}: {}", got.stderr);
        assert_eq!(
            got.stderr.lines().next(),
            Some(&format!("WARNING: the default connection \"odd\" can't be used: {unknown}. No saved connection is used.")[..]),
            "{args:?}"
        );
        assert!(got.stderr.contains("no base URL specified"), "{args:?}: {}", got.stderr);
    }
    let got = run_bare(&server, d, &["-c", "odd", "GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{}", got.stderr);
    assert_eq!(got.stderr.trim(), format!("The connection \"odd\" can't be used: {unknown}."));

    // With a credential on the command line the stored one is not looked at.
    for args in [&["-k", "CLIKEY", "GET", "/a"][..], &["-c", "odd", "-k", "CLIKEY", "GET", "/a"]] {
        let got = run_bare(&server, d, args);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{args:?}: {}", got.stderr);
        assert_eq!(authorization(&server), "Basic OkNMSUtFWQ==", "{args:?}");
    }
}

/// `API_CREDENTIALS_FILE` set to nothing is the variable not set. A value
/// that is no UTF-8 is still a path, and the file it names is the one read.
#[cfg(unix)]
#[test]
fn an_empty_credentials_variable_is_unset_and_any_path_is_used_as_it_is() {
    use std::os::unix::ffi::OsStrExt;

    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("local", format!("http://127.0.0.1:{}", server.port), "key", "STOREDKEY", "")], "local");
    let with = |value: &std::ffi::OsStr| {
        let mut cmd = api_bare(d);
        cmd.env("API_CREDENTIALS_FILE", value).args(["GET", "/a"]);
        ran(&server, cmd)
    };

    let empty = with(std::ffi::OsStr::new(""));
    assert_eq!((empty.code, &empty.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{}", empty.stderr);

    // Not the file in the working directory in its place: there is no such
    // file, so there is no connection.
    let odd = with(std::ffi::OsStr::from_bytes(b"/nonexistent/\xff.json"));
    assert_eq!((odd.code, odd.sent.len()), (Some(1), 0), "{}", odd.stderr);
    assert!(odd.stderr.contains("no base URL specified"), "{}", odd.stderr);

    // A file somewhere else, named by the variable.
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::rename(d.join(".api-credentials.json"), elsewhere.path().join("named.json")).unwrap();
    let named = with(elsewhere.path().join("named.json").as_os_str());
    assert_eq!((named.code, &named.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{}", named.stderr);
}

/// A server that sends a request round in circles is there. It is not asked
/// about as one that did not answer.
#[test]
fn a_redirect_loop_is_said_to_be_one() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let says = format!("Too many redirects from 127.0.0.1:{}", server.port);
    std::fs::write(d.join("loop.api"), "GET /loop\nGET /never\n").unwrap();
    std::fs::write(d.join("chain.api"), "GET /loop || GET /never\n").unwrap();
    for args in [&["GET", "/loop"][..], &["-sa", "loop.api"], &["-sa", "chain.api"], &["assert not GET /loop"]] {
        let got = run_in(&server, d, args);
        assert_eq!(got.code, Some(1), "{args:?}: {}", got.stderr);
        assert!(got.stderr.contains(&says), "{args:?}: {}", got.stderr);
        assert!(!got.stderr.contains("Is COS running"), "{args:?}: {}", got.stderr);
        assert!(!got.sent.is_empty() && got.sent.iter().all(|r| r == "GET /loop"), "{args:?}: {:?}", got.sent);
    }
}

#[cfg(unix)]
#[test]
fn the_prompt_says_a_redirect_loop_is_one() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    let shown = enter_line(&mut prompt, "GET /loop", "Too many redirects");
    assert!(shown.contains(&format!("Too many redirects from 127.0.0.1:{}", server.port)), "{shown}");
    assert!(!shown.contains("Is COS running"), "{shown}");
}

/// `-a` runs a file. A request beside it is not dropped without a word, and
/// not run after the file either: it is an error, and nothing is sent.
#[test]
fn a_file_and_a_request_on_one_command_line_is_an_error() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("f.api"), "GET /from-file\n").unwrap();
    for (args, file, request) in [
        (&["-sa", "f.api", "GET", "/ignored"][..], "-a f.api", "GET /ignored"),
        (&["-a", "f.api", "/ignored"], "-a f.api", "/ignored"),
        (&["-sfa", "f.api", "PUT", "/x", "{\"a\":1}"], "-a f.api", "PUT /x {\"a\":1}"),
        (&["GET", "/ignored", "-a", "f.api"], "-a f.api", "GET /ignored"),
        (&["-a", "-", "GET", "/ignored"], "-a -", "GET /ignored"),
    ] {
        let got = run_in(&server, d, args);
        assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{args:?}: {}", got.stderr);
        assert_eq!(
            got.stderr.trim(),
            format!("error: {file} runs a file and {request} is a request: give one of the two"),
            "{args:?}"
        );
        assert_eq!(got.stdout, "", "{args:?}");
    }
    let got = run_in(&server, d, &["-sa", "f.api"]);
    assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /from-file".to_string()][..]), "{}", got.stderr);
}

/// A base URL is `http://` or `https://`. Another scheme, or one that is not
/// written whole, is refused where it is given: with `-b`, and in a saved
/// connection. The API prefix is cut in any case.
#[test]
fn a_base_url_that_is_not_http_is_refused() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let host = format!("127.0.0.1:{}", server.port);
    std::fs::write(d.join("one.api"), "GET /a\n").unwrap();
    for (base, says) in [
        (format!("ftp://{host}"), "a base URL starts with http:// or https://, not ftp://".to_string()),
        (format!("http:/{host}"), format!("http:/{host} is not a URL: a base URL starts with http:// or https://")),
    ] {
        for args in [&["GET", "/a"][..], &["-sa", "one.api"]] {
            let mut all = vec!["-b", base.as_str(), "-k", "k"];
            all.extend_from_slice(args);
            let got = run_bare(&server, d, &all);
            assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{all:?}: {}", got.stderr);
            assert_eq!(got.stderr.trim(), format!("error: invalid value for -b: {base} ({says})"), "{all:?}");
        }
        // The same URL in a saved connection.
        write_credentials(d, &[("odd", base.clone(), "key", "k", "")], "odd");
        let got = run_bare(&server, d, &["GET", "/a"]);
        assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{base}: {}", got.stderr);
        assert_eq!(
            got.stderr.lines().next(),
            Some(&format!("WARNING: the default connection \"odd\" can't be used: {says}. No saved connection is used.")[..]),
            "{base}"
        );
        for args in [&["-c", "odd", "GET", "/a"][..], &["-k", "CLIKEY", "GET", "/a"]] {
            let got = run_bare(&server, d, args);
            assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{base} {args:?}: {}", got.stderr);
            assert!(got.stderr.contains(&says), "{base} {args:?}: {}", got.stderr);
            assert!(!got.stderr.contains("Is COS running"), "{base} {args:?}: {}", got.stderr);
        }
        std::fs::remove_file(d.join(".api-credentials.json")).unwrap();
    }

    for base in [format!("http://{host}/API/v1"), format!("http://{host}/Api"), format!("{host}/API/V1/people")] {
        let got = run_bare(&server, d, &["-b", &base, "-k", "k", "GET", "/a"]);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{base}: {}", got.stderr);
    }
}

/// The URL field of the form reads a URL as `-b` does, so it refuses what
/// `-b` refuses: the field stays, with the URL in it to correct.
#[cfg(unix)]
#[test]
fn the_connection_form_refuses_a_url_that_is_not_http() {
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api_bare(dir.path()));
    assert!(
        pump_until(&mut prompt, Duration::from_secs(10), |p| pty::plain(&p.screen).contains("URL")),
        "{}",
        pty::plain(&prompt.screen)
    );
    prompt.pump(Duration::from_millis(400));
    prompt.send(b"ftp://example.com");
    prompt.pump(Duration::from_millis(300));
    let mark = prompt.screen.len();
    prompt.send(b"\r");
    let says = "a base URL starts with http:// or https://, not ftp://";
    let said = pump_until(&mut prompt, Duration::from_secs(4), |p| pty::plain(&p.screen[mark..]).contains(says));
    let shown = pty::plain(&prompt.screen[mark..]);
    assert!(said, "{shown}");
    // Still the URL field: what is typed now is added to the URL.
    let mark = prompt.screen.len();
    prompt.send(b"/more");
    assert!(
        pump_until(&mut prompt, Duration::from_secs(4), |p| pty::plain(&p.screen[mark..]).contains("ftp://example.com/more")),
        "{}",
        pty::plain(&prompt.screen[mark..])
    );
    assert_eq!(prompt.exited(), None);
}

/// `url is` names a base URL, and is read as one: with a trailing slash, the
/// API prefix or a scheme in capitals it is the same URL. `url has` is a
/// piece of text, and matches as written.
#[test]
fn url_is_reads_its_value_as_a_base_url() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let host = format!("127.0.0.1:{}", server.port);
    for value in [
        format!("http://{host}"),
        format!("http://{host}/"),
        format!("HTTP://{host}"),
        format!("http://{host}/api/v1"),
        format!("http://{host}/API/v1/"),
        host.clone(),
    ] {
        let got = run_in(&server, d, &[&format!("url is {value}\nGET /gated")]);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /gated".to_string()][..]), "{value}: {}", got.stderr);
    }
    for line in [
        format!("url is https://{host}"),
        format!("url is http://{host}0"),
        format!("url is http://{host}/tenant"),
        format!("url has {host}/"),
        format!("url has HTTP://{host}"),
    ] {
        let got = run_in(&server, d, &[&format!("{line}\nGET /gated")]);
        assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{line}: {}", got.stderr);
        assert!(got.stderr.contains("URL gate failed"), "{line}: {}", got.stderr);
        // The line is named as it was written.
        assert!(got.stderr.contains(&line), "{line}: {}", got.stderr);
    }
}

/// A byte order mark in front of a file is not part of what the file says:
/// not of the credentials file, and not of a text body, alone or in a glob.
#[test]
fn a_byte_order_mark_is_dropped_from_the_store_and_from_a_text_body() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let sent = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let file = |name: &str, bytes: &[u8]| {
        std::fs::create_dir_all(d.join(name).parent().unwrap()).unwrap();
        std::fs::write(d.join(name), [b"\xEF\xBB\xBF", bytes].concat()).unwrap()
    };

    file("body.json", br#"{"a":1}"#);
    file("rows.csv", b"a,b\n1,2\n");
    file("rows.ndjson", b"{\"a\":1}\n{\"a\":2}\n");
    file("plain", br#"{"a":1}"#);
    for (body, request) in [
        ("@body.json", "PUT /x {\"a\":1}"),
        ("@rows.csv", "PUT /x a,b\n1,2\n"),
        ("@rows.ndjson", "PUT /x {\"a\":1}\n{\"a\":2}\n"),
        ("@plain", "PUT /x {\"a\":1}"),
    ] {
        let got = run_in(&server, d, &["PUT", "/x", body]);
        assert_eq!((got.code, got.sent), (Some(0), sent(&[request])), "{body}: {}", got.stderr);
    }
    // A file that is not text is sent as the bytes it holds.
    file("blob.bin", b"\xFF\x00\x01");
    let got = run_in(&server, d, &["PUT", "/x", "@blob.bin"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert!(got.sent[0].starts_with("PUT /x \u{feff}\u{fffd}"), "{:?}", got.sent);

    // Each file of a glob.
    file("g/1.json", br#"{"a":1}"#);
    file("g/2.json", br#"[{"b":2}]"#);
    let got = run_in(&server, d, &["PUT", "/x", "@g/*.json"]);
    assert_eq!((got.code, got.sent), (Some(0), sent(&[r#"PUT /x [{"a":1},{"b":2}]"#])), "{}", got.stderr);
    file("n/1.ndjson", b"{\"a\":1}\n");
    file("n/2.ndjson", b"{\"b\":2}");
    let got = run_in(&server, d, &["PUT", "/x", "@n/*.ndjson"]);
    assert_eq!((got.code, got.sent), (Some(0), sent(&["PUT /x {\"a\":1}\n{\"b\":2}\n"])), "{}", got.stderr);

    // The credentials file, as an editor on Windows may save it.
    let store = format!(
        r#"{{"connections":[{{"name":"local","url":"http://127.0.0.1:{}","auth_type":"key","credential":"k"}}],"default":"local"}}"#,
        server.port
    );
    std::fs::write(d.join(".api-credentials.json"), format!("\u{feff}{store}")).unwrap();
    let got = run_bare(&server, d, &["GET", "/a"]);
    assert_eq!((got.code, got.sent), (Some(0), sent(&["GET /a"])), "{}", got.stderr);
    assert!(!got.stderr.contains("WARNING"), "{}", got.stderr);
}

/// What a broken or half-written store is said to be, word for word, and
/// what is not worth a word: a file that is not there.
#[test]
fn what_is_wrong_with_the_store_is_said_in_full() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = d.join(".api-credentials.json");
    let url = format!("http://127.0.0.1:{}", server.port);
    let no_base = "Error: no base URL specified. Use -b <url> or -c <connection>.";

    // No file: an empty store, and nothing said about it.
    let got = run_bare(&server, d, &["GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(1), 0));
    assert_eq!(got.stderr.trim(), no_base);

    // A default that names none of the connections.
    write_credentials(d, &[("local", url.clone(), "key", "k", ""), ("stage", url.clone(), "key", "k", "")], "locl");
    let got = run_bare(&server, d, &["GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(1), 0));
    assert_eq!(
        got.stderr.lines().collect::<Vec<_>>(),
        [
            "WARNING: the default connection \"locl\" is not among the saved connections (local, stage). No saved connection is used.",
            no_base
        ]
    );
    // …also when there are none to be among.
    std::fs::write(&file, r#"{"connections":[],"default":"local"}"#).unwrap();
    let got = run_bare(&server, d, &["GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(1), 0));
    assert_eq!(
        got.stderr.lines().collect::<Vec<_>>(),
        ["WARNING: the default connection \"local\" is not among the saved connections (none). No saved connection is used.", no_base]
    );
    // With the connection on the command line there is nothing to warn of.
    let got = run_bare(&server, d, &["-b", &url, "-k", "k", "GET", "/a"]);
    assert_eq!((got.code, got.sent.len(), got.stderr.contains("WARNING")), (Some(0), 1, false), "{}", got.stderr);

    // A trailing comma: the reason, with its place, and the whole sentence.
    std::fs::write(&file, r#"{"connections":[],"default":"local",}"#).unwrap();
    let got = run_bare(&server, d, &["GET", "/a"]);
    assert_eq!((got.code, got.sent.len()), (Some(1), 0));
    assert_eq!(
        got.stderr.lines().collect::<Vec<_>>(),
        [
            &format!(
                "WARNING: could not read {}: it is not what the client wrote there (trailing comma at line 1 column 37). No saved connection is used.",
                ".api-credentials.json"
            )[..],
            no_base
        ]
    );
}

/// A response whose bytes are not all of its charset is shown and written
/// with U+FFFD in their place. That is said, once for the response.
#[test]
fn a_response_with_bytes_its_charset_does_not_have_is_said_to_be_changed() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let says = "WARNING: the response held bytes that are not valid UTF-8: each is now U+FFFD (\u{fffd})";
    let warnings = |stderr: &str| stderr.matches("WARNING").count();

    let got = run_in(&server, d, &["GET", "/notutf8"]);
    assert_eq!((got.code, got.stdout.trim()), (Some(0), "\"caf\u{fffd} x\""), "{}", got.stderr);
    assert!(got.stderr.contains(says), "{}", got.stderr);
    assert_eq!(warnings(&got.stderr), 1, "{}", got.stderr);

    // To a file, in a batch, and with `-s`: it is a warning, not a note.
    std::fs::write(d.join("b.api"), "GET /notutf8 > b.json\nGET /a\n").unwrap();
    for args in [&["GET", "/notutf8", ">", "f.json"][..], &["-s", "GET", "/notutf8", ">", "f.json"], &["-sa", "b.api"], &["-a", "b.api"]] {
        let got = run_in(&server, d, args);
        assert_eq!(got.code, Some(0), "{args:?}: {}", got.stderr);
        assert!(got.stderr.contains(says), "{args:?}: {}", got.stderr);
        assert_eq!(warnings(&got.stderr), 1, "{args:?}: {}", got.stderr);
    }
    assert_eq!(std::fs::read_to_string(d.join("f.json")).unwrap().trim(), "\"caf\u{fffd} x\"");
    assert_eq!(std::fs::read_to_string(d.join("b.json")).unwrap().trim(), "\"caf\u{fffd} x\"");

    // Nothing for a response that is what it says, nor for a check, whose
    // body goes nowhere, nor for a `-sa` line without an outfile.
    std::fs::write(d.join("shown.api"), "GET /notutf8\nGET /a\n").unwrap();
    for args in [&["GET", "/a"][..], &["assert GET /notutf8"], &["-sa", "shown.api"]] {
        let got = run_in(&server, d, args);
        assert_eq!((got.code, warnings(&got.stderr)), (Some(0), 0), "{args:?}: {}", got.stderr);
    }
}

#[cfg(unix)]
#[test]
fn the_prompt_says_that_a_response_had_bytes_replaced() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    let says = "response had bytes that are not valid UTF-8, now U+FFFD";
    let shown = enter_line(&mut prompt, "GET /notutf8", says);
    assert!(shown.contains(says), "{shown}");
    let shown = enter_line(&mut prompt, "GET /notutf8 > f.json", says);
    assert!(shown.contains(says), "{shown}");
    prompt.pump(Duration::from_millis(3300));
    let shown = enter_line(&mut prompt, "GET /a", "/api/v1/a");
    assert!(!shown.contains(says), "{shown}");
}

// ----- documented behaviour that nothing else pinned -----

/// `--export` and a `set export` line rewrite responses. A request body is sent
/// as it is written, a database key and a masked value in it included.
#[test]
fn a_request_body_is_never_rewritten_by_export() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    const BODY: &str = r#"{"identifiers": {"key":"k1"},  "secret":"********", "password": null}"#;
    let request = format!("PUT /x {BODY}");
    let sent = [request.clone()];
    std::fs::write(d.join("flag.api"), format!("{request}\n")).unwrap();
    std::fs::write(d.join("line.api"), format!("set export com.heads.seedID\n{request}\n")).unwrap();
    std::fs::write(d.join("body.json"), BODY).unwrap();

    for args in [
        &["--export", "com.heads.seedID", "PUT", "/x", BODY][..],
        &["--export", "com.heads.seedID", &request],
        &["--export", "com.heads.seedID", "PUT", "/x", "@body.json"],
        &["--export", "com.heads.seedID", "-sa", "flag.api"],
        &["-sa", "line.api"],
        &[&format!("set export com.heads.seedID\n{request}")],
    ] {
        let got = run_in(&server, d, args);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &sent[..]), "{args:?}: {}", got.stderr);
    }
    // And from stdin, as the body and as the program.
    for (args, stdin) in [(&["--export", "com.heads.seedID", "PUT", "/x"][..], BODY.to_string()), (&["-sa", "-"], format!("set export com.heads.seedID\n{request}\n"))]
    {
        server.take();
        let mut cmd = api(server.port, d);
        cmd.args(args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().expect("spawn api");
        child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        let out = child.wait_with_output().expect("api runs");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        assert_eq!((out.status.code(), &server.take()[..]), (Some(0), &sent[..]), "{args:?}");
    }
}

/// A `url` line gates the whole batch from wherever it stands: in a file
/// that is only included, too.
#[test]
fn a_url_line_in_an_included_file_gates_the_batch() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::create_dir_all(d.join("shared")).unwrap();
    std::fs::write(d.join("main.api"), "GET /own\nshared/gated.api\nGET /last\n").unwrap();
    std::fs::write(d.join("shared/gated.api"), "url has nomatch.example\nGET /included\n").unwrap();
    for args in [&["-sa", "main.api"][..], &["-a", "main.api"], &["main.api"]] {
        let got = run_in(&server, d, args);
        assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{args:?}: {}", got.stderr);
        assert!(got.stderr.contains("URL gate failed"), "{args:?}: {}", got.stderr);
        assert!(got.stderr.contains("url has nomatch.example"), "{args:?}: {}", got.stderr);
        assert_eq!(got.stdout, "", "{args:?}");
    }
    // A line that fits lets it all through.
    std::fs::write(d.join("shared/gated.api"), format!("url has 127.0.0.1:{}\nGET /included\n", server.port)).unwrap();
    let got = run_in(&server, d, &["-sa", "main.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert_eq!(got.sent, ["GET /own", "GET /included", "GET /last"]);
}

/// A batch that can't be run is refused when it is read: exit 1, the reason,
/// and none of its requests sent, the ones above the fault included. No
/// request is the point, so the base URL is the recording server and never a
/// host that would take one.
#[test]
fn a_batch_that_cannot_run_exits_one_and_sends_none_of_it() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = |name: &str, text: &str| std::fs::write(d.join(name), text).unwrap();
    // An allowlist of two, neither of which is where the client points.
    file("gated.api", "url has test.app.example.invalid\nurl has localhost:5000\nGET /first\n");
    file("a.api", "GET /first\nb.api\n");
    file("b.api", "a.api\n");
    file("lost.api", "GET /first\nmissing.api\n");
    file("badsleep.api", "GET /first\nsleep abc\n");
    for (name, says) in [
        ("gated.api", "URL gate failed"),
        ("a.api", "include loop"),
        ("lost.api", "include not found"),
        ("badsleep.api", "invalid sleep duration"),
    ] {
        for flags in ["-a", "-sa", "-sfa"] {
            let got = run_in(&server, d, &[flags, name]);
            assert_eq!((got.code, &got.sent), (Some(1), &Vec::new()), "{flags} {name}: {}", got.stderr);
            assert!(got.stderr.contains(says), "{flags} {name}: {}", got.stderr);
        }
    }
    // The server is there and takes what a batch that can run sends.
    file("fine.api", "GET /first\n");
    let got = run_in(&server, d, &["-sa", "fine.api"]);
    assert_eq!((got.code, got.sent), (Some(0), vec!["GET /first".to_string()]), "{}", got.stderr);
}

/// Under a `set export` line a request is not streamed, as under `--export`:
/// the whole body is needed. The requests around the line are.
#[test]
fn a_request_under_a_set_export_line_is_not_streamed() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(
        d.join("e.api"),
        "GET /a > before.json\nset export com.heads.seedID\nGET /keyed > keyed.json\nset export off\nGET /b > after.json\n",
    )
    .unwrap();
    let got = run_in(&server, d, &["--stream", "-sa", "e.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert_eq!(got.sent, ["GET /a", "GET /keyed", "GET /b"]);
    let streamed: Vec<bool> = server.heads().iter().map(|head| head.contains("stream=true")).collect();
    assert_eq!(streamed, [true, false, true], "{:?}", server.heads());
    let keyed: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(d.join("keyed.json")).unwrap()).unwrap();
    assert_eq!(keyed["identifiers"], serde_json::json!({"key?": "k1", "com.heads.seedID": "k1"}));
    assert!(keyed.get("secret").is_none(), "{keyed}");
}

/// `set include-nulls` is `-i` for the requests under it in its own file:
/// from the line down, to `off` or the end of the file, and not in a file
/// that is included. `-i` holds for the whole run, whatever a line says.
#[test]
fn a_set_line_holds_from_the_line_down_in_its_own_file() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(
        d.join("main.api"),
        "GET /a\nset include-nulls\nGET /b\nplain.api\nown.api\nGET /c && GET /d\nassert GET /e\nset include-nulls off\nGET /f\n",
    )
    .unwrap();
    std::fs::write(d.join("plain.api"), "GET /plain\n").unwrap();
    std::fs::write(d.join("own.api"), "GET /own-before\nSET INCLUDE-NULLS ON\nGET /own\n").unwrap();
    let sent = ["GET /a", "GET /b", "GET /plain", "GET /own-before", "GET /own", "GET /c", "GET /d", "GET /e", "GET /f"];
    let nulls = |server: &RecordingServer| -> Vec<bool> {
        server.heads().iter().map(|head| accept_of(head).contains(";skipNulls=false")).collect()
    };

    let got = run_in(&server, d, &["-sa", "main.api"]);
    assert_eq!((got.code, &got.sent[..]), (Some(0), &sent.map(String::from)[..]), "{}", got.stderr);
    assert_eq!(nulls(&server), [false, true, false, false, true, true, true, true, false], "{:?}", server.heads());
    // The log has each line where it is written, as it is shortest written.
    let lines: Vec<&str> = got.stdout.lines().filter(|line| line.starts_with("set ")).collect();
    assert_eq!(lines, ["set include-nulls", "set include-nulls", "set include-nulls off"], "{}", got.stdout);
    assert!(!got.stdout.contains("ignored"), "{}", got.stdout);

    // `-i` is for every request, and the line that would turn it off says
    // that it did not. A line that asks for what holds has nothing to say.
    let got = run_in(&server, d, &["-i", "-sa", "main.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), sent.len()), "{}", got.stderr);
    assert_eq!(nulls(&server), [true; 9], "{:?}", server.heads());
    assert_eq!(got.stdout.matches("↳ ignored: -i is set").count(), 1, "{}", got.stdout);
    assert!(got.stdout.contains("set include-nulls off\n↳ ignored: -i is set"), "{}", got.stdout);

    // From stdin and as one argument a line is a line of the program.
    for args in [&["-sa", "-"][..], &["set include-nulls\nGET /b\nset include-nulls off\nGET /f"]] {
        server.take();
        let mut cmd = api(server.port, d);
        cmd.args(args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().expect("spawn api");
        child.stdin.take().unwrap().write_all(b"set include-nulls\nGET /b\nset include-nulls off\nGET /f\n").unwrap();
        let out = child.wait_with_output().expect("api runs");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert_eq!(nulls(&server), [true, false], "{args:?}");
    }
}

/// Each setting does under its line what its option does for a run.
#[cfg(unix)]
#[test]
fn every_setting_does_what_its_option_does() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = |text: &str| std::fs::write(d.join("s.api"), text).unwrap();
    let accepts = |server: &RecordingServer| -> Vec<String> { server.heads().iter().map(|head| accept_of(head)).collect() };

    // ndjson and stream are in what the request asks for.
    file("GET /a\nset ndjson\nGET /b\nset ndjson off\nset stream\nGET /c > c.json\nset stream off\nGET /d > d.json\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert_eq!(
        accepts(&server),
        ["application/json", "application/x-ndjson", "application/json;stream=true", "application/json"],
        "{:?}",
        server.heads()
    );
    // `--no-streaming` is the one option that keeps a setting off.
    let got = run_in(&server, d, &["--no-streaming", "-sa", "s.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert!(accepts(&server).iter().all(|accept| !accept.contains("stream=true")), "{:?}", server.heads());
    assert!(got.stdout.contains("set stream\n↳ ignored: --no-streaming is set"), "{}", got.stdout);
    assert_eq!(got.stdout.matches("ignored").count(), 1, "{}", got.stdout);
    // The options that are on stay on, and each is named as it was given.
    let got = run_in(&server, d, &["--ndjson", "--stream", "-sa", "s.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert!(got.stdout.contains("set ndjson off\n↳ ignored: --ndjson is set"), "{}", got.stdout);
    assert!(got.stdout.contains("set stream off\n↳ ignored: --stream is set"), "{}", got.stdout);
    assert_eq!(got.stdout.matches("ignored").count(), 2, "{}", got.stdout);
    let mut cmd = api(server.port, d);
    cmd.env("API_STREAMING", "1").args(["-sa", "s.api"]);
    let got = ran(&server, cmd);
    assert!(got.stdout.contains("set stream off\n↳ ignored: API_STREAMING is set"), "{}", got.stdout);

    // raw: a file holds the body as the server sent it, not laid out.
    file("GET /keyed > laid-out.json\nset raw\nGET /keyed > raw.json\nset raw off\nGET /keyed > again.json\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    let lines = |name: &str| std::fs::read_to_string(d.join(name)).unwrap().trim_end().lines().count();
    assert!(lines("laid-out.json") > 1 && lines("again.json") > 1);
    assert_eq!(lines("raw.json"), 1);

    // fail-fast: the first failed request under the line ends the run, with
    // its body last on stdout. Above the line a failure is passed.
    file("GET /missing\nset fail-fast\nGET /gone\nGET /never\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!((got.code, &got.sent[..]), (Some(1), &["GET /missing".to_string(), "GET /gone".to_string()][..]), "{}", got.stderr);
    assert!(got.stdout.trim_end().ends_with(GONE.trim_end()), "{}", got.stdout);
    // It is the file's own: a failure in an included file is passed, as
    // without the line, and one after it is not.
    std::fs::write(d.join("inc.api"), "GET /missing\nGET /in-inc\n").unwrap();
    file("set fail-fast\ninc.api\nGET /conflict\nGET /never\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!((got.code, &got.sent[..]), (Some(1), &["GET /missing", "GET /in-inc", "GET /conflict"].map(String::from)[..]), "{}", got.stderr);
    // And off again.
    file("set fail-fast\nset fail-fast off\nGET /missing\nGET /after\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 2), "{}", got.stderr);

    // timeout: a request under the line is given up on after that long.
    file("set timeout 1\nGET /stall\nGET /never\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!((got.code, &got.sent[..]), (Some(1), &["GET /stall".to_string()][..]), "{}", got.stderr);
    assert!(got.stderr.contains("Timed out after 1s"), "{}", got.stderr);
    // `--timeout` is the run's, and the line says that it was passed over.
    file("set timeout 600\nGET /stall\nGET /never\n");
    let got = run_in(&server, d, &["--timeout", "1", "-sa", "s.api"]);
    assert_eq!(got.code, Some(1), "{}", got.stderr);
    assert!(got.stderr.contains("Timed out after 1s"), "{}", got.stderr);
    assert!(got.stdout.contains("set timeout 600\n↳ ignored: --timeout 1 is set"), "{}", got.stdout);

    // The preview lists every line and counts none of them.
    file("set include-nulls on\nset timeout off\nset export a.b.c\nGET /a\n");
    let mut cmd = api(server.port, d);
    cmd.args(["-spa", "s.api"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    server.take();
    let mut child = cmd.spawn().expect("spawn api");
    child.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let out = child.wait_with_output().expect("api runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Preview — 1 request | GET"), "{stderr}");
    assert!(stderr.contains("  set include-nulls\n  set timeout off\n  set export a.b.c\n  GET /a\n"), "{stderr}");
    assert_eq!(server.take(), Vec::<String>::new());
}

/// A request that times out got no answer. In a chain, a poll or an assert
/// that is not a "no": the run ends there with exit 1.
#[test]
fn a_timeout_in_a_chain_or_a_check_ends_the_run() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for (program, sent) in [
        ("GET /stall && GET /never", &["GET /stall"][..]),
        ("GET /stall || GET /never", &["GET /stall"]),
        ("GET /a && GET /stall || GET /never", &["GET /a", "GET /stall"]),
        ("sleep 1 while GET /stall", &["GET /stall"]),
        ("sleep 1 while not GET /stall", &["GET /stall"]),
        ("assert GET /stall", &["GET /stall"]),
        ("assert not GET /stall", &["GET /stall"]),
    ] {
        std::fs::write(d.join("t.api"), format!("{program}\nGET /never\n")).unwrap();
        for flags in ["-sa", "-sfa"] {
            let got = run_in(&server, d, &["--timeout", "1", flags, "t.api"]);
            assert_eq!((got.code, &got.sent[..]), (Some(1), &sent.iter().map(|s| s.to_string()).collect::<Vec<_>>()[..]), "{program} {flags}: {}", got.stderr);
            assert!(got.stderr.contains("Timed out after 1s"), "{program} {flags}: {}", got.stderr);
        }
    }
}

/// Every segment of a chain is a request. An include or a directive in one
/// is an error before anything is sent, not a step that is dropped.
#[test]
fn an_include_or_a_directive_in_a_chain_is_an_error() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("seed.api"), "GET /seeded\n").unwrap();
    for (line, segment) in [
        ("GET /a && seed.api", "seed.api"),
        ("GET /a && GET /b || seed.api", "seed.api"),
        ("GET /a || sleep 2", "sleep 2"),
        ("GET /a && assert GET /b", "assert GET /b"),
    ] {
        std::fs::write(d.join("c.api"), format!("GET /first\n{line}\nGET /last\n")).unwrap();
        for args in [&["-sa", "c.api"][..], &[line]] {
            let got = run_in(&server, d, args);
            assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{args:?}: {}", got.stderr);
            assert_eq!(got.stderr.trim(), format!("error: chain segment is not a request: `{segment}`"), "{args:?}");
        }
    }
}

/// `~/` is the home directory in an outfile and in an include line, wherever
/// the client is run from.
#[test]
fn a_tilde_path_is_in_the_home_directory() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let work = home.join("work");
    std::fs::create_dir_all(home.join("seeds")).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(home.join("seeds/one.api"), "GET /from-home\n").unwrap();
    std::fs::write(home.join("body.json"), r#"{"from":"home"}"#).unwrap();
    std::fs::write(work.join("t.api"), "~/seeds/one.api\n~/seeds/*.api\nPUT /x @~/body.json\nGET /a > ~/out.json\nGET /a >> ~/more.json\n").unwrap();
    let run = |args: &[&str]| {
        let mut cmd = api(server.port, home);
        cmd.current_dir(&work).args(args);
        ran(&server, cmd)
    };

    let got = run(&["-sa", "t.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert_eq!(got.sent, ["GET /from-home", "GET /from-home", r#"PUT /x {"from":"home"}"#, "GET /a", "GET /a"]);
    // Logged as written, written where it says.
    assert!(got.stdout.contains("\nGET /a > ~/out.json\n"), "{}", got.stdout);
    assert_eq!(left_in(home), ["body.json", "more.json", "out.json", "seeds", "work"]);
    assert_eq!(left_in(&work), ["t.api"]);

    // As arguments, and as the file to run.
    std::fs::remove_file(home.join("out.json")).unwrap();
    let got = run(&["GET", "/a", ">", "~/out.json"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert!(home.join("out.json").is_file());
    for args in [&["-sa", "~/seeds/one.api"][..], &["~/seeds/one.api"]] {
        let got = run(args);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /from-home".to_string()][..]), "{args:?}: {}", got.stderr);
    }
    assert_eq!(left_in(&work), ["t.api"]);
}

/// A connection given whole on the command line is used and not saved:
/// without a credentials file there is none afterwards either.
#[test]
fn a_connection_from_the_command_line_creates_no_credentials_file() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    std::fs::write(d.join("one.api"), "GET /a\n").unwrap();
    for args in [&["GET", "/a"][..], &["-sa", "one.api"], &["GET /a && GET /a"], &["--token", "t", "GET", "/a"]] {
        let mut all = vec!["-b", url.as_str(), "-k", "k"];
        all.extend_from_slice(args);
        let got = run_bare(&server, d, &all);
        assert_eq!((got.code, got.sent.is_empty()), (Some(0), false), "{all:?}: {}", got.stderr);
        let left: Vec<String> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
        assert_eq!(left, ["one.api"], "{all:?}");
    }
    // Nor at a path the variable names.
    let named = d.join("named-credentials.json");
    let mut cmd = api_bare(d);
    cmd.env("API_CREDENTIALS_FILE", &named).args(["-b", &url, "-k", "k", "GET", "/a"]);
    let got = ran(&server, cmd);
    assert_eq!((got.code, got.sent.len()), (Some(0), 1), "{}", got.stderr);
    assert!(!named.exists());
}

/// A file body that is not there, or a glob that matches nothing, is a hard
/// error in a batch: exit 1 at that line, with the lines before it sent and
/// the lines after it not.
#[test]
fn a_missing_file_body_stops_a_batch_where_it_stands() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::create_dir_all(d.join("empty")).unwrap();
    for (line, says) in [
        ("PUT /x @no-such-file.json", "File not found: no-such-file.json"),
        ("PUT /x @empty/*.json", "no files match: empty/*.json"),
        ("PUT /x @no-such-dir/*.ndjson", "no files match: no-such-dir/*.ndjson"),
        ("GET /a && PUT /x @no-such-file.json", "File not found: no-such-file.json"),
    ] {
        std::fs::write(d.join("m.api"), format!("GET /before\n{line}\nGET /after\n")).unwrap();
        let chained = line.starts_with("GET");
        for flags in ["-sa", "-a", "-sfa"] {
            let got = run_in(&server, d, &[flags, "m.api"]);
            let sent: &[&str] = if chained { &["GET /before", "GET /a"] } else { &["GET /before"] };
            assert_eq!((got.code, &got.sent[..]), (Some(1), &sent.iter().map(|s| s.to_string()).collect::<Vec<_>>()[..]), "{line} {flags}: {}", got.stderr);
            assert!(got.stderr.contains(says), "{line} {flags}: {}", got.stderr);
        }
    }
}

/// A describe block that is not the shape it should be is warned about, one
/// line for each thing, and the batch runs.
#[test]
fn a_describe_block_that_is_off_in_shape_warns_and_the_batch_runs() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(
        d.join("d.api"),
        "# Catalog\n{\n  \"title\": { \"sv_SE\": \"Katalog\", \"en-US\": \"Catalog\" },\n  \"description\": \"x\",\n  \"docsLink\": \"ftp://docs\",\n  \"owner\": \"me\"\n}\nGET /a\n",
    )
    .unwrap();
    let got = run_in(&server, d, &["-sa", "d.api"]);
    assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /a".to_string()][..]), "{}", got.stderr);
    assert_eq!(
        got.stderr.lines().collect::<Vec<_>>(),
        [
            "warning: describe block: title/sv_SE is not a locale",
            "warning: describe block: description is not an object of texts by locale, like { \"sv-SE\": \"…\" }",
            "warning: describe block: docsLink is not an http(s) link",
            "warning: describe block: owner is not a member of a describe block (title, description, docsLink)",
        ]
    );
    // The log is the log of a run without one.
    assert_eq!(got.stdout.lines().filter(|l| !l.starts_with("└─")).collect::<Vec<_>>(), [&format!("[http://127.0.0.1:{}]", server.port)[..], "GET /a"]);
}

/// A passing `PUT /assert` answers `200` with `null`, and `null` is falsy:
/// chained, it skips what follows; behind the `assert` keyword it fails.
#[test]
fn a_passing_assert_request_is_falsy_to_a_chain_and_to_the_assert_keyword() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    const CHECK: &str = r#"PUT /assert {"api/v1/people~count":{"is":3}}"#;
    std::fs::write(d.join("chain.api"), format!("{CHECK} && PUT /x {{\"a\":1}}\nGET /after\n")).unwrap();
    for flags in ["-sa", "-sfa"] {
        let got = run_in(&server, d, &[flags, "chain.api"]);
        assert_eq!((got.code, &got.sent[..]), (Some(0), &[CHECK.to_string(), "GET /after".to_string()][..]), "{flags}: {}", got.stderr);
        assert!(got.stdout.contains("↳ skipped 1 request"), "{flags}: {}", got.stdout);
    }
    std::fs::write(d.join("keyword.api"), format!("assert {CHECK}\nGET /never\n")).unwrap();
    let got = run_in(&server, d, &["-sa", "keyword.api"]);
    assert_eq!((got.code, &got.sent[..]), (Some(1), &[CHECK.to_string()][..]), "{}", got.stderr);
    assert!(got.stderr.contains(&format!("assertion failed: assert {CHECK} (null)")), "{}", got.stderr);
    // On a line of its own it is a request that went well.
    std::fs::write(d.join("own.api"), format!("{CHECK}\nPUT /x {{\"a\":1}}\n")).unwrap();
    let got = run_in(&server, d, &["-sfa", "own.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 2), "{}", got.stderr);
}

/// Under `-f`, a check that gets a status which is never an answer ends the
/// run with that response's body last on stdout. A 409 where a question was
/// asked is the answer "no", and the run goes on.
#[test]
fn fail_fast_prints_the_body_of_a_check_that_got_no_answer_and_lets_a_no_pass() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for (path, status, body) in [
        ("/denied", "401 Unauthorized", r#"{"error":"denied"}"#),
        ("/barred", "403 Forbidden", r#"{"error":"barred"}"#),
        ("/boom", "500 Internal Server Error", "{}"),
    ] {
        for check in [format!("assert GET {path}"), format!("assert not GET {path}"), format!("sleep 1 while GET {path}"), format!("sleep 1 while not GET {path}")] {
            std::fs::write(d.join("f.api"), format!("GET /before\n{check}\nGET /never\n")).unwrap();
            let got = run_in(&server, d, &["-sfa", "f.api"]);
            assert_eq!((got.code, &got.sent[..]), (Some(1), &["GET /before".to_string(), format!("GET {path}")][..]), "{check}: {}", got.stderr);
            assert!(got.stderr.contains("could not be evaluated"), "{check}: {}", got.stderr);
            assert!(got.stderr.trim_end().ends_with(", aborting"), "{check}: {}", got.stderr);
            // Everything after the last status line is the body.
            let last = got.stdout.rfind("└─HTTP/1.1 ").unwrap_or_else(|| panic!("{check}: {}", got.stdout));
            let (status_line, rest) = got.stdout[last..].split_once('\n').unwrap();
            assert!(status_line.contains(status), "{check}: {}", got.stdout);
            assert_eq!(rest.trim_end(), body, "{check}: {}", got.stdout);
        }
    }

    // A 409 as the answer to a question.
    std::fs::write(
        d.join("no.api"),
        "GET /conflict || GET /then\nGET /conflict && GET /skipped\nassert not GET /conflict\nsleep 1 while GET /conflict\nGET /after\n",
    )
    .unwrap();
    let got = run_in(&server, d, &["-sfa", "no.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert_eq!(got.sent, ["GET /conflict", "GET /then", "GET /conflict", "GET /conflict", "GET /conflict", "GET /after"]);
    assert!(!got.stdout.contains("\"error\""), "{}", got.stdout);
    // The last request of a chain asks nothing: there a 409 stops the run.
    std::fs::write(d.join("last.api"), "GET /a && GET /conflict\nGET /never\n").unwrap();
    let got = run_in(&server, d, &["-sfa", "last.api"]);
    assert_eq!((got.code, &got.sent[..]), (Some(1), &["GET /a".to_string(), "GET /conflict".to_string()][..]), "{}", got.stderr);
    assert!(got.stdout.trim_end().ends_with(r#"{"error":"conflict"}"#), "{}", got.stdout);
}

/// A declined `confirm` says `aborted`, and the `-sa` log has the line.
#[cfg(unix)]
#[test]
fn a_declined_confirm_says_aborted_and_the_log_has_the_line() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("c.api"), "GET /before\nconfirm Really?\nconfirm\nGET /after\n").unwrap();

    server.take();
    let mut cmd = api(server.port, dir.path());
    cmd.args(["-sa", "c.api"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let run = |cmd: &mut std::process::Command, answers: &str| {
        let mut child = cmd.spawn().expect("spawn api");
        child.stdin.take().unwrap().write_all(answers.as_bytes()).unwrap();
        let out = child.wait_with_output().expect("api runs");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        (out.status.code(), String::from_utf8_lossy(&out.stdout).to_string(), String::from_utf8_lossy(&out.stderr).to_string(), server.take())
    };

    let (code, stdout, stderr, sent) = run(&mut cmd, "y\nn\n");
    assert_eq!((code, &sent[..]), (Some(0), &["GET /before".to_string()][..]), "{stderr}");
    // Both questions, on the line the answers left them on, and the verdict.
    assert_eq!(stderr.trim_end(), "Really? [Y/n] Continue? [Y/n] aborted");
    let log: Vec<&str> = stdout.lines().filter(|l| !l.starts_with("└─")).collect();
    assert_eq!(log, [&format!("[http://127.0.0.1:{}]", server.port)[..], "GET /before", "confirm Really?", "confirm"], "{stdout}");

    let (code, stdout, stderr, sent) = run(&mut cmd, "\n\n");
    assert_eq!((code, &sent[..]), (Some(0), &["GET /before".to_string(), "GET /after".to_string()][..]), "{stderr}");
    assert!(!stderr.contains("aborted"), "{stderr}");
    let log: Vec<&str> = stdout.lines().filter(|l| !l.starts_with("└─")).collect();
    assert_eq!(log[1..], ["GET /before", "confirm Really?", "confirm", "GET /after"], "{stdout}");
}

/// At the prompt a `confirm` is answered with a key: Enter goes on, esc does
/// not, and the session stays either way.
#[cfg(unix)]
#[test]
fn a_confirm_at_the_prompt_takes_enter_for_yes_and_esc_for_no() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    for (key, sent) in [(&b"\r"[..], &["GET /before", "GET /after"][..]), (b"\x1b", &["GET /before"]), (b"y", &["GET /before", "GET /after"]), (b"n", &["GET /before"])] {
        prompt.send(b"\x15");
        prompt.pump(Duration::from_millis(60));
        server.take();
        prompt.paste("GET /before\rconfirm Really\rGET /after");
        prompt.pump(Duration::from_millis(80));
        let mark = prompt.screen.len();
        prompt.send(b"\r");
        assert!(
            pump_until(&mut prompt, Duration::from_secs(5), |p| pty::plain(&p.screen[mark..]).contains("Really? (Y/n)")),
            "{}",
            pty::plain(&prompt.screen[mark..])
        );
        assert_eq!(server.log.lock().unwrap().clone(), ["GET /before"]);
        prompt.send(key);
        pump_until(&mut prompt, Duration::from_secs(2), |_| server.seen() == sent.len());
        prompt.pump(Duration::from_millis(400));
        assert_eq!(server.take(), sent, "{key:?}: {}", pty::plain(&prompt.screen[mark..]));
        assert_eq!(prompt.exited(), None, "{key:?}");
    }
}

/// The `-sa` log names the environment once, however many files and requests
/// the run has. `-s` on a single request keeps the size line of an outfile
/// to itself.
#[test]
fn the_silent_log_names_the_base_once_and_s_drops_the_outfile_line() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let base = format!("[http://127.0.0.1:{}]", server.port);
    std::fs::write(d.join("main.api"), "GET /a\ninc.api\nGET /a && GET /b\ninc.api\nGET /c > c.json\n").unwrap();
    std::fs::write(d.join("inc.api"), "GET /inc\n").unwrap();
    let got = run_in(&server, d, &["-sa", "main.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 6), "{}", got.stderr);
    assert_eq!(got.stdout.lines().next(), Some(&base[..]));
    assert_eq!(got.stdout.matches(&base).count(), 1, "{}", got.stdout);
    assert_eq!(got.stdout.matches("127.0.0.1").count(), 1, "{}", got.stdout);

    // The size line: there for a request, and under the status line of a
    // batch line; gone with `-s`, where the file is still written.
    let shown = run_in(&server, d, &["GET", "/a", ">", "one.json"]);
    assert!(shown.stderr.contains("> one.json ("), "{}", shown.stderr);
    let batch = run_in(&server, d, &["-a", "main.api"]);
    assert!(batch.stderr.contains("> c.json ("), "{}", batch.stderr);
    std::fs::remove_file(d.join("one.json")).unwrap();
    let silent = run_in(&server, d, &["-s", "GET", "/a", ">", "one.json"]);
    assert_eq!((silent.code, silent.stdout.as_str(), silent.stderr.as_str()), (Some(0), "", ""));
    assert!(d.join("one.json").is_file());
    let silent = run_in(&server, d, &["-s", "GET", "/a", ">>", "one.json"]);
    assert_eq!((silent.code, silent.stdout.as_str(), silent.stderr.as_str()), (Some(0), "", ""));
}

/// A request that is sent on with a 307 arrives as the request it was: the
/// method, the body and the credential.
#[test]
fn a_redirected_request_keeps_its_method_body_and_authorization() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("r.api"), "PUT /moved {\"x\":1}\n").unwrap();
    for args in [&["PUT", "/moved", "{\"x\":1}"][..], &["-sa", "r.api"]] {
        let got = run_in(&server, d, args);
        assert_eq!(got.code, Some(0), "{args:?}: {}", got.stderr);
        assert_eq!(got.sent, ["PUT /moved {\"x\":1}", "PUT /landed {\"x\":1}"], "{args:?}");
        let heads = server.heads();
        assert_eq!(heads[0], heads[1], "{args:?}");
        assert!(heads[1].contains("content-type=application/json; authorization=Basic Oms=;"), "{args:?}: {heads:?}");
    }
    let got = run_in(&server, d, &["PATCH", "/moved", "{\"y\":2}"]);
    assert_eq!(got.sent, ["PATCH /moved {\"y\":2}", "PATCH /landed {\"y\":2}"]);
    assert!(got.stdout.contains("/api/v1/landed"), "{}", got.stdout);
}

/// A write that is answered with a 301, a 302 or a 303 is not sent on: what
/// would arrive is a `GET` without the body, and its 200 would stand under
/// the write in the log. The redirect is the answer, and `-f` stops at it.
/// A `GET` is sent on as before.
#[test]
fn a_write_is_not_sent_on_by_a_redirect_that_would_make_it_a_get() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for status in ["301", "302", "303"] {
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let write = format!("{method} /old{status} {{\"x\":1}}");
            std::fs::write(d.join("r.api"), format!("{write}\nGET /after\n")).unwrap();
            let got = run_in(&server, d, &["-sa", "r.api"]);
            assert_eq!(got.code, Some(0), "{write}: {}", got.stderr);
            assert_eq!(got.sent, [write.as_str(), "GET /after"], "{write}");
            assert!(got.stdout.contains(&format!("HTTP/1.1 {status} ")), "{write}: {}", got.stdout);

            let got = run_in(&server, d, &["-sfa", "r.api"]);
            assert_eq!(got.code, Some(1), "{write}: {}", got.stdout);
            assert_eq!(got.sent, [write.as_str()], "{write}");
        }
        let got = run_in(&server, d, &["-f", "PUT", &format!("/old{status}"), "{\"x\":1}"]);
        assert_eq!((got.code, got.sent.len()), (Some(1), 1), "{status}: {}", got.stderr);
        // A read is carried on, and is the answer it gets there.
        for method in ["GET", "HEAD"] {
            let got = run_in(&server, d, &["-f", method, &format!("/old{status}")]);
            assert_eq!(got.code, Some(0), "{method} {status}: {}", got.stderr);
            assert_eq!(got.sent, [format!("{method} /old{status}"), format!("{method} /landed")], "{status}");
        }
    }
    // In a chain a redirect that was not followed is a "no", as a 404 is.
    let got = run_in(&server, d, &[r#"PUT /old301 {"x":1} || GET /else"#]);
    assert_eq!(got.sent, [r#"PUT /old301 {"x":1}"#, "GET /else"], "{}", got.stderr);
}

/// A request whose answer is read whole does not ask for it to be streamed:
/// a streamed answer can hold an error behind a 200, which a `>>` would
/// then add to its file and an `assert` take for a yes.
#[test]
fn a_request_that_is_read_whole_does_not_ask_for_a_stream() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(
        d.join("s.api"),
        "GET /a >> all.json\nassert GET /b\nsleep 100ms while not GET /c\nGET /d > one.json\nGET /e\n",
    )
    .unwrap();
    let got = run_in(&server, d, &["--stream", "-sa", "s.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 5), "{}", got.stderr);
    let json = "application/json";
    let streamed = "application/json;stream=true";
    assert_eq!(accepts_of(&server), [json, json, json, streamed, streamed]);
    // One request, the same.
    for (args, asked) in [(&["GET", "/a", ">>", "all.json"][..], json), (&["GET", "/a", ">", "one.json"], streamed), (&["assert GET /a"], json)] {
        let mut with = vec!["--stream"];
        with.extend_from_slice(args);
        let got = run_in(&server, d, &with);
        assert_eq!(got.code, Some(0), "{args:?}: {}", got.stderr);
        assert_eq!(accepts_of(&server), [asked], "{args:?}");
    }
}

/// A file body is the file that is named when there is one, whatever its
/// name holds, and a file that can't be read is said to be that.
#[test]
fn a_file_body_named_like_a_pattern_is_that_file_and_a_directory_is_no_missing_file() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("export[1].json"), r#"{"n":1}"#).unwrap();
    std::fs::write(d.join("export1.json"), r#"{"n":"other"}"#).unwrap();
    std::fs::write(d.join("what?.json"), r#"{"n":2}"#).unwrap();
    std::fs::create_dir_all(d.join("folder")).unwrap();

    let got = run_in(&server, d, &["PUT", "/x", "@export[1].json"]);
    assert_eq!((got.code, got.sent), (Some(0), vec![r#"PUT /x {"n":1}"#.to_string()]), "{}", got.stderr);
    let got = run_in(&server, d, &["PUT", "/x", "@what?.json"]);
    assert_eq!((got.code, got.sent), (Some(0), vec![r#"PUT /x {"n":2}"#.to_string()]), "{}", got.stderr);
    // With no file of that name it is the pattern it also is.
    std::fs::remove_file(d.join("export[1].json")).unwrap();
    let got = run_in(&server, d, &["PUT", "/x", "@export[1].json"]);
    assert_eq!((got.code, got.sent), (Some(0), vec![r#"PUT /x [{"n":"other"}]"#.to_string()]), "{}", got.stderr);

    let got = run_in(&server, d, &["PUT", "/x", "@folder"]);
    assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{}", got.stderr);
    assert!(got.stderr.contains("could not read folder: "), "{}", got.stderr);
    assert!(!got.stderr.contains("File not found"), "{}", got.stderr);
}

/// A body piped on stdin is sent as it is, trimmed and nothing else: it is
/// not read as a body argument is, so a comment in it is not stripped and a
/// raw newline is not escaped. The same text as an argument is read.
#[test]
fn a_piped_body_is_sent_as_it_is_and_a_body_argument_is_read() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    const BODY: &str = "{\n  // the name\n  \"name\": \"a # b\",\n  \"note\": \"two\nlines\"\n}";
    std::fs::write(dir.path().join("real.json"), r#"{"from":"file"}"#).unwrap();
    for (stdin, sent) in [
        (format!("\n{BODY}\n\n"), format!("PUT /x {BODY}")),
        ("a,b # c\n1,2\n".to_string(), "PUT /x a,b # c\n1,2".to_string()),
        // An `@` in front is data too: no file is looked for, or sent.
        ("@handle,name\n1,2\n".to_string(), "PUT /x @handle,name\n1,2".to_string()),
        ("@real.json~map(x)".to_string(), "PUT /x @real.json~map(x)".to_string()),
    ] {
        server.take();
        let mut cmd = api(server.port, dir.path());
        cmd.args(["PUT", "/x"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().expect("spawn api");
        child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        let out = child.wait_with_output().expect("api runs");
        server.settle(Duration::from_millis(150), Duration::from_secs(3));
        assert_eq!((out.status.code(), server.take()), (Some(0), vec![sent]), "{stdin:?}");
    }
    let got = run_in(&server, dir.path(), &["PUT", "/x", BODY]);
    assert_eq!((got.code, got.sent), (Some(0), vec!["PUT /x {\n  \n  \"name\": \"a # b\",\n  \"note\": \"two\\nlines\"\n}".to_string()]), "{}", got.stderr);
}

/// A `kill` at a prompt that is doing nothing gives the terminal back as
/// the shell had it: cooked, bracketed paste off, wrapping on. Not only a
/// kill during a streamed transfer does.
#[cfg(unix)]
#[test]
fn a_kill_at_an_idle_prompt_gives_the_terminal_back() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api(server.port, dir.path()));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    assert!(!prompt.is_cooked(), "the prompt is not in raw mode");
    prompt.signal(libc::SIGTERM);
    assert_eq!(ended(&mut prompt), Some(false));
    assert!(prompt.is_cooked(), "the terminal is left in raw mode");
    let last = |code: &str| prompt.screen.rfind(code);
    assert!(last("\x1b[?2004l") > last("\x1b[?2004h"), "bracketed paste is left on");
    assert!(last("\x1b[?7h") > last("\x1b[?7l"), "wrapping is left off");
    assert!(last("\x1b[?7h").is_some());
}

/// A notice that is wider than the terminal is cut to it, at any width: it
/// ends in `…` inside the last column and takes one row.
#[cfg(unix)]
#[test]
fn a_notice_wider_than_the_terminal_is_cut_to_it() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    for cols in [40usize, 60] {
        let mut prompt = pty::Prompt::open_sized(api(server.port, dir.path()), cols as u16);
        prompt.wait_ready(Duration::from_secs(15));
        prompt.pump(Duration::from_millis(500));
        let (sent, _) = run_pasted(&mut prompt, &server, "assert GET /missing/a-long-path-that-does-not-fit-the-row-at-all/and-more/and-more-of-it~count");
        assert_eq!(sent.len(), 1, "{sent:?}");
        let rows = pty::rows(&prompt.screen, cols);
        let notice = rows.iter().rev().find(|row| row.contains("assertion failed")).unwrap_or_else(|| panic!("no notice:\n{}", rows.join("\n")));
        assert!(notice.trim_end().ends_with('…'), "at {cols}: {notice:?}");
        assert!(notice.trim_end().chars().count() <= cols, "at {cols}: {notice:?}");
        assert_eq!(ruler_rows(&rows).len(), 2, "at {cols}:\n{}", rows.join("\n"));
    }
}

/// `importing…` is said for a line that imports, not for one that merely
/// holds the word.
#[cfg(unix)]
#[test]
fn importing_is_said_only_for_an_import() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let mut prompt = pty::Prompt::open(api(server.port, dir.path()));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    let (sent, shown) = run_pasted(&mut prompt, &server, "sleep 100ms while not GET /imports~count");
    assert_eq!(sent, ["GET /imports~count"]);
    assert!(!shown.contains("importing"), "{shown}");
    let (sent, shown) = run_pasted(&mut prompt, &server, "POST /imports {\"source\":\"erp\"}\rGET /b");
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert!(!shown.contains("importing"), "{shown}");
    let (_, shown) = run_pasted(&mut prompt, &server, "import dir lib { \"path\": \"libdir\" }\rlib/d.api");
    assert!(shown.contains("importing…"), "{shown}");
}

/// A key typed in the body of a chain's second request is offered the keys
/// of that request's URI, not of the first one's: the ghost while it is
/// typed, as Tab has it.
#[cfg(unix)]
#[test]
fn a_key_typed_in_a_chain_is_offered_the_keys_of_its_own_segment() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_completing(&server, dir.path(), &["-x"]);
    // `/pets` has no keys to offer; a person has `givenName`.
    let shown = press(&mut prompt, &["GET /people && PUT /pets {", "\"", "g"]);
    assert!(!shown.contains("ivenName"), "{shown}");
    let shown = press(&mut prompt, &["GET /pets && PUT /people {", "\"", "g"]);
    assert!(shown.contains("ivenName"), "{shown}");
    let shown = press(&mut prompt, &["GET /pets && PUT /people {", "\"", "g", "\t"]);
    assert!(shown.contains("\"givenName\":"), "{shown}");
}

/// A token endpoint that answers without a token gave none: the run says so
/// and sends no request with an empty one.
#[test]
fn an_answer_without_a_token_is_no_token() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let url = format!("http://127.0.0.1:{}", server.port);
    write_credentials(dir.path(), &[("c", url, "oauth2", "secret", "tokenless")], "c");
    std::fs::write(dir.path().join("one.api"), "GET /from-file\n").unwrap();
    for args in [&["GET", "/a"][..], &["-sa", "one.api"]] {
        let got = run_bare(&server, dir.path(), args);
        assert_eq!(got.code, Some(1), "{args:?}: {}", got.stderr);
        assert!(got.stderr.contains("OAuth2 token exchange failed"), "{args:?}: {}", got.stderr);
        assert!(got.sent.iter().all(|line| line.contains("/oauth2/v1/token")), "{args:?}: {:?}", got.sent);
    }
}

/// What can be said without a server is said without one: a body that is
/// not closed, two documents asked for at once, a `set` line alone.
#[test]
fn a_command_line_that_cannot_be_run_sends_nothing() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("one.api"), "GET /from-file\n").unwrap();
    for (args, says) in [
        (&["PUT", "/x", "{\"a\":1"][..], "unclosed body"),
        (&["PUT /x [{\"a\":1}"], "unclosed body"),
        (&["--describe", "one.api", "--assert", "one.api"], "--describe and --assert each print a document of their own: use one"),
        (&["--imports", "one.api", "--describe", "one.api", "--assert", "one.api"], "--describe, --assert and --imports each print a document of their own: use one"),
        (&["set", "export", "com.heads.seedID"], "`set` alone sends nothing"),
        (&["set", "include-nulls"], "`set` alone sends nothing"),
        (&["set include-nulls off"], "`set` alone sends nothing"),
        (&["DELETE"], "DELETE needs a URI"),
        // A URI from a variable that is not set: the body is not the URI.
        (&["PUT", "", "{\"a\":1}"], "PUT needs a URI"),
        (&["delete", " ", "[1]"], "DELETE needs a URI"),
        (&["-c", "saved", "--1p", "vault/item", "GET", "/x"], "-c names a saved connection and --1p one in 1Password: give one of the two"),
    ] {
        let got = run_in(&server, dir.path(), args);
        assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{args:?}: {}", got.stderr);
        assert!(got.stderr.contains(says), "{args:?}: {}", got.stderr);
        assert_eq!(got.stdout, "", "{args:?}");
    }
}

/// The first ctrl+c asks for a second, and stops asking when its notice
/// goes: a ctrl+c long after it is a first one again, not the end.
#[cfg(unix)]
#[test]
fn a_first_ctrl_c_is_forgotten_with_its_notice() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    prompt.send(b"\x03");
    prompt.wait_for("ctrl+c again to exit", Duration::from_secs(3));
    prompt.pump(Duration::from_millis(3800));
    let mark = prompt.screen.len();
    prompt.send(b"\x03");
    let asked = pump_until(&mut prompt, Duration::from_secs(3), |p| pty::plain(&p.screen[mark..]).contains("ctrl+c again to exit"));
    assert!(asked, "{}", pty::plain(&prompt.screen[mark..]));
    assert_eq!(prompt.exited(), None, "the second ctrl+c ended the session");
    prompt.send(b"\x03");
    assert_eq!(ended(&mut prompt), Some(true));
}

/// A `sleep while` at the prompt is logged as one line with how long it
/// waited: its polls are not requests anyone sent by hand.
#[cfg(unix)]
#[test]
fn a_wait_at_the_prompt_is_logged_as_one_line() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    let (sent, shown) = run_pasted(&mut prompt, &server, "sleep 100ms while GET /zero\rGET /after");
    assert_eq!(sent, ["GET /zero", "GET /after"]);
    assert!(shown.contains("sleep 100ms while GET /zero"), "{shown}");
    assert!(shown.contains("↳ waited") && shown.contains("(1 check)"), "{shown}");
    // The poll has no block of its own: one status line, the request's.
    assert_eq!(shown.matches("200 OK").count(), 1, "{shown}");
}

/// ctrl+q with nothing saved says so and leaves the line as it is. ctrl+s
/// with a store that can't be written says why and leaves the session on
/// the connection it had. ctrl+c at the overwrite question ends the session
/// and writes nothing.
#[cfg(unix)]
#[test]
fn the_store_dialogs_say_what_they_could_not_do() {
    use std::os::unix::fs::PermissionsExt;

    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);

    // Nothing saved.
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = open_prompt(&server, dir.path(), &[]);
    prompt.paste("GET /kept");
    prompt.pump(Duration::from_millis(100));
    let mark = prompt.screen.len();
    prompt.send(b"\x11");
    let said = pump_until(&mut prompt, Duration::from_secs(5), |p| pty::plain(&p.screen[mark..]).contains("no saved connections"));
    assert!(said, "{}", pty::plain(&prompt.screen[mark..]));
    let rows = pty::rows(&prompt.screen, 200);
    assert_eq!(ruler_rows(&rows).len(), 2, "{}", rows.join("\n"));
    assert_eq!(entered(&mut prompt, &server), ["GET /kept"]);

    // A store that can't be written: a file that is read-only, in a
    // directory that takes no new file.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let locked = d.join("locked");
    std::fs::create_dir(&locked).unwrap();
    let file = locked.join("credentials.json");
    std::fs::write(&file, r#"{"connections":[],"default":""}"#).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o444)).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
    let mut cmd = api_bare(d);
    cmd.env("API_CREDENTIALS_FILE", &file).args(["-b", &url, "-k", "k"]);
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    let shown = save_as(&mut prompt, "mine", "save failed:");
    assert!(!shown.contains("connection mine saved"), "{shown}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), r#"{"connections":[],"default":""}"#);
    let rows = pty::rows(&prompt.screen, 200);
    assert_eq!(ruler_rows(&rows).len(), 2, "{}", rows.join("\n"));
    // The session goes on, on the connection it had.
    prompt.send(b"\x15");
    prompt.paste("GET /still");
    prompt.pump(Duration::from_millis(100));
    assert_eq!(entered(&mut prompt, &server), ["GET /still"]);
    drop(prompt);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

    // ctrl+c at the overwrite question.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("a", url.clone(), "key", "AKEY", ""), ("b", url.clone(), "key", "BKEY", "")], "a");
    let before = stored(d);
    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    save_as(&mut prompt, "b", "already exists. Overwrite?");
    prompt.send(b"\x03");
    assert_eq!(ended(&mut prompt), Some(true));
    assert_eq!(stored(d), before);
}

// ----- What the 2026-11-18 review found no test for: `set` lines, the
// closing line of an export, and the one HTTP client -----

/// Which requests of a run asked for what: the `accept` of each, in order.
fn accepts_of(server: &RecordingServer) -> Vec<String> {
    let header = |head: &str, name: &str| head.split(&format!("{name}=")).nth(1).unwrap().split("; ").next().unwrap().to_string();
    server.heads().iter().map(|head| header(head, "accept")).collect()
}

/// A batch whose export left masked data out says so once more where it
/// ends, wherever that is: at its last line, at a failed `assert`, at a
/// `confirm` that was declined or not answered, at a response that broke
/// off, at a chain that could not be judged and at a `-f` stop. Once, and
/// counting the responses.
#[test]
fn the_closing_line_of_an_export_is_said_once_wherever_the_batch_ends() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    const EACH: &str = "warning: response had masked data, left out at secret";
    const TOTAL: &str = "warning: 2 responses had masked data left out of the export; read those members out with ~just or ~without";
    let endings: [(&str, &[&str], Option<&str>, i32, usize); 8] = [
        ("GET /after", &["-sa", "e.api"], None, 0, 3),
        ("assert GET /missing\nGET /never", &["-sa", "e.api"], None, 1, 3),
        ("assert not GET /a\nGET /never", &["-sa", "e.api"], None, 1, 3),
        ("confirm Go on?\nGET /never", &["-sa", "e.api"], Some("n\n"), 0, 2),
        ("confirm Go on?\nGET /never", &["-sa", "e.api"], Some(""), 1, 2),
        ("GET /trunc\nGET /never", &["-sa", "e.api"], None, 1, 3),
        ("GET /boom && GET /never\nGET /never", &["-sa", "e.api"], None, 1, 3),
        ("GET /conflict\nGET /never", &["-sfa", "e.api"], None, 1, 3),
    ];
    for (ending, args, stdin, code, sent) in endings {
        std::fs::write(d.join("e.api"), format!("set export a.b.c\nGET /keyed > k1.json\nGET /keyed > k2.json\n{ending}\n")).unwrap();
        let got = ask(&server, d, args, stdin);
        let what = format!("{ending:?} {args:?}:\n{}", got.stderr);
        assert_eq!((got.code, got.sent.len()), (Some(code), sent), "{what}");
        assert_eq!(got.stderr.matches(EACH).count(), 2, "{what}");
        assert_eq!(got.stderr.matches("masked data left out of the export").count(), 1, "{what}");
        assert_eq!(got.stderr.lines().last(), Some(TOTAL), "{what}");
    }

    // A chain and a file given as the arguments are a batch too. One request
    // is not, and has said it already.
    for args in [&["--export", "a.b.c", "GET /keyed > k1.json && GET /keyed > k2.json"][..], &["--export", "a.b.c", "two.api"]] {
        std::fs::write(d.join("two.api"), "GET /keyed > k1.json\nGET /keyed > k2.json\n").unwrap();
        let got = run_in(&server, d, args);
        assert_eq!((got.code, got.sent.len()), (Some(0), 2), "{args:?}: {}", got.stderr);
        assert_eq!(got.stderr.lines().last(), Some(TOTAL), "{args:?}: {}", got.stderr);
        assert_eq!(got.stderr.matches("masked data left out of the export").count(), 1, "{args:?}: {}", got.stderr);
    }
    let one = run_in(&server, d, &["--export", "a.b.c", "GET", "/keyed", ">", "k1.json"]);
    assert_eq!(one.stderr.matches("masked data").count(), 1, "{}", one.stderr);
    assert!(one.stderr.contains(EACH), "{}", one.stderr);
}

/// A `set` line is its file's own in both directions and for every way a
/// file is brought in: an included file's line ends with that file, each
/// file of a glob starts with nothing set, and so does a file of an import.
#[test]
fn a_set_line_reaches_no_other_file_whichever_way_that_file_is_brought_in() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let file = |name: &str, text: &str| {
        std::fs::create_dir_all(d.join(name).parent().unwrap()).unwrap();
        std::fs::write(d.join(name), text).unwrap();
    };
    let exported = |name: &str| exported_under(d, name);
    let all = |sent: &[&str]| sent.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    // An included file's `set fail-fast` does not stop the file that
    // included it, though it stops its own.
    file("inc.api", "set fail-fast\nGET /in-inc\n");
    file("s.api", "inc.api\nGET /missing\nGET /after\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent), (Some(0), all(&["GET /in-inc", "GET /missing", "GET /after"])), "{}", got.stderr);
    file("inc.api", "set fail-fast\nGET /missing\nGET /never\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent), (Some(1), all(&["GET /missing"])), "{}", got.stderr);

    // A glob: the first file's line is not the second's, the including
    // file's is neither's, and it is back when the glob is done.
    file("parts/a.api", "set export a.b.c\nGET /keyed > a.json\n");
    file("parts/b.api", "GET /keyed > b.json\n");
    file("s.api", "set include-nulls\nparts/*.api\nGET /keyed > main.json\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 3), "{}", got.stderr);
    assert_eq!(accepts_of(&server), ["application/json", "application/json", "application/json;skipNulls=false"]);
    assert_eq!((exported("a.json"), exported("b.json"), exported("main.json")), (Some("a.b.c".to_string()), None, None));

    // A file of an import has lines of its own, which hold in it and end
    // with it.
    file("lib/s.api", "set export x.y.z\nset fail-fast\nGET /keyed > imp.json\n");
    file("s.api", "import dir cl { \"path\": \"lib\" }\ncl/s.api\nGET /keyed > after.json\nGET /missing\nGET /after\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 4), "{}", got.stderr);
    assert_eq!((exported("imp.json"), exported("after.json")), (Some("x.y.z".to_string()), None));
    file("lib/s.api", "set fail-fast\nGET /missing\nGET /never\n");
    let got = run_in(&server, d, &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent), (Some(1), all(&["GET /missing"])), "{}", got.stderr);

    // The preview lists an included file's own line where it stands, and
    // nothing for the settings put aside around it.
    file("inc.api", "set raw\nGET /in-inc\n");
    file("s.api", "set include-nulls\ninc.api\nGET /after\n");
    let got = ask(&server, d, &["-spa", "s.api"], Some("n\n"));
    assert_eq!((got.code, got.sent.len()), (Some(0), 0), "{}", got.stderr);
    let listed: Vec<&str> = got.stderr.lines().map(str::trim).filter(|line| line.starts_with("set ") || line.starts_with("GET ")).collect();
    assert_eq!(listed, ["set include-nulls", "set raw", "GET /in-inc", "GET /after"], "{}", got.stderr);
    assert!(got.stderr.contains("Preview — 2 requests"), "{}", got.stderr);
}

/// `set fail-fast` is `-f` for the lines under it in everything `-f` does:
/// a check that could not be judged ends the run with its body, an error is
/// kept out of an outfile, and a question may still be answered "no".
#[test]
fn set_fail_fast_does_all_that_the_option_does() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let run = |text: &str, args: &[&str]| {
        std::fs::write(d.join("s.api"), text).unwrap();
        run_in(&server, d, args)
    };
    let all = |sent: &[&str]| sent.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    const BARRED: &str = r#"{"error":"barred"}"#;

    // An `assert` and a poll that got no answer to judge: the body is last.
    for check in ["assert GET /barred", "sleep 1 while GET /barred"] {
        let got = run(&format!("set fail-fast\n{check}\nGET /never\n"), &["-sa", "s.api"]);
        assert_eq!((got.code, got.sent), (Some(1), all(&["GET /barred"])), "{check}: {}", got.stderr);
        assert!(got.stdout.trim_end().ends_with(BARRED), "{check}: {}", got.stdout);
        // Without the line there is no body.
        let got = run(&format!("{check}\nGET /never\n"), &["-sa", "s.api"]);
        assert_eq!(got.code, Some(1), "{check}: {}", got.stderr);
        assert!(!got.stdout.contains(BARRED), "{check}: {}", got.stdout);
    }

    // An error is not written to the outfile, and goes to stdout.
    let got = run("set fail-fast\nGET /gone > g.json\nGET /never\n", &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent), (Some(1), all(&["GET /gone"])), "{}", got.stderr);
    assert!(!d.join("g.json").exists());
    assert!(got.stdout.trim_end().ends_with(GONE.trim_end()), "{}", got.stdout);
    // Above the line it is written, as without `-f`.
    let got = run("GET /gone > g.json\nset fail-fast\nGET /after\n", &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 2), "{}", got.stderr);
    assert_eq!(std::fs::read_to_string(d.join("g.json")).unwrap().trim_end(), GONE_INDENTED);

    // A "no" that was asked for passes; the last request of a chain is a
    // plain request and does not.
    let got = run("set fail-fast\nGET /missing || GET /a\nassert not GET /missing\nGET /b\n", &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 4), "{}", got.stderr);
    let got = run("set fail-fast\nGET /missing || GET /conflict\nGET /never\n", &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent), (Some(1), all(&["GET /missing", "GET /conflict"])), "{}", got.stderr);

    // An outfile that can't be written ends the run under the line.
    let got = run("set fail-fast\nGET /a > no/such/dir/a.json\nGET /never\n", &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent), (Some(1), all(&["GET /a"])), "{}", got.stderr);
    assert!(got.stderr.contains("Error writing to no/such/dir/a.json"), "{}", got.stderr);

    // The options hold over a line that says `off`, and the log says so.
    let got = run("set fail-fast off\nGET /missing\nGET /never\n", &["-sfa", "s.api"]);
    assert_eq!((got.code, got.sent), (Some(1), all(&["GET /missing"])), "{}", got.stderr);
    assert!(got.stdout.contains("set fail-fast off\n↳ ignored: -f is set"), "{}", got.stdout);
    let got = run("set raw off\nGET /a > r.json\n", &["-r", "-sa", "s.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert!(got.stdout.contains("set raw off\n↳ ignored: -r is set"), "{}", got.stdout);
    assert_eq!(std::fs::read_to_string(d.join("r.json")).unwrap().trim_end(), r#"{"ok":"/api/v1/a"}"#);
}

/// What `set raw`, `set ndjson`, `set include-nulls` and `set stream` do to
/// a request and to what is printed, alone and together.
#[test]
fn set_lines_change_what_is_sent_asked_for_and_printed() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let run = |text: &str, args: &[&str]| {
        std::fs::write(d.join("s.api"), text).unwrap();
        run_in(&server, d, args)
    };
    let content_types = |server: &RecordingServer| -> Vec<String> {
        server.heads().iter().map(|head| head.split("content-type=").nth(1).unwrap().split(';').next().unwrap().to_string()).collect()
    };

    // raw: an export is laid out on stdout, and on one line under the line.
    // (A body that is not rewritten goes to a pipe as it came either way.)
    let got = run("set export a.b.c\nGET /keyed\nset raw\nGET /keyed\nset raw off\nGET /keyed\n", &["-a", "s.api"]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    const LAID_OUT: &str = "{\n  \"identifiers\": {\n    \"key?\": \"k1\",\n    \"a.b.c\": \"k1\"\n  },\n  \"name\": \"Ann\"\n}";
    assert_eq!(got.stdout.matches(LAID_OUT).count(), 2, "{}", got.stdout);
    assert_eq!(got.stdout.matches(r#"{"identifiers":{"key?":"k1","a.b.c":"k1"},"name":"Ann"}"#).count(), 1, "{}", got.stdout);

    // ndjson: sent as NDJSON and asked for, until `off`.
    let got = run("set ndjson\nPUT /x {\"a\":1}\nset ndjson off\nPUT /y {\"a\":1}\n", &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 2), "{}", got.stderr);
    assert_eq!(content_types(&server), ["application/x-ndjson", "application/json"]);
    assert_eq!(accepts_of(&server), ["application/x-ndjson", "application/json"]);

    // What a file has set is put together in one `Accept`, with the format
    // of the outfile.
    let got = run("set include-nulls\nset stream\nGET /a > x.csv\nGET /b > x.json\nset stream off\nGET /c > y.csv\n", &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 3), "{}", got.stderr);
    assert_eq!(
        accepts_of(&server),
        ["text/csv;stream=true;skipNulls=false", "application/json;stream=true;skipNulls=false", "text/csv;skipNulls=false"]
    );

    // `set export` under `set stream`: the whole body is needed, so the
    // request is not streamed, and is again once export is off.
    let got = run("set stream\nGET /keyed > s1.json\nset export a.b.c\nGET /keyed > s2.json\nset export off\nGET /keyed > s3.json\n", &["-sa", "s.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 3), "{}", got.stderr);
    assert_eq!(accepts_of(&server), ["application/json;stream=true", "application/json", "application/json;stream=true"]);
    assert_eq!((exported_under(d, "s1.json"), exported_under(d, "s2.json"), exported_under(d, "s3.json")), (None, Some("a.b.c".to_string()), None));
    // A streamed outfile holds the server's bytes, a buffered one is laid out.
    assert!(!std::fs::read_to_string(d.join("s1.json")).unwrap().contains('\n'));
    assert!(std::fs::read_to_string(d.join("s2.json")).unwrap().contains("\n  "));

    // `--no-streaming` keeps the line off: the file is written buffered.
    let got = run("set stream\nGET /keyed > n.json\n", &["--no-streaming", "-sa", "s.api"]);
    assert_eq!(accepts_of(&server), ["application/json"], "{}", got.stderr);
    assert!(std::fs::read_to_string(d.join("n.json")).unwrap().contains("\n  "));
    assert!(got.stdout.contains("↳ ignored: --no-streaming is set"), "{}", got.stdout);
}

/// `--assert` reads a file with `set` lines as a run does: the lines are no
/// assertions and are passed over, and a line that would stop a run stops
/// the listing.
#[test]
fn assert_lists_a_file_with_set_lines_and_refuses_one_that_would_not_run() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("a.api"), "set fail-fast\nPUT /assert {\"api/v1/x\":{\"is\":1}}\nset fail-fast off\nPUT v1/assert {\"api/v1/y\":{\"is not\":null}}\n").unwrap();
    let got = run_in(&server, d, &["-r", "--assert", "a.api"]);
    assert_eq!((got.code, got.sent.len()), (Some(0), 0), "{}", got.stderr);
    assert_eq!(got.stdout.trim_end(), r#"[{"api/v1/x":{"is":1}},{"api/v1/y":{"is not":null}}]"#);

    std::fs::write(d.join("a.api"), "set nulls\nPUT /assert {\"api/v1/x\":{\"is\":1}}\n").unwrap();
    for option in ["--assert", "--imports"] {
        let got = run_in(&server, d, &[option, "a.api"]);
        assert_eq!((got.code, got.sent.len(), got.stdout.as_str()), (Some(1), 0, ""), "{option}: {}", got.stderr);
        assert!(got.stderr.starts_with("error: ") && got.stderr.contains("unknown setting `nulls`"), "{option}: {}", got.stderr);
    }
}

/// A response that is not JSON is left as it came by `--export`, with a
/// warning, wherever it goes: stdout, a `.sql` file, a file of no format.
#[test]
fn an_export_leaves_what_is_not_json_unchanged_and_says_so() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    const WARNING: &str = "WARNING: --export left a response that is not JSON unchanged";

    let got = run_in(&server, d, &["-s", "--export", "a.b.c", "GET", "/zero/select%201"]);
    assert_eq!((got.code, got.stdout.trim_end()), (Some(0), "select%201"), "{}", got.stderr);
    assert_eq!(got.stderr.matches(WARNING).count(), 1, "{}", got.stderr);
    for name in ["out.sql", "out.txt"] {
        let got = run_in(&server, d, &["--export", "a.b.c", "GET", "/zero/insert", ">", name]);
        assert_eq!(got.code, Some(0), "{name}: {}", got.stderr);
        assert_eq!(std::fs::read_to_string(d.join(name)).unwrap().trim_end(), "insert", "{name}");
        assert_eq!(got.stderr.matches(WARNING).count(), 1, "{name}: {}", got.stderr);
    }
    // JSON gets no such warning.
    let got = run_in(&server, d, &["--export", "a.b.c", "GET", "/a", ">", "out.json"]);
    assert!(!got.stderr.contains("WARNING"), "{}", got.stderr);
}

/// A server that keeps a connection open between requests, as COS does, and
/// counts the connections it was given. One left alone for `idle` is closed.
/// `/hop` is sent on to `onward` as the request it was (307).
struct KeepAliveServer {
    port: u16,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl KeepAliveServer {
    fn start(idle: Duration, onward: Option<String>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (counted, logged) = (Arc::clone(&connections), Arc::clone(&requests));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                counted.fetch_add(1, Ordering::SeqCst);
                let (logged, onward) = (Arc::clone(&logged), onward.clone());
                std::thread::spawn(move || {
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(idle)).unwrap();
                    let mut data: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 8192];
                    loop {
                        // One request: its head, and the body it says it has.
                        let head_end = loop {
                            if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                                break at + 4;
                            }
                            match stream.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => data.extend_from_slice(&buf[..n]),
                            }
                        };
                        let head = String::from_utf8_lossy(&data[..head_end]).to_string();
                        let length: usize = head
                            .lines()
                            .find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                            .unwrap_or(0);
                        while data.len() < head_end + length {
                            match stream.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => data.extend_from_slice(&buf[..n]),
                            }
                        }
                        data.drain(..head_end + length);
                        let mut words = head.split_whitespace();
                        let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
                        let path = path.strip_prefix("/api/v1").unwrap_or(path);
                        logged.lock().unwrap().push(format!("{method} {path}"));
                        let answer = match &onward {
                            Some(to) if path.contains("/hop") => {
                                format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {to}\r\nContent-Length: 0\r\n\r\n")
                            }
                            _ => "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}".to_string(),
                        };
                        if stream.write_all(answer.as_bytes()).and_then(|()| stream.flush()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        KeepAliveServer { port, connections, requests }
    }

    fn api(&self, dir: &Path) -> std::process::Command {
        let mut cmd = api_bare(dir);
        cmd.args(["-b", &format!("http://127.0.0.1:{}", self.port), "-k", "k"]);
        cmd
    }

    fn seen(&self) -> (usize, Vec<String>) {
        (self.connections.load(Ordering::SeqCst), self.requests.lock().unwrap().clone())
    }
}

/// The requests of a run go through one client, so a line that follows
/// another is sent on the connection that is already open: no handshake per
/// line. A connection left alone for longer than the client keeps one is not
/// written to again, so a request after a pause is never lost to a server
/// that was just closing its end.
#[test]
fn the_lines_of_a_batch_share_a_connection_and_a_pause_gets_a_new_one() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    let server = KeepAliveServer::start(Duration::from_secs(30), None);
    std::fs::write(d.join("b.api"), "GET /a\nPUT /b {\"x\":1}\nassert GET /c\nGET /d > d.json\n").unwrap();
    let out = server.api(d).args(["-sa", "b.api"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(server.seen(), (1, ["GET /a", "PUT /b", "GET /c", "GET /d"].map(String::from).to_vec()));

    // The server closes a connection it has not heard from for 3.5 seconds;
    // the client gives its own up before that. Every request arrives, once.
    let server = KeepAliveServer::start(Duration::from_millis(3500), None);
    std::fs::write(d.join("b.api"), "GET /a\nGET /b\nsleep 4\nPUT /c {\"x\":1}\nGET /d\n").unwrap();
    let out = server.api(d).args(["-sa", "b.api"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(server.seen(), (2, ["GET /a", "GET /b", "PUT /c", "GET /d"].map(String::from).to_vec()));
}

/// A redirect to another host is followed as the request it was, without
/// the credential: the key was given for the host it was sent to.
#[test]
fn a_redirect_to_another_host_does_not_take_the_credential_along() {
    let other = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let onward = format!("http://127.0.0.1:{}/api/v1/landed", other.port);
    let server = KeepAliveServer::start(Duration::from_secs(30), Some(onward));

    other.take();
    let out = server.api(dir.path()).args(["PUT", "/hop", r#"{"x":1}"#]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    other.settle(Duration::from_millis(150), Duration::from_secs(3));
    assert_eq!(server.seen().1, ["PUT /hop"]);
    assert_eq!(other.log.lock().unwrap().clone(), [r#"PUT /landed {"x":1}"#]);
    assert_eq!(authorization(&other), "-");
    // Sent straight there, the same request carries it.
    let direct = run_in(&other, dir.path(), &["PUT", "/landed", r#"{"x":1}"#]);
    assert_eq!(direct.code, Some(0), "{}", direct.stderr);
    assert!(authorization(&other).starts_with("Basic "), "{:?}", other.heads());
}

/// The settings menu through what a window and a clipboard do to it: a
/// resize while it is open redraws it once, under the output; a paste closes
/// it and lands on the input line; and the timeout's dialog leaves the
/// timeout as it was when it is left with esc or with nothing typed.
#[cfg(unix)]
#[test]
fn the_settings_menu_takes_a_resize_a_paste_and_an_unanswered_dialog() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open_with(api(server.port, dir.path()), 100, 60);
    prompt.wait_ready(Duration::from_secs(15));
    press(&mut prompt, &["GET /kept"]);
    assert_eq!(entered(&mut prompt, &server), ["GET /kept"]);
    let menu_rows = |rows: &[String]| rows.iter().filter(|row| row.contains("Response streaming")).count();

    // Resized while open: one menu, one ruler above it, the output kept.
    prompt.send(b"\x14");
    prompt.wait_for("Response streaming", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(200));
    let mark = prompt.screen.len();
    for cols in [90u16] {
        prompt.resize(cols, 60);
        prompt.pump(Duration::from_millis(700));
        let rows = pty::rows(&prompt.screen[mark..], cols as usize);
        let shown = rows.join("\n");
        assert!(rows.iter().any(|row| row.contains("/api/v1/kept")), "{cols}:\n{shown}");
        assert_eq!(menu_rows(&rows), 1, "{cols}:\n{shown}");
        assert_eq!(ruler_rows(&rows).len(), 1, "{cols}:\n{shown}");
        assert_eq!(rows.last().unwrap(), "  ↑/↓ to move, enter to change, ctrl+t or esc to close", "{cols}:\n{shown}");
        assert_eq!(rows.len(), ruler_rows(&rows)[0] + 11, "{cols}:\n{shown}");
    }
    // Closed, the command area is right under the output.
    prompt.send(b"\x1b");
    prompt.pump(Duration::from_millis(500));
    let rows = pty::rows(&prompt.screen[mark..], 90);
    let shown = rows.join("\n");
    let rulers = ruler_rows(&rows);
    let answered = rows.iter().rposition(|row| row.contains("/api/v1/kept")).expect("the response is still there");
    assert_eq!((rulers.len(), menu_rows(&rows)), (2, 0), "{shown}");
    assert!(rulers[0] > answered && rulers[0] <= answered + 3, "{shown}");
    assert_eq!(rows.len(), rulers[1] + 2, "{shown}");

    // A paste is "any other key": it closes the menu and is the line.
    prompt.send(b"\x15\x14");
    prompt.wait_for("Response streaming", Duration::from_secs(5));
    prompt.pump(Duration::from_millis(200));
    prompt.paste("GET /pasted");
    prompt.pump(Duration::from_millis(500));
    let rows = pty::rows(&prompt.screen[mark..], 90);
    let shown = rows.join("\n");
    let rulers = ruler_rows(&rows);
    assert_eq!((rulers.len(), menu_rows(&rows)), (2, 0), "{shown}");
    assert_eq!(rows[rulers[0] + 1], "GET /pasted", "{shown}");
    assert_eq!(entered(&mut prompt, &server), ["GET /pasted"]);

    // The timeout's dialog: esc and an empty answer leave it at 600s, with
    // the menu back and saying so; a pasted number is an answer.
    let timeout_row = |prompt: &pty::Prompt| {
        let rows = pty::rows(&prompt.screen[mark..], 90);
        let row = rows.iter().find(|row| row.contains("Timeout  ")).unwrap_or_else(|| panic!("no menu:\n{}", rows.join("\n")));
        (row.clone(), rows.last().unwrap().clone())
    };
    let dialog = |prompt: &mut pty::Prompt| {
        prompt.send(b"\r");
        prompt.wait_for("Timeout in seconds", Duration::from_secs(5));
        prompt.pump(Duration::from_millis(300));
    };
    prompt.send(b"\x14");
    prompt.pump(Duration::from_millis(400));
    prompt.send(b"\x1b[A");
    prompt.pump(Duration::from_millis(300));
    for leave in [&b"\x1b"[..], b"\r"] {
        dialog(&mut prompt);
        prompt.send(leave);
        prompt.pump(Duration::from_millis(500));
        let (row, said) = timeout_row(&prompt);
        assert!(row.starts_with("› Timeout") && row.ends_with("  600s"), "{leave:?}: {row:?}");
        assert_eq!(said, "  cancelled", "{leave:?}");
    }
    dialog(&mut prompt);
    prompt.paste("45");
    prompt.pump(Duration::from_millis(300));
    prompt.send(b"\r");
    prompt.pump(Duration::from_millis(500));
    let (row, said) = timeout_row(&prompt);
    assert!(row.ends_with("  45s"), "{row:?}");
    assert_eq!(said, "  timeout 45s");
    // ctrl+c in the dialog leaves the client, and the terminal as it was.
    dialog(&mut prompt);
    prompt.send(b"\x03");
    let start = Instant::now();
    while prompt.exited().is_none() && start.elapsed() < Duration::from_secs(5) {
        prompt.pump(Duration::from_millis(100));
    }
    assert!(prompt.exited().is_some(), "{}", screen_tail(&prompt));
    let rows = pty::rows(&prompt.screen[mark..], 90);
    assert!(!rows.iter().any(|row| row.contains("Timeout in seconds")), "{}", rows.join("\n"));
}

/// `set stream` typed at the prompt is the menu's first row: on a server
/// that streams it turns streaming on and marks it, `off` turns it off, and
/// while export is on a `> file` is not streamed, whatever the line said. On
/// a server that does not stream it is refused.
#[cfg(unix)]
#[test]
fn set_stream_typed_at_the_prompt_is_the_menus_first_row() {
    const COLS: usize = 120;
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    let last_row = |prompt: &pty::Prompt| pty::rows(&prompt.screen, COLS).last().unwrap().trim_end().to_string();

    let mut cmd = api_bare(d);
    cmd.args(["-b", &url, "-k", "streamer"]);
    let mut prompt = pty::Prompt::open_sized(cmd, COLS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    assert!(!last_row(&prompt).ends_with("streaming"), "{}", last_row(&prompt));

    let (sent, shown) = run_pasted(&mut prompt, &server, "set stream");
    assert!(sent.is_empty() && shown.contains("streamed bodies may encode errors"), "{shown}");
    assert!(last_row(&prompt).ends_with(" streaming"), "{}", last_row(&prompt));
    let (_, _, accepts) = run_pasted_accepts(&mut prompt, &server, "GET /keyed > streamed.json");
    assert_eq!(accepts, ["application/json;stream=true"]);
    assert!(!std::fs::read_to_string(d.join("streamed.json")).unwrap().contains('\n'));

    // Export needs the whole body: its marker takes the place of the other,
    // and the file holds seed data.
    run_pasted(&mut prompt, &server, "set export a.b.c");
    assert!(last_row(&prompt).ends_with(" export"), "{}", last_row(&prompt));
    let (_, _, accepts) = run_pasted_accepts(&mut prompt, &server, "GET /keyed > exported.json");
    assert_eq!(accepts, ["application/json"]);
    assert_eq!(exported_under(d, "exported.json"), Some("a.b.c".to_string()));
    run_pasted(&mut prompt, &server, "set export off");
    assert!(last_row(&prompt).ends_with(" streaming"), "{}", last_row(&prompt));

    let (_, shown) = run_pasted(&mut prompt, &server, "set stream off");
    assert!(shown.contains("streaming off"), "{shown}");
    prompt.pump(Duration::from_millis(300));
    assert!(!last_row(&prompt).ends_with("streaming"), "{}", last_row(&prompt));
    let (_, _, accepts) = run_pasted_accepts(&mut prompt, &server, "GET /keyed > buffered.json");
    assert_eq!(accepts, ["application/json"]);
    drop(prompt);

    // A server that does not stream.
    let mut prompt = pty::Prompt::open_sized(api(server.port, d), COLS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    let (sent, shown) = run_pasted(&mut prompt, &server, "set stream");
    assert!(sent.is_empty() && shown.contains("streaming not available on this server"), "{shown}");
    let (_, _, accepts) = run_pasted_accepts(&mut prompt, &server, "GET /keyed > plain.json");
    assert_eq!(accepts, ["application/json"]);
}

/// On a hint line too narrow for every marker the ones on the left go
/// first, and what the prompt has to say (here the warning of an export) is
/// said on that one row too: nothing wraps, at 60 columns.
#[cfg(unix)]
#[test]
fn a_narrow_hint_row_keeps_the_last_markers_and_the_warning_to_one_row() {
    const COLS: usize = 60;
    const ALL: &str = "nulls · fail-fast · ndjson · raw · timeout 45s · export";
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = api(server.port, dir.path());
    cmd.args(["-i", "-f", "--ndjson", "-r", "--timeout", "45", "--export", "a.b.c"]);
    let mut prompt = pty::Prompt::open_sized(cmd, COLS as u16);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(800));

    let rows = pty::rows(&prompt.screen, COLS);
    let hint = rows.last().unwrap();
    let shown = rows.join("\n");
    assert!(hint.chars().count() <= COLS, "{shown}");
    let markers = hint.strip_prefix("  ctrl+h for shortcuts ").unwrap_or_else(|| panic!("{shown}")).trim();
    // Whole markers, the last ones, ending where the row ends.
    assert!(ALL.ends_with(markers) && markers.ends_with("export") && markers != ALL, "{markers:?}\n{shown}");
    assert!(markers.starts_with(|c: char| c.is_ascii_alphabetic()), "a marker cut in two: {markers:?}");
    assert!(hint.ends_with("export"), "{shown}");
    let before = rows.len();

    // The warning is the hint row's.
    let (sent, _) = run_pasted(&mut prompt, &server, "GET /keyed > k.ndjson");
    assert_eq!(sent, ["GET /keyed"]);
    let rows = pty::rows(&prompt.screen, COLS);
    let hint = rows.last().unwrap();
    let shown = rows.join("\n");
    // It leaves no room for a marker, and none is squeezed in or cut.
    assert_eq!(hint, "  warning: response had masked data, left out at secret", "{shown}");
    assert_eq!(rows.iter().filter(|row| row.contains("masked data")).count(), 1, "{shown}");
    assert_eq!(ruler_rows(&rows[before - 4..]).len(), 2, "{shown}");
    // When it has been said, the markers are back.
    let back = pump_until(&mut prompt, Duration::from_secs(6), |p| {
        pty::rows(&p.screen, COLS).last().is_some_and(|row| row.ends_with("timeout 45s · export"))
    });
    assert!(back, "{}", pty::rows(&prompt.screen, COLS).join("\n"));
}

/// A file run from the prompt is told which of its lines the session
/// overrides, for every setting the session has on, and a file that stops
/// (a declined `confirm`, esc in a `sleep`, fail-fast) leaves the session
/// with what it had before the file set its own.
#[cfg(unix)]
#[test]
fn a_file_at_the_prompt_neither_overrides_the_session_nor_leaves_its_settings_behind() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let url = format!("http://127.0.0.1:{}", server.port);
    std::fs::write(d.join("own.api"), "set timeout 5\nset fail-fast off\nset stream off\nset raw off\nset ndjson off\nGET /a > a.json\n").unwrap();
    std::fs::write(d.join("declined.api"), "set include-nulls\nGET /first\nconfirm Go on?\nGET /never\n").unwrap();
    std::fs::write(d.join("slept.api"), "set include-nulls\nGET /first\nsleep 30\nGET /never\n").unwrap();
    std::fs::write(d.join("tripped.api"), "set include-nulls\nset fail-fast\nGET /missing\nGET /never\n").unwrap();

    // Every setting the session has on is named under the line it overrides.
    let mut cmd = api_bare(d);
    cmd.args(["-b", &url, "-k", "streamer", "--timeout", "45", "-f", "--stream", "-r", "--ndjson"]);
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    let (sent, shown, accepts) = run_pasted_accepts(&mut prompt, &server, "own.api");
    assert_eq!(sent, ["GET /a"], "{shown}");
    for held in ["set timeout 45", "set fail-fast", "set stream", "set raw", "set ndjson"] {
        assert!(shown.contains(&format!("↳ ignored: the session has {held}")), "{held}: {shown}");
    }
    assert_eq!(shown.matches("↳ ignored").count(), 5, "{shown}");
    assert_eq!(accepts, ["application/x-ndjson;stream=true"]);
    drop(prompt);

    // A file that stops: its `set include-nulls` is not the session's.
    let mut prompt = pty::Prompt::open(api(server.port, d));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    let stops: [(&str, &[u8], &[&str]); 3] = [
        ("declined.api", b"n", &["GET /first"]),
        ("slept.api", b"\x1b", &["GET /first"]),
        ("tripped.api", b"", &["GET /missing"]),
    ];
    for (file, key, sends) in stops {
        let (sent, shown, accepts) = run_pasted_accepts(&mut prompt, &server, file);
        assert_eq!(sent, sends, "{file}: {shown}");
        assert_eq!(accepts, ["application/json;skipNulls=false"], "{file}: the file's own line holds in it");
        prompt.send(key);
        prompt.pump(Duration::from_millis(700));
        let (sent, shown, accepts) = run_pasted_accepts(&mut prompt, &server, "GET /missing\rGET /after");
        assert_eq!(sent, ["GET /missing", "GET /after"], "{file}: fail-fast was left on\n{shown}");
        assert_eq!(accepts, ["application/json", "application/json"], "{file}: include-nulls was left on");
    }
}

/// The request of an `assert` and of a `sleep while` is read as a plain line
/// is: a comment in its body is not sent and a raw tab in a string is
/// escaped. Sent as written, the server could not read the body, and its 400
/// would be the "no" that lets an `assert not` pass.
#[test]
fn the_request_of_a_check_is_sent_as_a_plain_line_sends_it() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let body = "{\"q\": 1 /* active only */, \"t\": \"a\tb\" // tail\n}";
    let one_line = "{\"q\": 1 /* active only */, \"t\": \"a\tb\"}";
    std::fs::write(
        d.join("checks.api"),
        format!("PUT /plain {body}\nassert PUT /checked {one_line}\nassert not PUT /missing {one_line}\nsleep while not PUT /polled {one_line}\n"),
    )
    .unwrap();
    let got = run_in(&server, d, &["-sa", "checks.api"]);
    assert_eq!(got.code, Some(0), "{}{}", got.stdout, got.stderr);
    assert_eq!(got.sent.len(), 4, "{:?}", got.sent);
    // What arrived, as the JSON it is: the two bodies differ in blanks only.
    let sent_body = |line: &str| -> serde_json::Value {
        let body = line.splitn(3, ' ').nth(2).unwrap();
        serde_json::from_str(body).unwrap_or_else(|e| panic!("{body}: {e}"))
    };
    let plain = sent_body(&got.sent[0]);
    assert_eq!(plain, serde_json::json!({"q": 1, "t": "a\tb"}));
    for line in &got.sent[1..] {
        assert_eq!(sent_body(line), plain, "{line}");
    }

    // As an argument and from stdin too.
    let got = run_in(&server, d, &[&format!("assert PUT /checked {one_line}")]);
    assert_eq!(got.code, Some(0), "{}", got.stderr);
    assert_eq!(got.sent.iter().map(|l| sent_body(l)).collect::<Vec<_>>(), [plain.clone()]);
}

/// `>>` adds to what its target holds without reading it as text first: a
/// file that is not UTF-8 keeps its bytes and gets the addition behind them.
#[test]
fn an_append_to_a_file_that_is_not_utf8_keeps_its_bytes() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("notes.txt"), b"caf\xe9").unwrap();
    std::fs::write(d.join("rows.ndjson"), b"{\"n\":\"caf\xe9\"}\n").unwrap();
    std::fs::write(d.join("add.api"), "GET /one >> notes.txt\nGET /two >> rows.ndjson\nGET /after\n").unwrap();
    let got = run_in(&server, d, &["-sfa", "add.api"]);
    assert_eq!(got.code, Some(0), "{}{}", got.stdout, got.stderr);
    assert!(!got.stderr.contains("Error writing"), "{}", got.stderr);
    assert_eq!(got.sent, ["GET /one", "GET /two", "GET /after"]);
    let notes = std::fs::read(d.join("notes.txt")).unwrap();
    assert!(notes.starts_with(b"caf\xe9\n"), "{notes:?}");
    assert!(String::from_utf8_lossy(&notes).contains("/one"), "{notes:?}");
    let rows = std::fs::read(d.join("rows.ndjson")).unwrap();
    assert_eq!(rows, b"{\"n\":\"caf\xe9\"}\n{\"ok\":\"/api/v1/two\"}\n", "{}", String::from_utf8_lossy(&rows));
}

/// A file named at the prompt runs as a file, however little it holds: a
/// file of one request is not that request typed. Its body-less `PUT` is
/// sent as a batch sends it (the body editor is for a line that was typed),
/// and what its describe block is warned for is said.
#[cfg(unix)]
#[test]
fn a_file_of_one_request_runs_as_a_file_at_the_prompt() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("one.api"), "# one request\nPUT /bodyless\n").unwrap();
    std::fs::write(d.join("told.api"), "{ \"title\": \"Katalog\" }\nGET /described\n").unwrap();
    let mut prompt = pty::Prompt::open(api(server.port, d));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));

    let (sent, shown) = run_pasted(&mut prompt, &server, "one.api");
    assert_eq!(sent, ["PUT /bodyless"], "{shown}");
    // No body editor was opened: the next line is a line.
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /next");
    assert_eq!(sent, ["GET /next"], "{shown}");

    let (sent, shown) = run_pasted(&mut prompt, &server, "told.api");
    assert_eq!(sent, ["GET /described"], "{shown}");
    assert!(shown.contains("describe block in told.api: title is not an object of texts by locale"), "{shown}");

    // The same request typed still opens the editor for its body.
    let (sent, shown) = run_pasted(&mut prompt, &server, "PUT /bodyless");
    assert_eq!(sent.len(), 0, "{shown}");
    prompt.send(b"{\"a\":1}\x04");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    assert_eq!(server.take(), ["PUT /bodyless {\"a\":1}"]);
}

/// A default connection that names nothing, or can't be used, is no
/// connection: at a terminal the picker opens, as it does with no default,
/// where the session used to end with `no base URL specified`.
#[cfg(unix)]
#[test]
fn a_default_that_cannot_be_used_opens_the_picker_at_a_terminal() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let cases: [(&[(&str, String, &str, &str, &str)], &str, &str); 2] = [
        (&[("alpha", url.clone(), "key", "k1", "")], "locl", "the default connection \"locl\" is not among the saved connections (alpha)"),
        (
            &[("alpha", url.clone(), "key", "k1", ""), ("odd", url.clone(), "bearer", "t", "")],
            "odd",
            "the default connection \"odd\" can't be used: its auth_type \"bearer\"",
        ),
    ];
    for (connections, default, warning) in cases {
        let dir = tempfile::tempdir().unwrap();
        write_credentials(dir.path(), connections, default);
        let mut prompt = pty::Prompt::open(api_bare(dir.path()));
        prompt.wait_for("+ Add new connection", Duration::from_secs(15));
        let shown = pty::plain(&prompt.screen);
        assert!(shown.contains(warning), "{default}: {shown}");
        assert!(!shown.contains("no base URL specified"), "{default}: {shown}");
        prompt.pump(Duration::from_millis(400));
        // The picker opens on the default, which is the one that can't be
        // used: a connection that works is searched for.
        prompt.send(b"alpha");
        prompt.pump(Duration::from_millis(300));
        prompt.send(b"\r");
        prompt.wait_ready(Duration::from_secs(15));
        prompt.pump(Duration::from_millis(600));
        let (sent, shown) = run_pasted(&mut prompt, &server, "GET /picked");
        assert_eq!(sent, ["GET /picked"], "{default}: {shown}");
    }

    // Without a terminal nothing is asked: the warning, and no connection.
    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), cases[0].0, "locl");
    let got = run_bare(&server, dir.path(), &["GET", "/x"]);
    assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{}", got.stderr);
    assert!(got.stderr.contains("no base URL specified"), "{}", got.stderr);
}

/// A connection made in the form that ctrl+q opens is loaded behind the
/// form, with its spinner turning, as the form a session starts with does:
/// the session used to stand still, form and all, until the server answered.
#[cfg(unix)]
#[test]
fn a_connection_added_in_a_session_loads_behind_its_form() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("alpha", url.clone(), "key", "k1", "")], "alpha");
    let mut prompt = pty::Prompt::open(api_bare(d));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(500));
    keys_then(&mut prompt, "\x11", "+ Add new connection");
    keys_then(&mut prompt, "\x1b[B\r", "Type the API base URL");
    prompt.paste(&url);
    keys_then(&mut prompt, "\r", "Use ← → to choose auth method");
    keys_then(&mut prompt, "\r", "Type your API key");
    // A server that takes four seconds to answer `/about`.
    prompt.paste("slowabout");
    prompt.pump(Duration::from_millis(300));
    let mark = prompt.screen.len();
    prompt.send(b"\r");
    let loading = pump_until(&mut prompt, Duration::from_secs(12), |p| pty::plain(&p.screen[mark..]).contains("loading..."));
    assert!(loading, "no spinner while the connection loaded:\n{}", pty::plain(&prompt.screen[mark..]));
    // Keys pressed meanwhile are read away, not typed into the prompt.
    prompt.send(b"zzz");
    let opened = pump_until(&mut prompt, Duration::from_secs(12), |p| pty::plain(&p.screen[mark..]).contains("ctrl+s to save this connection"));
    assert!(opened, "{}", pty::plain(&prompt.screen[mark..]));
    prompt.pump(Duration::from_millis(500));
    server.take();
    prompt.send(b"\r");
    pump_until(&mut prompt, Duration::from_secs(4), |_| server.seen() > 0);
    assert_eq!(server.take(), ["GET /"], "what was typed behind the form reached the prompt");
}

/// A program on stdin that is not text is not run in part: `could not read
/// stdin`, exit 1 and nothing sent, for a run and for a document about it.
#[test]
fn a_program_on_stdin_that_is_not_utf8_is_refused() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    for args in [&["-sa", "-"][..], &["-a", "-"], &["--describe", "-"], &["--assert", "-"], &["--imports", "-"]] {
        server.take();
        let mut cmd = api(server.port, dir.path());
        cmd.args(args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"GET /first\nGET /caf\xe9\n").unwrap();
        let out = child.wait_with_output().unwrap();
        server.settle(Duration::from_millis(150), Duration::from_secs(2));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!((out.status.code(), server.seen()), (Some(1), 0), "{args:?}: {stderr}");
        assert!(stderr.contains("could not read stdin"), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

/// A streamed response on stdout reads as the buffered one does, and a
/// chain under `--stream` is judged by what the server answered.
#[test]
fn a_streamed_response_prints_and_is_judged_as_a_buffered_one() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for uri in ["/a", "/numbers", "/zero"] {
        let buffered = run_in(&server, d, &["GET", uri]);
        let streamed = run_in(&server, d, &["--stream", "GET", uri]);
        assert_eq!(streamed.code, Some(0), "{uri}: {}", streamed.stderr);
        assert_eq!(streamed.stdout, buffered.stdout, "{uri}");
        assert!(streamed.stdout.ends_with('\n'), "{uri}: {:?}", streamed.stdout);
        assert_eq!(accepts_of(&server), ["application/json;stream=true"], "{uri}");
    }
    // A falsy answer is a "no", a truthy one a "yes", streamed or not.
    for flag in [&[][..], &["--stream"]] {
        let run = |line: &str| {
            let mut args = flag.to_vec();
            args.push(line);
            run_in(&server, d, &args)
        };
        assert_eq!(run("GET /zero && GET /never").sent, ["GET /zero"], "{flag:?}");
        assert_eq!(run("GET /zero || GET /then").sent, ["GET /zero", "GET /then"], "{flag:?}");
        assert_eq!(run("GET /a && GET /then").sent, ["GET /a", "GET /then"], "{flag:?}");
        assert_eq!(run("GET /missing || GET /then").sent, ["GET /missing", "GET /then"], "{flag:?}");
        let failed = run("assert GET /zero");
        assert_eq!(failed.code, Some(1), "{flag:?}");
        assert!(failed.stderr.contains("assertion failed: assert GET /zero (0)"), "{flag:?}: {}", failed.stderr);
    }
}

/// `-m` prints the describe block of a file named as a one-shot argument
/// too, with no `-a`, and the file runs.
#[test]
fn describe_first_works_for_a_file_named_as_an_argument() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(
        d.join("catalog.api"),
        "{ \"title\": { \"en-US\": \"Catalog\" }, \"docsLink\": \"https://docs.example.com/catalog\" }\nGET /products\n",
    )
    .unwrap();
    std::fs::write(d.join("bare.api"), "GET /products\n").unwrap();
    let mut cmd = api(server.port, d);
    cmd.args(["-m", "catalog.api"]).env("LANG", "en_US.UTF-8").env_remove("LC_ALL").env_remove("LC_MESSAGES");
    let got = ran(&server, cmd);
    assert_eq!((got.code, &got.sent[..]), (Some(0), &["GET /products".to_string()][..]), "{}", got.stderr);
    assert!(got.stderr.starts_with("Catalog\nhttps://docs.example.com/catalog\n"), "{}", got.stderr);
    // A file without a block prints nothing for it, and a request is no file.
    for args in [&["-m", "bare.api"][..], &["-m", "GET", "/products"]] {
        let got = run_in(&server, d, args);
        assert_eq!((got.code, got.sent.len()), (Some(0), 1), "{args:?}: {}", got.stderr);
        assert!(!got.stderr.contains("Catalog"), "{args:?}: {}", got.stderr);
    }
}

/// A file that can't be read as text, and a glob that is none, stop the
/// batch before anything is sent, naming the file or the pattern.
#[test]
fn an_include_that_cannot_be_read_stops_the_batch() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("latin.api"), b"GET /caf\xe9\n").unwrap();
    std::fs::write(d.join("latin.json"), b"{ \"path\": \"caf\xe9\" }").unwrap();
    for (program, says) in [
        ("GET /first\nlatin.api\n", "could not read include"),
        ("GET /first\nshared/[.api\n", "invalid include glob 'shared/[.api'"),
        ("import dir lib @latin.json\nGET /first\n", "import file is not UTF-8 text: latin.json"),
    ] {
        std::fs::write(d.join("batch.api"), program).unwrap();
        for args in [&["-sa", "batch.api"][..], &["--assert", "batch.api"]] {
            let got = run_in(&server, d, args);
            assert_eq!((got.code, got.sent.len()), (Some(1), 0), "{program:?} {args:?}: {}", got.stderr);
            assert!(got.stderr.contains(says), "{program:?} {args:?}: {}", got.stderr);
        }
    }
}

/// A file written from the prompt can be opened with ctrl+o, and the hint
/// says so; a write that failed leaves no such hint, and a clipboard none.
#[cfg(unix)]
#[test]
fn the_prompt_offers_to_open_a_file_it_wrote() {
    let server = RecordingServer::start();
    let dir = tempfile::tempdir().unwrap();
    let mut prompt = pty::Prompt::open(api(server.port, dir.path()));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));

    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /a > kept.json");
    assert_eq!(sent, ["GET /a"]);
    assert!(shown.contains("ctrl+o to open file"), "{shown}");
    assert!(dir.path().join("kept.json").exists());
    prompt.pump(Duration::from_millis(3300));

    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /b > no-such-dir/lost.json");
    assert_eq!(sent, ["GET /b"]);
    assert!(shown.contains("Error writing to no-such-dir/lost.json"), "{shown}");
    assert!(!shown.contains("ctrl+o to open file"), "{shown}");

    // An error is not appended, and is not a file to open either.
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /missing >> kept.json");
    assert_eq!(sent, ["GET /missing"]);
    assert!(shown.contains("(not appended)"), "{shown}");
    assert!(!shown.contains("ctrl+o to open file"), "{shown}");
}

/// `-c` with a connection that can't be used says why and, at a terminal,
/// opens the prompt all the same: another connection can be picked there.
#[cfg(unix)]
#[test]
fn a_connection_that_cannot_be_used_still_opens_the_prompt_at_a_terminal() {
    let server = RecordingServer::start();
    let url = format!("http://127.0.0.1:{}", server.port);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write_credentials(d, &[("alpha", url.clone(), "key", "k1", ""), ("odd", url.clone(), "bearer", "t", "")], "alpha");
    let mut cmd = api_bare(d);
    cmd.args(["-c", "odd"]);
    let mut prompt = pty::Prompt::open(cmd);
    prompt.wait_for("The connection \"odd\" can't be used: its auth_type \"bearer\"", Duration::from_secs(15));
    prompt.wait_ready(Duration::from_secs(15));
    prompt.pump(Duration::from_millis(600));
    // Nothing of the connection is sent anywhere.
    assert_eq!(server.seen(), 0);
    keys_then(&mut prompt, "\x11", "+ Add new connection");
    prompt.send(b"alpha");
    prompt.pump(Duration::from_millis(300));
    keys_then(&mut prompt, "\r", "connected to: alpha");
    prompt.pump(Duration::from_millis(500));
    let (sent, shown) = run_pasted(&mut prompt, &server, "GET /picked");
    assert_eq!(sent, ["GET /picked"], "{shown}");
}
