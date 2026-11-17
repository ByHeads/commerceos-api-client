#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read as IoRead, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cli_clipboard;
use reqwest::blocking::Client;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use colored::Colorize;
use crossterm::{
    cursor,
    event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyModifiers, KeyboardEnhancementFlags, PushKeyboardEnhancementFlags, PopKeyboardEnhancementFlags},
    execute, queue,
    style::Print,
    terminal::{self, Clear, ClearType},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Set once a write to stdout has failed: the reader has gone away
/// (`api -sa seed.api | head -2`). Nothing more is written there.
static STDOUT_CLOSED: AtomicBool = AtomicBool::new(false);

/// Stdout for everything the client prints. A closed stdout is not a reason
/// to stop: a batch is run for its requests, and its log is a by-product. So
/// a failed write is remembered, what follows is dropped, and the run goes
/// on to exit by how its requests went.
struct Out;

impl Write for Out {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !STDOUT_CLOSED.load(Ordering::Relaxed) && io::stdout().write_all(buf).is_err() {
            STDOUT_CLOSED.store(true, Ordering::Relaxed);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !STDOUT_CLOSED.load(Ordering::Relaxed) && io::stdout().flush().is_err() {
            STDOUT_CLOSED.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

/// `print!` to a stdout that may have closed. See `Out`.
macro_rules! out {
    ($($arg:tt)*) => {{
        let _ = write!(Out, $($arg)*);
    }};
}

/// `println!` to a stdout that may have closed. See `Out`.
macro_rules! outln {
    () => {{
        let _ = writeln!(Out);
    }};
    ($($arg:tt)*) => {{
        let _ = writeln!(Out, $($arg)*);
    }};
}

/// Whether the prompt turned bracketed paste on, and whether it pushed the
/// kitty keyboard flags: what `restore_terminal` has to undo.
static BRACKETED_PASTE_ON: AtomicBool = AtomicBool::new(false);
static KEYBOARD_FLAGS_PUSHED: AtomicBool = AtomicBool::new(false);

/// Put the terminal back the way the shell had it: keyboard flags popped,
/// bracketed paste off, cursor shown, raw mode off. Each part is undone only
/// if it was done, so this is safe to call from anywhere, any number of
/// times, and does nothing in a run that never touched the terminal.
fn restore_terminal() {
    let modes = leave_prompt_modes();
    let raw = terminal::is_raw_mode_enabled().unwrap_or(false);
    if !(modes || raw) {
        return;
    }
    let _ = execute!(io::stdout(), cursor::Show);
    let _ = terminal::disable_raw_mode();
}

/// Pop the keyboard flags and turn bracketed paste off, each only if the
/// prompt turned it on and it has not been undone yet. Says whether there
/// was anything to undo.
fn leave_prompt_modes() -> bool {
    let keyboard = KEYBOARD_FLAGS_PUSHED.swap(false, Ordering::SeqCst);
    let paste = BRACKETED_PASTE_ON.swap(false, Ordering::SeqCst);
    let mut stdout = io::stdout();
    if keyboard {
        let _ = execute!(stdout, PopKeyboardEnhancementFlags);
    }
    if paste {
        let _ = execute!(stdout, DisableBracketedPaste);
    }
    keyboard || paste
}

/// Restores the terminal when it goes out of scope, so every way out of the
/// prompt does: a normal return, an error passed up with `?`, a panic.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// End the process, with the terminal restored first. `std::process::exit`
/// runs no destructors, so an exit from inside the prompt would otherwise
/// leave the shell in raw mode with bracketed paste on.
fn exit_process(code: i32) -> ! {
    restore_terminal();
    let _ = io::stdout().flush();
    std::process::exit(code)
}

/// A panic prints its message through the default hook; before that, the
/// terminal is restored so the message is readable and the shell usable.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default_hook(info);
    }));
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long a footer status message stays up before clearing.
const STATUS_MSG_TTL: Duration = Duration::from_secs(3);

/// Why a streamed 200 can still be a failure: the status line is sent before the
/// body is generated, so errors arrive inside the stream. It only has to be
/// noticed, not read — the explanation it points at lives in the ctrl+h panel,
/// see `STREAMING_HELP_PROSE`.
const STREAMING_INFO_MSG: &str = "streamed bodies may encode errors, ctrl+h for more info";

/// The persistent footer marker shown while streaming is active.
const STREAMING_INDICATOR: &str = "streaming";
/// Shown in the same place while export mode is on. Streaming is not asked
/// for then, so the two never have to share the line.
const EXPORT_INDICATOR: &str = "export";

/// Prose of the long-form streaming caveat, shown in the ctrl+h panel while
/// streaming is active — the footer notice only has room to point here. The
/// link to the full documentation is appended by `streaming_help_lines`.
///
/// Kept under `STREAMING_HELP_MAX_COLS` a line: the help block is drawn at a
/// fixed height, so a line that wraps would desync the count from the rows
/// actually printed.
const STREAMING_HELP_PROSE: &[&str] = &[
    "  Response streaming is on, which means a 200 response can still",
    "  carry an error inside the body — the status line is sent before",
    "  the body is generated, so failures may show up mid-payload. Check",
    "  the content, not just the status.",
];

/// Width the help section is written to. Lines are printed as-is, so anything
/// longer would wrap and break the fixed-height block.
const STREAMING_HELP_MAX_COLS: usize = 68;

/// Where the API docs live for a connection — `ctrl+b` opens this, and the
/// streaming help section deep-links into it. Falls back to the public host
/// before a connection is established.
/// Open a file or URL with the system handler, swallowing its stdio so
/// Launch Services errors never leak into the raw-mode terminal.
/// Returns false when the handler could not be run or reported failure.
fn open_external(target: &str) -> bool {
    use std::process::Stdio;
    Command::new("open")
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
}

fn api_docs_url(base_uri: &str) -> String {
    if base_uri.is_empty() {
        "https://dev.heads.com/api-docs".to_string()
    } else {
        format!("{}/api-docs", base_uri)
    }
}

/// The streaming help section, with the docs link resolved against the current
/// connection. The link is a line of its own so it stays copy-pasteable.
fn streaming_help_lines(base_uri: &str) -> Vec<String> {
    let mut lines: Vec<String> = STREAMING_HELP_PROSE.iter().map(|l| l.to_string()).collect();
    lines.push(String::new());
    lines.push(format!(
        "  {}#description/streaming",
        api_docs_url(base_uri)
    ));
    lines
}

/// The shortcuts the ctrl+h panel lists, one per row.
const HELP_LINES: [&str; 24] = [
    "  enter      Send request",
    "  opt+enter  New line (multiline body) [or ctrl+n]",
    "  up/down    Navigate input history",
    "  tab        Complete URI (endpoints, operators, properties)",
    "  ctrl+space Cycle method: GET → PUT → PATCH → POST",
    "  ctrl+g     GET the URI on the line",
    "  ctrl+x     Clear body (keep method and URI)",
    "  ctrl+f     Clear all (reset to GET /)",
    "  ctrl+u     Clear entire input line (empty)",
    "  ctrl+k     Kill from cursor to end of line",
    "  alt+←/→    Move by word (or ctrl+←/→, alt+b/f)",
    "  alt+bksp   Delete word backward (or ctrl+w)",
    "  alt+d      Delete word forward",
    "  ctrl+y     Copy last request as curl command",
    "  ctrl+j     Erase last response body",
    "  ctrl+l     Erase all output",
    "  ctrl+s     Save connection",
    "  ctrl+q     Switch connection",
    "  ctrl+b     Open API docs in browser",
    "  ctrl+o     Open last saved file",
    "  ctrl+t     Toggle response streaming",
    "  ctrl+r     Toggle export mode (responses as seed data)",
    "  ctrl+c     Quit",
    "",
];

/// The rows of the ctrl+h panel under its ruler, exactly as they are drawn:
/// a blank row, the shortcuts, the line that says how to close it, and the
/// streaming section (a blank separator plus its text) when streaming is on.
///
/// What is drawn and what is cleared on closing are both taken from here, so
/// they can't disagree. Two things keep the panel to rows that can be
/// cleared again:
///
/// - The streaming lines are wrapped to the terminal width here rather than
///   by the terminal: the docs link carries the connection's host, and a
///   long one takes more than one row.
/// - The panel never grows past the screen. Rows that scrolled off the top
///   could not be reached to clear them and would be left behind, so on a
///   terminal too short for all of it the last row says how much is missing.
fn help_rows(state: &AppState) -> Vec<String> {
    let mut rows: Vec<String> = vec![String::new()];
    rows.extend(HELP_LINES.iter().map(|line| line.to_string()));
    rows.push("  ctrl+h or esc to close".to_string());
    if state.config.streaming {
        rows.push(String::new());
        for line in streaming_help_lines(&state.config.base_uri) {
            rows.extend(hard_wrap_ansi(&line, state.width as usize).split("\r\n").map(str::to_string));
        }
    }
    // The ruler above and these rows have to fit on the screen with the
    // cursor's row under them. A height of 0 is a terminal that gave none.
    let fits = (state.height as usize).saturating_sub(2).max(2);
    if state.height > 0 && rows.len() > fits {
        let hidden = rows.len() - (fits - 1);
        rows.truncate(fits - 1);
        rows.push(format!("  … {} more rows: enlarge the window. ctrl+h or esc to close", hidden));
    }
    rows
}

/// Rows from the ctrl+h panel's ruler down to the cursor under its last
/// row: the ruler and the rows of `help_rows`. It is how far up the clear
/// has to start.
fn help_line_count(state: &AppState) -> u16 {
    1 + help_rows(state).len() as u16
}

// Braille spinner frames (consistent everywhere)
const SPINNER_FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

// API operators for tab completion
const API_OPERATORS: &[&str] = &[
    "with(", "just(", "without(", "where(", "orderBy(",
    "take(", "skip(", "first", "last", "count",
    "flat", "entries", "array", "map(",
];

#[derive(Parser, Debug)]
#[command(name = "api")]
#[command(about = "Interactive CLI client for CommerceOS API")]
#[command(disable_version_flag = true)]
struct Args {
    /// Print version
    #[arg(short = 'v', long = "version")]
    version: bool,

    /// HTTP method (GET, POST, PUT, PATCH, DELETE), or a whole .api line
    /// (a directive, a && chain, or a file to run)
    #[arg(value_name = "METHOD")]
    method: Option<String>,

    /// URI path (e.g., /people)
    #[arg(value_name = "URI")]
    uri: Option<String>,

    /// Request body (JSON); further words are joined into the .api line
    #[arg(value_name = "BODY", num_args = 0..)]
    body: Vec<String>,

    /// Base URI
    #[arg(short = 'b', long = "base-uri")]
    base_uri: Option<String>,

    /// API key for authentication
    #[arg(short = 'k', long = "key")]
    key: Option<String>,

    /// Bearer token for authentication (long form only — `-t` is --stream)
    #[arg(long = "token")]
    token: Option<String>,

    /// Use a saved connection (by alias or URL)
    #[arg(short = 'c', long = "connection", value_name = "ALIAS_OR_URL")]
    connection: Option<String>,

    /// Get base-uri and key from 1Password
    #[arg(long = "1p", value_name = "SELECTOR", hide = true)]
    one_password: Option<String>,

    /// Skip the OS keychain; read/write connections from a plaintext JSON file
    /// (path from API_CREDENTIALS_FILE, else ./.api-credentials.json)
    #[arg(long = "no-keychain")]
    no_keychain: bool,

    /// Use /api/me/v1 instead of /api/v1
    #[arg(long = "me")]
    me: bool,

    /// Do not print status info
    #[arg(short = 's', long = "silent")]
    silent: bool,

    /// Output raw JSON (no pretty printing)
    #[arg(short = 'r', long = "raw")]
    raw: bool,

    /// Include null values in response
    #[arg(short = 'i', long = "include-nulls")]
    include_nulls: bool,

    /// Use NDJSON for request and response
    #[arg(long = "ndjson")]
    ndjson: bool,

    /// Enable experimental features (body completion, syntax highlighting)
    #[arg(short = 'x', long = "experimental")]
    experimental: bool,

    /// Bulk mode: execute requests from a file (one per line). Use without value or with `-` to read from stdin.
    #[arg(short = 'a', long = "all", value_name = "FILE", num_args = 0..=1, default_missing_value = "-")]
    all: Option<String>,

    /// Preview the request(s) and confirm before sending (default: yes)
    #[arg(short = 'p', long = "preview")]
    preview: bool,

    /// Stop at the first response of 400 or above: print its body and exit 1
    #[arg(short = 'f', long = "fail-fast")]
    fail_fast: bool,

    /// Print the describe block of the .api file being run before running it
    #[arg(short = 'm', long = "describe-first")]
    describe_first: bool,

    /// Print the describe block of a .api file as JSON and send nothing
    #[arg(long = "describe", value_name = "FILE")]
    describe: Option<String>,

    /// Print the bodies of every `PUT /assert` a .api file makes, includes
    /// and imports followed, as one JSON array, and send nothing
    #[arg(long = "assert", value_name = "FILE")]
    assert: Option<String>,

    /// Export mode: turn responses into seed data. Database keys are dropped,
    /// and a record with no other identifier keeps its key as `key?` and under
    /// this name, a namespaced key such as com.heads.seedID
    #[arg(long = "export", value_name = "EXTERNAL_ID")]
    export: Option<String>,

    /// Stream the response body instead of buffering it (also: API_STREAMING=1)
    #[arg(short = 't', long = "stream")]
    stream: bool,

    /// Disable streaming even when --stream or API_STREAMING asked for it
    #[arg(long = "no-streaming")]
    no_streaming: bool,

    /// Request timeout in seconds; 0 disables it (default: 600 = 10 minutes)
    #[arg(long = "timeout", value_name = "SECONDS")]
    timeout: Option<u64>,
}

#[derive(Clone)]
struct Config {
    base_uri: String,
    api_key: String,
    token: String,
    api_path: String,
    silent: bool,
    raw: bool,
    include_nulls: bool,
    ndjson: bool,
    complete: bool,
    outfile: String,
    /// `>> file` instead of `> file`: append to the target, merging arrays and
    /// format-aware for `.ndjson`/`.csv`, rather than overwriting.
    outfile_append: bool,
    /// Streaming is active for this request: the user asked for it and (in the
    /// TUI, where we know) the server advertises `response:streaming`.
    streaming: bool,
    /// The user asked for streaming via `--stream` or `API_STREAMING`. Kept
    /// separate from `streaming` so the TUI can re-derive the effective value
    /// when the server flag arrives, and so ctrl+t has something to toggle.
    stream_requested: bool,
    /// Server advertises `response:streaming`. Only known in the TUI, which
    /// reads it from /about at startup; assumed true elsewhere.
    server_streaming: bool,
    experimental: bool,
    /// In silent bulk mode: print status line (with `|-` prefix) but suppress body output
    bulk_silent: bool,
    /// Request timeout in seconds. Always set — see `DEFAULT_TIMEOUT_SECS`.
    /// `0` means no timeout (indefinite), via `--timeout 0`.
    timeout_secs: u64,
    /// Preview request(s) and confirm before sending
    preview: bool,
    /// Send the request and classify the response, but print nothing for a
    /// non-error status: no status line, no body, no outfile. Used by
    /// `sleep while` polls, which only care about truthiness. Error statuses
    /// still print so an aborted poll says why.
    quiet: bool,
    /// Print the status line as usual but never the body — the response is a
    /// verdict, not data. Used by `assert`, whose payload must not leak into
    /// whatever the batch is producing on stdout.
    check_only: bool,
    /// Status and body of the last response taken in `quiet`/`check_only`
    /// mode, so the caller can say *why* a check failed.
    last_response: Option<(u16, String)>,
    /// A "no" is an acceptable answer to this request: it's an `assert not`,
    /// or a chain segment with something after it. A 404 then prints orange
    /// rather than red — see `status_tone`.
    expect_falsy: bool,
    /// `-f`: a response of 400 or above ends the run. See `fail_fast_trips`.
    fail_fast: bool,
    /// `-m`: print the describe block of the file being run before it runs.
    describe_first: bool,
    /// Export mode, from `--export <name>` or ctrl+r at the prompt: responses
    /// are rewritten as seed data, with `name` as the external identifier a
    /// lone database key is kept under, beside `key?`. `None` is off. See
    /// `export_value`.
    export_id: Option<String>,
    /// Export mode was set for the whole run or session (`--export`, ctrl+r)
    /// and an `export` line does not change it: the command line overrides.
    export_pinned: bool,
    /// The status of the last response the prompt received, for `-f` there.
    last_status: Option<u16>,
    /// OAuth2 client credentials of the connection, when it has them: what a
    /// token that ran out is renewed with. Empty for a key or a plain token.
    oauth2_client_id: String,
    oauth2_client_secret: String,
    /// The run is one request given as arguments (`api GET /x > file`), not
    /// a batch: what it could not write ends it with exit 1.
    one_shot: bool,
    /// The session runs a saved connection (`-c`) with a `-b`, `-k` or
    /// `--token` in the place of what is stored for it. What it holds is then
    /// not that connection: saved under a new name it is a new connection,
    /// and the stored one stays. Ends with a save and with a `ctrl+q` switch.
    connection_overridden: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            base_uri: String::new(),
            api_key: String::new(),
            token: String::new(),
            api_path: "/api/v1".to_string(),
            silent: false,
            raw: false,
            include_nulls: false,
            ndjson: false,
            complete: false,
            outfile: String::new(),
            outfile_append: false,
            streaming: false,
            stream_requested: false,
            server_streaming: true,
            experimental: false,
            bulk_silent: false,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            preview: false,
            quiet: false,
            check_only: false,
            last_response: None,
            expect_falsy: false,
            fail_fast: false,
            describe_first: false,
            export_id: None,
            export_pinned: false,
            last_status: None,
            oauth2_client_id: String::new(),
            oauth2_client_secret: String::new(),
            one_shot: false,
            connection_overridden: false,
        }
    }
}

/// Default request timeout. Set explicitly because reqwest's *blocking* client
/// otherwise applies its own 30s default — far too short for large exports.
const DEFAULT_TIMEOUT_SECS: u64 = 600; // 10 minutes

/// The TLS setup every HTTP client here uses: rustls on ring, TLS 1.2 and 1.3,
/// verifying against the Mozilla root certificates compiled into the binary.
/// Nothing is read from the machine, so a server is trusted the same way on
/// every platform and in a container that has no certificates installed.
fn tls_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// Where every HTTP client starts, so none is built without `tls_config`.
fn client_builder() -> reqwest::blocking::ClientBuilder {
    Client::builder().tls_backend_preconfigured(tls_config())
}

/// Build the HTTP client. The timeout is always passed explicitly, so reqwest's
/// hidden default can never apply; `0` disables it (`--timeout 0`).
fn build_request_client(timeout_secs: u64) -> Client {
    let timeout = if timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(timeout_secs))
    };
    client_builder()
        .timeout(timeout)
        .build()
        .expect("could not set up the HTTP client")
}

/// How a request timeout should be described in errors and help text.
fn describe_timeout(timeout_secs: u64) -> String {
    if timeout_secs == 0 {
        "no timeout".to_string()
    } else {
        format!("{}s", timeout_secs)
    }
}

// Saved connection for keychain credential storage
const KEYCHAIN_SERVICE: &str = "com.heads.api-client";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavedConnection {
    name: String,
    url: String,
    auth_type: String,   // "key", "token", or "oauth2"
    credential: String,  // API key, Bearer token, or OAuth2 client_secret
    /// OAuth2 client ID. Only an OAuth2 connection has one, so a key or a
    /// token connection may leave it out.
    #[serde(default)]
    client_id: String,
}

// All connection data stored in a single keychain entry
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct KeychainData {
    #[serde(default, alias = "environments")]
    connections: Vec<SavedConnection>,
    #[serde(default)]
    default: String,
}

fn keychain_entry() -> keyring::Entry {
    keyring::Entry::new(KEYCHAIN_SERVICE, "data").expect("failed to create keyring entry")
}

// When set, all credential I/O goes to this plaintext JSON file instead of the
// OS keychain (enabled by `--no-keychain`). Set once at the top of main() before
// any keychain access, so the background-load thread observes it too.
static NO_KEYCHAIN_FILE: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();

/// Enable file-backed credential storage (no keychain). `path` is the JSON file
/// to use. Call once at startup before any keychain access.
fn enable_no_keychain(path: PathBuf) {
    let _ = NO_KEYCHAIN_FILE.set(Some(path));
}

/// Returns the credentials file path when `--no-keychain` is active, else None.
fn no_keychain_file() -> Option<PathBuf> {
    NO_KEYCHAIN_FILE.get().cloned().flatten()
}

thread_local! {
    static KEYCHAIN_CACHE: std::cell::RefCell<Option<KeychainData>> = const { std::cell::RefCell::new(None) };
}

/// Why the store of saved connections could not be read, if it couldn't.
/// Said once on stderr when that is safe, and kept for the prompt to show.
static STORE_PROBLEM: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn store_problem() -> Option<String> {
    STORE_PROBLEM.lock().ok().and_then(|problem| problem.clone())
}

/// The saved connections in `json`. Nothing at all is an empty store, as a
/// file that was created but never written to.
fn parse_store(json: &str) -> Result<KeychainData, String> {
    if json.trim().is_empty() {
        return Ok(KeychainData::default());
    }
    serde_json::from_str(json).map_err(|e| format!("it is not what the client wrote there ({})", e))
}

/// Read a credentials file. One that does not exist is an empty store; one
/// that can't be read, or doesn't hold what the client writes, is an error.
/// The difference matters: an empty store may be written, a broken one must
/// not be written over.
fn read_store_file(path: &std::path::Path) -> Result<KeychainData, String> {
    match fs::read_to_string(path) {
        Ok(json) => parse_store(&json).map_err(|e| format!("could not read {}: {}", path.display(), e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(KeychainData::default()),
        Err(e) => Err(format!("could not read {}: {}", path.display(), e)),
    }
}

/// Write a credentials file in one step: to a file beside it, then renamed
/// over it, so a reader never finds half a file. The mode of the file that
/// was there is kept.
fn write_store_file(path: &std::path::Path, data: &KeychainData) -> Result<(), String> {
    let json = serde_json::to_string(data).map_err(|e| e.to_string())?;
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(format!(".tmp-{}", std::process::id()));
    let tmp = path.with_file_name(name);
    let written = fs::write(&tmp, &json)
        .and_then(|()| match fs::metadata(path) {
            Ok(existing) => fs::set_permissions(&tmp, existing.permissions()),
            Err(_) => Ok(()),
        })
        .and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written.map_err(|e| format!("credentials file error: {}", e))
}

/// Read the store from where it is kept, not from the cache.
fn read_store() -> Result<KeychainData, String> {
    if let Some(path) = no_keychain_file() {
        return read_store_file(&path);
    }
    match keychain_entry().get_password() {
        Ok(json) => parse_store(&json).map_err(|e| format!("could not read the saved connections in the keychain: {}", e)),
        Err(keyring::Error::NoEntry) => Ok(KeychainData::default()),
        Err(e) => Err(format!("could not read the keychain: {}", e)),
    }
}

/// The saved connections, read once per run. A store that could not be read
/// counts as empty here, and the reason is said: once on stderr, unless the
/// prompt has the terminal, where `store_problem` is shown instead.
fn load_keychain_data() -> KeychainData {
    KEYCHAIN_CACHE.with(|cache| {
        if let Some(ref data) = *cache.borrow() {
            return data.clone();
        }
        let data = read_store().unwrap_or_else(|problem| {
            if !terminal::is_raw_mode_enabled().unwrap_or(false) {
                eprintln!("WARNING: {}. No saved connection is used.", problem);
            }
            if let Ok(mut kept) = STORE_PROBLEM.lock() {
                *kept = Some(problem);
            }
            KeychainData::default()
        });
        *cache.borrow_mut() = Some(data.clone());
        data
    })
}

fn save_keychain_data(data: &KeychainData) -> Result<(), String> {
    if let Some(path) = no_keychain_file() {
        write_store_file(&path, data)?;
    } else {
        let json = serde_json::to_string(data).map_err(|e| e.to_string())?;
        keychain_entry().set_password(&json).map_err(|e| format!("keychain error: {}", e))?;
    }
    KEYCHAIN_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(data.clone());
    });
    Ok(())
}

/// Change the store: read it afresh, apply `change`, write it back. Read
/// afresh so that what another session saved in the meantime is kept, and so
/// that a store which can't be read is never written over: the change is
/// refused with the reason, and the store is left as it is.
fn update_store(change: impl FnOnce(&mut KeychainData)) -> Result<(), String> {
    let mut data = read_store().map_err(|problem| format!("{}; left as it is", problem))?;
    change(&mut data);
    save_keychain_data(&data)
}

fn list_connections() -> Vec<String> {
    load_keychain_data().connections.iter().map(|e| e.name.clone()).collect()
}

fn load_connection(name: &str) -> Option<SavedConnection> {
    load_keychain_data().connections.iter().find(|e| e.name == name).cloned()
}

/// Put `env` in the store, in the place of the connection of the same name
/// if there is one. With `replaces`, the connection of that name is being
/// saved under a new one: the old entry goes, and if it was the default the
/// new name is.
fn put_connection(data: &mut KeychainData, env: &SavedConnection, replaces: Option<&str>) {
    if let Some(old) = replaces.filter(|old| *old != env.name) {
        data.connections.retain(|e| e.name != old);
        if data.default == old {
            data.default = env.name.clone();
        }
    }
    match data.connections.iter_mut().find(|e| e.name == env.name) {
        Some(existing) => *existing = env.clone(),
        None => data.connections.push(env.clone()),
    }
}

fn save_connection(env: &SavedConnection, replaces: Option<&str>) -> Result<(), String> {
    update_store(|data| put_connection(data, env, replaces))
}

fn delete_connection(name: &str) -> Result<(), String> {
    update_store(|data| {
        data.connections.retain(|e| e.name != name);
        if data.default == name {
            data.default.clear();
        }
    })
}

fn get_default_connection() -> Option<String> {
    let data = load_keychain_data();
    if data.default.is_empty() { None } else { Some(data.default) }
}

fn set_default_connection(name: &str) -> Result<(), String> {
    update_store(|data| data.default = name.to_string())
}

/// A value as it is written in an `application/x-www-form-urlencoded` body:
/// letters, digits and `-._*` as they are, a space as `+`, every other byte
/// as `%XX`. A secret holding `&`, `=`, `+` or `%` arrives as it was given.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => out.push(byte as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

// OAuth2 client credentials token exchange
fn oauth2_token_exchange(base_uri: &str, client_id: &str, client_secret: &str) -> Result<(String, u64), String> {
    let token_url = format!("{}/oauth2/v1/token", base_uri.trim_end_matches('/'));
    let client = client_builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .post(&token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            form_encode(client_id),
            form_encode(client_secret)
        ))
        .send()
        .map_err(|e| format!("token request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("token endpoint returned {}", resp.status()));
    }

    let body: Value = resp.json().map_err(|e| format!("invalid token response: {}", e))?;
    let access_token = body["access_token"]
        .as_str()
        .ok_or("missing access_token in response")?
        .to_string();
    let expires_in = body["expires_in"].as_u64().unwrap_or(3600);

    Ok((access_token, expires_in))
}

// OpenAPI spec structures for tab completion
#[derive(Debug, Deserialize, Default)]
struct ApiSpec {
    // What a spec leaves out is left out of completion; it does not make the
    // whole spec unreadable.
    #[serde(default)]
    paths: HashMap<String, PathItem>,
    components: Option<Components>,
    tags: Option<Vec<TagItem>>,
}

#[derive(Debug, Deserialize, Default)]
struct TagItem {
    #[serde(default)]
    name: String,
    #[serde(rename = "x-type")]
    x_type: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Components {
    #[serde(default)]
    schemas: HashMap<String, SchemaDefinition>,
}

#[derive(Debug, Deserialize, Default)]
struct PathItem {
    get: Option<OperationItem>,
    post: Option<OperationItem>,
    put: Option<OperationItem>,
    patch: Option<OperationItem>,
    delete: Option<OperationItem>,
    parameters: Option<Vec<PathParameter>>,
}

#[derive(Debug, Deserialize, Default)]
struct PathParameter {
    name: Option<String>,
    schema: Option<SchemaRef>,
}

#[derive(Debug, Deserialize, Default)]
struct OperationItem {
    #[serde(default)]
    responses: HashMap<String, ResponseItem>,
    parameters: Option<Vec<PathParameter>>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
struct ResponseItem {
    content: Option<HashMap<String, MediaTypeItem>>,
}

#[derive(Debug, Deserialize, Default)]
struct MediaTypeItem {
    schema: Option<SchemaRef>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct SchemaRef {
    #[serde(rename = "$ref")]
    ref_path: Option<String>,
    #[serde(rename = "type")]
    schema_type: Option<String>,
    items: Option<Box<SchemaRef>>,
    properties: Option<HashMap<String, SchemaRef>>,
    #[serde(rename = "enum")]
    enum_values: Option<Vec<serde_json::Value>>,
    examples: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize, Default)]
struct SchemaDefinition {
    #[serde(rename = "type")]
    schema_type: Option<String>,
    properties: Option<HashMap<String, SchemaRef>>,
    #[serde(rename = "allOf")]
    all_of: Option<Vec<SchemaRef>>,
    #[serde(rename = "x-indexer")]
    x_indexer: Option<IndexerInfo>,
    #[serde(rename = "x-array-members")]
    x_array_members: Option<HashMap<String, ArrayMemberInfo>>,
    #[serde(rename = "x-primitive-members")]
    x_primitive_members: Option<HashMap<String, ArrayMemberInfo>>,
    #[serde(rename = "additionalProperties")]
    additional_properties: Option<AdditionalPropertiesInfo>,
    #[serde(rename = "x-parent-type")]
    x_parent_type: Option<String>,
    #[serde(rename = "x-child-types")]
    x_child_types: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct AdditionalPropertiesInfo {
    #[serde(rename = "x-additionalPropertiesName")]
    additional_properties_name: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct ArrayMemberInfo {
    #[serde(rename = "$ref")]
    ref_path: Option<String>,
    #[serde(rename = "type")]
    member_type: Option<String>,
    items: Option<Box<SchemaRef>>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct IndexerInfo {
    #[serde(rename = "indexType")]
    index_type: Option<String>,
    #[serde(rename = "returnType")]
    return_type: Option<String>,
}

struct BackgroundLoadResult {
    streaming: bool,
    complete: bool,
    /// The server answered the request for its API spec, and the answer was
    /// not a spec the client could read: completion has nothing to go by.
    spec_unreadable: bool,
    connected: bool,  // true if server responded (even without metadata)
    // 1Password resolved credentials (if applicable)
    base_uri: Option<String>,
    api_key: Option<String>,
    error: Option<String>,
    // OpenAPI data
    endpoints: Vec<String>,
    schema_props: HashMap<String, Vec<String>>,
    endpoint_types: HashMap<String, String>,
    param_types: HashMap<String, String>,
    endpoint_schemas: HashMap<String, String>,
    indexer_info: HashMap<String, IndexerInfo>,
    prop_types: HashMap<String, HashMap<String, String>>,
    array_members: HashMap<String, HashMap<String, String>>,
    primitive_members: HashMap<String, HashMap<String, String>>,
    additional_props_key: HashMap<String, String>,
    array_schemas: std::collections::HashSet<String>,
    array_endpoints: std::collections::HashSet<String>,
    enum_values: HashMap<String, HashMap<String, Vec<String>>>,  // schema → prop → enum values
    subtypes: HashMap<String, Vec<String>>,  // base schema → list of subtype @type values
    parent_types: HashMap<String, String>,  // schema → parent schema (from x-parent-type)
    mapped_types: Vec<String>,
    spec: Option<ApiSpec>,
}

struct AppState {
    config: Config,
    input: String,
    cursor_pos: usize,
    method: String,
    uri: String,
    body: String,
    history: Vec<String>,
    history_idx: i32,
    history_stash: String,  // saves unsent input when browsing history
    prev_method: String,
    prev_uri: String,
    prev_body: String,
    prev_outfile: String,
    /// The last request's outfile as written (`clipboard` among them), and
    /// whether it was `>>`.
    prev_display_outfile: String,
    prev_outfile_append: bool,
    display_outfile: String,  // Original outfile path (with ~ unexpanded) for display
    last_outfile: String,
    last_display_outfile: String,  // Display version of last outfile
    show_help: bool,
    prev_show_help: bool,  // Track previous help state for clearing
    prev_input_lines: u16, // Track number of input lines for clearing multiline
    loading: bool,
    loading_frame: usize,
    loading_connection_name: Option<String>,  // Connection name for "Connecting to X..." spinner
    status_msg: String,
    status_msg_at: Option<std::time::Instant>,
    /// Set when streaming turns on, to pulse the footer indicator white.
    streaming_flash_at: Option<std::time::Instant>,
    /// The external identifier name export mode uses in this session: the
    /// one from `--export`, or the one typed the first time ctrl+r turned
    /// export on. Kept while export is off, so turning it on again does not
    /// ask twice.
    export_name: Option<String>,
    ctrl_c_pending: bool,
    ctrl_c_at: Option<std::time::Instant>,
    width: u16,
    height: u16,
    prev_width: u16,
    output_history: Vec<OutputBlock>,  // Logged requests, re-rendered on resize
    /// Printed before the next request's log line (`assert `), see
    /// `OutputBlock::prefix`. Taken by `execute_request`.
    log_prefix: String,
    // Tab completion
    spec: Option<ApiSpec>,
    endpoints: Vec<String>,
    schema_props: HashMap<String, Vec<String>>,
    endpoint_types: HashMap<String, String>,
    param_types: HashMap<String, String>,  // endpoint pattern -> parameter type name
    endpoint_schemas: HashMap<String, String>,  // endpoint path -> schema name (via tags x-type)
    indexer_info: HashMap<String, IndexerInfo>,  // schema name -> x-indexer info
    prop_types: HashMap<String, HashMap<String, String>>,  // schema name -> (property name -> property type)
    array_members: HashMap<String, HashMap<String, String>>,  // schema name -> (member name -> member type)
    primitive_members: HashMap<String, HashMap<String, String>>,  // schema name -> (member name -> member type)
    additional_props_key: HashMap<String, String>,  // schema name -> additionalProperties key type (e.g., "date-time")
    array_schemas: std::collections::HashSet<String>,  // schemas that are array types (for fallback detection)
    array_endpoints: std::collections::HashSet<String>,  // endpoints that return arrays (response has items)
    enum_values: HashMap<String, HashMap<String, Vec<String>>>,  // schema → prop → enum values
    subtypes: HashMap<String, Vec<String>>,  // base schema → subtype @type values
    parent_types: HashMap<String, String>,  // schema → parent schema (from x-parent-type)
    mapped_types: Vec<String>,  // mapped type names for ~map() completion
    completions: Vec<String>,
    completion_idx: usize,
    last_tab_input: String,
    completion_uri_suffix: String,  // URI text after cursor for mid-URI completion
    connection_alias: String,  // Current connection alias (for Ctrl+S pre-fill)
    last_was_splash: bool,  // True if last output was a splash (for consecutive env switches)
    last_method_cycle: Option<std::time::Instant>,  // For ctrl+space reset-to-GET-after-5s logic
    stashed_body: String,  // Body hidden when switching to GET, restored when switching back
    // Full chain text while a `&&` chain is executing — the per-request input
    // restore shows this instead of the just-sent segment, so the input area
    // holds the whole chain from Enter to finish. None outside chains.
    chain_input: Option<String>,
    method_auto_promoted: bool,  // True while the current PUT came from body auto-promotion (reverts to GET if the body is cleared)
    method_auto_promoted_uri: String,  // URI whose method was auto-promoted — revert only fires while the last segment still targets it
    // Body input mode (for POST/PUT/PATCH without body)
    body_input_mode: bool,
    body_input_buffer: String,
    /// The terminal was resized during a wait; the screen is drawn again as
    /// soon as the prompt is back.
    resize_pending: bool,
    body_input_method: String,
    body_input_uri: String,
    // OAuth2 credentials for token refresh
    // Bracketed-paste identifier-expansion state
    // Cycles through identifiers when the same JSON is re-pasted within 10s.
    last_paste_raw: String,
    last_paste_cycle_idx: usize,
    last_paste_at: Option<std::time::Instant>,
}

impl AppState {
    fn new(config: Config) -> Self {
        let export_name = config.export_id.clone();
        AppState {
            config,
            input: "GET /".to_string(),
            cursor_pos: 5,
            method: "GET".to_string(),
            uri: "/".to_string(),
            body: String::new(),
            history: Vec::new(),
            history_idx: -1,
            history_stash: String::new(),
            prev_method: String::new(),
            prev_uri: String::new(),
            prev_body: String::new(),
            prev_outfile: String::new(),
            prev_display_outfile: String::new(),
            prev_outfile_append: false,
            display_outfile: String::new(),
            last_outfile: String::new(),
            last_display_outfile: String::new(),
            show_help: false,
            prev_show_help: false,
            prev_input_lines: 1,
            loading: false,
            loading_frame: 0,
            loading_connection_name: None,
            status_msg: String::new(),
            status_msg_at: None,
            streaming_flash_at: None,
            export_name,
            ctrl_c_pending: false,
            ctrl_c_at: None,
            width: 80,
            height: 24,
            prev_width: 80,
            output_history: Vec::new(),
            log_prefix: String::new(),
            spec: None,
            endpoints: Vec::new(),
            schema_props: HashMap::new(),
            endpoint_types: HashMap::new(),
            param_types: HashMap::new(),
            endpoint_schemas: HashMap::new(),
            indexer_info: HashMap::new(),
            prop_types: HashMap::new(),
            array_members: HashMap::new(),
            primitive_members: HashMap::new(),
            additional_props_key: HashMap::new(),
            array_schemas: std::collections::HashSet::new(),
            array_endpoints: std::collections::HashSet::new(),
            enum_values: HashMap::new(),
            subtypes: HashMap::new(),
            parent_types: HashMap::new(),
            mapped_types: Vec::new(),
            completions: Vec::new(),
            completion_idx: 0,
            last_tab_input: String::new(),
            completion_uri_suffix: String::new(),
            connection_alias: String::new(),
            last_was_splash: false,
            last_method_cycle: None,
            stashed_body: String::new(),
            chain_input: None,
            method_auto_promoted: false,
            method_auto_promoted_uri: String::new(),
            body_input_mode: false,
            body_input_buffer: String::new(),
            resize_pending: false,
            body_input_method: String::new(),
            body_input_uri: String::new(),
            last_paste_raw: String::new(),
            last_paste_cycle_idx: 0,
            last_paste_at: None,
        }
    }
}

// Convert character index to byte index for safe UTF-8 string slicing
/// Return bracket nesting depth at cursor position, skipping quoted strings.
fn bracket_depth_at(input: &str, cursor_pos: usize) -> i32 {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (i, ch) in input.chars().enumerate() {
        if i >= cursor_pos {
            break;
        }
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && in_string {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if !in_string {
            match ch {
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
        }
    }
    depth
}

/// Check if cursor position is inside unmatched `{}`/`[]` pairs.
fn cursor_inside_brackets(input: &str, cursor_pos: usize) -> bool {
    bracket_depth_at(input, cursor_pos) > 0
}

/// Reformat a single-line JSON string to pretty-printed multi-line.
/// Returns (formatted_string, new_cursor_char_offset) where cursor is placed at the
/// equivalent position in the formatted output.
fn reformat_json_multiline(json: &str, cursor_offset: usize) -> (String, usize) {
    let mut out = String::new();
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape = false;
    let mut new_cursor = 0usize;
    let mut src_char_idx = 0usize;
    let mut cursor_set = false;

    for ch in json.chars() {
        if src_char_idx == cursor_offset && !cursor_set {
            new_cursor = out.chars().count();
            cursor_set = true;
        }

        if escape {
            escape = false;
            out.push(ch);
            src_char_idx += 1;
            continue;
        }
        if ch == '\\' && in_string {
            escape = true;
            out.push(ch);
            src_char_idx += 1;
            continue;
        }
        if in_string {
            out.push(ch);
            if ch == '"' { in_string = false; }
            src_char_idx += 1;
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                out.push(ch);
            }
            '{' | '[' => {
                depth += 1;
                out.push(ch);
                // Peek ahead: if [ is followed by { (skipping whitespace), keep them on same line
                let rest: String = json.chars().skip(src_char_idx + 1).collect();
                let next_nws = rest.chars().find(|c| !c.is_whitespace());
                if ch == '[' && next_nws == Some('{') {
                    // Don't add newline — the { will handle it
                } else {
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth));
                }
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                // Don't add extra newline before ] if it follows } (keep }] together)
                let last_nws = out.chars().rev().find(|c| !c.is_whitespace());
                if ch == ']' && last_nws == Some('}') {
                    // Trim trailing whitespace/newline from after }
                    let trimmed = out.trim_end().len();
                    out.truncate(trimmed);
                } else {
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth));
                }
                out.push(ch);
            }
            ',' => {
                out.push(ch);
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
            ':' => {
                out.push_str(": ");
            }
            ' ' | '\t' => {
                // Skip original whitespace outside strings (we add our own)
            }
            _ => {
                out.push(ch);
            }
        }
        src_char_idx += 1;
    }

    if !cursor_set {
        new_cursor = out.chars().count();
    }

    (out, new_cursor)
}

/// Find the byte offset where the JSON body starts in the input (after method + URI).
/// Returns None if there's no body.
fn find_body_start(input: &str) -> Option<usize> {
    let trimmed_start = input.len() - input.trim_start().len();
    let trimmed = input.trim_start();
    // Skip method (first word)
    let first_end = trimmed.find(|c: char| c.is_whitespace())?;
    let after_first = &trimmed[first_end..];
    let after_first_trimmed = after_first.trim_start();
    let skip1 = first_end + (after_first.len() - after_first_trimmed.len());
    // If first word is a method, skip URI too
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    let first_word = &trimmed[..first_end];
    if methods.contains(&first_word.to_uppercase().as_str()) {
        // Skip URI (second word)
        let uri_end = after_first_trimmed.find(|c: char| c.is_whitespace())?;
        let after_uri = &after_first_trimmed[uri_end..];
        let body_offset = after_uri.len() - after_uri.trim_start().len();
        Some(trimmed_start + skip1 + uri_end + body_offset)
    } else if first_word.starts_with('/') {
        // URI only, body follows
        Some(trimmed_start + skip1)
    } else {
        None
    }
}

/// Apply JSON syntax highlighting to a string. Returns ANSI-colored version.
/// If `cursor_char_pos` is Some, returns (before_cursor, char_at_cursor, after_cursor) split
/// in the highlighted output, preserving correct highlighting state across the split.
fn highlight_json_split(s: &str, cursor_char_pos: Option<usize>) -> (String, Option<char>, String) {
    let full = highlight_json(s);
    match cursor_char_pos {
        None => (full, None, String::new()),
        Some(pos) => {
            // Walk the highlighted string, counting only non-ANSI characters,
            // tracking the active ANSI color so we can restore it after the cursor
            let mut char_count = 0usize;
            let bytes = full.as_bytes();
            let len = bytes.len();
            let mut i = 0;
            let mut split_byte = None;
            let mut cursor_end_byte = None;
            let mut active_color = String::new();
            let mut color_at_split = String::new();
            while i < len {
                if bytes[i] == 0x1b {
                    // Capture the full ANSI escape sequence
                    let seq_start = i;
                    while i < len && bytes[i] != b'm' {
                        i += 1;
                    }
                    if i < len { i += 1; }
                    let seq = &full[seq_start..i];
                    if seq == "\x1b[0m" {
                        active_color.clear();
                    } else {
                        active_color = seq.to_string();
                    }
                    continue;
                }
                if char_count == pos && split_byte.is_none() {
                    split_byte = Some(i);
                    color_at_split = active_color.clone();
                    let ch_len = full[i..].chars().next().map_or(1, |c| c.len_utf8());
                    cursor_end_byte = Some(i + ch_len);
                }
                let ch_len = full[i..].chars().next().map_or(1, |c| c.len_utf8());
                i += ch_len;
                char_count += 1;
            }
            match (split_byte, cursor_end_byte) {
                (Some(sb), Some(ce)) => {
                    let before = full[..sb].to_string();
                    let cursor_ch = full[sb..].chars().next().unwrap_or(' ');
                    // Restore active color after the cursor so highlighting continues
                    let after = if !color_at_split.is_empty() {
                        format!("{}{}", color_at_split, &full[ce..])
                    } else {
                        full[ce..].to_string()
                    };
                    (before, Some(cursor_ch), after)
                }
                _ => {
                    (full, None, String::new())
                }
            }
        }
    }
}

fn highlight_json(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let r = "\x1b[0m";
    let c_key = "\x1b[38;5;110m";     // keys: soft blue
    let c_str = "\x1b[38;5;114m";     // string values: green
    let c_num = "\x1b[38;5;179m";     // numbers: yellow
    let c_bool = "\x1b[38;5;176m";    // booleans/null: magenta
    let c_brace = "\x1b[38;5;245m";   // brackets/braces: gray
    let c_at = "\x1b[38;5;147m";      // @type key: light purple

    let mut out = String::with_capacity(s.len() * 2);
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_string = false;
    let mut string_start = 0;
    let mut is_key = true; // after { or , we expect a key
    let mut escape = false;

    while i < len {
        let ch = chars[i];

        if escape {
            escape = false;
            i += 1;
            continue;
        }

        if in_string {
            if ch == '\\' {
                escape = true;
                i += 1;
                continue;
            }
            if ch == '\n' {
                // JSON strings are single-line — terminate unterminated string at newline
                let string_content: String = chars[string_start..i].iter().collect();
                let color = if is_key {
                    if string_content.contains("@type") { c_at } else { c_key }
                } else {
                    c_str
                };
                out.push_str(&format!("{}{}{}", color, string_content, r));
                out.push('\n');
                in_string = false;
                i += 1;
                continue;
            }
            if ch == '"' {
                // End of string — collect the whole string and colorize
                let string_content: String = chars[string_start..=i].iter().collect();
                let color = if is_key {
                    if string_content.contains("@type") { c_at } else { c_key }
                } else {
                    c_str
                };
                out.push_str(&format!("{}{}{}", color, string_content, r));
                in_string = false;
                i += 1;
                continue;
            }
            i += 1;
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                string_start = i;
                i += 1;
            }
            '{' | '}' | '[' | ']' => {
                out.push_str(&format!("{}{}{}", c_brace, ch, r));
                if ch == '{' || ch == '[' {
                    is_key = ch == '{';
                }
                i += 1;
            }
            ':' => {
                out.push(ch);
                is_key = false;
                i += 1;
            }
            ',' => {
                out.push(ch);
                is_key = true;
                i += 1;
            }
            't' | 'f' | 'n' => {
                // Check for true/false/null
                let remaining: String = chars[i..].iter().take(5).collect();
                if remaining.starts_with("true") {
                    out.push_str(&format!("{}true{}", c_bool, r));
                    i += 4;
                } else if remaining.starts_with("false") {
                    out.push_str(&format!("{}false{}", c_bool, r));
                    i += 5;
                } else if remaining.starts_with("null") {
                    out.push_str(&format!("{}null{}", c_bool, r));
                    i += 4;
                } else {
                    out.push(ch);
                    i += 1;
                }
            }
            '0'..='9' | '-' => {
                // Number
                let start = i;
                while i < len && (chars[i].is_ascii_digit() || chars[i] == '.' || chars[i] == '-' || chars[i] == 'e' || chars[i] == 'E' || chars[i] == '+') {
                    i += 1;
                }
                let num: String = chars[start..i].iter().collect();
                out.push_str(&format!("{}{}{}", c_num, num, r));
            }
            _ => {
                out.push(ch);
                i += 1;
            }
        }
    }

    // Handle unterminated string (user is still typing)
    if in_string {
        let string_content: String = chars[string_start..].iter().collect();
        let color = if is_key {
            if string_content.contains("@type") { c_at } else { c_key }
        } else {
            c_str
        };
        out.push_str(&format!("{}{}{}", color, string_content, r));
    }

    out
}

fn char_to_byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(i, _)| i)
        .unwrap_or(s.len())
}

/// Where the cursor lands one line up in a multi-line input: the same column,
/// or the end of that line if it is shorter. Positions and columns are
/// counted in characters, so a line of `å` is as wide as a line of `a`. On the
/// first line the cursor stays where it is.
fn cursor_line_up(input: &str, cursor_pos: usize) -> usize {
    let chars: Vec<char> = input.chars().collect();
    let pos = cursor_pos.min(chars.len());
    let Some(line_start) = chars[..pos].iter().rposition(|&c| c == '\n').map(|i| i + 1) else {
        return cursor_pos;
    };
    let col = pos - line_start;
    let prev_end = line_start - 1;
    let prev_start = chars[..prev_end].iter().rposition(|&c| c == '\n').map_or(0, |i| i + 1);
    prev_start + col.min(prev_end - prev_start)
}

/// Where the cursor lands one line down, as `cursor_line_up` does it. On the
/// last line the cursor stays where it is.
fn cursor_line_down(input: &str, cursor_pos: usize) -> usize {
    let chars: Vec<char> = input.chars().collect();
    let pos = cursor_pos.min(chars.len());
    let line_start = chars[..pos].iter().rposition(|&c| c == '\n').map_or(0, |i| i + 1);
    let col = pos - line_start;
    let Some(next_start) = chars[pos..].iter().position(|&c| c == '\n').map(|i| pos + i + 1) else {
        return cursor_pos;
    };
    let next_end = chars[next_start..].iter().position(|&c| c == '\n').map_or(chars.len(), |i| next_start + i);
    next_start + col.min(next_end - next_start)
}

/// Whether a key typed this character, as opposed to a shortcut that happens
/// to carry a letter (`ctrl+a`, `alt+b`). Shift is part of typing.
fn types_a_character(modifiers: KeyModifiers) -> bool {
    (modifiers - KeyModifiers::SHIFT).is_empty()
}

/// A "word character" for readline-style word navigation: alphanumeric + underscore.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Find the start of the previous word from `cursor_pos` (char index).
/// Skips trailing non-word chars, then skips the word itself.
fn word_boundary_back(s: &str, cursor_pos: usize) -> usize {
    let chars: Vec<char> = s.chars().collect();
    let mut i = cursor_pos;
    // Skip non-word chars immediately before cursor
    while i > 0 && !is_word_char(chars[i - 1]) {
        i -= 1;
    }
    // Skip word chars
    while i > 0 && is_word_char(chars[i - 1]) {
        i -= 1;
    }
    i
}

/// Find the start of the next word from `cursor_pos` (char index).
/// Skips current word (if any), then skips non-word chars.
fn word_boundary_forward(s: &str, cursor_pos: usize) -> usize {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut i = cursor_pos;
    // Skip word chars at cursor
    while i < len && is_word_char(chars[i]) {
        i += 1;
    }
    // Skip non-word chars
    while i < len && !is_word_char(chars[i]) {
        i += 1;
    }
    i
}

// Get character count (not byte length)
fn char_len(s: &str) -> usize {
    s.chars().count()
}

/// Narrowest body worth echoing on the request line. Below this the body is
/// dropped entirely rather than rendered as a stub like `{…`.
const MIN_INLINE_BODY_CHARS: usize = 8;

/// Squash a request body onto a single line for logging: JSON is re-serialized
/// compact, anything else has its whitespace runs (newlines included) collapsed
/// to single spaces. A pasted 40-line JSON object becomes one short line.
fn compact_body_for_display(body: &str) -> String {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Some(compact) = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| serde_json::to_string(&v).ok())
        {
            return compact;
        }
    }
    body.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Collapse only the whitespace runs that contain a newline, each to a single
/// space. Everything else is left byte-for-byte, so a body typed on one line is
/// echoed exactly as sent — this is the minimum reshaping needed to keep a
/// multi-line body on the request line.
fn collapse_newlines_for_log(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut run = String::new();
    for c in body.chars() {
        if c.is_whitespace() {
            run.push(c);
        } else {
            if !run.is_empty() {
                if run.contains('\n') || run.contains('\r') {
                    out.push(' ');
                } else {
                    out.push_str(&run);
                }
                run.clear();
            }
            out.push(c);
        }
    }
    // Trailing whitespace run, if any.
    if !run.is_empty() {
        if run.contains('\n') || run.contains('\r') {
            out.push(' ');
        } else {
            out.push_str(&run);
        }
    }
    out
}

/// Fit a body onto the request line: collapsed to one line, then cut to `budget`
/// visible columns with an ellipsis. The `…` is counted inside the budget, so the
/// result never exceeds it and the line lands at the terminal edge rather than
/// wrapping. Counts chars rather than bytes, so multibyte input (`Möör`) is
/// neither over-counted nor split mid-codepoint.
fn fit_body_to_width(body: &str, budget: usize) -> String {
    fit_to_width(&collapse_newlines_for_log(body), budget)
}

/// The first `count` characters of `text`, or all of it. Cut on a character,
/// never inside one, so a non-ASCII host or URL is as safe to cut as any.
fn head_chars(text: &str, count: usize) -> &str {
    match text.char_indices().nth(count) {
        Some((i, _)) => &text[..i],
        None => text,
    }
}

/// The last `count` characters of `text`, or all of it.
fn tail_chars(text: &str, count: usize) -> &str {
    let len = char_len(text);
    if len <= count {
        return text;
    }
    &text[char_to_byte_idx(text, len - count)..]
}

/// Cut `text` to `budget` visible columns, keeping its start: the end gives
/// way to an ellipsis, which is counted inside the budget.
fn fit_to_width(text: &str, budget: usize) -> String {
    if char_len(text) <= budget {
        return text.to_string();
    }
    if budget == 0 {
        return String::new();
    }
    // Reserve one column for the ellipsis itself.
    let head: String = text.chars().take(budget - 1).collect();
    format!("{}…", head)
}

/// Cut `text` to `budget` visible columns, keeping its end: for a value
/// being typed, where the end is what the next key adds to.
fn fit_tail_to_width(text: &str, budget: usize) -> String {
    let len = char_len(text);
    if len <= budget {
        return text.to_string();
    }
    if budget == 0 {
        return String::new();
    }
    let tail: String = text.chars().skip(len - (budget - 1)).collect();
    format!("…{}", tail)
}

/// `s` without its ANSI colour codes: what `visible_len` counts.
fn visible_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            in_escape = c != 'm';
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            out.push(c);
        }
    }
    out
}

// Strip ANSI escape codes and return visible character count
fn visible_len(s: &str) -> usize {
    let mut count = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            count += 1;
        }
    }
    count
}

// Calculate visual line count accounting for terminal width wrapping
fn visual_line_count(rendered: &str, width: usize) -> u16 {
    if width == 0 {
        return 1;
    }
    let mut total_lines: u16 = 0;
    for line in rendered.split('\n') {
        let visible = visible_len(line);
        // Each logical line takes at least 1 visual line
        // Additional visual lines if it wraps
        let lines_for_this = if visible == 0 {
            1
        } else {
            ((visible + width - 1) / width) as u16 // ceiling division
        };
        total_lines += lines_for_this;
    }
    total_lines
}

/// Clamp a rendered multi-line input to a viewport of at most `max_lines` visual
/// lines, keeping the cursor's logical line visible. Returns the (possibly
/// windowed) text and its visual line count. Clipped content above/below is shown
/// as a dimmed `⋯` marker line.
///
/// This keeps the printed input block from ever exceeding the screen, which would
/// otherwise scroll the terminal and desync `render()`'s relative cursor math —
/// the cause of the input area jumping upward after a multi-line paste.
fn clamp_input_viewport(rendered: &str, width: usize, max_lines: u16, cursor_line: usize) -> (String, u16) {
    let total = visual_line_count(rendered, width);
    if total <= max_lines {
        return (rendered.to_string(), total);
    }
    let logical: Vec<&str> = rendered.split('\n').collect();
    let n = logical.len();
    if n == 0 {
        return (rendered.to_string(), total);
    }
    let line_h = |l: &str| -> u16 {
        let v = visible_len(l);
        if width == 0 || v == 0 { 1 } else { ((v + width - 1) / width) as u16 }
    };

    let cursor_line = cursor_line.min(n - 1);
    // Greedy window containing the cursor line. Expand downward first (so a paste
    // with the cursor at the end keeps its most recent lines), then upward,
    // reserving a line for each `⋯` marker that will be shown.
    let mut start = cursor_line;
    let mut end = cursor_line + 1; // exclusive
    let mut used: u16 = line_h(logical[cursor_line]);
    loop {
        let mut grew = false;
        if end < n {
            let h = line_h(logical[end]);
            let markers_after = (start > 0) as u16 + ((end + 1) < n) as u16;
            if used + h + markers_after <= max_lines {
                used += h;
                end += 1;
                grew = true;
            }
        }
        if start > 0 {
            let h = line_h(logical[start - 1]);
            let markers_after = ((start - 1) > 0) as u16 + (end < n) as u16;
            if used + h + markers_after <= max_lines {
                used += h;
                start -= 1;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    let marker = "\x1b[38;5;240m⋯\x1b[0m";
    let mut out = String::new();
    let mut count: u16 = 0;
    if start > 0 {
        out.push_str(marker);
        out.push('\n');
        count += 1;
    }
    for idx in start..end {
        out.push_str(logical[idx]);
        count += line_h(logical[idx]);
        if idx + 1 < end {
            out.push('\n');
        }
    }
    if end < n {
        out.push('\n');
        out.push_str(marker);
        count += 1;
    }
    (out, count)
}

/// Hard-wrap a possibly-ANSI string to `width` visible columns, inserting `\r\n`
/// at each wrap point. ANSI escape sequences (`\x1b…m`) contribute zero width and
/// are copied verbatim. Existing `\n` are treated as hard breaks and reset the
/// column counter. With terminal auto-wrap disabled, the rows printed equal the
/// rows counted here exactly — no right-margin "pending wrap" phantom rows — which
/// keeps render()'s relative clear math correct on every terminal.
fn hard_wrap_ansi(s: &str, width: usize) -> String {
    if width == 0 {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    let mut col = 0usize;
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            out.push(c);
            if c == 'm' {
                in_escape = false;
            }
            continue;
        }
        if c == '\x1b' {
            in_escape = true;
            out.push(c);
            continue;
        }
        if c == '\n' {
            out.push(c);
            col = 0;
            continue;
        }
        if col == width {
            out.push_str("\r\n");
            col = 0;
        }
        out.push(c);
        col += 1;
    }
    out
}

fn get_history_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".api_history"))
}

/// The history file never holds more entries than this.
const HISTORY_LIMIT: usize = 1000;

/// Stands for a line break inside a history entry. The file holds one entry
/// per line, and an entry may be a body of several lines; this character
/// (the "symbol for newline") takes the place of each of its line breaks.
/// A line of a file written before entries were kept this way holds none,
/// and is read as it always was.
const HISTORY_NEWLINE: char = '\u{2424}';

fn history_line(entry: &str) -> String {
    entry.replace("\r\n", "\n").replace(['\n', '\r'], &HISTORY_NEWLINE.to_string())
}

fn history_entry(line: &str) -> String {
    line.replace(HISTORY_NEWLINE, "\n")
}

/// The history file holds every line and body typed, secrets among them, so
/// it is the user's alone. (On Windows the profile directory's own access
/// rules are what keep it so.)
fn keep_history_private(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            if meta.permissions().mode() & 0o777 != 0o600 {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn load_history() -> Vec<String> {
    get_history_path().map(|path| load_history_from(&path)).unwrap_or_default()
}

/// Read the history, and bring the file within its limits while at it: an
/// older file may be readable by others, and may have grown without bound.
fn load_history_from(path: &std::path::Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    keep_history_private(path);
    let mut entries: Vec<String> = text.lines().filter(|line| !line.is_empty()).map(history_entry).collect();
    if entries.len() > HISTORY_LIMIT {
        entries.drain(..entries.len() - HISTORY_LIMIT);
        save_history_to(path, &entries);
    }
    entries
}

/// Write the last `HISTORY_LIMIT` entries as the whole file, in one step.
fn save_history_to(path: &std::path::Path, history: &[String]) {
    let kept = &history[history.len().saturating_sub(HISTORY_LIMIT)..];
    let mut text = String::new();
    for entry in kept {
        text.push_str(&history_line(entry));
        text.push('\n');
    }
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(format!(".tmp-{}", std::process::id()));
    let tmp = path.with_file_name(name);
    if fs::write(&tmp, text).is_ok() {
        keep_history_private(&tmp);
        if fs::rename(&tmp, path).is_err() {
            let _ = fs::remove_file(&tmp);
        }
    }
}

fn append_history(entry: &str) {
    if let Some(path) = get_history_path() {
        append_history_to(&path, entry);
    }
}

fn append_history_to(path: &std::path::Path, entry: &str) {
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    if let Ok(mut file) = options.open(path) {
        let _ = writeln!(file, "{}", history_line(entry));
    }
}

// Shared picker data structure
struct PickerState {
    items: Vec<String>,
    saved_connections: Vec<Option<SavedConnection>>,
    default_name: Option<String>,
    max_alias_len: usize,
    selected: usize,
    extra_lines: u16,
    search_query: String,
    filtered_indices: Vec<usize>,  // Indices into items/saved_connections that match search
}

impl PickerState {
    fn new(envs: &[String]) -> Self {
        let mut items: Vec<String> = Vec::new();
        let mut saved_connections: Vec<Option<SavedConnection>> = Vec::new();
        let default_name = get_default_connection();

        // First pass: find max alias length for URL alignment
        let mut max_alias_len = 0usize;
        for name in envs {
            if let Some(env) = load_connection(name) {
                max_alias_len = max_alias_len.max(env.name.len());
                saved_connections.push(Some(env));
            }
        }

        // Second pass: build formatted items with aligned URLs
        for env_opt in &saved_connections {
            if let Some(env) = env_opt {
                let is_default = default_name.as_deref() == Some(env.name.as_str());
                let suffix = if is_default { " ♥" } else { "  " };
                let padding = max_alias_len.saturating_sub(env.name.len()) + 3;
                items.push(format!("{}{}{}{}", env.name, suffix, " ".repeat(padding), env.url));
            }
        }
        items.push("+ Add new connection".to_string());
        saved_connections.push(None);

        let selected = default_name
            .as_ref()
            .and_then(|d| envs.iter().position(|n| n == d))
            .unwrap_or(0);

        let extra_lines: u16 = if items.len() > 1 { 1 } else { 0 };
        let filtered_indices: Vec<usize> = (0..items.len()).collect();

        PickerState {
            items,
            saved_connections,
            default_name,
            max_alias_len,
            selected,
            extra_lines,
            search_query: String::new(),
            filtered_indices,
        }
    }

    fn fuzzy_matches(query: &str, text: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let text_lower = text.to_lowercase();
        let query_lower = query.to_lowercase();
        let mut query_chars = query_lower.chars().peekable();
        for c in text_lower.chars() {
            if query_chars.peek() == Some(&c) {
                query_chars.next();
            }
            if query_chars.peek().is_none() {
                return true;
            }
        }
        false
    }

    fn update_filter(&mut self) {
        self.filtered_indices.clear();
        for (i, env_opt) in self.saved_connections.iter().enumerate() {
            if let Some(env) = env_opt {
                // Match against name or URL
                if Self::fuzzy_matches(&self.search_query, &env.name) ||
                   Self::fuzzy_matches(&self.search_query, &env.url) {
                    self.filtered_indices.push(i);
                }
            } else {
                // Always include "+ Add new" slot (shows search query when searching, or add new when not)
                self.filtered_indices.push(i);
            }
        }
        // Reset selection to first filtered item (but not the "+ Add new" slot when searching)
        if self.search_query.is_empty() {
            self.selected = *self.filtered_indices.first().unwrap_or(&0);
        } else {
            // When searching, select first actual env match, not the search line
            self.selected = self.filtered_indices.iter()
                .find(|&&i| self.saved_connections.get(i).map(|e| e.is_some()).unwrap_or(false))
                .copied()
                .unwrap_or(*self.filtered_indices.first().unwrap_or(&0));
        }
    }

    fn add_search_char(&mut self, c: char) {
        self.search_query.push(c);
        self.update_filter();
    }

    fn delete_search_char(&mut self) {
        self.search_query.pop();
        self.update_filter();
    }

    fn clear_search(&mut self) {
        self.search_query.clear();
        self.filtered_indices = (0..self.items.len()).collect();
    }

    fn rebuild_items(&mut self) {
        for (i, env_opt) in self.saved_connections.iter().enumerate() {
            if let Some(env) = env_opt {
                let is_default = self.default_name.as_deref() == Some(env.name.as_str());
                let suffix = if is_default { " ♥" } else { "  " };
                let padding = self.max_alias_len.saturating_sub(env.name.len()) + 3;
                self.items[i] = format!("{}{}{}{}", env.name, suffix, " ".repeat(padding), env.url);
            }
        }
    }

    fn toggle_default(&mut self) {
        if let Some(Some(env)) = self.saved_connections.get(self.selected) {
            if self.default_name.as_deref() == Some(env.name.as_str()) {
                let _ = set_default_connection("");
                self.default_name = None;
            } else {
                let _ = set_default_connection(&env.name);
                self.default_name = Some(env.name.clone());
            }
            self.rebuild_items();
        }
    }

    fn move_up(&mut self) {
        // Find current position in filtered list and move up
        if let Some(pos) = self.filtered_indices.iter().position(|&i| i == self.selected) {
            if pos > 0 {
                self.selected = self.filtered_indices[pos - 1];
            }
        }
    }

    fn move_down(&mut self) {
        // Find current position in filtered list and move down
        if let Some(pos) = self.filtered_indices.iter().position(|&i| i == self.selected) {
            if pos < self.filtered_indices.len() - 1 {
                self.selected = self.filtered_indices[pos + 1];
            }
        }
    }

    fn selected_env(&self) -> Option<SavedConnection> {
        self.saved_connections[self.selected].clone()
    }

    fn delete_selected(&mut self) -> Option<String> {
        if let Some(Some(env)) = self.saved_connections.get(self.selected) {
            let env_name = env.name.clone();
            let _ = delete_connection(&env_name);
            if self.default_name.as_deref() == Some(env_name.as_str()) {
                self.default_name = None;
            }
            self.items.remove(self.selected);
            self.saved_connections.remove(self.selected);
            if self.selected >= self.items.len() && self.selected > 0 {
                self.selected -= 1;
            }
            // Update extra_lines if we deleted all saved connections
            self.extra_lines = if self.items.len() > 1 { 1 } else { 0 };
            // Rebuild filtered indices
            self.update_filter();
            return Some(env_name);
        }
        None
    }
}

// Setup guide form fields
#[derive(Clone)]
enum SetupField {
    Url,
    Auth,        // Arrow-key selection: API Key / OAuth2
    Credential,  // API key or client_secret
    ClientId,    // Only shown for OAuth2
    Done,        // No field active (used for final render on success)
}

// Result of connection flow
enum ConnectionFlowResult {
    Connected(SavedConnection, Option<BackgroundLoadResult>, Option<Config>),  // env + preloaded result + resolved config
    Cancelled,
    Quit,
}

// Unified connection picker/setup flow that renders in the command area
struct ConnectionFlow {
    // Picker state
    picker: PickerState,
    picker_error_msg: Option<String>,
    picker_error_clear_at: Option<Instant>,
    connecting_idx: Option<usize>,
    spinner_frame: usize,

    // Setup form state
    in_setup: bool,
    setup_url: String,
    setup_auth_idx: usize,
    setup_credential: String,
    setup_client_id: String,
    setup_active_field: SetupField,
    setup_status: String,
    setup_status_clear_at: Option<Instant>,
    setup_conn_fail_count: u32,
    // Configuration
    show_splash: bool,
    width: u16,

    // Delete confirmation state
    delete_confirming: Option<usize>,

    // Track rendered lines for accurate cursor positioning
    last_rendered_lines: u16,
}

impl ConnectionFlow {
    fn for_startup(envs: &[String], width: u16, show_splash: bool) -> Self {
        let has_connections = !envs.is_empty();
        let picker = PickerState::new(envs);
        // Calculate initial rendered lines based on starting mode
        let last_rendered_lines = if has_connections {
            // Picker mode: top ruler + items + extra_lines + bottom ruler
            1 + picker.items.len() as u16 + picker.extra_lines + 1
        } else {
            // Setup mode: top ruler + url + auth + cred + bottom ruler = 5
            5
        };
        ConnectionFlow {
            picker,
            picker_error_msg: None,
            picker_error_clear_at: None,
            connecting_idx: None,
            spinner_frame: 0,
            in_setup: !has_connections,  // Start in setup if no saved connections
            setup_url: String::new(),
            setup_auth_idx: 0,
            setup_credential: String::new(),
            setup_client_id: String::new(),
            setup_active_field: SetupField::Url,
            setup_status: String::new(),
            setup_status_clear_at: None,
            setup_conn_fail_count: 0,
            show_splash,
            width,
            delete_confirming: None,
            last_rendered_lines,
        }
    }

    fn for_runtime(envs: &[String], width: u16) -> Self {
        let picker = PickerState::new(envs);
        // Runtime always starts in picker mode: top ruler + items + extra_lines + bottom ruler
        let last_rendered_lines = 1 + picker.items.len() as u16 + picker.extra_lines + 1;
        ConnectionFlow {
            picker,
            picker_error_msg: None,
            picker_error_clear_at: None,
            connecting_idx: None,
            spinner_frame: 0,
            in_setup: false,
            setup_url: String::new(),
            setup_auth_idx: 0,
            setup_credential: String::new(),
            setup_client_id: String::new(),
            setup_active_field: SetupField::Url,
            setup_status: String::new(),
            setup_status_clear_at: None,
            setup_conn_fail_count: 0,
            show_splash: false,
            width,
            delete_confirming: None,
            last_rendered_lines,
        }
    }

    fn rendered_lines(&self) -> u16 {
        if self.in_setup {
            // Setup form: top ruler + URL + Auth + (ClientId if oauth2) + Credential + bottom ruler
            // Hint line doesn't have \r\n, cursor stays on it, so we don't count it
            let base = 1 + 1 + 1 + 1 + 1; // top ruler, url, auth, cred, bottom ruler
            if self.setup_auth_idx == 2 {
                base + 1 // + client_id for OAuth2
            } else {
                base
            }
        } else {
            // Picker: top ruler + env items + (no matches) + separator + search/add line + bottom ruler
            // Hint line doesn't have \r\n, cursor stays on it, so we don't count it

            // Count env items (excluding "+ Add new")
            let env_count = self.picker.filtered_indices.iter()
                .filter(|&&i| !self.picker.items.get(i).map(|item| item.starts_with("+")).unwrap_or(false))
                .count() as u16;

            // Check if we have any envs displayed
            let had_env = self.picker.filtered_indices.iter().any(|&i| {
                self.picker.saved_connections.get(i).map(|e| e.is_some()).unwrap_or(false)
            });

            // No matches if only "+ Add new" in filtered list or empty
            let no_matches = self.picker.filtered_indices.is_empty() ||
                self.picker.filtered_indices.iter().all(|&i| self.picker.items.get(i).map(|item| item.starts_with("+")).unwrap_or(false));

            // Separator shows if had envs OR if searching
            let separator_line = if had_env || !self.picker.search_query.is_empty() { 1 } else { 0 };
            let no_matches_line = if no_matches && !self.picker.search_query.is_empty() { 1 } else { 0 };
            let search_or_add_line = 1; // Always have either search line or "+ Add new"

            1 + env_count + no_matches_line + separator_line + search_or_add_line + 1
        }
    }

    fn splash_lines() -> u16 {
        5 // blank + title + url + bottom + blank
    }

    fn render(&mut self, stdout: &mut io::Stdout, first: bool) -> io::Result<()> {
        let w = self.width as usize;
        let ruler = "─".repeat(w);

        if !first {
            // Use tracked line count from previous render for accurate cursor positioning
            execute!(stdout, cursor::MoveUp(self.last_rendered_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;
        }

        if self.in_setup {
            self.render_setup(stdout, &ruler, first)?;
        } else {
            self.render_picker(stdout, &ruler, first)?;
        }

        // Update tracked line count after rendering
        self.last_rendered_lines = self.rendered_lines();

        stdout.flush()?;
        Ok(())
    }

    fn render_splash(&self, stdout: &mut io::Stdout) -> io::Result<()> {
        let w = self.width as usize;
        let box_width = 60usize.min(w);

        if box_width < 37 {
            // Narrow splash: just app name and hint
            let narrow_title = " CommerceOS API ";
            let narrow_title_len = narrow_title.len();
            let inner = box_width.saturating_sub(2);
            let top_pad = inner.saturating_sub(narrow_title_len);
            let top_left = top_pad / 2;
            let top_right = top_pad - top_left;
            execute!(stdout, Print("\r\n"))?;
            execute!(stdout, Print(format!("{}{}{}{}{}\r\n",
                "╭".dimmed(),
                "─".repeat(top_left).dimmed(),
                format!(" {} ", "CommerceOS API".bold()),
                "─".repeat(top_right).dimmed(),
                "╮".dimmed()
            )))?;
            let hint = "ctrl+b for docs";
            let hint_space = inner.saturating_sub(hint.len());
            let hint_left = hint_space / 2;
            let hint_right = hint_space - hint_left;
            execute!(stdout, Print(format!("{}{}{}{}{}\r\n",
                "│".dimmed(),
                " ".repeat(hint_left),
                hint.dimmed(),
                " ".repeat(hint_right),
                "│".dimmed()
            )))?;
            execute!(stdout, Print(format!("{}\r\n", format!("╰{}╯", "─".repeat(inner)).dimmed())))?;
            execute!(stdout, Print("\r\n"))?;
        } else {
            let title = "CommerceOS API Client";
            let version = format!("v{}", VERSION);
            let title_len = title.len() + version.len() + 3;
            let top_padding = box_width.saturating_sub(4 + title_len + 1);

            execute!(stdout, Print("\r\n"))?;
            execute!(stdout, Print(format!("{}{}{}{}\r\n",
                "╭───".dimmed(),
                format!(" {} {} ", title.bold(), version.dimmed()),
                "─".repeat(top_padding.max(1)).dimmed(),
                "╮".dimmed()
            )))?;

            let hint_text = "ctrl+b for docs";
            let hint_section = 7 + hint_text.len();
            let display_url = if self.in_setup && !self.setup_url.is_empty() {
                self.setup_url.as_str()
            } else {
                " "
            };
            if box_width > hint_section {
                let host_space = box_width - hint_section;
                let host_display = tail_chars(display_url, host_space);
                execute!(stdout, Print(format!("{}{:width$}{}{}{}\r\n",
                    "│ ".dimmed(),
                    host_display.dimmed(),
                    " │ ".dimmed(),
                    hint_text.dimmed(),
                    " │".dimmed(),
                    width = host_space
                )))?;
            } else {
                let host_space = box_width.saturating_sub(4);
                let host_display = tail_chars(display_url, host_space);
                execute!(stdout, Print(format!("{}{:width$}{}\r\n",
                    "│ ".dimmed(),
                    host_display.dimmed(),
                    " │".dimmed(),
                    width = host_space
                )))?;
            }
            execute!(stdout, Print(format!("{}\r\n", format!("╰{}╯", "─".repeat(box_width.saturating_sub(2))).dimmed())))?;
            execute!(stdout, Print("\r\n"))?;
        }

        Ok(())
    }

    fn render_picker(&self, stdout: &mut io::Stdout, ruler: &str, _first: bool) -> io::Result<()> {
        let w = self.width as usize;

        // Top ruler with embedded title (always "Choose a connection")
        let title = "  Choose a connection  ";
        let title_len = title.len();
        let (left, right) = if w < 37 {
            // Centered for narrow terminals
            let total = w.saturating_sub(title_len);
            (total / 2, total - total / 2)
        } else {
            // Right-aligned
            let r = 7;
            (w.saturating_sub(title_len).saturating_sub(r), r)
        };
        execute!(stdout, Print(format!(
            "{}{}{}\r\n",
            "─".repeat(left).dimmed(),
            title.dimmed(),
            "─".repeat(right).dimmed()
        )))?;

        // Calculate separator length based on longest env line in filtered results
        let max_env_len = self.picker.filtered_indices.iter()
            .filter_map(|&i| {
                if self.picker.saved_connections.get(i).map(|e| e.is_some()).unwrap_or(false) {
                    Some(self.picker.items[i].chars().count())
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(30);
        let separator = "─".repeat(max_env_len);

        // Render only filtered items (excluding "+ Add new" which we handle separately)
        let mut had_env = false;
        for &i in &self.picker.filtered_indices {
            let item = &self.picker.items[i];
            let is_add_new = item.starts_with("+");

            // Skip "+ Add new" here - we handle it after the separator
            if is_add_new {
                continue;
            }

            let spinner = if self.connecting_idx == Some(i) {
                format!(" {}", SPINNER_FRAMES[self.spinner_frame % SPINNER_FRAMES.len()]).dimmed().to_string()
            } else {
                String::new()
            };

            if self.delete_confirming == Some(i) {
                // Show delete confirmation - replace URL part with "Delete? y/n", keep name/suffix/padding
                if let Some(Some(env)) = self.picker.saved_connections.get(i) {
                    let is_default = item.contains(" ♥");
                    let suffix = if is_default { " ♥" } else { "  " };
                    let max_alias_len = self.picker.saved_connections.iter()
                        .filter_map(|e| e.as_ref().map(|env| env.name.len()))
                        .max()
                        .unwrap_or(0);
                    let padding = max_alias_len.saturating_sub(env.name.len()) + 3;
                    execute!(stdout, Print(format!("  › \x1b[1m{}{}{}{}\x1b[0m\r\n", env.name, suffix, " ".repeat(padding), "Delete? y/n")))?;
                } else {
                    execute!(stdout, Print(format!("    {}\r\n", item)))?;
                }
            } else if i == self.picker.selected {
                execute!(stdout, Print(format!("  › \x1b[1m{}{}\x1b[0m\r\n", item, spinner)))?;
            } else {
                execute!(stdout, Print(format!("    {}{}\r\n", item, spinner)))?;
            }

            if self.picker.saved_connections.get(i).map(|e| e.is_some()).unwrap_or(false) {
                had_env = true;
            }
        }

        // Check if there are no matches (only "+ Add new" in filtered list or empty)
        let no_matches = self.picker.filtered_indices.is_empty() ||
           self.picker.filtered_indices.iter().all(|&i| self.picker.items[i].starts_with("+"));

        // Show "(no matches)" ABOVE the separator when searching with no results
        if no_matches && !self.picker.search_query.is_empty() {
            execute!(stdout, Print(format!("    {}\r\n", "(no matches)".dimmed())))?;
        }

        // Separator line - show if we had envs OR if searching (so it's always visible during search)
        if had_env || !self.picker.search_query.is_empty() {
            execute!(stdout, Print(format!("    {}\r\n", separator.dimmed())))?;
        }

        // Show search line or "+ Add new connection"
        if !self.picker.search_query.is_empty() {
            execute!(stdout, Print(format!("    {} {}\r\n", "search:".dimmed(), self.picker.search_query)))?;
        } else {
            // Find and render the "+ Add new" item
            for &i in &self.picker.filtered_indices {
                let item = &self.picker.items[i];
                if item.starts_with("+") {
                    if i == self.picker.selected {
                        execute!(stdout, Print(format!("  › \x1b[1m{}\x1b[0m\r\n", item)))?;
                    } else {
                        execute!(stdout, Print(format!("    {}\r\n", item)))?;
                    }
                    break;
                }
            }
        }

        // Bottom ruler
        execute!(stdout, Print(format!("{}\r\n", ruler.dimmed())))?;

        // Hint or error line
        if let Some(ref msg) = self.picker_error_msg {
            // "deleted" messages are info (gray), others are errors (red)
            if msg.ends_with("deleted") {
                execute!(stdout, Print(format!("  {}", msg.dimmed())))?;
            } else {
                execute!(stdout, Print(format!("  {}", msg.red())))?;
            }
        } else {
            execute!(stdout, Print(format!("  {}", "type to search, tab default, del delete, esc cancel".dimmed())))?;
        }

        Ok(())
    }

    fn render_setup(&self, stdout: &mut io::Stdout, ruler: &str, _first: bool) -> io::Result<()> {
        let auth_options = ["API key", "Bearer token", "OAuth2 Client Credentials"];
        let w = self.width as usize;

        // Top ruler with embedded title
        let title = "  New connection  ";
        let title_len = title.len();
        let (left, right) = if w < 37 {
            // Centered for narrow terminals
            let total = w.saturating_sub(title_len);
            (total / 2, total - total / 2)
        } else {
            // Right-aligned
            let r = 7;
            (w.saturating_sub(title_len).saturating_sub(r), r)
        };
        execute!(stdout, Print(format!(
            "{}{}{}\r\n",
            "─".repeat(left).dimmed(),
            title.dimmed(),
            "─".repeat(right).dimmed()
        )))?;

        // URL field with ghost text
        self.render_url_field(stdout)?;

        // Auth method field
        self.render_auth_field(stdout, &auth_options)?;

        // Client ID (only for OAuth2)
        if self.setup_auth_idx == 2 {
            let client_id_confirmed = matches!(self.setup_active_field, SetupField::Credential | SetupField::Done);
            self.render_text_field(stdout, "Client ID:", &self.setup_client_id,
                matches!(self.setup_active_field, SetupField::ClientId), false, client_id_confirmed)?;
        }

        // Credential field
        let cred_label = match self.setup_auth_idx {
            0 => "API key:",
            1 => "Token:",
            _ => "Secret:",
        };
        let cred_confirmed = matches!(self.setup_active_field, SetupField::Done);
        self.render_text_field(stdout, cred_label, &self.setup_credential,
            matches!(self.setup_active_field, SetupField::Credential), true, cred_confirmed)?;

        // Bottom ruler
        execute!(stdout, Print(format!("{}\r\n", ruler.dimmed())))?;

        // Status or hint
        if !self.setup_status.is_empty() {
            execute!(stdout, Print(format!("  {}", self.setup_status)))?;
        } else {
            let hint = match self.setup_active_field {
                SetupField::Url => "Type the API base URL, Tab to complete, Enter to continue",
                SetupField::Auth => "Use ← → to choose auth method, then press Enter",
                SetupField::ClientId => "Type your OAuth2 client ID, then press Enter",
                SetupField::Credential => match self.setup_auth_idx {
                    0 => "Type your API key, then press Enter",
                    1 => "Type your bearer token, then press Enter",
                    _ => "Type your client secret, then press Enter",
                },
                SetupField::Done => "",
            };
            execute!(stdout, Print(format!("  {}", hint.dimmed())))?;
        }

        Ok(())
    }

    fn render_url_field(&self, stdout: &mut io::Stdout) -> io::Result<()> {
        let is_active = matches!(self.setup_active_field, SetupField::Url);
        let url = &self.setup_url;

        // Ghost text calculation
        let localhost_full = "localhost:5000";
        let suffix = ".app.heads.com";
        let starts_with_digit = url.chars().next().map_or(false, |c| c.is_ascii_digit());

        let ghost = if !is_active || url.is_empty() || url.starts_with("http://") || url.starts_with("https://") {
            String::new()
        } else if localhost_full.starts_with(url) && !starts_with_digit {
            localhost_full[url.len()..].to_string()
        } else if !starts_with_digit
            && !url.starts_with("localhost") && !url.starts_with("127.0.0.1") && !url.starts_with("[::1]")
            && !url.contains(".app.heads.com")
        {
            let mut ghost = suffix.to_string();
            for i in (1..=suffix.len()).rev() {
                if url.ends_with(&suffix[..i]) {
                    ghost = suffix[i..].to_string();
                    break;
                }
            }
            ghost
        } else {
            String::new()
        };

        let prefix = if is_active { "  › " } else { "    " };
        // Truncate URL to fit terminal width (prefix=4 + label=14 + cursor/check=2)
        let max_url_len = (self.width as usize).saturating_sub(21);

        if is_active {
            let display_url = tail_chars(url, max_url_len);
            let ghost_budget = max_url_len.saturating_sub(char_len(display_url));
            let display_ghost = head_chars(&ghost, ghost_budget);
            execute!(stdout, Print(format!("{}{:<14}{}\x1b[2m{}\x1b[0m\x1b[48;5;247m\x1b[38;5;0m \x1b[0m\r\n",
                prefix, "URL:".dimmed(), display_url, display_ghost)))?;
        } else if url.is_empty() {
            execute!(stdout, Print(format!("{}{:<14}\r\n", prefix, "URL:".dimmed())))?;
        } else {
            let display_url = tail_chars(url, max_url_len);
            execute!(stdout, Print(format!("{}{:<14}{} ✓\r\n", prefix, "URL:".dimmed(), display_url)))?;
        }

        Ok(())
    }

    fn render_auth_field(&self, stdout: &mut io::Stdout, auth_options: &[&str]) -> io::Result<()> {
        let is_active = matches!(self.setup_active_field, SetupField::Auth);
        let confirmed = matches!(self.setup_active_field, SetupField::ClientId | SetupField::Credential | SetupField::Done);
        let prefix = if is_active { "  › " } else { "    " };

        if is_active {
            execute!(stdout, Print(format!("{}{:<14}\x1b[1m{}\x1b[0m  {}\r\n",
                prefix, "Auth method:".dimmed(), auth_options[self.setup_auth_idx], "← →".dimmed())))?;
        } else if confirmed {
            execute!(stdout, Print(format!("{}{:<14}{} ✓\r\n", prefix, "Auth method:".dimmed(), auth_options[self.setup_auth_idx])))?;
        } else {
            execute!(stdout, Print(format!("{}{:<14}{}\r\n", prefix, "Auth method:".dimmed(), auth_options[self.setup_auth_idx])))?;
        }

        Ok(())
    }

    fn render_text_field(&self, stdout: &mut io::Stdout, label: &str, value: &str, is_active: bool, mask: bool, confirmed: bool) -> io::Result<()> {
        let display_val = if mask && !value.is_empty() {
            "•".repeat(value.chars().count())
        } else {
            value.to_string()
        };

        let prefix = if is_active { "  › " } else { "    " };
        // Truncate display value to fit terminal width (prefix=4 + label=14 + cursor=1 + margin=1)
        let max_val_len = (self.width as usize).saturating_sub(20);
        let char_count = display_val.chars().count();
        let display_val = if char_count > max_val_len {
            // Show the rightmost portion so the user sees what they just typed
            let skip = char_count - max_val_len;
            display_val.chars().skip(skip).collect::<String>()
        } else {
            display_val
        };

        if is_active {
            execute!(stdout, Print(format!("{}{:<14}{}\x1b[48;5;247m\x1b[38;5;0m \x1b[0m\r\n", prefix, label.dimmed(), display_val)))?;
        } else if !value.is_empty() && confirmed {
            execute!(stdout, Print(format!("{}{:<14}{} ✓\r\n", prefix, label.dimmed(), display_val)))?;
        } else if !value.is_empty() {
            execute!(stdout, Print(format!("{}{:<14}{}\r\n", prefix, label.dimmed(), display_val)))?;
        } else {
            execute!(stdout, Print(format!("{}{:<14}\r\n", prefix, label.dimmed())))?;
        }

        Ok(())
    }

    fn test_connection(&mut self) -> bool {
        let url = &self.setup_url;
        let credential = &self.setup_credential;
        let client_id = &self.setup_client_id;
        let auth_idx = self.setup_auth_idx;

        if auth_idx == 2 {
            // OAuth2
            match oauth2_token_exchange(url, client_id, credential) {
                Ok(_) => {
                    self.setup_status = "\x1b[32m✓ Connected\x1b[0m".to_string();
                    true
                }
                Err(_) => {
                    self.setup_status = "\x1b[31m✗ connection could not be established, try again\x1b[0m".to_string();
                    false
                }
            }
        } else {
            // API key or Bearer token
            let client = client_builder().timeout(Duration::from_secs(10)).build().ok();
            if let Some(client) = client {
                let test_url = format!("{}/api/v1", url.trim_end_matches('/'));
                let mut req = client.get(&test_url);
                if auth_idx == 1 {
                    req = req.header("Authorization", format!("Bearer {}", credential));
                } else {
                    req = req.header("Authorization", format!("Basic {}", BASE64.encode(format!(":{}", credential).as_bytes())));
                }
                match req.send() {
                    Ok(resp) if resp.status().is_success() => {
                        self.setup_status = "\x1b[32m✓ Connected\x1b[0m".to_string();
                        true
                    }
                    Ok(resp) if resp.status().as_u16() == 401 => {
                        self.setup_status = "\x1b[31m✗ authentication failed, try again\x1b[0m".to_string();
                        false
                    }
                    Ok(resp) => {
                        self.setup_status = format!("\x1b[33m⚠ server returned {}, try again\x1b[0m", resp.status());
                        false
                    }
                    Err(_) => {
                        self.setup_status = "\x1b[31m✗ connection could not be established, try again\x1b[0m".to_string();
                        false
                    }
                }
            } else {
                self.setup_status = "\x1b[31m✗ connection could not be established, try again\x1b[0m".to_string();
                false
            }
        }
    }

    fn test_picker_connection_animated(&mut self, env: &SavedConnection, stdout: &mut io::Stdout) -> io::Result<Option<(BackgroundLoadResult, Config)>> {
        let mut test_config = Config::default();
        if let Err(e) = apply_connection_to_config(&mut test_config, env) {
            // Said where a failed connection test is said; the picker stays.
            self.picker_error_msg = Some(format!("{}: {}", env.name, e));
            self.picker_error_clear_at = Some(Instant::now() + Duration::from_secs(3));
            return Ok(None);
        }
        let resolved_config = test_config.clone();
        let env_name = env.name.clone();

        // Run background_load in a thread
        let (tx, rx) = std::sync::mpsc::channel::<BackgroundLoadResult>();
        thread::spawn(move || {
            let result = background_load(&test_config, None);
            let _ = tx.send(result);
        });

        // Animate spinner while waiting
        loop {
            // Check for result
            if let Ok(result) = rx.try_recv() {
                if let Some(err) = &result.error {
                    let err_text = if err.contains("401") {
                        "unauthorized"
                    } else if err.contains("403") {
                        "forbidden"
                    } else {
                        "connection failed"
                    };
                    self.picker_error_msg = Some(format!("{}: {}", env_name, err_text));
                    self.picker_error_clear_at = Some(Instant::now() + Duration::from_secs(3));
                    return Ok(None);
                } else {
                    return Ok(Some((result, resolved_config)));
                }
            }

            // Animate spinner
            self.spinner_frame += 1;
            self.render(stdout, false)?;

            // Small sleep to avoid busy loop
            thread::sleep(Duration::from_millis(80));

            // Check for ctrl+c to cancel
            if event::poll(Duration::from_millis(0))? {
                if let Event::Key(key) = event::read()? {
                    if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
                        return Ok(None);
                    }
                }
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, stdout: &mut io::Stdout) -> io::Result<Option<ConnectionFlowResult>> {
        // Ctrl+C always quits
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
            return Ok(Some(ConnectionFlowResult::Quit));
        }

        // Ctrl+B opens docs
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('b') {
            let _ = open_external("https://dev.heads.com/api-docs");
            return Ok(None);
        }

        if self.in_setup {
            self.handle_setup_key(key, stdout)
        } else {
            self.handle_picker_key(key, stdout)
        }
    }

    fn handle_picker_key(&mut self, key: KeyEvent, stdout: &mut io::Stdout) -> io::Result<Option<ConnectionFlowResult>> {
        // Handle delete confirmation
        if let Some(_idx) = self.delete_confirming {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Some(deleted_name) = self.picker.delete_selected() {
                        // If no saved connections left (only "+ Add new"), go to setup
                        if self.picker.items.len() == 1 {
                            self.in_setup = true;
                            self.setup_active_field = SetupField::Url;
                        }
                        self.picker_error_msg = Some(format!("{} deleted", deleted_name));
                        self.picker_error_clear_at = Some(Instant::now() + Duration::from_secs(2));
                    }
                    self.delete_confirming = None;
                    self.render(stdout, false)?;
                    return Ok(None);
                }
                _ => {
                    self.delete_confirming = None;
                    self.render(stdout, false)?;
                    return Ok(None);
                }
            }
        }

        match (key.modifiers, key.code) {
            (_, KeyCode::Up) => {
                self.picker.move_up();
                self.render(stdout, false)?;
            }
            (_, KeyCode::Down) => {
                self.picker.move_down();
                self.render(stdout, false)?;
            }
            (_, KeyCode::Tab) => {
                self.picker.toggle_default();
                self.render(stdout, false)?;
            }
            (_, KeyCode::Delete) => {
                // Start delete confirmation if on a saved connection(only Delete key, not Backspace)
                if self.picker.saved_connections.get(self.picker.selected).map(|e| e.is_some()).unwrap_or(false) {
                    self.delete_confirming = Some(self.picker.selected);
                    self.render(stdout, false)?;
                }
            }
            (_, KeyCode::Backspace) => {
                // Backspace deletes search character
                if !self.picker.search_query.is_empty() {
                    self.picker.delete_search_char();
                    self.render(stdout, false)?;
                }
            }
            (KeyModifiers::NONE, KeyCode::Char(c)) => {
                // Regular characters add to search
                self.picker.add_search_char(c);
                self.render(stdout, false)?;
            }
            (_, KeyCode::Enter) => {
                match self.picker.selected_env() {
                    Some(env) => {
                        // Test connection with animated spinner
                        self.connecting_idx = Some(self.picker.selected);
                        self.render(stdout, false)?;

                        let result = self.test_picker_connection_animated(&env, stdout)?;
                        self.connecting_idx = None;

                        if let Some((bg_result, resolved_config)) = result {
                            return Ok(Some(ConnectionFlowResult::Connected(env, Some(bg_result), Some(resolved_config))));
                        } else {
                            self.render(stdout, false)?;
                        }
                    }
                    None => {
                        // Switch to setup mode
                        self.in_setup = true;
                        self.setup_url.clear();
                        self.setup_auth_idx = 0;
                        self.setup_credential.clear();
                        self.setup_client_id.clear();
                        self.setup_active_field = SetupField::Url;
                        self.setup_status.clear();
                        self.render(stdout, false)?;
                    }
                }
            }
            (_, KeyCode::Esc) => {
                return Ok(Some(ConnectionFlowResult::Cancelled));
            }
            _ => {}
        }

        Ok(None)
    }

    fn handle_setup_key(&mut self, key: KeyEvent, stdout: &mut io::Stdout) -> io::Result<Option<ConnectionFlowResult>> {
        match &self.setup_active_field {
            SetupField::Url => match key.code {
                KeyCode::Enter if !self.setup_url.is_empty() => {
                    // Scheme added, and the API prefix cut: only the base URL
                    // is kept, read the way `-b` reads it.
                    let (base_url, trimmed) = base_url_of(&self.setup_url);
                    self.setup_url = base_url;
                    if trimmed {
                        self.setup_status = "trimmed to base URL".dimmed().to_string();
                        self.setup_status_clear_at = Some(Instant::now() + Duration::from_secs(3));
                    }
                    self.setup_active_field = SetupField::Auth;
                    self.render(stdout, false)?;
                }
                KeyCode::Tab if !self.setup_url.is_empty() => {
                    // Accept ghost text
                    let localhost_full = "localhost:5000";
                    let suffix = ".app.heads.com";
                    if localhost_full.starts_with(&self.setup_url) {
                        self.setup_url = localhost_full.to_string();
                    } else if !self.setup_url.starts_with("localhost") && !self.setup_url.starts_with("127.0.0.1") && !self.setup_url.starts_with("[::1]")
                        && !self.setup_url.starts_with("http://") && !self.setup_url.starts_with("https://")
                        && !self.setup_url.contains(".app.heads.com")
                    {
                        let mut matched = false;
                        for i in (1..=suffix.len()).rev() {
                            if self.setup_url.ends_with(&suffix[..i]) {
                                self.setup_url.push_str(&suffix[i..]);
                                matched = true;
                                break;
                            }
                        }
                        if !matched {
                            self.setup_url.push_str(suffix);
                        }
                    }
                    self.render(stdout, false)?;
                }
                KeyCode::Char(c) if types_a_character(key.modifiers) => {
                    self.setup_url.push(c);
                    self.render(stdout, false)?;
                }
                KeyCode::Backspace => {
                    self.setup_url.pop();
                    self.render(stdout, false)?;
                }
                KeyCode::Esc => {
                    // Back to picker if there are saved connections
                    if self.picker.items.len() > 1 {
                        self.in_setup = false;
                        self.render(stdout, false)?;
                    } else {
                        return Ok(Some(ConnectionFlowResult::Cancelled));
                    }
                }
                _ => {}
            },
            SetupField::Auth => match key.code {
                KeyCode::Right => {
                    self.setup_auth_idx = (self.setup_auth_idx + 1) % 3;
                    self.setup_credential.clear();
                    self.setup_client_id.clear();
                    self.render(stdout, false)?;
                }
                KeyCode::Left => {
                    self.setup_auth_idx = (self.setup_auth_idx + 2) % 3;
                    self.setup_credential.clear();
                    self.setup_client_id.clear();
                    self.render(stdout, false)?;
                }
                KeyCode::Enter => {
                    if self.setup_auth_idx == 2 {
                        self.setup_active_field = SetupField::ClientId;
                    } else {
                        self.setup_active_field = SetupField::Credential;
                    }
                    self.render(stdout, false)?;
                }
                KeyCode::Esc => {
                    // Strip scheme and go back to URL
                    if self.setup_url.starts_with("https://") {
                        self.setup_url = self.setup_url.strip_prefix("https://").unwrap().to_string();
                    } else if self.setup_url.starts_with("http://") {
                        self.setup_url = self.setup_url.strip_prefix("http://").unwrap().to_string();
                    }
                    self.setup_active_field = SetupField::Url;
                    self.render(stdout, false)?;
                }
                _ => {}
            },
            SetupField::ClientId => match key.code {
                KeyCode::Enter if !self.setup_client_id.is_empty() => {
                    self.setup_active_field = SetupField::Credential;
                    self.render(stdout, false)?;
                }
                KeyCode::Char(c) if types_a_character(key.modifiers) => {
                    self.setup_client_id.push(c);
                    self.render(stdout, false)?;
                }
                KeyCode::Backspace if !self.setup_client_id.is_empty() => {
                    self.setup_client_id.pop();
                    self.render(stdout, false)?;
                }
                KeyCode::Esc => {
                    self.setup_active_field = SetupField::Auth;
                    self.render(stdout, false)?;
                }
                _ => {}
            },
            SetupField::Credential => match key.code {
                KeyCode::Enter if !self.setup_credential.is_empty() => {
                    // Test connection
                    self.setup_status = "testing connection...".dimmed().to_string();
                    self.render(stdout, false)?;

                    let success = self.test_connection();

                    if success {
                        // Brief success display then return
                        self.setup_active_field = SetupField::Done;
                        self.render(stdout, false)?;

                        let auth_type = match self.setup_auth_idx {
                            0 => "key",
                            1 => "token",
                            _ => "oauth2",
                        }.to_string();
                        return Ok(Some(ConnectionFlowResult::Connected(SavedConnection {
                            name: String::new(),
                            url: self.setup_url.clone(),
                            auth_type,
                            credential: self.setup_credential.clone(),
                            client_id: self.setup_client_id.clone(),
                        }, None, None)));  // Setup doesn't preload - will load after
                    } else {
                        self.setup_conn_fail_count += 1;
                        if self.setup_conn_fail_count >= 3 && !self.setup_status.contains("authentication") {
                            self.setup_status = "\x1b[31m✗ connection could not be established, check URL\x1b[0m".to_string();
                        }
                        // Clear credential on auth failure
                        if self.setup_status.contains("authentication") {
                            self.setup_credential.clear();
                        }
                        self.setup_status_clear_at = Some(Instant::now() + Duration::from_secs(3));
                        self.render(stdout, false)?;
                    }
                }
                KeyCode::Char(c) if types_a_character(key.modifiers) => {
                    self.setup_credential.push(c);
                    self.render(stdout, false)?;
                }
                KeyCode::Backspace if !self.setup_credential.is_empty() => {
                    self.setup_credential.pop();
                    self.render(stdout, false)?;
                }
                KeyCode::Esc => {
                    if self.setup_auth_idx == 2 {
                        self.setup_active_field = SetupField::ClientId;
                    } else {
                        self.setup_active_field = SetupField::Auth;
                    }
                    self.render(stdout, false)?;
                }
                _ => {}
            },
            SetupField::Done => {}
        }

        Ok(None)
    }

    fn run(&mut self, stdout: &mut io::Stdout) -> io::Result<ConnectionFlowResult> {
        // Render splash if showing
        if self.show_splash {
            self.render_splash(stdout)?;
        }

        // Initial render
        self.render(stdout, true)?;

        loop {
            // Clear picker error after timeout
            if let Some(clear_at) = self.picker_error_clear_at {
                if Instant::now() >= clear_at {
                    self.picker_error_msg = None;
                    self.picker_error_clear_at = None;
                    self.render(stdout, false)?;
                }
            }

            // Clear setup status after timeout
            if let Some(clear_at) = self.setup_status_clear_at {
                if Instant::now() >= clear_at {
                    self.setup_status.clear();
                    self.setup_status_clear_at = None;
                    self.render(stdout, false)?;
                }
            }

            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(key) => {
                        if key.kind != event::KeyEventKind::Press { continue; }

                        if let Some(result) = self.handle_key(key, stdout)? {
                            return Ok(result);
                        }
                    }
                    Event::Resize(w, _h) => {
                        self.width = w;

                        // Disable raw mode for redraw
                        terminal::disable_raw_mode()?;

                        // Clear screen and move to home
                        out!("\x1b[2J\x1b[3J\x1b[H");
                        io::stdout().flush().ok();

                        // Redraw splash if showing
                        if self.show_splash {
                            self.render_splash(stdout)?;
                        }

                        io::stdout().flush().ok();

                        // Re-enable raw mode
                        terminal::enable_raw_mode()?;

                        // Re-render the flow UI
                        self.render(stdout, true)?;
                    }
                    _ => {}
                }
            }
        }
    }
}

/// A base URL as the client keeps it, from what was typed for one, and
/// whether a path was cut off it.
///
/// - The scheme is read in any case (`HTTP://host`) and kept in lower case.
///   Without one it is `http` for `localhost`, an IP address, or a host with
///   an explicit port, and `https` for everything else.
/// - The API prefix is not part of the base: `/api`, `/api/v1` and whatever
///   follows are cut, and so is a trailing slash. Only a path component is
///   cut, so the `api` of `api.example.com` stays.
fn base_url_of(text: &str) -> (String, bool) {
    let text = text.trim();
    let lower = text.to_ascii_lowercase();
    let (scheme, rest) = if lower.starts_with("https://") {
        (Some("https://"), &text[8..])
    } else if lower.starts_with("http://") {
        (Some("http://"), &text[7..])
    } else {
        (None, text)
    };
    let (host, path) = match rest.find('/') {
        Some(at) => rest.split_at(at),
        None => (rest, ""),
    };
    // The first `/api` that is a whole path component, and all after it.
    let mut kept = path;
    let mut from = 0;
    while let Some(found) = path[from..].find("/api") {
        let at = from + found;
        let after = &path[at + 4..];
        if after.is_empty() || after.starts_with('/') {
            kept = &path[..at];
            break;
        }
        from = at + 4;
    }
    let kept = kept.trim_end_matches('/');
    let scheme = scheme.unwrap_or(if host_is_local(host) { "http://" } else { "https://" });
    (format!("{}{}{}", scheme, host, kept), kept.len() != path.len())
}

/// Whether a host written without a scheme is one to reach over plain
/// `http`: `localhost`, an IP address, or anything with an explicit port.
fn host_is_local(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.starts_with('[')
        || bare.parse::<std::net::IpAddr>().is_ok()
        || host.contains(':')
}

/// The base URL for what was given as one, on the command line or in a saved
/// connection. See `base_url_of`.
fn normalize_base_uri(uri: &str) -> String {
    base_url_of(uri).0
}

/// Bail out when there's no host to send to. Without this the request goes to a
/// bare path, reqwest fails, and the caller asks whether COS is running on the
/// empty string.
fn require_base_uri(config: &Config) {
    if config.base_uri.is_empty() {
        eprintln!("{}", "Error: no base URL specified. Use -b <url> or -c <connection>.".red());
        exit_process(1);
    }
}

/// Point `config` at a saved connection: its URL and its credentials, and
/// nothing else. Flags (`-i`, `--timeout`, `-f`, `--export`…) are the
/// session's and stay as they are.
///
/// An OAuth2 connection exchanges its client credentials for a token here.
/// When that fails the URL and the client credentials are still set, so a
/// later request can renew the token; `Err` says why there is none yet. It is
/// the caller's to decide what a failure means: a batch ends, the prompt and
/// the connection picker say so and stay.
fn apply_connection_to_config(config: &mut Config, env: &SavedConnection) -> Result<(), String> {
    config.base_uri = normalize_base_uri(&env.url);
    // Only an OAuth2 connection has credentials to renew a token with.
    config.oauth2_client_id.clear();
    config.oauth2_client_secret.clear();
    match env.auth_type.as_str() {
        "token" => {
            config.token = env.credential.clone();
            config.api_key = String::new();
        }
        "oauth2" => {
            config.api_key = String::new();
            config.token = String::new();
            config.oauth2_client_id = env.client_id.clone();
            config.oauth2_client_secret = env.credential.clone();
            let (token, _expires) = oauth2_token_exchange(&config.base_uri, &env.client_id, &env.credential)
                .map_err(|e| format!("OAuth2 token exchange failed: {}", e))?;
            config.token = token;
        }
        _ => {
            // "key" or anything else
            config.api_key = env.credential.clone();
            config.token = String::new();
        }
    }
    Ok(())
}

/// Take over the connection another config holds (URL and credentials) and
/// leave everything else in `config` alone.
fn adopt_connection(config: &mut Config, from: &Config) {
    config.base_uri = from.base_uri.clone();
    config.api_key = from.api_key.clone();
    config.token = from.token.clone();
    config.oauth2_client_id = from.oauth2_client_id.clone();
    config.oauth2_client_secret = from.oauth2_client_secret.clone();
}

/// Switch `config` to a connection the connection dialog returned. The
/// dialog has usually connected already and hands back what it resolved (a
/// token exchanged once, not twice); otherwise the connection is applied.
fn connect(config: &mut Config, env: &SavedConnection, resolved: Option<Config>) -> Result<(), String> {
    match resolved {
        Some(resolved) => {
            adopt_connection(config, &resolved);
            Ok(())
        }
        None => apply_connection_to_config(config, env),
    }
}

/// A saved connection with what the command line gave in its place: `-b`
/// for its URL, `-k` or `--token` for its credential. The flags win, so one
/// saved connection can be used with another key, or against another host.
fn override_connection(env: &SavedConnection, url: Option<&str>, key: Option<&str>, token: Option<&str>) -> SavedConnection {
    let mut env = env.clone();
    if let Some(url) = url {
        env.url = url.to_string();
    }
    let given = token.map(|t| ("token", t)).or(key.map(|k| ("key", k)));
    if let Some((auth_type, credential)) = given {
        env.auth_type = auth_type.to_string();
        env.credential = credential.to_string();
        env.client_id.clear();
    }
    env
}

fn main() {
    install_panic_hook();
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) => {
            // Help and version are "success" errors in clap — print them normally
            if e.kind() == clap::error::ErrorKind::DisplayHelp || e.kind() == clap::error::ErrorKind::DisplayVersion {
                out!("{}", e);
                exit_process(0);
            }
            // A value an option can't take (`--timeout abc`) is named with
            // its option; it is not an unexpected option.
            if matches!(e.kind(), clap::error::ErrorKind::ValueValidation | clap::error::ErrorKind::InvalidValue) {
                let context = |kind| e.get(kind).map(|v| v.to_string());
                if let (Some(arg), Some(value)) = (
                    context(clap::error::ContextKind::InvalidArg),
                    context(clap::error::ContextKind::InvalidValue),
                ) {
                    let option = arg.split_whitespace().next().unwrap_or(&arg);
                    eprintln!("error: invalid value for {}: {}", option, value);
                    exit_process(1);
                }
            }
            // For unexpected arguments, print a simple message
            let msg = e.to_string();
            if let Some(arg) = msg.split('\'').nth(1) {
                eprintln!("error: unexpected option {}", arg);
            } else {
                eprintln!("error: {}", msg.lines().next().unwrap_or("invalid arguments"));
            }
            exit_process(1);
        }
    };

    if args.version {
        outln!("v{}", VERSION);
        exit_process(0);
    }

    // `--describe` and `--assert` read a file and print what it says. Nothing
    // is sent, so neither needs a connection.
    if args.describe.is_some() && args.assert.is_some() {
        eprintln!("error: --describe and --assert each print a document of their own: use one");
        exit_process(1);
    }
    if let Some(file) = &args.describe {
        exit_process(print_describe_block(file, args.raw));
    }
    if let Some(file) = &args.assert {
        let api_path = if args.me { "/api/me/v1" } else { "/api/v1" };
        exit_process(print_assertions(file, api_path, args.raw));
    }

    // Route all credential I/O to a file instead of the OS keychain.
    // Must happen before any keychain access below.
    if args.no_keychain {
        let path = std::env::var("API_CREDENTIALS_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".api-credentials.json"));
        enable_no_keychain(path);
    }

    let mut config = Config::default();

    // Apply CLI args to config
    if let Some(ref uri) = args.base_uri {
        config.base_uri = normalize_base_uri(uri);
    }
    config.silent = args.silent;
    config.raw = args.raw;
    config.include_nulls = args.include_nulls;
    config.ndjson = args.ndjson;
    // Streaming is opt-in: --no-streaming beats --stream beats API_STREAMING.
    config.stream_requested = !args.no_streaming && (args.stream || env_streaming_requested());
    config.experimental = args.experimental;
    if let Some(secs) = args.timeout {
        config.timeout_secs = secs;
    }
    config.preview = args.preview;
    config.fail_fast = args.fail_fast;
    config.describe_first = args.describe_first;
    if let Some(name) = &args.export {
        if !is_namespaced_key(name) {
            eprintln!("error: invalid export identifier: {} ({})", name, NAMESPACED_KEY_HELP);
            exit_process(1);
        }
        config.export_id = Some(name.clone());
        config.export_pinned = true;
    }

    if args.me {
        config.api_path = "/api/me/v1".to_string();
    }

    // Detect whether user explicitly provided auth/connection args
    let has_explicit_auth = args.key.is_some() || args.token.is_some() || args.one_password.is_some();
    let has_explicit_uri = args.base_uri.is_some();
    let mut from_setup = false;
    let mut loaded_connection_alias = String::new();
    let mut connecting_to: Option<String> = None;
    let mut oauth2_creds: Option<(String, String)> = None;
    let mut startup_preloaded: Option<BackgroundLoadResult> = None;

    // Handle 1Password integration
    let op_selector = args.one_password;
    if op_selector.is_none() {
        // Set auth from args (only when not using 1Password)
        if let Some(key) = args.key.clone() {
            config.api_key = key;
        }
        if let Some(token) = args.token.clone() {
            config.token = token;
        }
    }

    // A directive, chain, include, or whole line in one argument runs through
    // the batch runner — same syntax as a `.api` file and the interactive prompt.
    let program_line = one_shot_program_line(&args.method, &args.uri, &args.body);

    // Parse positional args like bash client
    let body_arg = if args.body.is_empty() { None } else { Some(args.body.join(" ")) };
    let (method, uri, body) = parse_positional_args(args.method, args.uri, body_arg);

    // `-t` used to take a bearer token and now means --stream, so an old
    // invocation leaves the token sitting in the method slot. Say so rather
    // than letting it become a request to a nonsense method.
    if args.stream && looks_like_bearer_token(&method) {
        eprintln!(
            "{}",
            "error: -t is now --stream. Use --token <TOKEN> for a bearer token.".red()
        );
        exit_process(1);
    }

    // The arguments as one line, read the way a `.api` file reads it: a body
    // comment, a raw newline in a string, or a `> file` in an argument of its
    // own means the same thing here as there.
    let (method, uri, mut body) = if program_line.is_none() && !method.is_empty() {
        // A `> file` given in the URI argument with the body after it
        // (`api PUT "/x > out.json" '{…}'`) goes last, where a line keeps it.
        let (uri, redirect) = match outfile_marker_at(&uri) {
            Some(i) => (uri[..i].trim().to_string(), uri[i..].to_string()),
            None => (uri, String::new()),
        };
        let joined = format!("{} {} {}{}", method, uri, body, redirect);
        match normalize_request_text(&joined).map(|t| parse_request_line(&t)) {
            Ok(Some(parts)) => parts,
            Ok(None) => (method, uri, body),
            Err(e) => {
                eprintln!("error: {}", e);
                exit_process(1);
            }
        }
    } else {
        (method, uri, body)
    };

    // A one-shot request that can't be sent is refused before anything else
    // happens (`>> clipboard`), as a line of a file is.
    if program_line.is_none() && !method.is_empty() {
        if let Err(e) = refuse_request(&format!("{} {}", method, uri)) {
            eprintln!("error: {}", e);
            exit_process(1);
        }
    }

    // A piped stdin is the body of a request that takes one and was given
    // none. A GET or a DELETE never reads it: it would wait for a pipe that
    // stays open, and swallow the input of a `while read` loop around it.
    let takes_body = ["POST", "PUT", "PATCH"].contains(&method.as_str()) && !uri.is_empty();
    if body.is_empty() && takes_body && args.all.is_none() && program_line.is_none() && !io::stdin().is_terminal() {
        // `-p` asks a question, and with no terminal its answer comes from
        // stdin too. Stdin can't be both.
        if args.preview && !terminal_can_answer() {
            eprintln!(
                "error: -p reads its answer from stdin here, so the body can't come from stdin too. \
                 Give the body as an argument or an @file, or leave -p off."
            );
            exit_process(1);
        }
        let mut stdin_content = String::new();
        if io::stdin().read_to_string(&mut stdin_content).is_ok() {
            body = stdin_content.trim().to_string();
        }
    }

    // If method expects a body but none provided, read interactively from stdin
    if body.is_empty()
        && program_line.is_none()
        && io::stdin().is_terminal()
        && ["POST", "PUT", "PATCH"].contains(&method.as_str())
        && !uri.is_empty()
    {
        eprintln!("Reading body from stdin (ctrl+d to finish):");
        let mut stdin_content = String::new();
        if io::stdin().read_to_string(&mut stdin_content).is_ok() {
            body = stdin_content.trim().to_string();
        }
    }

    // Whether this run opens the prompt: no request, no file, no program
    // line. Only then may a dialog be shown; a batch never opens one.
    let wants_prompt = uri.is_empty() && args.all.is_none() && program_line.is_none();

    // Handle -c flag: load saved connection by alias or URL
    if let Some(ref connection_selector) = args.connection {
        let envs = list_connections();
        // An exact alias first, then a URL, with or without its scheme.
        let by_alias = envs.iter().find(|name| *name == connection_selector).and_then(|name| load_connection(name));
        let found = by_alias.or_else(|| {
            envs.iter().filter_map(|name| load_connection(name)).find(|env| {
                let url_bare = env.url.trim_start_matches("https://").trim_start_matches("http://");
                env.url == *connection_selector || url_bare == *connection_selector
            })
        });
        let Some(env) = found else {
            eprintln!("Connection \"{}\" not found. Saved connections: {}", connection_selector,
                if envs.is_empty() { "none".to_string() } else { envs.join(", ") });
            exit_process(1);
        };
        loaded_connection_alias = env.name.clone();
        // `-b`, `-k` and `--token` win over what the connection has stored.
        let env = override_connection(&env, args.base_uri.as_deref(), args.key.as_deref(), args.token.as_deref());
        config.connection_overridden = args.base_uri.is_some() || args.key.is_some() || args.token.is_some();
        if let Err(e) = apply_connection_to_config(&mut config, &env) {
            eprintln!("{}", e);
            // The prompt opens all the same, where another connection can
            // be picked; a batch has nothing to run against.
            if !(wants_prompt && io::stdout().is_terminal()) {
                exit_process(1);
            }
        }
        // Show UI immediately with async loading (like 1P and picker)
        if !loaded_connection_alias.is_empty() && wants_prompt && io::stdout().is_terminal() {
            connecting_to = Some(loaded_connection_alias.clone());
        }
    }

    // If -b provided without auth, go straight to setup with URL pre-filled
    if has_explicit_uri && !has_explicit_auth && args.connection.is_none() && wants_prompt && io::stdout().is_terminal() {
        let (term_width, _) = terminal::size().unwrap_or((80, 24));
        let envs: Vec<String> = Vec::new();
        let mut flow = ConnectionFlow::for_startup(&envs, term_width, true);
        // Pre-fill URL in setup and focus on auth method
        flow.setup_url = config.base_uri.clone();
        flow.setup_active_field = SetupField::Auth;

        let mut stdout = io::stdout();
        terminal::enable_raw_mode().unwrap();
        execute!(stdout, cursor::Hide).unwrap();

        match flow.run(&mut stdout) {
            Ok(ConnectionFlowResult::Connected(env, _preloaded, resolved_config)) => {
                // Store OAuth2 credentials for token refresh
                if env.auth_type == "oauth2" {
                    oauth2_creds = Some((env.client_id.clone(), env.credential.clone()));
                }
                if let Err(e) = connect(&mut config, &env, resolved_config) {
                    eprintln!("{}\r", e);
                }

                // Stay on form with animated spinner while loading
                {
                    let bg_config = config.clone();
                    let (tx, rx) = std::sync::mpsc::channel();
                    thread::spawn(move || { let _ = tx.send(background_load(&bg_config, None)); });
                    let mut frame = 0usize;
                    loop {
                        if let Ok(result) = rx.try_recv() {
                            startup_preloaded = Some(result);
                            break;
                        }
                        flow.setup_status = format!("{} loading...", SPINNER_FRAMES[frame % SPINNER_FRAMES.len()]).dimmed().to_string();
                        flow.render(&mut stdout, false).ok();
                        thread::sleep(Duration::from_millis(80));
                        frame += 1;
                    }
                }

                // Clear the flow UI
                let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                terminal::disable_raw_mode().unwrap();
                execute!(stdout, cursor::Show).unwrap();

                // Print fresh splash with connected URL
                print_splash_with_width(&config, term_width);
                io::stdout().flush().ok();

                from_setup = true;
            }
            Ok(ConnectionFlowResult::Cancelled) | Ok(ConnectionFlowResult::Quit) => {
                // Clear the flow UI before exiting
                let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                terminal::disable_raw_mode().unwrap();
                execute!(stdout, cursor::Show).unwrap();
                exit_process(0);
            }
            Err(e) => {
                let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                terminal::disable_raw_mode().unwrap();
                execute!(stdout, cursor::Show).unwrap();
                eprintln!("Error: {}", e);
                exit_process(1);
            }
        }
    }

    // If no explicit uri arg, check saved connections. Passing --key/--token
    // without -b still resolves the URL from the default connection — supplying
    // credentials shouldn't discard the saved host — but keeps the CLI auth.
    if args.connection.is_none() && !has_explicit_uri && op_selector.is_none() {
        let envs = list_connections();
        let default_connection = get_default_connection();

        if !envs.is_empty() {
            // If there's a default connection, auto-load it
            if let Some(ref def) = default_connection {
                if let Some(env) = load_connection(def) {
                    if has_explicit_auth {
                        // URL only. Deliberately not apply_connection_to_config:
                        // an oauth2 connection would exchange a token we'd throw
                        // away, and the CLI credential must win.
                        config.base_uri = normalize_base_uri(&env.url);
                    } else {
                        loaded_connection_alias = env.name.clone();
                        if let Err(e) = apply_connection_to_config(&mut config, &env) {
                            eprintln!("{}", e);
                            if !(wants_prompt && io::stdout().is_terminal()) {
                                exit_process(1);
                            }
                        }
                    }
                }
            } else if !has_explicit_auth && wants_prompt && io::stdout().is_terminal() {
                // No default set + interactive: show unified connection flow
                let (term_width, _) = terminal::size().unwrap_or((80, 24));
                let mut flow = ConnectionFlow::for_startup(&envs, term_width, true);

                let mut stdout = io::stdout();
                terminal::enable_raw_mode().unwrap();
                execute!(stdout, cursor::Hide).unwrap();

                match flow.run(&mut stdout) {
                    Ok(ConnectionFlowResult::Connected(env, preloaded, resolved_config)) => {
                        if !env.name.is_empty() {
                            loaded_connection_alias = env.name.clone();
                        }
                        from_setup = true;

                        // Store OAuth2 credentials for token refresh
                        if env.auth_type == "oauth2" {
                            oauth2_creds = Some((env.client_id.clone(), env.credential.clone()));
                        }
                        // Use resolved config if available (avoids duplicate token exchange)
                        if let Err(e) = connect(&mut config, &env, resolved_config) {
                            eprintln!("{}\r", e);
                        }

                        // Stay on form with animated spinner while loading
                        if let Some(pre) = preloaded {
                            startup_preloaded = Some(pre);
                        } else {
                            let bg_config = config.clone();
                            let (tx, rx) = std::sync::mpsc::channel();
                            thread::spawn(move || { let _ = tx.send(background_load(&bg_config, None)); });
                            let mut frame = 0usize;
                            loop {
                                if let Ok(result) = rx.try_recv() {
                                    startup_preloaded = Some(result);
                                    break;
                                }
                                flow.setup_status = format!("{} loading...", SPINNER_FRAMES[frame % SPINNER_FRAMES.len()]).dimmed().to_string();
                                flow.render(&mut stdout, false).ok();
                                thread::sleep(Duration::from_millis(80));
                                frame += 1;
                            }
                        }

                        // Clear the flow UI
                        let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                        execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                        terminal::disable_raw_mode().unwrap();
                        execute!(stdout, cursor::Show).unwrap();

                        // Print fresh splash with connected URL
                        print_splash_with_width(&config, term_width);
                        io::stdout().flush().ok();
                    }
                    Ok(ConnectionFlowResult::Cancelled) | Ok(ConnectionFlowResult::Quit) => {
                        let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                        execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                        terminal::disable_raw_mode().unwrap();
                        execute!(stdout, cursor::Show).unwrap();
                        exit_process(0);
                    }
                    Err(e) => {
                        let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                        execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                        terminal::disable_raw_mode().unwrap();
                        execute!(stdout, cursor::Show).unwrap();
                        eprintln!("Error: {}", e);
                        exit_process(1);
                    }
                }
            }
        } else if !has_explicit_auth && wants_prompt && io::stdout().is_terminal() {
            // No saved connections + interactive: show unified connection flow (setup only)
            let (term_width, _) = terminal::size().unwrap_or((80, 24));
            let envs: Vec<String> = Vec::new();
            let mut flow = ConnectionFlow::for_startup(&envs, term_width, true);

            let mut stdout = io::stdout();
            terminal::enable_raw_mode().unwrap();
            execute!(stdout, cursor::Hide).unwrap();

            match flow.run(&mut stdout) {
                Ok(ConnectionFlowResult::Connected(env, _preloaded, resolved_config)) => {
                    // Store OAuth2 credentials for token refresh
                    if env.auth_type == "oauth2" {
                        oauth2_creds = Some((env.client_id.clone(), env.credential.clone()));
                    }

                    // Apply config first so splash shows correct URL
                    if let Err(e) = connect(&mut config, &env, resolved_config) {
                        eprintln!("{}\r", e);
                    }

                    // Stay on form with animated spinner while loading
                    {
                        let bg_config = config.clone();
                        let (tx, rx) = std::sync::mpsc::channel();
                        thread::spawn(move || { let _ = tx.send(background_load(&bg_config, None)); });
                        let mut frame = 0usize;
                        loop {
                            if let Ok(result) = rx.try_recv() {
                                startup_preloaded = Some(result);
                                break;
                            }
                            flow.setup_status = format!("{} loading...", SPINNER_FRAMES[frame % SPINNER_FRAMES.len()]).dimmed().to_string();
                            flow.render(&mut stdout, false).ok();
                            thread::sleep(Duration::from_millis(80));
                            frame += 1;
                        }
                    }

                    from_setup = true;

                    // Clear flow UI including splash
                    let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                    execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                    terminal::disable_raw_mode().unwrap();
                    execute!(stdout, cursor::Show).unwrap();

                    // Print fresh splash with the connected URL
                    print_splash_with_width(&config, term_width);
                    io::stdout().flush().ok();
                }
                Ok(ConnectionFlowResult::Cancelled) | Ok(ConnectionFlowResult::Quit) => {
                    let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                    execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                    terminal::disable_raw_mode().unwrap();
                    execute!(stdout, cursor::Show).unwrap();
                    exit_process(0);
                }
                Err(e) => {
                    let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                    execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                    terminal::disable_raw_mode().unwrap();
                    execute!(stdout, cursor::Show).unwrap();
                    eprintln!("Error: {}", e);
                    exit_process(1);
                }
            }
        }
    }

    // Bulk mode: execute requests from a file or stdin
    if let Some(ref bulk_arg) = args.all {
        // Resolve 1Password credentials before running
        if let Some(selector) = &op_selector {
            match get_1password_credentials(selector) {
                Ok((base_uri, api_key)) => {
                    config.base_uri = base_uri;
                    config.api_key = api_key;
                }
                Err(e) => {
                    eprintln!("{}", e);
                    exit_process(1);
                }
            }
        }
        if bulk_arg == "-" {
            let mut stdin_content = String::new();
            if io::stdin().read_to_string(&mut stdin_content).is_err() {
                eprintln!("error: could not read stdin");
                exit_process(1);
            }
            // No base_dir for stdin — includes can still use absolute paths
            run_bulk_from_str(&mut config, &stdin_content, None);
        } else {
            run_bulk(&mut config, bulk_arg);
        }
        return;
    }

    // One-shot .api line: `api assert /x`, `api "GET /a && PUT /b {…}"`,
    // `api seed.api`. Runs like `-a` on a one-line file, so a failed assert
    // exits 1 and a chain chains. Includes resolve against the working
    // directory.
    if let Some(line) = program_line {
        // `api export com.heads.seedID` would set a mode and send nothing.
        let alone = line.lines().filter(|l| !l.trim().is_empty()).count() == 1
            && line.split_whitespace().next().is_some_and(|w| w.eq_ignore_ascii_case("export"));
        if alone {
            eprintln!("error: `export` alone sends nothing. Use --export <name> with a request, or put the line in a .api file.");
            exit_process(1);
        }
        // The file named on the line is the file being run, so `-m` prints
        // its describe block, as `-ma` on the file would.
        if config.describe_first {
            config.describe_first = false;
            if let Some(block) = describe_block_of_named_file(&line) {
                print_describe_first(&block);
            }
        }
        if let Some(selector) = &op_selector {
            match get_1password_credentials(selector) {
                Ok((base_uri, api_key)) => {
                    config.base_uri = base_uri;
                    config.api_key = api_key;
                }
                Err(e) => {
                    eprintln!("{}", e);
                    exit_process(1);
                }
            }
        }
        // A mistyped request would otherwise be reported as a missing include.
        match split_bulk_requests(&line, None) {
            Err(e) => {
                eprintln!("error: {}", describe_program_error(&e));
                exit_process(1);
            }
            Ok(program) if program.only_describes() => {
                eprintln!("error: {}", DESCRIBE_ALONE);
                exit_process(1);
            }
            Ok(_) => {}
        }
        run_bulk_from_str(&mut config, &line, None);
        return;
    }

    // Non-interactive mode if URI provided
    if !uri.is_empty() {
        // Non-interactive still blocks on 1Password (needs creds before request)
        if let Some(selector) = &op_selector {
            match get_1password_credentials(selector) {
                Ok((base_uri, api_key)) => {
                    config.base_uri = base_uri;
                    config.api_key = api_key;
                }
                Err(e) => {
                    eprintln!("{}", e);
                    exit_process(1);
                }
            }
        }
        config.one_shot = true;
        run_non_interactive(&mut config, &method, &uri, &body);
        return;
    }

    // Interactive mode (1Password loads in background)
    // "Auth came from the CLI and we have a host to use it against" — the URL
    // may have come from the default connection rather than -b, and a 401 there
    // is still the user's own credential failing, so report it instead of
    // reopening the picker.
    let from_cli_auth = has_explicit_auth && !config.base_uri.is_empty();
    if let Err(e) = run_interactive(config, op_selector, from_setup, loaded_connection_alias, connecting_to, oauth2_creds, startup_preloaded, from_cli_auth) {
        eprintln!("Error: {}", e);
        exit_process(1);
    }
}

/// Whether a positional method slot is really a bearer token left over from the
/// old `-t <TOKEN>` spelling. Deliberately narrow: a JWT-shaped string (three
/// dot-separated segments, no slashes) that could never be an HTTP method.
fn looks_like_bearer_token(method: &str) -> bool {
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    if method.is_empty() || methods.contains(&method) || method.starts_with('/') {
        return false;
    }
    method.len() > 40
        && !method.contains('/')
        && method.split('.').count() == 3
        && method
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// The positional arguments as one `.api` line, when they should be run by the
/// batch runner rather than sent as a single request: a directive or include
/// (`api assert /x`, `api seed.api`), a `&&`/`||` chain (`api GET /a "&&" PUT
/// /b`), or a whole line in one argument (`api "GET /about"`). A plain
/// `METHOD URI [BODY]` returns `None` and takes the one-shot path unchanged.
///
/// Rejoining with single spaces loses the shell's original spacing, which
/// matters only inside a body — and a body that cares is a quoted argument
/// anyway, which survives verbatim.
fn one_shot_program_line(method: &Option<String>, uri: &Option<String>, body: &[String]) -> Option<String> {
    let first = method.as_deref()?.trim();
    if first.is_empty() {
        return None;
    }
    let line: Vec<&str> = std::iter::once(first)
        .chain(uri.as_deref())
        .chain(body.iter().map(String::as_str))
        .collect();
    let line = line.join(" ");
    let whole_line_in_first_arg = first.contains(char::is_whitespace);
    if is_program_line(&line) || whole_line_in_first_arg || split_request_chain(&line).len() > 1 {
        Some(line)
    } else {
        None
    }
}

fn parse_positional_args(
    method: Option<String>,
    uri: Option<String>,
    body: Option<String>,
) -> (String, String, String) {
    let mut result_method = String::new();
    let mut result_uri = String::new();
    let mut result_body = String::new();

    if let Some(m) = method {
        if m.starts_with('/') {
            result_uri = m;
            result_method = "GET".to_string();
        } else {
            result_method = m.to_uppercase();
        }
    }

    if let Some(u) = uri {
        if result_uri.is_empty() {
            result_uri = u;
        } else {
            result_body = u;
        }
    }

    if let Some(b) = body {
        result_body = b;
    }

    (result_method, result_uri, result_body)
}

/// Coarse progress of `background_load`, published so the spinner can say which
/// step is actually running. A global rather than a threaded-through parameter
/// because only one background load is ever in flight, and it would otherwise
/// have to reach all eight call sites.
mod load_phase {
    use std::sync::atomic::{AtomicU8, Ordering};

    /// Waiting on the 1Password CLI.
    pub const RESOLVING_1P: u8 = 0;
    /// Waiting on the server's `/about`.
    pub const CONNECTING: u8 = 1;
    /// Waiting on the OpenAPI spec and mapped types.
    pub const LOADING_SPEC: u8 = 2;

    static PHASE: AtomicU8 = AtomicU8::new(RESOLVING_1P);

    pub fn set(phase: u8) {
        PHASE.store(phase, Ordering::Relaxed);
    }

    pub fn get() -> u8 {
        PHASE.load(Ordering::Relaxed)
    }
}

/// How long to wait for an `op` invocation before giving up. The 1Password CLI
/// can block indefinitely on an unsurfaced biometric prompt or a stale session,
/// which otherwise hangs the whole client with no way to tell what it's waiting for.
const OP_TIMEOUT_SECS: u64 = 30;

/// Run a command with a deadline, killing it if it overruns.
///
/// `Command::output()` waits forever; this doesn't. The pipes are drained on
/// their own threads so a child writing more than the pipe buffer can't deadlock
/// against our wait. Returns `Ok(None)` when the deadline passed.
fn output_with_timeout(cmd: &mut Command, timeout: Duration) -> io::Result<Option<std::process::Output>> {
    use std::process::Stdio;

    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let mut child_stdout = child.stdout.take();
    let mut child_stderr = child.stderr.take();
    let stdout_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = child_stdout.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let stderr_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = child_stderr.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => {
                return Ok(Some(std::process::Output {
                    status,
                    stdout: stdout_handle.join().unwrap_or_default(),
                    stderr: stderr_handle.join().unwrap_or_default(),
                }));
            }
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(None);
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Run an `op` command, mapping both failure modes to a message the user can act
/// on. `context` names what was being read, e.g. "the environment list".
fn op_read(args: &[&str], context: &str) -> Result<std::process::Output, String> {
    let mut cmd = Command::new("op");
    cmd.args(args);
    match output_with_timeout(&mut cmd, Duration::from_secs(OP_TIMEOUT_SECS)) {
        Ok(Some(output)) => Ok(output),
        Ok(None) => Err(format!(
            "1Password did not respond within {}s while reading {}.\n\
             Is `op` signed in? Try: op signin",
            OP_TIMEOUT_SECS, context
        )),
        Err(e) => Err(format!("could not run 1Password CLI: {}", e)),
    }
}

/// The trimmed stderr of a failed `op` call, for appending to an error message.
/// Empty when `op` said nothing useful, so callers can keep their own wording.
fn op_stderr_detail(output: &std::process::Output) -> String {
    let msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if msg.is_empty() {
        String::new()
    } else {
        format!("\n{}", msg)
    }
}

/// Whether `program` can be started at all: found on the `PATH` and
/// runnable. What it then does with `--version` is not asked.
fn command_exists(program: &str) -> bool {
    use std::process::Stdio;
    Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn get_1password_credentials(selector: &str) -> Result<(String, String), String> {
    // Check that the `op` command is there by running it: that it can't be
    // started is the answer, on every platform (there is no `which` to ask
    // on Windows).
    if !command_exists("op") {
        return Err("1Password CLI is required for this option (try: brew install 1password-cli)".to_string());
    }

    // Validate selector format
    if !selector.contains('/') {
        return Err(format!(
            "invalid selector {}, should be of format <organization>/<environment>",
            selector
        ));
    }

    // Read environments.json from 1Password
    let output = op_read(
        &["read", "op://Shared/COS environments/environments.json"],
        "the environment list",
    )?;

    if !output.status.success() {
        return Err(format!("could not read from 1Password.{}", op_stderr_detail(&output)));
    }

    let env_data: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("could not parse environments.json: {}", e))?;

    // Navigate the nested structure
    let parts: Vec<&str> = selector.split('/').collect();
    let mut current = &env_data;

    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // Last part - get url and key
            let url = current
                .get(part)
                .and_then(|v| v.get("url"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("could not find an environment by '{}'. Check `COS environments` in 1P for available environments.", selector))?;

            let key_ref = current
                .get(part)
                .and_then(|v| v.get("key"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("could not find an environment by '{}'. Check `COS environments` in 1P for available environments.", selector))?;

            // Read the actual key from the reference
            let key_output = op_read(&["read", key_ref], "the API key")?;

            if !key_output.status.success() {
                let stderr_msg = String::from_utf8_lossy(&key_output.stderr).trim().to_string();
                let hint = if stderr_msg.to_lowercase().contains("access")
                    || stderr_msg.to_lowercase().contains("permission")
                    || stderr_msg.to_lowercase().contains("not found")
                {
                    format!(
                        "no access to the API key for '{}' in 1Password.\n\
                         Ask the environment owner to grant you access.",
                        selector
                    )
                } else {
                    format!(
                        "could not read API key for '{}' from 1Password.{}",
                        selector,
                        op_stderr_detail(&key_output)
                    )
                };
                return Err(hint);
            }

            let api_key = String::from_utf8_lossy(&key_output.stdout)
                .trim()
                .to_string();

            if api_key.is_empty() {
                return Err(format!(
                    "1Password returned an empty key for '{}'.",
                    selector
                ));
            }

            // A URL from 1Password is read as one given with `-b`: it may
            // come without a scheme, or with the API prefix.
            return Ok((normalize_base_uri(url), api_key));
        } else {
            current = current
                .get(part)
                .ok_or_else(|| format!("could not find an environment by '{}'. Check `COS environments` in 1P for available environments.", selector))?;
        }
    }

    Err(format!("could not find an environment by '{}'. Check `COS environments` in 1P for available environments.", selector))
}

/// Returns (connected, complete) where:
/// - connected: true if server responded at all
/// Check connection by calling /about endpoint
/// Returns: (connected, complete, streaming)
/// - connected: true if server responded
/// - complete: true if server has openapi-metadata-version >= 1.1
/// - streaming: true if response:streaming feature flag is present
/// Err(status) for auth errors (401/403)
fn check_connection(config: &Config) -> Result<(bool, bool, bool), u16> {
    let client = client_builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("could not set up the HTTP client");

    let url = format!("{}{}/about", config.base_uri, config.api_path);

    let mut request = client.get(&url);

    if let Some(authorization) = auth_header(config) {
        request = request.header("Authorization", authorization);
    }

    match request.send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 401 || status == 403 {
                return Err(status);
            }
            // Server responded - we're connected
            if let Ok(body) = resp.json::<serde_json::Value>() {
                let complete = if let Some(version) = body.get("openapi-metadata-version").and_then(|v| v.as_str()) {
                    if let Some((major, minor)) = version.split_once('.') {
                        if let (Ok(maj), Ok(min)) = (major.parse::<u32>(), minor.parse::<u32>()) {
                            maj > 1 || (maj == 1 && min >= 1)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };
                // Check for streaming in feature-flags array within /about response
                let streaming = body.get("feature-flags")
                    .and_then(|v| v.as_array())
                    .map(|flags| flags.iter().any(|f| f.as_str() == Some("response:streaming")))
                    .unwrap_or(false);
                Ok((true, complete, streaming))
            } else {
                Ok((true, false, false))  // connected but couldn't parse
            }
        }
        Err(_) => Ok((false, false, false)),  // connection failed
    }
}

/// Parse a single request line — same semantics as the interactive client's `parse_input`.
/// Returns (method, uri_with_outfile_suffix, body) where the URI includes ` > outfile`
/// if present, so run_non_interactive parses it the same way.
/// Whether `word`, the first word of a line, opens a request: an HTTP method
/// or a `/path`. A `/path` that names a `.api` file is an include instead —
/// that suffix is the only thing telling an absolute include from a URI.
fn starts_a_request(word: &str) -> bool {
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    methods.contains(&word.to_uppercase().as_str())
        || (word.starts_with('/') && !names_api_file(word))
}

fn names_api_file(word: &str) -> bool {
    word.to_ascii_lowercase().ends_with(".api")
}

/// One request's text the way a `.api` file holds it: body comments stripped
/// and raw newlines inside JSON strings escaped. The prompt and the one-shot
/// arguments go through this too, so the same text means the same request
/// wherever it is written.
fn normalize_request_text(text: &str) -> Result<String, String> {
    let (cleaned, depth) = strip_body_comments_and_count(text);
    if depth > 0 {
        return Err(format!("unclosed body (depth {})", depth));
    }
    Ok(escape_newlines_in_strings(&cleaned))
}

/// Where the ` > outfile` (or ` >> outfile`) of a request starts: the last
/// ` >` that is outside a JSON string and outside brackets and parentheses.
/// A `>` in a body (`{"a":"b > c"}`) or in a URI operator
/// (`~where(name="a > b")`) is the request's own, as `&&` there is.
///
/// A text whose quotes or brackets don't balance has no inside or outside to
/// go by, so there the last ` >` is taken, as it always was.
fn outfile_marker_at(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut found = None;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (i, ch) in text.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => depth -= 1,
            ' ' if depth <= 0 && bytes.get(i + 1) == Some(&b'>') => found = Some(i),
            _ => {}
        }
    }
    if in_string || depth > 0 {
        return text.rfind(" >");
    }
    found
}

/// A URI as `parse_request_line` hands it back, split into the URI and its
/// ` > outfile` suffix (empty when there is none).
fn split_uri_outfile(uri: &str) -> (&str, &str) {
    match outfile_marker_at(uri) {
        Some(at) => uri.split_at(at),
        None => (uri, ""),
    }
}

/// Where the URI ends in the text that follows a method: at the first blank
/// that is outside quotes and parentheses, so `/x~where(name="a b")` is one
/// URI. With unbalanced quotes or parentheses it ends at the first blank.
fn uri_end(text: &str) -> usize {
    let mut depth = 0i32;
    let mut in_string = false;
    for (i, ch) in text.char_indices() {
        if in_string {
            in_string = ch != '"';
            continue;
        }
        match ch {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => depth -= 1,
            c if c.is_whitespace() && depth <= 0 => return i,
            _ => {}
        }
    }
    if in_string || depth > 0 {
        return text.find(char::is_whitespace).unwrap_or(text.len());
    }
    text.len()
}

/// A request that could be parsed but must not be sent, and why. Checked
/// while a file or a line is read, so nothing has been sent when it is said.
fn refuse_request(request: &str) -> Result<(), String> {
    let Some((_, uri, _)) = parse_request_line(request) else {
        return Ok(());
    };
    let (_, redirect) = split_uri_outfile(&uri);
    if let Some(target) = redirect.strip_prefix(" >>") {
        if is_clipboard_target(target) {
            return Err("cannot append to clipboard — use > clipboard".to_string());
        }
    }
    Ok(())
}

fn parse_request_line(line: &str) -> Option<(String, String, String)> {
    let mut working = line.trim().to_string();
    if working.is_empty() || working.starts_with('#') {
        return None;
    }

    // Strip ` > outfile` / ` >> outfile` from the end (matches parse_input),
    // preserving which marker it was so append survives the round-trip.
    let outfile_suffix: String = if let Some(idx) = outfile_marker_at(&working) {
        let mut rest = &working[idx + 2..];
        let append = rest.starts_with('>');
        if append {
            rest = &rest[1..];
        }
        let path = rest.trim().to_string();
        if !path.is_empty() {
            let suffix = format!(" {} {}", if append { ">>" } else { ">" }, path);
            working = working[..idx].trim().to_string();
            suffix
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    let first_end = working.find(|c: char| c.is_whitespace()).unwrap_or(working.len());
    let first_word = &working[..first_end];
    let first_upper = first_word.to_uppercase();

    let (method, uri, body) = if methods.contains(&first_upper.as_str()) {
        let after_method = working[first_end..].trim_start();
        if after_method.is_empty() {
            (first_upper, "/".to_string(), String::new())
        } else {
            let uri_end = uri_end(after_method);
            let uri = after_method[..uri_end].to_string();
            let body = after_method[uri_end..].trim_start_matches(|c: char| c == ' ' || c == '\t').to_string();
            (first_upper, uri, body)
        }
    } else if starts_a_request(first_word) {
        let first_end = uri_end(&working);
        let uri = working[..first_end].to_string();
        let body = working[first_end..].trim_start_matches(|c: char| c == ' ' || c == '\t').to_string();
        ("GET".to_string(), uri, body)
    } else {
        return None;
    };

    // Append outfile suffix to URI, where `split_uri_outfile` finds it again
    Some((method, format!("{}{}", uri, outfile_suffix), body))
}

/// Replace raw newlines, tabs, and carriage returns inside JSON string literals
/// with their escape sequences (`\n`, `\t`, `\r`) so the body is valid JSON.
fn escape_newlines_in_strings(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_string = false;
    let mut escape = false;
    for ch in s.chars() {
        if escape {
            out.push(ch);
            escape = false;
            continue;
        }
        if in_string && ch == '\\' {
            out.push(ch);
            escape = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            out.push(ch);
            continue;
        }
        if in_string {
            match ch {
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                _ => out.push(ch),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Resolve a user-provided URI into the full request path, applying the
/// default `api_path` prefix only when the URI doesn't already specify one.
///
/// - `/api/...` or `/api` → used as-is
/// - `/v<N>` or `/v<N>/...` → prepend `/api` (so it becomes `/api/v<N>/...`)
/// - anything else → prepend `api_path` (typically `/api/v1`)
///
/// A missing leading slash is added first, so a path copied out of a URL or a
/// log (`api/v1/people`, `people`) is the same request as `/api/v1/people` and
/// `/people` — rather than being glued onto the prefix as `/api/v1api/v1/…`.
fn resolve_request_path(api_path: &str, uri: &str) -> String {
    let with_slash;
    let uri = if uri.is_empty() || uri.starts_with('/') {
        uri
    } else {
        with_slash = format!("/{}", uri);
        &with_slash
    };
    // Already absolute under /api
    if uri == "/api" || uri.starts_with("/api/") {
        return uri.to_string();
    }
    // Version-only prefix: /v<digits> followed by `/` or end-of-string
    if let Some(rest) = uri.strip_prefix("/v") {
        let digit_count = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        if digit_count > 0 {
            let after_digits = &rest[digit_count..];
            if after_digits.is_empty() || after_digits.starts_with('/') {
                return format!("/api{}", uri);
            }
        }
    }
    // Default: prepend configured api_path
    format!("{}{}", api_path, uri)
}

/// Strip JSONC-style comments from JSON bodies (depth > 0) and return the
/// final bracket depth. Comments outside bodies (in the URI portion) are kept.
/// String-aware: comment markers inside `"..."` are preserved.
///
/// Supports: `// line`, `# line`, `/* block */`.
fn strip_body_comments_and_count(s: &str) -> (String, i32) {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape = false;

    while i < chars.len() {
        let ch = chars[i];

        if in_string {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        // Strip comments only inside JSON bodies (depth > 0)
        if depth > 0 {
            // `// ...` line comment
            if ch == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            // `# ...` line comment
            if ch == '#' {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            // `/* ... */` block comment (lenient: consumes to EOF if unclosed)
            if ch == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                if i + 1 < chars.len() {
                    i += 2; // skip closing */
                } else {
                    i = chars.len();
                }
                continue;
            }
        }

        match ch {
            '"' => {
                in_string = true;
                out.push(ch);
            }
            '{' | '[' => {
                depth += 1;
                out.push(ch);
            }
            '}' | ']' => {
                depth -= 1;
                out.push(ch);
            }
            _ => out.push(ch),
        }
        i += 1;
    }

    (out, depth)
}

/// Special `> outfile` sentinel: when the outfile is the bare token "clipboard"
/// (any casing, surrounding whitespace tolerated) the response body is copied
/// to the system clipboard instead of written to disk.
fn is_clipboard_target(s: &str) -> bool {
    s.trim().eq_ignore_ascii_case("clipboard")
}

/// Append `new_content` to the file at `path` for the `>>` redirect, merging by
/// content rather than blindly concatenating:
///
/// What became of a TUI response body. `Streamed` means it already went to the
/// outfile and the accompanying string is only the retained prefix, so nothing
/// downstream should try to write it again.
enum BodyDelivery {
    Buffered,
    Streamed {
        overflowed: bool,
        error: Option<String>,
        /// Bytes written to the outfile.
        bytes: u64,
    },
}

/// How much of a streamed body is retained for `classify_response`. Every falsy
/// payload (`false`, `null`, `0`, `""`) is a handful of bytes, so a body that
/// overflows this can only be truthy — the prefix decides chains exactly as a
/// fully buffered read would.
const CLASSIFY_PREFIX_BYTES: usize = 4096;

/// Short human-readable size for the `> outfile` marker line: `512 B`,
/// `47.1 KB`, `128 MB`. Units are 1024-based; one decimal below 100, none above.
fn format_byte_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if bytes < 1024 {
        return format!("{} B", bytes);
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    // Rounding can carry a value up to the next unit (1023.97 KB → "1024 KB").
    if value >= 999.5 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value < 99.95 {
        format!("{:.1} {}", value, UNITS[unit])
    } else {
        format!("{:.0} {}", value, UNITS[unit])
    }
}

/// The `> outfile (47.1 KB)` line shown under the status line after a redirect.
/// `bytes` is what this request wrote; an append shows it as a `+` delta.
fn outfile_marker(target: &str, bytes: u64, append: bool) -> String {
    if append {
        format!(">> {} (+{})", target, format_byte_size(bytes))
    } else {
        format!("> {} ({})", target, format_byte_size(bytes))
    }
}

/// Size of `path` on disk, 0 when it doesn't exist yet. Sampled either side of
/// a `>>` append, because merging can splice brackets or drop a CSV header —
/// the growth of the file is the only honest count of what was added.
fn file_len(path: &str) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// `TransferProgress::total` when the response carries no length.
const TOTAL_UNKNOWN: u64 = u64::MAX;

/// How long a request runs before the progress line appears, so a fast one
/// never flickers.
const PROGRESS_DELAY: Duration = Duration::from_millis(500);

/// How often the progress line is redrawn.
const PROGRESS_TICK: Duration = Duration::from_millis(80);

/// Where an in-flight request stands. Written by the thread doing the I/O,
/// read by the one drawing the progress line.
struct TransferProgress {
    /// 0 until the response headers arrive.
    status: AtomicU16,
    received: AtomicU64,
    total: AtomicU64,
}

/// One consistent reading of a `TransferProgress`.
#[derive(Clone, Copy, Debug, PartialEq)]
struct ProgressSnapshot {
    /// `None` while still waiting for the response headers.
    status: Option<u16>,
    received: u64,
    /// `None` when the server sent no length, which is every chunked response.
    total: Option<u64>,
}

impl TransferProgress {
    fn new() -> Arc<Self> {
        Arc::new(TransferProgress {
            status: AtomicU16::new(0),
            received: AtomicU64::new(0),
            total: AtomicU64::new(TOTAL_UNKNOWN),
        })
    }

    fn headers_arrived(&self, resp: &reqwest::blocking::Response) {
        self.total
            .store(resp.content_length().unwrap_or(TOTAL_UNKNOWN), Ordering::Relaxed);
        self.status.store(resp.status().as_u16(), Ordering::Relaxed);
    }

    fn snapshot(&self) -> ProgressSnapshot {
        let status = self.status.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        ProgressSnapshot {
            status: (status != 0).then_some(status),
            received: self.received.load(Ordering::Relaxed),
            total: (total != TOTAL_UNKNOWN).then_some(total),
        }
    }
}

/// The progress line without its spinner: `waiting for response... 4s`, then
/// `200 OK, received 12.4 MB of 47.1 MB (26%)`. `show_status` is off where the
/// status line is already on screen above.
fn progress_text(snapshot: &ProgressSnapshot, elapsed: Duration, show_status: bool) -> String {
    let Some(status) = snapshot.status else {
        return if elapsed.as_secs() == 0 {
            "waiting for response...".to_string()
        } else {
            format!("waiting for response... {}", format_elapsed(elapsed))
        };
    };

    let mut text = String::new();
    if show_status {
        let reason = reqwest::StatusCode::from_u16(status)
            .ok()
            .and_then(|s| s.canonical_reason())
            .unwrap_or("");
        text.push_str(format!("{} {}", status, reason).trim_end());
        text.push_str(", ");
    }
    text.push_str(&format!("received {}", format_byte_size(snapshot.received)));
    if let Some(total) = snapshot.total.filter(|t| *t > 0) {
        let percent = snapshot.received.min(total) as u128 * 100 / total as u128;
        text.push_str(&format!(" of {} ({}%)", format_byte_size(total), percent));
    }
    text
}

/// Counts the bytes read through it into a `TransferProgress`.
struct CountingReader<'a, R> {
    inner: R,
    progress: &'a TransferProgress,
}

impl<'a, R: IoRead> CountingReader<'a, R> {
    fn new(inner: R, progress: &'a TransferProgress) -> Self {
        CountingReader { inner, progress }
    }
}

impl<R: IoRead> IoRead for CountingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.progress.received.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// The `charset` parameter of a `Content-Type` value, if it names one.
fn charset_of(content_type: &str) -> Option<&str> {
    content_type.split(';').skip(1).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches('"'))
    })
}

/// Decode a body as reqwest's `text()` would: the declared charset, UTF-8
/// when there is none, a leading byte-order mark dropped.
fn decode_body(bytes: &[u8], content_type: Option<&str>) -> String {
    let encoding = content_type
        .and_then(charset_of)
        .and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8);
    let (text, _, _) = encoding.decode(bytes);
    text.into_owned()
}

/// Read a whole response body, counting it into `progress` as it arrives.
fn read_body_text(resp: reqwest::blocking::Response, progress: &TransferProgress) -> io::Result<String> {
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut bytes = Vec::new();
    CountingReader::new(resp, progress).read_to_end(&mut bytes)?;
    Ok(decode_body(&bytes, content_type.as_deref()))
}

/// Whether a failed body read was the client's own timeout, which reqwest
/// hands to `Read` wrapped in an `io::Error`.
fn io_error_is_timeout(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::TimedOut
        || e.get_ref()
            .and_then(|inner| inner.downcast_ref::<reqwest::Error>())
            .map(|inner| inner.is_timeout())
            .unwrap_or(false)
}

/// The TLS failure behind a request that got no response, if that is what
/// stopped it. rustls's error sits some levels down, and where an `io::Error`
/// carries it, inside that error rather than behind it.
fn tls_failure<'a>(e: &'a (dyn std::error::Error + 'static)) -> Option<&'a rustls::Error> {
    let mut next = Some(e);
    while let Some(err) = next {
        if let Some(tls) = err.downcast_ref::<rustls::Error>() {
            return Some(tls);
        }
        let carried = err
            .downcast_ref::<io::Error>()
            .and_then(|io| io.get_ref())
            .and_then(|inner| tls_failure(inner));
        if carried.is_some() {
            return carried;
        }
        next = err.source();
    }
    None
}

/// What to say when the server answered the connection but not with a
/// certificate the client accepts, or not with TLS at all. A server that is
/// there must not be reported as one that isn't.
fn describe_tls_failure(e: &rustls::Error, host: &str) -> String {
    use rustls::CertificateError as Cert;
    match e {
        rustls::Error::InvalidCertificate(why) => {
            let why = match why {
                Cert::Expired | Cert::ExpiredContext { .. } => "it has expired".to_string(),
                Cert::NotValidYet | Cert::NotValidYetContext { .. } => "it is not valid yet".to_string(),
                Cert::NotValidForName | Cert::NotValidForNameContext { .. } => {
                    "it is for another host name".to_string()
                }
                Cert::Revoked => "it has been revoked".to_string(),
                // Self-signed, or signed by an authority of one's own. The
                // roots are the public ones compiled into the client, so
                // such a certificate can't be made to pass on this machine.
                _ => "it is not signed by a public certificate authority".to_string(),
            };
            format!("The certificate of {} is not trusted: {}.", host, why)
        }
        other => format!("No secure connection to {}: {}", host, other),
    }
}

/// The host part of a base URL, as the connection messages name it.
fn host_of(base_uri: &str) -> &str {
    base_uri.trim_start_matches("https://").trim_start_matches("http://")
}

/// Why a request produced no response to show.
struct RequestFailure {
    timed_out: bool,
    /// A refused certificate or a failed handshake, described.
    tls: Option<String>,
}

impl RequestFailure {
    fn of(e: reqwest::Error, base_uri: &str) -> Self {
        RequestFailure {
            timed_out: e.is_timeout(),
            tls: tls_failure(&e).map(|tls| describe_tls_failure(tls, host_of(base_uri))),
        }
    }
}

impl From<io::Error> for RequestFailure {
    fn from(e: io::Error) -> Self {
        RequestFailure { timed_out: io_error_is_timeout(&e), tls: None }
    }
}

/// Draws the progress line on stderr from a side thread while the caller
/// blocks on the request. The line erases itself, so nothing of it is left in
/// the scrollback.
struct ProgressTicker {
    shared: Arc<TickerShared>,
    handle: Option<thread::JoinHandle<()>>,
}

struct TickerShared {
    progress: Arc<TransferProgress>,
    started: Instant,
    stopped: AtomicBool,
    /// Whether the line is on screen. Held while stderr is drawn or erased.
    drawn: std::sync::Mutex<bool>,
}

fn erase_progress_line() {
    let mut stderr = io::stderr();
    let _ = execute!(stderr, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine));
}

impl ProgressTicker {
    /// A disabled ticker draws nothing and costs no thread.
    fn start(progress: Arc<TransferProgress>, enabled: bool) -> Self {
        let shared = Arc::new(TickerShared {
            progress,
            started: Instant::now(),
            stopped: AtomicBool::new(false),
            drawn: std::sync::Mutex::new(false),
        });
        let handle = enabled.then(|| {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let mut frame = 0;
                loop {
                    thread::park_timeout(PROGRESS_TICK);
                    if shared.stopped.load(Ordering::Relaxed) {
                        break;
                    }
                    if shared.started.elapsed() < PROGRESS_DELAY {
                        continue;
                    }
                    let mut drawn = shared.drawn.lock().unwrap();
                    if shared.stopped.load(Ordering::Relaxed) {
                        break;
                    }
                    let line = format!(
                        "{} {}",
                        SPINNER_FRAMES[frame % SPINNER_FRAMES.len()],
                        progress_text(&shared.progress.snapshot(), shared.started.elapsed(), false)
                    );
                    let mut stderr = io::stderr();
                    let _ = execute!(
                        stderr,
                        cursor::MoveToColumn(0),
                        Clear(ClearType::CurrentLine),
                        Print(line.dimmed())
                    );
                    *drawn = true;
                    frame += 1;
                }
            })
        });
        ProgressTicker { shared, handle }
    }

    /// Print something of the caller's own with the progress line out of the
    /// way. The next tick draws it again underneath.
    fn interrupt(&self, print: impl FnOnce()) {
        let mut drawn = self.shared.drawn.lock().unwrap();
        if *drawn {
            erase_progress_line();
            *drawn = false;
        }
        print();
    }

    fn stop(&mut self) {
        let Some(handle) = self.handle.take() else { return };
        self.shared.stopped.store(true, Ordering::Relaxed);
        handle.thread().unpark();
        let _ = handle.join();
        let mut drawn = self.shared.drawn.lock().unwrap();
        if *drawn {
            erase_progress_line();
            *drawn = false;
        }
    }
}

impl Drop for ProgressTicker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// What a streamed copy left behind, since the body itself was never held.
struct StreamedBody {
    /// The leading `CLASSIFY_PREFIX_BYTES` of the body.
    prefix: String,
    /// The body was longer than the prefix.
    overflowed: bool,
    /// Last byte written, so stdout can match the buffered path's trailing
    /// newline. `None` for an empty body.
    last_byte: Option<u8>,
    /// Total bytes written to the sink.
    bytes: u64,
}

/// Copy a streaming response into `sink` without holding the whole body, keeping
/// the leading `CLASSIFY_PREFIX_BYTES` so `&&`/`||` chains still see a payload
/// to judge.
fn stream_to_sink(mut resp: impl IoRead, sink: &mut dyn Write) -> io::Result<StreamedBody> {
    let mut prefix: Vec<u8> = Vec::new();
    let mut overflowed = false;
    let mut last_byte = None;
    let mut bytes: u64 = 0;
    let mut buf = [0u8; 32 * 1024];

    loop {
        let n = resp.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if prefix.len() < CLASSIFY_PREFIX_BYTES {
            let take = (CLASSIFY_PREFIX_BYTES - prefix.len()).min(n);
            prefix.extend_from_slice(&buf[..take]);
            overflowed |= take < n;
        } else {
            overflowed = true;
        }
        last_byte = Some(buf[n - 1]);
        bytes += n as u64;
        sink.write_all(&buf[..n])?;
    }
    sink.flush()?;

    Ok(StreamedBody {
        prefix: String::from_utf8_lossy(&prefix).into_owned(),
        overflowed,
        last_byte,
        bytes,
    })
}

/// Chain verdict for a streamed body, from the retained prefix. An overflowing
/// body is truthy by construction — see `CLASSIFY_PREFIX_BYTES`.
fn classify_streamed(status: u16, prefix: &str, overflowed: bool) -> RequestOutcome {
    if overflowed && (200..300).contains(&status) {
        RequestOutcome::Truthy
    } else {
        classify_response(status, prefix)
    }
}

/// Whether `path` names an NDJSON file (`.ndjson` or `.njson`, any case).
fn is_ndjson_path(path: &str) -> bool {
    outfile_format(path) == OutFormat::Ndjson
}

/// `content` as NDJSON, when it is one JSON value: a list becomes one compact
/// line per element (none for an empty list), anything else one compact line.
/// `None` when it is not one JSON value, which is what NDJSON of several
/// lines is: that is left as it came.
fn ndjson_lines(content: &str) -> Option<String> {
    let line = |v: &Value| serde_json::to_string(v).ok();
    let lines: Vec<String> = match serde_json::from_str::<Value>(content.trim()).ok()? {
        Value::Array(items) => items.iter().map(line).collect::<Option<_>>()?,
        single => vec![line(&single)?],
    };
    Some(lines.iter().map(|l| format!("{}\n", l)).collect())
}

/// Write `content` to the outfile at `path`, replacing what is there, and
/// return the bytes written. An NDJSON target gets NDJSON: a response that is
/// one JSON value (a single record, or a list from a server that was not
/// asked for NDJSON) is never written indented or as a list there, so the
/// file reads the same after `>` as after any number of `>>`.
fn write_outfile(path: &str, content: &str) -> io::Result<u64> {
    let lines = if is_ndjson_path(path) { ndjson_lines(content) } else { None };
    let content = lines.as_deref().unwrap_or(content);
    fs::write(path, content).map(|()| content.len() as u64)
}

/// - target missing or empty → plain write, identical to `>`
/// - `.ndjson`/`.njson` target → a JSON-array payload is exploded to one compact
///   object per line, a single JSON value becomes one compact line, and
///   anything else (already-NDJSON) is text-appended; the first write too
/// - `.csv` target → the payload's first line (its header row) is dropped,
///   since the target already carries one
/// - both sides parse as JSON → one array, merged as a textual splice: arrays
///   concatenate, single values are wrapped/pushed, so `"a"` then `"b"` yields
///   `["a","b"]`. Only array punctuation is added — neither side is
///   re-serialized, so existing bytes keep their exact formatting
/// - anything else → text append, with a separating newline when the target
///   doesn't end in one
///
/// No path ever rewrites existing content bytes. An unparseable target is
/// always text-appended — appending must never destroy what's already there.
fn append_to_outfile(path: &str, new_content: &str) -> io::Result<()> {
    let existing = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    if existing.trim().is_empty() {
        // The first append is a plain write, in the shape the target takes.
        return write_outfile(path, new_content).map(|_| ());
    }

    // Text append: keep existing bytes untouched, separate with one newline.
    let text_append = |existing: &str, addition: &str| -> String {
        let mut out = String::with_capacity(existing.len() + addition.len() + 1);
        out.push_str(existing);
        if !existing.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(addition);
        out
    };

    let path_lower = path.to_lowercase();
    let merged = if is_ndjson_path(path) {
        // NDJSON: keep the one-value-per-line shape whatever shape the payload
        // arrived in.
        match ndjson_lines(new_content) {
            // An empty list has no line to add.
            Some(lines) if lines.is_empty() => return Ok(()),
            Some(lines) => text_append(&existing, &lines),
            None => text_append(&existing, new_content),
        }
    } else if path_lower.ends_with(".csv") {
        // CSV: the target already has a header row — drop the payload's.
        let body = match new_content.split_once('\n') {
            Some((_header, rest)) => rest,
            // Header-only payload (empty result set): nothing to add.
            None => return Ok(()),
        };
        if body.trim().is_empty() {
            return Ok(());
        }
        text_append(&existing, body)
    } else {
        match (
            serde_json::from_str::<Value>(existing.trim()),
            serde_json::from_str::<Value>(new_content.trim()),
        ) {
            // Both sides JSON → the file becomes/stays one array: array+array
            // concatenates, array+value pushes, value+value wraps both, and
            // value+array wraps the existing value then appends the rest. The
            // second append to a `>>` target is what turns a bare first
            // response into an array.
            //
            // Merged as a TEXTUAL SPLICE: the parsed values only classify the
            // shapes; the file is assembled from the original bytes with array
            // punctuation added. Nothing is re-serialized, so existing content
            // keeps its exact formatting (`1e2` stays `1e2`, not `100.0`).
            (Ok(existing_v), Ok(new_v)) => {
                let strip_brackets = |s: &str, is_array: bool| -> String {
                    if is_array {
                        s.trim()[1..s.trim().len() - 1].trim().to_string()
                    } else {
                        s.trim().to_string()
                    }
                };
                let e_interior = strip_brackets(&existing, existing_v.is_array());
                let n_interior = strip_brackets(new_content, new_v.is_array());
                // Appending an empty array adds nothing — leave the file alone.
                if n_interior.is_empty() {
                    return Ok(());
                }
                if e_interior.is_empty() {
                    format!("[{}]", n_interior)
                } else {
                    format!("[{},{}]", e_interior, n_interior)
                }
            }
            _ => text_append(&existing, new_content),
        }
    };

    fs::write(path, merged)
}

/// `MatchOptions` for glob expansion: behave like a shell — `*` does NOT match
/// path segments beginning with `.`, so `mapped-types/*` skips `.DS_Store` etc.
fn glob_match_options() -> glob::MatchOptions {
    glob::MatchOptions {
        require_literal_leading_dot: true,
        ..Default::default()
    }
}

/// OS-junk basenames that don't start with `.` and so wouldn't be caught by the
/// leading-dot rule. Matched case-insensitively.
fn is_os_junk(path: &std::path::Path) -> bool {
    const JUNK: &[&str] = &[
        "thumbs.db",
        "thumbs.db:encryptable",
        "desktop.ini",
        "$recycle.bin",
    ];
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => {
            let lower = name.to_ascii_lowercase();
            JUNK.iter().any(|j| *j == lower.as_str())
        }
        None => false,
    }
}

/// One executable step in a parsed `.api` bulk program, in file order.
#[derive(Debug, Clone, PartialEq)]
enum BulkStep {
    Request(String),
    /// Two or more requests joined by `&&` / `||`; whether each runs depends on
    /// its operator and the previous executed segment's outcome (see
    /// `chain_segment_should_run`). Split at parse time so `-p` preview and the
    /// URL gate see every segment.
    Chain(Vec<(ChainOp, String)>),
    Sleep(Duration),
    /// `sleep [N] while [not] <request>` — poll `request` every `interval`
    /// until its outcome is falsy (or truthy, when `negate`), then continue.
    /// Truthiness is `classify_response`, the same rule `&&` chains use.
    SleepWhile {
        interval: Duration,
        negate: bool,
        request: String,
    },
    /// `assert [not] <request>` — run `request` once and abort the batch unless
    /// its outcome is truthy (falsy, when `negate`). Same truthiness as chains.
    Assert { negate: bool, request: String },
    /// `confirm [message]` — pause and ask the user for confirmation before
    /// continuing. If a message is provided, it's used as the prompt; otherwise
    /// the default "Continue?" is used.
    Confirm(Option<String>),
    /// Export mode from here on: under `name`, or off. `written` is an
    /// `export <name>` / `export off` line of a file and is shown in the
    /// preview and the log. The rest are the parser's own, put around an
    /// included file so that a file's export mode stays that file's: off on
    /// the way in, back to what it was on the way out.
    Export { name: Option<String>, written: bool },
}

/// Outcome of a single request, deciding whether a `&&` chain continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestOutcome {
    /// 2xx with a truthy body — a following `&&` segment runs.
    Truthy,
    /// A definite negative answer: falsy body, or a "not there" status. The chain
    /// stops, but nothing went wrong.
    Falsy,
    /// The request couldn't answer at all — auth, server fault, timeout, transport.
    Errored,
    /// ctrl+c / esc while the request was in flight.
    Aborted,
}

/// Statuses that mean the question wasn't answered, rather than answered "no".
/// These must not read as a quiet falsy, or a chain would silently skip its write
/// when the real problem is expired credentials or a broken server.
fn status_is_error(status: u16) -> bool {
    matches!(status, 401 | 403 | 408 | 429) || status >= 500
}

// ---------------------------------------------------------------------------
// `--export <external-id>`: responses as seed data
// ---------------------------------------------------------------------------

/// What the API prints in place of a value the caller may not read.
const MASKED_VALUES: [&str; 2] = ["********", "*******"];

/// Whether `name` is a namespaced key, the form the API wants an external
/// identifier's name in: exactly three dot-separated segments and at most 128
/// characters (`com.heads.seedID`). The segments are word characters; the
/// second may also hold `-`, and the third `-` and `$`. The same rule as the
/// server's `isNamespacedKey` (`^\w+\.[\w-]+\.[\w$-]+$`), so a name accepted
/// here is one a write accepts.
fn is_namespaced_key(name: &str) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let segments: Vec<&str> = name.split('.').collect();
    name.len() <= 128
        && segments.len() == 3
        && segments.iter().all(|segment| !segment.is_empty())
        && segments[0].chars().all(word)
        && segments[1].chars().all(|c| word(c) || c == '-')
        && segments[2].chars().all(|c| word(c) || c == '-' || c == '$')
}

/// What to say about a name that is not a namespaced key.
const NAMESPACED_KEY_HELP: &str = "a namespaced key has three dot-separated segments, such as com.heads.seedID";

/// Rewrite a response value in place so that it can be sent to another
/// environment as seed data.
///
/// A database key (`identifiers.key`) names an object in the environment it
/// was read from and nowhere else, and a write that names an object by a key
/// no object has is refused. So no `key` is left in the export.
///
/// - A record that has another identifier is found by that one, where it was
///   read and anywhere else. Its key is dropped.
/// - A record that has none would be created anew by every write. It gets
///   its key as the value of the external identifier `id_key`, which finds
///   it from the second write on, and as `key?`, the optional key. The API
///   takes `key?` to name the object where one has that key, and reads the
///   identifiers as if it were not written where none has. So the first
///   write back where the record was read finds it too, and gives it the name.
///
/// `key?` is written where the name is made from the key and nowhere else,
/// which is the rule of the platform's own export mode.
///
/// Beyond that: a masked value becomes `null` (where it was is added to
/// `masked`, so the caller can say what was lost), and `identifiers` is
/// moved to the front of its object, behind `@type`, where a reader looks for
/// it. Members otherwise keep the order the server gave them.
///
/// Children are rewritten before the object that holds them, so a masked
/// `key` is `null` by the time its record is looked at and is left alone.
/// `key` and `key?` are never both left in one object: the API refuses that.
fn export_value(value: &mut Value, id_key: &str, path: &mut String, masked: &mut Vec<String>) {
    match value {
        Value::String(text) if MASKED_VALUES.contains(&text.as_str()) => {
            let at = if path.is_empty() { "(root)" } else { path.as_str() };
            if !masked.iter().any(|seen| seen == at) {
                masked.push(at.to_string());
            }
            *value = Value::Null;
        }
        // An item is at its list's path: `clients/secret` names the secret of
        // every client, once, however many there are.
        Value::Array(items) => {
            for item in items {
                export_value(item, id_key, path, masked);
            }
        }
        Value::Object(object) => {
            let parent = path.len();
            for (name, member) in object.iter_mut() {
                if parent > 0 {
                    path.push('/');
                }
                path.push_str(name);
                export_value(member, id_key, path, masked);
                path.truncate(parent);
            }
            export_identifiers(object, id_key);
            put_identifiers_first(object);
        }
        _ => {}
    }
}

/// Take `identifiers.key` out of `object`. A record that has no other
/// identifier gets the key back as `key?` and as `id_key`, in the key's
/// place, `key?` first. One that has another identifier gets neither.
///
/// An identifier that is `null` is not one the record has: with `-i` the
/// server lists every identifier a record could have (`"clientID": null`),
/// and a masked one has just been nulled. Neither can find the record, so
/// neither stands in for the key. The member itself is left where it is.
fn export_identifiers(object: &mut Map<String, Value>, id_key: &str) {
    let Some(Value::Object(identifiers)) = object.get_mut("identifiers") else {
        return;
    };
    let has_key = identifiers.get("key").is_some_and(|key| !key.is_null() && *key != Value::Bool(false));
    if !has_key {
        return;
    }
    let only_key = identifiers
        .iter()
        .all(|(name, value)| matches!(name.as_str(), "@type" | "key" | "key?") || value.is_null());
    for (name, value) in std::mem::take(identifiers) {
        match name.as_str() {
            "key" => {
                if only_key {
                    identifiers.insert("key?".to_string(), value.clone());
                    identifiers.insert(id_key.to_string(), value);
                }
            }
            // An answer never carries one. If it did, the key read beside it
            // is the one to go by, and the two may not stand together.
            "key?" => {}
            _ => {
                identifiers.insert(name, value);
            }
        }
    }
}

/// Move `identifiers` to the front of `object`, right behind `@type` when
/// there is one. An object without `identifiers` is left as it is.
fn put_identifiers_first(object: &mut Map<String, Value>) {
    if !object.contains_key("identifiers") {
        return;
    }
    let (mut leading, mut rest) = (Vec::new(), Vec::new());
    for (name, value) in std::mem::take(object) {
        match name.as_str() {
            "@type" => leading.insert(0, (name, value)),
            "identifiers" => leading.push((name, value)),
            _ => rest.push((name, value)),
        }
    }
    object.extend(leading.into_iter().chain(rest));
}

/// A response body after `--export`.
#[derive(Debug, PartialEq)]
struct ExportedBody {
    text: String,
    /// Where the masked values that became `null` were: paths from the top
    /// of the response, without positions in lists, each once, in the order
    /// they were first met.
    masked: Vec<String>,
    /// Whether the body was JSON (or NDJSON). One that is not is unchanged.
    is_json: bool,
}

/// Apply `--export` to a response body.
///
/// A JSON body is rewritten whole and printed indented, or on one line when
/// `compact`. An NDJSON body is rewritten line by line, one compact value per
/// line. `ndjson` says which of the two to try first, for the body of one
/// line that is both. Anything else (CSV, SQL, text) is returned unchanged
/// and reported through `is_json`.
fn export_body(text: &str, id_key: &str, ndjson: bool, compact: bool) -> ExportedBody {
    let whole = || -> Option<(String, Vec<String>)> {
        let mut value: Value = serde_json::from_str(text).ok()?;
        let mut masked = Vec::new();
        export_value(&mut value, id_key, &mut String::new(), &mut masked);
        let out = if compact { serde_json::to_string(&value) } else { serde_json::to_string_pretty(&value) };
        Some((out.ok()?, masked))
    };
    let by_line = || -> Option<(String, Vec<String>)> {
        let mut masked = Vec::new();
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            if !line.trim().is_empty() {
                let mut value: Value = serde_json::from_str(line).ok()?;
                export_value(&mut value, id_key, &mut String::new(), &mut masked);
                out.push_str(&serde_json::to_string(&value).ok()?);
            }
            out.push('\n');
        }
        if !text.ends_with('\n') {
            out.pop();
        }
        Some((out, masked))
    };
    if text.trim().is_empty() {
        return ExportedBody { text: text.to_string(), masked: Vec::new(), is_json: true };
    }
    let exported = if ndjson { by_line().or_else(whole) } else { whole().or_else(by_line) };
    match exported {
        Some((text, masked)) => ExportedBody { text, masked, is_json: true },
        None => ExportedBody { text: text.to_string(), masked: Vec::new(), is_json: false },
    }
}

/// What the user has to be told about an exported body, if anything: values
/// that were masked are gone from the seed data, and a body that is not JSON
/// was not exported at all.
fn export_warning(exported: &ExportedBody) -> Option<String> {
    if !exported.is_json {
        Some("WARNING: --export left a response that is not JSON unchanged".to_string())
    } else if exported.masked.is_empty() {
        None
    } else {
        // Two places are named; the rest are counted, so the line stays one
        // line however much of a response was masked.
        let named = exported.masked.iter().take(2).map(String::as_str).collect::<Vec<_>>().join(", ");
        let more = match exported.masked.len().saturating_sub(2) {
            0 => String::new(),
            1 => " and 1 other place".to_string(),
            n => format!(" and {} other places", n),
        };
        Some(format!("Response had masked data, now null at {}{}", named, more))
    }
}

/// Whether a response with `status` ends the run under `-f`.
///
/// Any status of 400 or above does, with two kinds of request left alone. A
/// request asked as a question (a chain segment with another after it,
/// `assert not`) may be answered "no", so its 404 or 409 is an answer and the
/// run goes on; 401/403/408/429/5xx are never an answer and still end it. A
/// poll and an `assert` report their own failure, with the reason, and are
/// not `-f`'s to cut short; when one ends the run on a status that is never
/// an answer, `exit_on_unjudged_check` prints the body for `-f`.
fn fail_fast_trips(config: &Config, status: u16) -> bool {
    config.fail_fast
        && status >= 400
        && !config.quiet
        && !config.check_only
        && (!config.expect_falsy || status_is_error(status))
}

/// End a `-f` run on the response that tripped it: the body goes to stdout
/// exactly as the server sent it, the last thing there, so whatever is
/// driving the client can read why (the 409 of a failed `/assert`, say).
/// This holds in `-sa` mode too, where bodies are otherwise not printed. The
/// status line is already out.
fn fail_fast_exit(body: &str) -> ! {
    let mut out = Out;
    let _ = out.write_all(body.as_bytes());
    if !body.is_empty() && !body.ends_with('\n') {
        let _ = out.write_all(b"\n");
    }
    let _ = out.flush();
    exit_process(1);
}

/// An `assert` or a poll got a response it could not judge (401/403/408/429/
/// 5xx) and is ending the run. It has said so itself on stderr; under `-f`
/// the body follows on stdout, last, as for any response that ends a run.
/// Without `-f`, or when there was no response (a timeout), it exits 1 as is.
fn exit_on_unjudged_check(config: &mut Config) -> ! {
    match config.last_response.take() {
        Some((_, body)) if config.fail_fast => fail_fast_exit(&body),
        _ => exit_process(1),
    }
}

/// How a status line should read at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusTone {
    /// 2xx — green.
    Ok,
    /// A "no" that the line asking was prepared for — orange. The 404 that
    /// lets `assert not GET /x` pass, or that sends `GET /x || PUT /x` on to
    /// its second half.
    Expected,
    /// Everything else — red.
    Bad,
}

/// The tone for `status`. Only a definite "no" can be expected: an error
/// status (401/403/408/429/5xx) means the question went unanswered, which no
/// line is ever prepared for, so it stays red whatever was expected.
fn status_tone(status: u16, expect_falsy: bool) -> StatusTone {
    if (200..300).contains(&status) {
        StatusTone::Ok
    } else if expect_falsy && !status_is_error(status) {
        StatusTone::Expected
    } else {
        StatusTone::Bad
    }
}

/// 256-colour orange. Not `truecolor()`: without `COLORTERM` the crate
/// degrades that to plain yellow, and Terminal.app never sets it.
const ORANGE_FG: &str = "\x1b[38;5;208m";

/// `404 Not Found`, coloured by tone. Shared by the batch and interactive
/// senders so the two can't drift apart.
fn format_status(status: reqwest::StatusCode, expect_falsy: bool) -> String {
    let text = format!("{} {}", status.as_u16(), status.canonical_reason().unwrap_or(""));
    match status_tone(status.as_u16(), expect_falsy) {
        StatusTone::Ok => text.green().to_string(),
        // Honours NO_COLOR, CLICOLOR_FORCE and piped output like the crate's
        // own colours do.
        StatusTone::Expected if colored::control::SHOULD_COLORIZE.should_colorize() => {
            format!("{}{}\x1b[0m", ORANGE_FG, text)
        }
        StatusTone::Expected => text,
        StatusTone::Bad => text.red().to_string(),
    }
}

/// Classify a completed response the way JavaScript coerces a value, so
/// `~count` chains read naturally: `false`, `0`, `""`, and `null` are falsy;
/// `[]`, `{}`, and everything else are truthy.
///
/// Status is checked first — only a 2xx can be truthy. A 404 (and other non-auth
/// 4xx) is a definite "no" that merely stops the chain, while auth failures, 5xx,
/// and timeouts are errors.
/// `API_STREAMING` asks for streaming globally, the way `--stream` does per-run.
/// Anything other than the listed truthy words is off, so a stray value never
/// silently changes how responses are written.
fn env_streaming_requested() -> bool {
    std::env::var("API_STREAMING")
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn classify_response(status: u16, body: &str) -> RequestOutcome {
    if !(200..300).contains(&status) {
        return if status_is_error(status) {
            RequestOutcome::Errored
        } else {
            RequestOutcome::Falsy
        };
    }

    // An empty body carries no value to test, so the 2xx status is the answer —
    // e.g. a 204 from a successful DELETE continues the chain.
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return RequestOutcome::Truthy;
    }

    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::Bool(false)) | Ok(Value::Null) => RequestOutcome::Falsy,
        Ok(Value::Number(n)) if n.as_f64() == Some(0.0) => RequestOutcome::Falsy,
        Ok(Value::String(s)) if s.is_empty() => RequestOutcome::Falsy,
        // Arrays and objects are truthy in JS however empty they are, as is any
        // non-JSON payload (CSV, NDJSON) that reached a 2xx.
        _ => RequestOutcome::Truthy,
    }
}

/// The separator that introduced a chain segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainOp {
    /// `&&` — run when the previous executed segment was truthy. Also the
    /// (never consulted) op of a chain's first segment.
    And,
    /// `||` — run when the previous executed segment was falsy.
    Or,
}

impl ChainOp {
    fn as_str(self) -> &'static str {
        match self {
            ChainOp::And => "&&",
            ChainOp::Or => "||",
        }
    }
}

/// Whether a chain segment runs, given the outcome of the last EXECUTED segment
/// (`None` until one has run — the first segment always runs). Skipped segments
/// don't update that outcome, which is what makes shell-style if-then-else work:
/// in `a && b || c`, a falsy `a` skips `b` and `a`'s own falsiness then runs `c`.
/// Errored and Aborted stop the whole chain before this is ever consulted —
/// everything that throws in `&&` throws in `||` too.
fn chain_segment_should_run(prev: Option<RequestOutcome>, op: ChainOp) -> bool {
    match prev {
        None => true,
        Some(RequestOutcome::Truthy) => op == ChainOp::And,
        Some(RequestOutcome::Falsy) => op == ChainOp::Or,
        Some(RequestOutcome::Errored) | Some(RequestOutcome::Aborted) => false,
    }
}

/// Split a request line on top-level `&&` / `||`, ignoring separators inside
/// JSON strings or brackets so a body like `{"expr": "a && b"}` stays a single
/// request. Each segment carries the operator that introduced it (the first
/// segment's op is `And`, but it's never consulted).
///
/// Always returns at least one segment for non-blank input, so callers can treat
/// every line as a chain. Empty segments (from a stray or trailing separator)
/// are dropped; the following segment keeps its own operator.
fn split_request_chain(input: &str) -> Vec<(ChainOp, String)> {
    let mut segments: Vec<(ChainOp, String)> = Vec::new();
    let mut current = String::new();
    // Operator that introduced the segment being accumulated.
    let mut op = ChainOp::And;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if escape {
            escape = false;
            current.push(ch);
            continue;
        }
        if ch == '\\' && in_string {
            escape = true;
            current.push(ch);
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            current.push(ch);
            continue;
        }
        if !in_string {
            match ch {
                // Parentheses count too: `~where(a=1||b=2)` is one request.
                '{' | '[' | '(' => depth += 1,
                '}' | ']' | ')' => depth -= 1,
                // Only a top-level doubled `&&` / `||` separates requests.
                c @ ('&' | '|') if depth <= 0 && chars.peek() == Some(&c) => {
                    chars.next();
                    segments.push((op, current.trim().to_string()));
                    current.clear();
                    op = if c == '&' { ChainOp::And } else { ChainOp::Or };
                    continue;
                }
                _ => {}
            }
        }
        current.push(ch);
    }
    segments.push((op, current.trim().to_string()));
    segments.retain(|(_, s)| !s.is_empty());
    segments
}

/// A URL gate condition collected from `url has` / `url is` lines anywhere in the
/// file (and its includes). Validated once, before any request runs.
#[derive(Debug, Clone, PartialEq)]
enum UrlCondition {
    /// `url has X` — substring match (`*X*`).
    Has(String),
    /// `url is X` — literal equality.
    Is(String),
}

impl UrlCondition {
    fn matches(&self, url: &str) -> bool {
        match self {
            UrlCondition::Has(s) => url.contains(s.as_str()),
            UrlCondition::Is(s) => url == s,
        }
    }
    /// The original directive text, for error messages.
    fn directive(&self) -> String {
        match self {
            UrlCondition::Has(s) => format!("url has {}", s),
            UrlCondition::Is(s) => format!("url is {}", s),
        }
    }
}

/// A parsed bulk program: ordered steps plus all URL gate conditions.
#[derive(Debug, Default)]
struct BulkProgram {
    steps: Vec<BulkStep>,
    url_conditions: Vec<UrlCondition>,
    /// `url` lines found in imported repositories, one gate per repository.
    import_gates: Vec<ImportGate>,
    /// The imports the program made, in the order they were declared.
    import_notes: Vec<ImportNote>,
    /// The describe block of the file itself. One in an included or imported
    /// file is checked and left where it is: it describes that file.
    describe: Option<serde_json::Map<String, serde_json::Value>>,
    /// What the describe blocks read hold that a describe block should not,
    /// one line each. A warning: the batch runs all the same.
    describe_warnings: Vec<String>,
}

impl BulkProgram {
    /// The text was a describe block and nothing else, so running it would
    /// send nothing.
    fn only_describes(&self) -> bool {
        self.describe.is_some() && self.steps.is_empty() && self.url_conditions.is_empty()
    }

    /// The gate collecting the `url` lines of `repo`.
    fn import_gate(&mut self, repo: &ImportedRepo) -> &mut Vec<UrlCondition> {
        let at = match self.import_gates.iter().position(|g| g.checkout == repo.checkout) {
            Some(at) => at,
            None => {
                self.import_gates.push(ImportGate {
                    alias: repo.alias.clone(),
                    checkout: repo.checkout.clone(),
                    conditions: Vec::new(),
                });
                self.import_gates.len() - 1
            }
        };
        &mut self.import_gates[at].conditions
    }
}

/// Parse a `sleep <value>` directive into a Duration. Accepts a bare number
/// (seconds), or a `ms`/`s` suffix (`500ms`, `2s`, `0.5s`). Fractional seconds
/// allowed. Returns an error string for missing/invalid/negative values.
fn parse_sleep_directive(rest: &str) -> Result<Duration, String> {
    let v = rest.trim();
    if v.is_empty() {
        return Err("sleep requires a duration (e.g. `sleep 5`, `sleep 500ms`)".to_string());
    }
    let (num_str, is_ms) = if let Some(n) = v.strip_suffix("ms") {
        (n.trim(), true)
    } else if let Some(n) = v.strip_suffix('s') {
        (n.trim(), false)
    } else {
        (v, false)
    };
    let num: f64 = num_str
        .parse()
        .map_err(|_| format!("invalid sleep duration: `{}`", v))?;
    if !num.is_finite() || num < 0.0 {
        return Err(format!("invalid sleep duration: `{}`", v));
    }
    let secs = if is_ms { num / 1000.0 } else { num };
    // A number of seconds no `Duration` can hold (`1e20`) is not a duration.
    Duration::try_from_secs_f64(secs).map_err(|_| format!("invalid sleep duration: `{}`", v))
}

/// Poll interval when `sleep while` names none.
const DEFAULT_SLEEP_WHILE_INTERVAL: Duration = Duration::from_secs(5);

/// Parse what follows the `sleep` keyword into a step:
///
/// - `sleep N`                      → `BulkStep::Sleep`
/// - `sleep [N] while <request>`     → poll while the response is truthy
/// - `sleep [N] while not <request>` → poll while the response is falsy
///
/// `N` takes the same forms as plain `sleep` and defaults to 5s. The request is
/// anything a bulk line accepts (implied GET included) but must fit on one line
/// and can't be a `&&`/`||` chain or write to an outfile — a poll has no output.
fn parse_sleep_step(rest: &str) -> Result<BulkStep, String> {
    let rest = rest.trim();
    let mut words = rest.split_whitespace();
    let first = words.next().unwrap_or("");
    let second = words.next().unwrap_or("");

    let (interval, condition) = if first.eq_ignore_ascii_case("while") {
        (DEFAULT_SLEEP_WHILE_INTERVAL, rest[first.len()..].trim())
    } else if second.eq_ignore_ascii_case("while") {
        let after_first = rest[first.len()..].trim_start();
        (parse_sleep_directive(first)?, after_first[second.len()..].trim())
    } else {
        return Ok(BulkStep::Sleep(parse_sleep_directive(rest)?));
    };

    let (negate, request) = parse_condition(
        condition,
        "sleep while",
        "usage: `sleep [interval] while [not] <request>`",
    )?;
    Ok(BulkStep::SleepWhile { interval, negate, request })
}

/// Parse `assert [not] <request>`: run the request once and stop the batch
/// unless it's truthy (falsy, with `not`). Shares its condition grammar with
/// `sleep while`.
fn parse_assert_step(rest: &str) -> Result<BulkStep, String> {
    let (negate, request) =
        parse_condition(rest, "assert", "usage: `assert [not] <request>`")?;
    Ok(BulkStep::Assert { negate, request })
}

/// Parse `confirm [message]`: ask the user for confirmation before continuing.
/// If a message is provided, it's used as the prompt (with a `? [Y/n]` suffix if
/// it doesn't already end with `?`); otherwise the default "Continue?" is used.
fn parse_confirm_step(rest: &str) -> Result<BulkStep, String> {
    let msg = rest.trim();
    let message = if msg.is_empty() {
        None
    } else {
        Some(msg.to_string())
    };
    Ok(BulkStep::Confirm(message))
}

/// The `[not] <request>` tail shared by `sleep while` and `assert`. The request
/// must be a single-line request (implied GET allowed, inline body allowed),
/// not a `&&`/`||` chain and not writing to an outfile — its response is only
/// ever judged, never shown. `what` names the directive in error messages.
fn parse_condition(condition: &str, what: &str, usage: &str) -> Result<(bool, String), String> {
    let condition = condition.trim();
    let (negate, request) = match condition.split_once(char::is_whitespace) {
        Some((w, tail)) if w.eq_ignore_ascii_case("not") => (true, tail.trim()),
        None if condition.eq_ignore_ascii_case("not") => (true, ""),
        _ => (false, condition),
    };

    if request.is_empty() {
        return Err(format!("{} requires a request — {}", what, usage));
    }
    let (_, depth) = strip_body_comments_and_count(request);
    if depth != 0 {
        return Err(format!("{} condition must fit on one line: `{}`", what, request));
    }
    if split_request_chain(request).len() > 1 {
        return Err(format!("{} condition can't be a `&&`/`||` chain: `{}`", what, request));
    }
    let (_, uri, _) = parse_request_line(request)
        .ok_or_else(|| format!("{} condition is not a request: `{}` — {}", what, request, usage))?;
    if outfile_marker_at(&uri).is_some() {
        return Err(format!(
            "{} condition can't write to a file (its output is discarded): `{}`",
            what, request
        ));
    }
    Ok((negate, request.to_string()))
}

/// Parse what follows `export`: the name of an external identifier, which
/// turns export mode on for the rest of the file, or `off`.
fn parse_export_step(rest: &str) -> Result<BulkStep, String> {
    let mut words = rest.split_whitespace();
    let name = match (words.next(), words.next()) {
        (Some(word), None) if word.eq_ignore_ascii_case("off") => None,
        (Some(word), None) if is_namespaced_key(word) => Some(word.to_string()),
        (None, _) => {
            return Err("export needs a name: `export com.heads.seedID`, or `export off`".to_string());
        }
        _ => return Err(format!("invalid export identifier: {} ({})", rest, NAMESPACED_KEY_HELP)),
    };
    Ok(BulkStep::Export { name, written: true })
}

/// The `export com.heads.seedID` line as shown in previews and the logs.
fn format_export(name: &Option<String>) -> String {
    format!("export {}", name.as_deref().unwrap_or("off"))
}

/// Apply an `export` step: the mode it sets holds until the next one. With
/// `--export` (or ctrl+r at the prompt) the run has a mode of its own, and
/// the step changes nothing. Returns whether it applied.
fn apply_export_step(config: &mut Config, name: &Option<String>) -> bool {
    if config.export_pinned {
        return false;
    }
    config.export_id = name.clone();
    true
}

/// The `assert not GET /x` line as shown in previews and the `-sa` log.
fn format_assert(negate: bool, request: &str) -> String {
    let shown = parse_request_line(request)
        .map(|(m, u, b)| format_request_preview(&m, &u, &b))
        .unwrap_or_else(|| request.to_string());
    format!("assert {}{}", if negate { "not " } else { "" }, shown)
}

/// Why an assertion failed, for the error line: the status when it wasn't a
/// 2xx (`404 Not Found`), otherwise the falsy body itself (`0`, `null`),
/// compacted and cut short so a large payload can't flood the terminal.
fn describe_check_response(status: u16, body: &str) -> String {
    if !(200..300).contains(&status) {
        let reason = reqwest::StatusCode::from_u16(status)
            .ok()
            .and_then(|c| c.canonical_reason())
            .unwrap_or("");
        return format!("{} {}", status, reason).trim().to_string();
    }
    let compact = compact_body_for_display(body);
    let compact = compact.trim();
    if compact.is_empty() {
        return "empty response".to_string();
    }
    const MAX: usize = 80;
    if compact.chars().count() > MAX {
        let cut: String = compact.chars().take(MAX).collect();
        format!("{}…", cut)
    } else {
        compact.to_string()
    }
}

/// The `sleep 20s while not GET /x` line as shown in previews and the `-sa` log.
fn format_sleep_while(interval: Duration, negate: bool, request: &str) -> String {
    let shown = parse_request_line(request)
        .map(|(m, u, b)| format_request_preview(&m, &u, &b))
        .unwrap_or_else(|| request.to_string());
    format!(
        "sleep {} while {}{}",
        format_duration(interval),
        if negate { "not " } else { "" },
        shown
    )
}

/// The `confirm [message]` line as shown in previews and the `-sa` log.
fn format_confirm(message: &Option<String>) -> String {
    match message {
        Some(msg) => format!("confirm {}", msg),
        None => "confirm".to_string(),
    }
}

/// Human-friendly elapsed time for a wait in progress and the `sleep while`
/// summary: `800ms`, `12s`, `1m40s`, `1h2m3s`.
fn format_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    if secs == 0 {
        format!("{}ms", d.as_millis())
    } else if secs < 60 {
        format!("{}s", secs)
    } else {
        format_minutes(secs)
    }
}

/// `XmYs`, or `XhYmZs` from an hour up. Shared by the live progress line and
/// the finished status line so a request reads the same while it runs and once
/// it is done.
fn format_minutes(secs: u64) -> String {
    if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m{}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

/// How long a finished request took, next to its status: `0.02s`, `45.38s`,
/// then `2m33s` from a minute up, in the same shape as the progress line that
/// was counting while it ran. Hundredths matter for a quick request and are
/// noise for a slow one.
fn format_latency(d: Duration) -> String {
    // Round to hundredths first so 59.999s reads `1m0s`, not `60.00s`.
    let hundredths = (d.as_secs_f64() * 100.0).round() as u64;
    if hundredths < 60 * 100 {
        format!("{}.{:02}s", hundredths / 100, hundredths % 100)
    } else {
        format_minutes(hundredths / 100)
    }
}

/// If `line` (already trimmed, known not to be a request) is a `url has`/`url is`
/// gate directive, parse it. Returns `Ok(Some(cond))` for a url directive,
/// `Ok(None)` if it isn't one (so the caller falls through to include handling),
/// or `Err` for a malformed `url` directive.
fn parse_url_condition(trimmed: &str) -> Result<Option<UrlCondition>, String> {
    // Words may be separated by any run of blanks, and the keywords are read
    // in any case, as every other directive's are.
    let (keyword, rest) = split_first_word(trimmed);
    if !keyword.eq_ignore_ascii_case("url") {
        return Ok(None);
    }
    let (op, value) = split_first_word(rest);
    let op = op.to_ascii_lowercase();
    let op = op.as_str();
    match op {
        "has" | "is" if !value.is_empty() => Ok(Some(if op == "has" {
            UrlCondition::Has(value.to_string())
        } else {
            UrlCondition::Is(value.to_string())
        })),
        "has" | "is" => Err(format!("`url {}` requires a value", op)),
        _ => Err(format!(
            "invalid url directive: `{}` (expected `url has <value>` or `url is <value>`)",
            trimmed
        )),
    }
}

/// Evaluate collected URL conditions against `url` (an OR allowlist): passes when
/// there are no conditions, or at least one matches. Returns an error string
/// describing the gate when none match.
fn evaluate_url_gate(conditions: &[UrlCondition], url: &str) -> Result<(), String> {
    if conditions.is_empty() || conditions.iter().any(|c| c.matches(url)) {
        return Ok(());
    }
    let mut msg = format!(
        "URL gate failed — {} matches none of the allowed conditions:",
        if url.is_empty() { "(no base URL)" } else { url }
    );
    for c in conditions {
        msg.push_str(&format!("\n  {}", c.directive()));
    }
    Err(msg)
}

// ---------------------------------------------------------------------------
// `import git <alias> {…}`: .api files from a git repository
// ---------------------------------------------------------------------------

/// A repository an `import` made available, as the file that declared it
/// sees it.
#[derive(Debug, Clone, PartialEq)]
struct ImportedRepo {
    /// The directory the alias stands for: the checkout, or its `path`
    /// subdirectory.
    root: PathBuf,
    /// The checkout itself, canonical. Nothing an imported file names may
    /// leave it.
    checkout: PathBuf,
    /// The alias it was declared under, for messages.
    alias: String,
}

/// The aliases one file declared. An included file starts with none: an
/// alias is visible only in the file that declares it.
type ImportAliases = HashMap<String, ImportedRepo>;

/// The `url` lines of one imported repository. They form a gate of their own
/// that must pass as well, so an import can narrow where a batch may run but
/// never widen it.
#[derive(Debug)]
struct ImportGate {
    alias: String,
    checkout: PathBuf,
    conditions: Vec<UrlCondition>,
}

/// One import as the run log shows it: `import cl <url> 2.1.0 (a1b2c3d)`.
#[derive(Debug, Clone, PartialEq)]
struct ImportNote {
    text: String,
    /// The remote could not be reached and a cached copy was used instead.
    stale: bool,
}

/// Where an import's files come from.
#[derive(Debug, PartialEq)]
enum ImportSource {
    /// `import git`: a repository at a tag, a branch or a commit.
    Git { url: String, git_ref: String },
    /// `import dir`: a directory on this machine, used where it is.
    Dir { path: String },
    /// `import archive`: a downloaded `.tar.gz`, `.tar` or `.zip`.
    Archive {
        url: String,
        sha256: Option<String>,
        /// The environment variable holding a bearer token for the download.
        token_env: Option<String>,
    },
}

/// What an `import` line asks for.
#[derive(Debug, PartialEq)]
struct ImportSpec {
    alias: String,
    source: ImportSource,
    /// A subdirectory of a repository or an archive for the alias to stand for.
    path: Option<String>,
}

/// A checkout in the import cache.
#[derive(Debug, Clone)]
struct FetchedImport {
    checkout: PathBuf,
    sha: String,
    stale: bool,
}

/// Aliases declared at the interactive prompt, which live for the session.
fn session_imports() -> &'static std::sync::Mutex<ImportAliases> {
    static SESSION: std::sync::OnceLock<std::sync::Mutex<ImportAliases>> = std::sync::OnceLock::new();
    SESSION.get_or_init(Default::default)
}

/// Split off the first whitespace-delimited word.
fn split_first_word(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

const IMPORT_USAGE: &str = "expected `import <git|dir|archive> <alias> { … }` or `import <git|dir|archive> <alias> @file.json`";

/// Parse an assembled `import …` directive (comments stripped, brackets
/// balanced). `file_dir` and `within` are the file it stands in, when that
/// file is itself imported: its `@file` is then read from its own repository.
fn parse_import_directive(
    text: &str,
    file_dir: Option<&std::path::Path>,
    within: Option<&ImportedRepo>,
) -> Result<ImportSpec, String> {
    let (_, rest) = split_first_word(text);
    let (kind, rest) = split_first_word(rest);
    let (alias, body) = split_first_word(rest);
    if kind.is_empty() || alias.is_empty() || body.is_empty() {
        return Err(format!("incomplete import: {}", IMPORT_USAGE));
    }
    let kind_lower = kind.to_ascii_lowercase();
    let allowed: &[&str] = match kind_lower.as_str() {
        "git" => &["url", "ref", "path"],
        "dir" => &["path"],
        "archive" => &["url", "sha256", "token_env", "path"],
        _ => return Err(format!("unknown import kind `{}` (expected `git`, `dir` or `archive`)", kind)),
    };
    let reserved = starts_a_request(alias)
        || DIRECTIVES.iter().any(|d| alias.eq_ignore_ascii_case(d));
    if reserved || !alias.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(format!(
            "invalid import alias `{}` (letters, digits, `-` and `_`; not a method or directive)",
            alias
        ));
    }

    let json = if body.starts_with('@') {
        let (file_body, functions) = parse_body_functions(body);
        if !functions.is_empty() {
            return Err("an import's `@file` takes no `~map(…)` suffix".to_string());
        }
        let raw = file_body.trim_start_matches('@').trim();
        if raw.is_empty() || raw.contains(['*', '?', '[']) {
            return Err(format!("an import reads one JSON file, not `@{}`", raw));
        }
        let path = match within {
            Some(repo) => rebase_import_path(raw, file_dir, repo)?,
            None => raw.to_string(),
        };
        let contents = resolve_at_file_body(&path)?.contents;
        let text = String::from_utf8(contents)
            .map_err(|_| format!("import file is not UTF-8 text: {}", raw))?;
        normalize_request_text(&text).map_err(|e| format!("import file {}: {}", raw, e))?
    } else if body.starts_with('{') {
        body.to_string()
    } else {
        return Err(format!("invalid import: {}", IMPORT_USAGE));
    };

    let value: Value = serde_json::from_str(json.trim())
        .map_err(|e| format!("import {}: invalid JSON: {}", alias, e))?;
    let keys = allowed.iter().map(|k| format!("`{}`", k)).collect::<Vec<_>>().join(", ");
    let Some(object) = value.as_object() else {
        return Err(format!("import {}: expected a JSON object with {}", alias, keys));
    };
    if let Some(unknown) = object.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("import {}: unknown key `{}` (expected {})", alias, unknown, keys));
    }
    let text_of = |key: &str| -> Result<Option<String>, String> {
        match object.get(key) {
            None => Ok(None),
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
            Some(_) => Err(format!("import {}: `{}` must be a non-empty string", alias, key)),
        }
    };
    let required = |key: &str| -> Result<String, String> {
        text_of(key)?.ok_or_else(|| format!("import {}: `{}` is required", alias, key))
    };

    let source = match kind_lower.as_str() {
        "git" => {
            let url = required("url")?;
            let git_ref = required("ref")?;
            validate_import_url(&url).map_err(|e| format!("import {}: {}", alias, e))?;
            if git_ref.starts_with('-') || git_ref.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(format!("import {}: invalid ref `{}`", alias, git_ref));
            }
            ImportSource::Git { url, git_ref }
        }
        // The directory itself is `path`; there is no subdirectory to pick.
        "dir" => return Ok(ImportSpec {
            alias: alias.to_string(),
            source: ImportSource::Dir { path: required("path")? },
            path: None,
        }),
        _ => {
            let url = required("url")?;
            validate_archive_url(&url).map_err(|e| format!("import {}: {}", alias, e))?;
            let sha256 = text_of("sha256")?.map(|s| s.to_ascii_lowercase());
            if sha256.as_ref().is_some_and(|s| s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit())) {
                return Err(format!("import {}: `sha256` must be 64 hexadecimal characters", alias));
            }
            let token_env = text_of("token_env")?;
            let is_env_name = |name: &String| {
                !name.starts_with(|c: char| c.is_ascii_digit())
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            };
            if token_env.as_ref().is_some_and(|name| !is_env_name(name)) {
                return Err(format!(
                    "import {}: `token_env` names an environment variable, not the token itself",
                    alias
                ));
            }
            ImportSource::Archive { url, sha256, token_env }
        }
    };

    let path = text_of("path")?;
    if let Some(p) = &path {
        let stays_inside = !p.starts_with('~')
            && std::path::Path::new(p).components().all(|c| {
                matches!(c, std::path::Component::Normal(_) | std::path::Component::CurDir)
            });
        if !stays_inside {
            return Err(format!("import {}: `path` must be a relative path inside the import", alias));
        }
    }
    Ok(ImportSpec { alias: alias.to_string(), source, path })
}

/// An archive is downloaded over `https://`, or read from `file://`. Plain
/// `http://` is accepted for this machine only, as the client's own
/// connections are.
fn validate_archive_url(url: &str) -> Result<(), String> {
    let unsupported = || format!("unsupported url `{}` (use https:// or file://)", url);
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(unsupported());
    }
    if let Some(path) = url.strip_prefix("file://") {
        return if path.starts_with('/') { Ok(()) } else { Err(unsupported()) };
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| unsupported())?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_url(&parsed) => Ok(()),
        _ => Err(unsupported()),
    }
}

fn is_loopback_url(url: &reqwest::Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// Only transports that reach a repository: `https://`, `ssh://` (or the
/// `user@host:path` spelling of it) and `file://`. Anything else, an option
/// in disguise included, is refused before git ever sees it.
fn validate_import_url(url: &str) -> Result<(), String> {
    let scp_like = || {
        let Some((user_host, path)) = url.split_once(':') else { return false };
        let Some((user, host)) = user_host.split_once('@') else { return false };
        let plain = |s: &str| {
            !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        };
        plain(user) && plain(host) && !path.is_empty() && !path.starts_with("//")
    };
    let ok = !url.starts_with('-')
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
        && (["https://", "ssh://", "file://"].iter().any(|scheme| url.starts_with(scheme)) || scp_like());
    if ok {
        Ok(())
    } else {
        Err(format!("unsupported url `{}` (use https://, ssh://, user@host:path or file://)", url))
    }
}

/// Where fetched repositories are kept: `API_IMPORT_CACHE`, or
/// `~/.cache/api/imports`.
fn import_cache_dir() -> Result<PathBuf, String> {
    if let Some(dir) = std::env::var_os("API_IMPORT_CACHE").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    dirs::home_dir()
        .map(|home| home.join(".cache").join("api").join("imports"))
        .ok_or_else(|| "no home directory for the import cache; set API_IMPORT_CACHE".to_string())
}

/// A directory name for `name`: readable, and unique through a hash of the
/// exact text (FNV-1a, so it is the same name on every run and every build).
fn import_cache_key(name: &str) -> String {
    let mut readable = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
            readable.push(c);
        } else if !readable.ends_with('_') {
            readable.push('_');
        }
    }
    let readable: String = readable.trim_matches('_').chars().take(80).collect();
    let hash = name
        .bytes()
        .fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
    format!("{}-{:016x}", readable, hash)
}

/// A git command that can't stop to ask for anything and can't be steered
/// onto another transport. Symlinks are checked out as plain files, so a
/// repository can't point at a file outside itself.
fn git_command(dir: Option<&std::path::Path>) -> Command {
    let mut cmd = Command::new("git");
    if let Some(dir) = dir {
        cmd.arg("-C").arg(dir);
    }
    cmd.args(["-c", "core.symlinks=false", "-c", "advice.detachedHead=false"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_ALLOW_PROTOCOL", "https:ssh:file")
        .stdin(std::process::Stdio::null());
    if std::env::var_os("GIT_SSH_COMMAND").is_none() && std::env::var_os("GIT_SSH").is_none() {
        cmd.env("GIT_SSH_COMMAND", "ssh -oBatchMode=yes");
    }
    cmd
}

/// Run a git command, returning its stdout or the reason it failed.
fn run_git(mut cmd: Command) -> Result<String, String> {
    let output = cmd.output().map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            "an import needs `git` on the PATH".to_string()
        } else {
            format!("could not run git: {}", e)
        }
    })?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reason = stderr.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("; ");
    Err(if reason.is_empty() { format!("git exited with {}", output.status) } else { reason })
}

/// From `git ls-remote` output, the commit `git_ref` names and the full ref
/// to fetch it by. A tag wins over a branch of the same name, and an
/// annotated tag resolves to the commit it points at.
fn pick_remote_ref(listing: &str, git_ref: &str) -> Option<(String, String)> {
    let refs: Vec<(&str, &str)> = listing
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(sha, name)| (sha.trim(), name.trim()))
        .collect();
    let wanted = [
        format!("refs/tags/{}^{{}}", git_ref),
        format!("{}^{{}}", git_ref),
        format!("refs/tags/{}", git_ref),
        format!("refs/heads/{}", git_ref),
        git_ref.to_string(),
    ];
    wanted.iter().find_map(|name| {
        refs.iter()
            .find(|(_, n)| n == name)
            .map(|(sha, n)| (sha.to_string(), n.trim_end_matches("^{}").to_string()))
    })
}

fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Fetch `fetch_name` (a full ref name or a commit SHA) of `url` into the
/// cache directory `repo_cache`, returning the commit it turned out to be.
/// The work happens in a scratch directory that is renamed into place, so an
/// interrupted fetch leaves nothing that looks like a checkout.
fn fetch_into_cache(url: &str, fetch_name: &str, repo_cache: &std::path::Path) -> Result<String, String> {
    let scratch = cache_scratch_dir(repo_cache)?;

    let fetched = (|| -> Result<String, String> {
        let mut init = git_command(None);
        init.arg("init").arg("-q").arg(&scratch);
        run_git(init)?;
        let mut fetch = git_command(Some(&scratch));
        fetch.args(["fetch", "-q", "--depth", "1", "--no-tags", "--", url, fetch_name]);
        run_git(fetch)?;
        let mut rev = git_command(Some(&scratch));
        rev.args(["rev-parse", "--verify", "FETCH_HEAD^{commit}"]);
        let sha = run_git(rev)?.trim().to_string();
        let mut checkout = git_command(Some(&scratch));
        checkout.args(["checkout", "-q", "FETCH_HEAD"]);
        run_git(checkout)?;
        // Only the files are kept; the history is not needed again.
        let _ = fs::remove_dir_all(scratch.join(".git"));
        Ok(sha)
    })();

    let sha = match fetched {
        Ok(sha) => sha,
        Err(e) => {
            let _ = fs::remove_dir_all(&scratch);
            return Err(e);
        }
    };
    move_into_cache(&scratch, &repo_cache.join(&sha))?;
    Ok(sha)
}

/// What a git ref or an archive URL resolved to earlier in this process, by
/// cache directory, kind, URL and ref (or pinned hash). A one-shot line is
/// parsed twice on its way to being run, and should ask the remote once.
type ResolvedImports = std::sync::Mutex<HashMap<(PathBuf, &'static str, String, String), FetchedImport>>;

fn resolved_imports() -> &'static ResolvedImports {
    static RESOLVED: std::sync::OnceLock<ResolvedImports> = std::sync::OnceLock::new();
    RESOLVED.get_or_init(Default::default)
}

/// Forget what refs and URLs resolved to, so the next import asks again. The
/// prompt does this for every line it runs: a session can outlast a push, and
/// typing an `import` again is how its user asks for the new commit.
fn forget_resolved_imports() {
    resolved_imports().lock().unwrap().clear();
}

/// How long a checkout or an unpacked archive may go unused before a later
/// fetch clears it out of the cache.
const IMPORT_CACHE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The file whose modification time says when `checkout` was last used. It
/// sits beside the checkout, not in it, so the import's own files are left
/// exactly as they were fetched.
fn import_used_marker(checkout: &std::path::Path) -> PathBuf {
    let mut name = checkout.file_name().unwrap_or_default().to_os_string();
    name.push(".used");
    checkout.with_file_name(name)
}

/// Record that `checkout` was used just now.
fn mark_import_used(checkout: &std::path::Path) {
    let _ = fs::write(import_used_marker(checkout), b"");
}

/// Remove what the import cache no longer needs: checkouts and unpacked
/// archives last used more than `max_age` ago, and the scratch directories of
/// fetches that never finished. `keep` is the one this run just fetched.
/// Called only when a fetch has brought something new in, so a run that finds
/// everything cached never pays for the walk.
fn prune_import_cache(cache_dir: &std::path::Path, keep: &std::path::Path, max_age: Duration) {
    let now = std::time::SystemTime::now();
    let unused_for = |path: &std::path::Path| -> Option<Duration> {
        let modified = fs::metadata(path).and_then(|m| m.modified()).ok()?;
        now.duration_since(modified).ok()
    };
    let is_hash = |name: &str| (name.len() == 40 || name.len() == 64) && name.chars().all(|c| c.is_ascii_hexdigit());
    // One directory per repository, and `archives` beside them.
    for group in fs::read_dir(cache_dir).into_iter().flatten().flatten() {
        for entry in fs::read_dir(group.path()).into_iter().flatten().flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path == keep || !path.is_dir() {
                continue;
            }
            let marker = import_used_marker(&path);
            // A checkout made before there were markers is as old as it is.
            let idle = if name.starts_with(".tmp-") {
                unused_for(&path)
            } else if is_hash(&name) {
                unused_for(&marker).or_else(|| unused_for(&path))
            } else {
                None
            };
            if idle.is_some_and(|idle| idle > max_age) {
                let _ = fs::remove_dir_all(&path);
                let _ = fs::remove_file(&marker);
            }
        }
    }
}

/// A path for work in progress under `parent` (created if need be), named so
/// two runs never share one. The directory itself is not created.
fn cache_scratch_dir(parent: &std::path::Path) -> Result<PathBuf, String> {
    fs::create_dir_all(parent).map_err(|e| format!("could not create {}: {}", parent.display(), e))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(".tmp-{}-{}-{}", std::process::id(), nanos, n)))
}

/// Give finished work in `scratch` its place in the cache. If `dest` is
/// already there, another run got to it first and its copy is kept.
fn move_into_cache(scratch: &std::path::Path, dest: &std::path::Path) -> Result<(), String> {
    if dest.is_dir() || fs::rename(scratch, dest).is_err() {
        let _ = fs::remove_dir_all(scratch);
        if !dest.is_dir() {
            return Err(format!("could not move the import into {}", dest.display()));
        }
    }
    Ok(())
}

/// SHA-256 of `bytes`, as lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{:02x}", b)).collect()
}

/// The most an archive may unpack to. An import holds `.api` files and their
/// bodies; anything near this is a mistake or an attack.
const ARCHIVE_UNPACKED_LIMIT: u64 = 1024 * 1024 * 1024;

/// Where an archive entry named `name` goes under `dest`, or an error if the
/// name would put it anywhere else.
fn archive_entry_dest(name: &std::path::Path, dest: &std::path::Path) -> Result<PathBuf, String> {
    let inside = name.components().all(|c| {
        matches!(c, std::path::Component::Normal(_) | std::path::Component::CurDir)
    });
    if !inside {
        return Err(format!("archive entry leaves the archive: {}", name.display()));
    }
    Ok(dest.join(name))
}

/// Write one archive entry's bytes to `path`, counting them against what the
/// whole archive may still unpack to.
fn write_archive_file(
    mut from: impl io::Read,
    path: &std::path::Path,
    remaining: &mut u64,
) -> Result<(), String> {
    let failed = |e: io::Error| format!("could not unpack {}: {}", path.display(), e);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(failed)?;
    }
    let mut file = fs::File::create(path).map_err(failed)?;
    let written = io::copy(&mut (&mut from).take(*remaining + 1), &mut file).map_err(failed)?;
    if written > *remaining {
        return Err("archive unpacks to more than 1 GB".to_string());
    }
    *remaining -= written;
    Ok(())
}

/// Unpack a `.zip`, `.tar.gz` or `.tar` (told apart by content, not by name)
/// into `dest`. Only files and directories are written: links and device
/// entries are skipped, and an entry named outside the archive is an error.
fn unpack_archive(bytes: &[u8], dest: &std::path::Path) -> Result<(), String> {
    unpack_archive_within(bytes, dest, ARCHIVE_UNPACKED_LIMIT)
}

/// `unpack_archive` with the size it may unpack to given.
fn unpack_archive_within(bytes: &[u8], dest: &std::path::Path, limit: u64) -> Result<(), String> {
    let mut remaining = limit;
    fs::create_dir_all(dest).map_err(|e| format!("could not create {}: {}", dest.display(), e))?;

    if bytes.starts_with(b"PK\x03\x04") {
        let mut zip = zip::ZipArchive::new(io::Cursor::new(bytes))
            .map_err(|e| format!("could not read the zip archive: {}", e))?;
        for i in 0..zip.len() {
            let entry = zip.by_index(i).map_err(|e| format!("could not read the zip archive: {}", e))?;
            let Some(name) = entry.enclosed_name() else {
                return Err(format!("archive entry leaves the archive: {}", String::from_utf8_lossy(entry.name_raw())));
            };
            let path = archive_entry_dest(&name, dest)?;
            if entry.is_dir() {
                fs::create_dir_all(&path).map_err(|e| format!("could not unpack {}: {}", path.display(), e))?;
            } else if entry.is_file() {
                write_archive_file(entry, &path, &mut remaining)?;
            }
        }
        return Ok(());
    }

    let gzipped = bytes.starts_with(&[0x1f, 0x8b]);
    let plain_tar = bytes.len() > 262 && &bytes[257..262] == b"ustar";
    if !gzipped && !plain_tar {
        return Err("not a .tar.gz, .tar or .zip archive".to_string());
    }
    let reader: Box<dyn io::Read + '_> = if gzipped {
        Box::new(flate2::read::GzDecoder::new(bytes))
    } else {
        Box::new(bytes)
    };
    let mut tar = tar::Archive::new(reader);
    let unreadable = |e: io::Error| format!("could not read the tar archive: {}", e);
    for entry in tar.entries().map_err(unreadable)? {
        let entry = entry.map_err(unreadable)?;
        let kind = entry.header().entry_type();
        if !kind.is_dir() && !kind.is_file() {
            continue;
        }
        let name = entry.path().map_err(unreadable)?.into_owned();
        let path = archive_entry_dest(&name, dest)?;
        if kind.is_dir() {
            fs::create_dir_all(&path).map_err(|e| format!("could not unpack {}: {}", path.display(), e))?;
        } else {
            write_archive_file(entry, &path, &mut remaining)?;
        }
    }
    Ok(())
}

/// Download an archive. `token` goes along as a bearer token; the client's
/// own API credentials never do. A redirect is followed only to `https://`
/// (or to this machine), so a download can't be steered onto plain http.
fn download_archive(url: &str, token: Option<&str>) -> Result<Vec<u8>, String> {
    if let Some(path) = url.strip_prefix("file://") {
        return fs::read(path).map_err(|e| e.to_string());
    }
    let client = client_builder()
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let secure = attempt.url().scheme() == "https" || is_loopback_url(attempt.url());
            if attempt.previous().len() > 10 {
                attempt.error("too many redirects")
            } else if !secure {
                attempt.error("redirected to a url that is not https")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| e.to_string())?;
    let mut request = client.get(url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().map_err(|e| describe_download_error(&e))?;
    let status = response.status();
    if !status.is_success() {
        return Err(status.to_string());
    }
    response.bytes().map(|b| b.to_vec()).map_err(|e| describe_download_error(&e))
}

/// A download failure without the URL in it (the caller names the import)
/// and with the cause that reqwest keeps one level down.
fn describe_download_error(e: &reqwest::Error) -> String {
    let mut text = e.to_string();
    if let Some(url) = e.url() {
        text = text.replace(&format!(" for url ({})", url), "");
    }
    match std::error::Error::source(e) {
        Some(cause) => format!("{}: {}", text, cause),
        None => text,
    }
}

/// Make the archive at `url` available locally and return where it was
/// unpacked.
///
/// With a `sha256`, the cache is asked first and a hit needs no network; a
/// download whose hash differs is an error. Without one the archive is
/// downloaded on every run, since the URL may serve something new, and if it
/// can't be reached the copy it last served is used, marked stale.
fn fetch_archive_import(
    url: &str,
    sha256: Option<&str>,
    token_env: Option<&str>,
) -> Result<FetchedImport, String> {
    let cache_dir = import_cache_dir()?;
    let archives = cache_dir.join("archives");
    let memo_key = (cache_dir.clone(), "archive", url.to_string(), sha256.unwrap_or_default().to_string());
    if let Some(known) = resolved_imports().lock().unwrap().get(&memo_key) {
        return Ok(known.clone());
    }
    let mut unpacked_now = false;
    let found = |sha: String, stale: bool| {
        let checkout = archives.join(&sha);
        FetchedImport { checkout: checkout.canonicalize().unwrap_or(checkout), sha, stale }
    };

    let pinned_in_cache = sha256.filter(|sha| archives.join(sha).is_dir());
    let fetched = if let Some(sha) = pinned_in_cache {
        found(sha.to_string(), false)
    } else {
        let token = match token_env {
            Some(name) => Some(std::env::var(name).ok().filter(|t| !t.is_empty()).ok_or_else(|| {
                format!("import archive {}: environment variable {} is not set", url, name)
            })?),
            None => None,
        };
        let last_served = archives.join("refs").join(import_cache_key(url));
        match download_archive(url, token.as_deref()) {
            Ok(bytes) => {
                let sha = sha256_hex(&bytes);
                if let Some(expected) = sha256.filter(|expected| *expected != sha) {
                    return Err(format!(
                        "import archive {}: sha256 mismatch (expected {}, got {})",
                        url, expected, sha
                    ));
                }
                if !archives.join(&sha).is_dir() {
                    let scratch = cache_scratch_dir(&archives)?;
                    if let Err(e) = unpack_archive(&bytes, &scratch) {
                        let _ = fs::remove_dir_all(&scratch);
                        return Err(format!("import archive {}: {}", url, e));
                    }
                    move_into_cache(&scratch, &archives.join(&sha))?;
                    unpacked_now = true;
                }
                if sha256.is_none() {
                    // Remembered for the day the url can't be reached.
                    let _ = fs::create_dir_all(archives.join("refs"));
                    let _ = fs::write(&last_served, &sha);
                }
                found(sha, false)
            }
            Err(e) => {
                let cached = fs::read_to_string(&last_served)
                    .ok()
                    .map(|sha| sha.trim().to_string())
                    .filter(|sha| sha256.is_none() && sha.len() == 64 && archives.join(sha).is_dir());
                match cached {
                    Some(sha) => found(sha, true),
                    None => return Err(format!("could not reach import {}: {}", url, e)),
                }
            }
        }
    };
    let unpacked = archives.join(&fetched.sha);
    mark_import_used(&unpacked);
    if unpacked_now {
        prune_import_cache(&cache_dir, &unpacked, IMPORT_CACHE_MAX_AGE);
    }
    resolved_imports().lock().unwrap().insert(memo_key, fetched.clone());
    Ok(fetched)
}

/// The directory an unpacked archive's files start in: the one directory at
/// its top when that is all there is (`cloddy-2.1.0/…`, the way a release
/// tarball is packed), otherwise the top itself.
fn archive_top_dir(checkout: &std::path::Path) -> PathBuf {
    let mut entries = match fs::read_dir(checkout) {
        Ok(entries) => entries.flatten().map(|e| e.path()).filter(|p| !is_os_junk(p)),
        Err(_) => return checkout.to_path_buf(),
    };
    match (entries.next(), entries.next()) {
        (Some(only), None) if only.is_dir() => only,
        _ => checkout.to_path_buf(),
    }
}

/// The directory `import dir` names. From a file of the batch's own it is a
/// path like an include's: relative to that file, `~/` or absolute. From an
/// imported file it must stay inside that file's import.
fn resolve_import_dir(
    alias: &str,
    raw: &str,
    base_dir: Option<&std::path::Path>,
    within: Option<&ImportedRepo>,
) -> Result<PathBuf, String> {
    let dir = match within {
        Some(repo) => PathBuf::from(rebase_import_path(raw, base_dir, repo).map_err(|_| {
            format!("import {}: `path` must be a relative path inside the import", alias)
        })?),
        None => {
            let expanded = match dirs::home_dir() {
                Some(home) if raw == "~" => home,
                _ => PathBuf::from(expand_home(raw)),
            };
            match base_dir {
                Some(base) if expanded.is_relative() => base.join(expanded),
                _ => expanded,
            }
        }
    };
    if !dir.is_dir() {
        return Err(format!("import {}: not a directory: {}", alias, raw));
    }
    dir.canonicalize().map_err(|e| format!("import {}: {}: {}", alias, raw, e))
}

/// Make `git_ref` of `url` available locally and return its checkout.
///
/// A commit SHA already in the cache costs nothing. A tag or a branch is
/// resolved with one `git ls-remote` and fetched only when it points at a
/// commit the cache doesn't hold. If the remote can't be reached, the commit
/// the ref last resolved to is used, marked stale.
fn fetch_git_import(url: &str, git_ref: &str) -> Result<FetchedImport, String> {
    let cache_dir = import_cache_dir()?;
    let memo_key = (cache_dir.clone(), "git", url.to_string(), git_ref.to_string());
    if let Some(known) = resolved_imports().lock().unwrap().get(&memo_key) {
        return Ok(known.clone());
    }

    let repo_cache = cache_dir.join(import_cache_key(url));
    let last_resolved = repo_cache.join("refs").join(import_cache_key(git_ref));
    let mut stale = false;
    let (mut sha, fetch_name) = if is_full_sha(git_ref) {
        (git_ref.to_ascii_lowercase(), git_ref.to_string())
    } else {
        let mut ls = git_command(None);
        ls.args(["ls-remote", "--", url, git_ref]);
        match run_git(ls) {
            Ok(listing) => pick_remote_ref(&listing, git_ref)
                .ok_or_else(|| format!("import ref not found: {} in {}", git_ref, url))?,
            Err(e) => {
                let cached = fs::read_to_string(&last_resolved)
                    .ok()
                    .map(|sha| sha.trim().to_string())
                    .filter(|sha| is_full_sha(sha) && repo_cache.join(sha).is_dir());
                match cached {
                    Some(sha) => {
                        stale = true;
                        (sha, String::new())
                    }
                    None => return Err(format!("could not reach import {}: {}", url, e)),
                }
            }
        }
    };

    let fetched_now = !repo_cache.join(&sha).is_dir();
    if fetched_now {
        sha = fetch_into_cache(url, &fetch_name, &repo_cache)
            .map_err(|e| format!("could not fetch import {} {}: {}", url, git_ref, e))?;
    }
    if !is_full_sha(git_ref) && !stale {
        // Remembered for the day the remote can't be reached.
        let _ = fs::create_dir_all(repo_cache.join("refs"));
        let _ = fs::write(&last_resolved, &sha);
    }
    let checkout = repo_cache.join(&sha);
    mark_import_used(&checkout);
    if fetched_now {
        prune_import_cache(&cache_dir, &checkout, IMPORT_CACHE_MAX_AGE);
    }
    let fetched = FetchedImport {
        checkout: checkout.canonicalize().unwrap_or(checkout),
        sha,
        stale,
    };
    resolved_imports().lock().unwrap().insert(memo_key, fetched.clone());
    Ok(fetched)
}

/// `path` with its `.` and `..` components resolved by name alone.
fn normalize_path_lexically(path: &std::path::Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The path an imported file's `@path` stands for: relative to that file,
/// and inside its repository. An imported file can't reach for a file on the
/// machine that runs it.
fn rebase_import_path(
    raw: &str,
    file_dir: Option<&std::path::Path>,
    repo: &ImportedRepo,
) -> Result<String, String> {
    let outside = || format!("import {}: `@{}` must be a relative path inside the import", repo.alias, raw);
    if raw.starts_with('~') || std::path::Path::new(raw).is_absolute() {
        return Err(outside());
    }
    let resolved = normalize_path_lexically(&file_dir.unwrap_or(&repo.root).join(raw));
    if !resolved.starts_with(&repo.checkout) {
        return Err(outside());
    }
    // And where it really is: a link that leads out of the import (possible
    // in an `import dir`, whose files are used where they are) is refused as
    // an include through such a link is. A file that is not there is left to
    // fail where it is read, and a glob to the files it matches.
    let root = repo.checkout.canonicalize().ok();
    let leads_out = |path: &std::path::Path| match (path.canonicalize(), &root) {
        (Ok(real), Some(root)) => !real.starts_with(root),
        _ => false,
    };
    if leads_out(&resolved) {
        return Err(outside());
    }
    // A pattern is no file, so it is every file it matches that is checked:
    // one of them may be a link out, or the directory they are in may be.
    let pattern = resolved.to_string_lossy().to_string();
    if pattern.chars().any(|c| c == '*' || c == '?' || c == '[') {
        if let Ok(matches) = glob::glob_with(&pattern, glob_match_options()) {
            if matches.filter_map(|m| m.ok()).any(|m| leads_out(&m)) {
                return Err(outside());
            }
        }
    }
    Ok(pattern)
}

/// A step of an imported file with the `@file` body of its request, if it has
/// one, pointed at the repository the file came from: the request of an
/// `assert` and of a `sleep while` is a request of that file like any other.
fn rebase_step(step: BulkStep, file_dir: Option<&std::path::Path>, repo: &ImportedRepo) -> Result<BulkStep, String> {
    Ok(match step {
        BulkStep::Assert { negate, request } => {
            BulkStep::Assert { negate, request: rebase_at_body(&request, file_dir, repo)? }
        }
        BulkStep::SleepWhile { interval, negate, request } => {
            BulkStep::SleepWhile { interval, negate, request: rebase_at_body(&request, file_dir, repo)? }
        }
        other => other,
    })
}

/// The `@file` bodies of imported files as they were written, by the body
/// they were rebased to. A request from an import is sent with the path its
/// file really has, and logged with the one its line has.
static WRITTEN_BODIES: std::sync::Mutex<Option<HashMap<String, String>>> = std::sync::Mutex::new(None);

/// A body as its line wrote it: for the `@file` body of an imported file,
/// the path in the file, not the one in the cache it was resolved to.
fn body_as_written(body: &str) -> String {
    if !body.starts_with('@') {
        return body.to_string();
    }
    WRITTEN_BODIES
        .lock()
        .ok()
        .and_then(|written| written.as_ref().and_then(|map| map.get(body).cloned()))
        .unwrap_or_else(|| body.to_string())
}

/// A request from an imported file with its `@file` body, if it has one,
/// pointed at the repository the file came from. Any other request is
/// returned as it is.
fn rebase_at_body(
    request: &str,
    file_dir: Option<&std::path::Path>,
    repo: &ImportedRepo,
) -> Result<String, String> {
    let Some((method, uri_and_outfile, body)) = parse_request_line(request) else {
        return Ok(request.to_string());
    };
    if !body.starts_with('@') {
        return Ok(request.to_string());
    }
    let (file_body, _) = parse_body_functions(&body);
    let functions = &body[file_body.len()..];
    let raw = file_body.trim_start_matches('@').trim();
    let path = rebase_import_path(raw, file_dir, repo)?;
    let rebased = format!("@{}{}", path, functions);
    if let Ok(mut written) = WRITTEN_BODIES.lock() {
        written.get_or_insert_with(HashMap::new).insert(rebased.clone(), body.clone());
    }
    let (uri, outfile) = split_uri_outfile(&uri_and_outfile);
    Ok(format!("{} {} {}{}", method, uri, rebased, outfile))
}

/// An include that starts with a declared alias (`cl/sv.api`): the repository
/// it names and the path inside it.
fn alias_include<'a>(spec: &'a str, aliases: &'a ImportAliases) -> Option<(&'a ImportedRepo, &'a str)> {
    let (alias, rest) = split_alias(spec, cfg!(windows))?;
    aliases.get(alias).map(|repo| (repo, rest))
}

/// `alias/rest` as its two parts. Where `\` separates a path too (Windows),
/// `alias\rest` is the same include.
fn split_alias(spec: &str, backslash_separates: bool) -> Option<(&str, &str)> {
    let at = spec.find(|c: char| c == '/' || (backslash_separates && c == '\\'))?;
    Some((&spec[..at], &spec[at + 1..]))
}

/// Refuse an include that an imported file (or an alias path) points outside
/// its repository.
fn ensure_inside_import(path: &std::path::Path, repo: &ImportedRepo, spec: &str) -> Result<(), String> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if canonical.starts_with(&repo.checkout) {
        Ok(())
    } else {
        Err(format!("import {}: include leaves the import: {}", repo.alias, spec))
    }
}

/// Handle an assembled `import` directive: fetch the repository and bind the
/// alias for the rest of the file.
fn declare_import(
    text: &str,
    base_dir: Option<&std::path::Path>,
    within: Option<&ImportedRepo>,
    aliases: &mut ImportAliases,
    declared: &mut std::collections::HashSet<String>,
    program: &mut BulkProgram,
) -> Result<(), String> {
    let spec = parse_import_directive(text, base_dir, within)?;
    if !declared.insert(spec.alias.clone()) {
        return Err(format!("import alias `{}` is declared twice", spec.alias));
    }
    // `cl/sv.api` must mean one thing: a directory of that name next to the
    // file would make it two.
    let local = match base_dir {
        Some(dir) => dir.join(&spec.alias),
        None => PathBuf::from(&spec.alias),
    };
    if local.exists() {
        return Err(format!(
            "import alias `{}` clashes with {} (pick another alias)",
            spec.alias,
            local.display()
        ));
    }

    // The directory the alias's files live under (which nothing in them may
    // leave), where the alias starts, and how the log describes the import.
    let (checkout, top, described, stale) = match &spec.source {
        ImportSource::Git { url, git_ref } => {
            let fetched = fetch_git_import(url, git_ref)?;
            let short_sha: String = fetched.sha.chars().take(7).collect();
            let described = format!("{} {} ({}", url, git_ref, short_sha);
            (fetched.checkout.clone(), fetched.checkout, described, fetched.stale)
        }
        ImportSource::Dir { path } => {
            let dir = resolve_import_dir(&spec.alias, path, base_dir, within)?;
            (dir.clone(), dir.clone(), dir.display().to_string(), false)
        }
        ImportSource::Archive { url, sha256, token_env } => {
            let fetched = fetch_archive_import(url, sha256.as_deref(), token_env.as_deref())?;
            let short_sha: String = fetched.sha.chars().take(7).collect();
            let top = archive_top_dir(&fetched.checkout);
            (fetched.checkout, top, format!("{} (sha256 {}", url, short_sha), fetched.stale)
        }
    };
    let root = match &spec.path {
        Some(path) => top.join(path),
        None => top,
    };
    if !root.is_dir() {
        return Err(format!(
            "import {}: no directory `{}` in {}",
            spec.alias,
            spec.path.as_deref().unwrap_or("."),
            described.split(" (").next().unwrap_or(&described)
        ));
    }

    // A git or archive description is left open at `(…` for the stale remark.
    let closing = match (&spec.source, stale) {
        (ImportSource::Dir { .. }, _) => "",
        (_, true) => ", cached copy: remote unreachable)",
        (_, false) => ")",
    };
    let note = ImportNote {
        text: format!("import {} {}{}", spec.alias, described, closing),
        stale,
    };
    if !program.import_notes.contains(&note) {
        program.import_notes.push(note);
    }
    aliases.insert(
        spec.alias.clone(),
        ImportedRepo { root, checkout, alias: spec.alias },
    );
    Ok(())
}

/// Where a describe block may stand: before the first request, import,
/// include or directive of its file, with only comments, blank lines and
/// `url` lines above it. Anywhere else a `{` that starts a line is a body
/// that lost its request, and is refused instead of being read as either.
#[derive(Default)]
struct DescribePlacement {
    /// Something other than a comment or a `url` line has been read.
    opened: bool,
    /// The file's describe block has been read.
    described: bool,
    /// The line above is a `PUT`, `POST` or `PATCH` with no body, so a JSON
    /// block here is most likely the body, written a line too low.
    bodyless: bool,
}

impl DescribePlacement {
    /// A blank line or a comment.
    fn gap(&mut self) {
        self.bodyless = false;
    }

    /// The first line of whatever comes next. `Ok(true)`: it opens the
    /// file's describe block.
    fn begin(&mut self, trimmed: &str) -> Result<bool, String> {
        let hint = if self.bodyless { " (a body starts on the request line)" } else { "" };
        if trimmed.starts_with('[') {
            return Err(format!("a describe block is a JSON object, not an array{}", hint));
        }
        if trimmed.starts_with('{') {
            if self.opened {
                return Err(format!("a describe block must come before the first request{}", hint));
            }
            if self.described {
                return Err("a file has one describe block, and this is a second".to_string());
            }
            return Ok(true);
        }
        self.bodyless = false;
        if !matches!(parse_url_condition(trimmed), Ok(Some(_))) {
            self.opened = true;
        }
        Ok(false)
    }

    /// A request has been read whole (`""` for anything else).
    fn request(&mut self, text: &str) {
        self.bodyless = parse_request_line(text)
            .is_some_and(|(method, _, body)| body.is_empty() && ["PUT", "POST", "PATCH"].contains(&method.as_str()));
    }
}

const DESCRIBE_ALONE: &str = "a describe block alone sends nothing. It goes at the top of a .api file.";

type DescribeBlock = serde_json::Map<String, serde_json::Value>;

/// Read the text of a describe block, comments stripped, as the object it is.
fn parse_describe_block(text: &str) -> Result<DescribeBlock, String> {
    match serde_json::from_str::<serde_json::Value>(text.trim()) {
        Ok(serde_json::Value::Object(block)) => Ok(block),
        Ok(_) => Err("a describe block is a JSON object".to_string()),
        Err(e) => Err(format!("invalid describe block: {}", e)),
    }
}

/// A locale key in the one spelling it is printed in (`sv-se` → `sv-SE`,
/// `ZH-hans-cn` → `zh-Hans-CN`), or `None` when it is no locale: a language
/// of two or three letters, then optionally a script of four letters and a
/// region of two letters or three digits, joined by `-`.
fn canonical_locale(key: &str) -> Option<String> {
    let mut parts = key.split('-');
    let language = parts.next()?;
    if !(2..=3).contains(&language.len()) || !language.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let mut out = language.to_ascii_lowercase();
    let mut next = parts.next();
    if let Some(script) = next.filter(|p| p.len() == 4 && p.chars().all(|c| c.is_ascii_alphabetic())) {
        out.push('-');
        out.push_str(&script[..1].to_ascii_uppercase());
        out.push_str(&script[1..].to_ascii_lowercase());
        next = parts.next();
    }
    if let Some(region) = next {
        let letters = region.len() == 2 && region.chars().all(|c| c.is_ascii_alphabetic());
        let digits = region.len() == 3 && region.chars().all(|c| c.is_ascii_digit());
        if !(letters || digits) {
            return None;
        }
        out.push('-');
        out.push_str(&region.to_ascii_uppercase());
        next = parts.next();
    }
    next.is_none().then_some(out)
}

/// Check a describe block against what one holds, `title` and `description`
/// as texts by locale and `docsLink` as a link, and return it with its locale
/// keys in one spelling, beside a line for each thing that is not as it
/// should be. Nothing is dropped but a locale given twice: a member this
/// client does not know may be one a later client does.
fn check_describe_block(block: DescribeBlock) -> (DescribeBlock, Vec<String>) {
    use serde_json::Value;
    let mut out = DescribeBlock::new();
    let mut warnings = Vec::new();
    for (key, value) in block {
        match (key.as_str(), value) {
            ("title" | "description", Value::Object(texts)) => {
                let mut checked = DescribeBlock::new();
                for (locale, text) in texts {
                    let name = canonical_locale(&locale).unwrap_or_else(|| {
                        warnings.push(format!("{}/{} is not a locale", key, locale));
                        locale.clone()
                    });
                    if !text.is_string() {
                        warnings.push(format!("{}/{} is not a text", key, locale));
                    }
                    if checked.contains_key(&name) {
                        warnings.push(format!("{}/{} is given twice", key, locale));
                        continue;
                    }
                    checked.insert(name, text);
                }
                out.insert(key, Value::Object(checked));
            }
            ("title" | "description", other) => {
                warnings.push(format!("{} is not an object of texts by locale, like {{ \"sv-SE\": \"…\" }}", key));
                out.insert(key, other);
            }
            ("docsLink", link) => {
                if !link.as_str().is_some_and(|l| l.starts_with("https://") || l.starts_with("http://")) {
                    warnings.push("docsLink is not an http(s) link".to_string());
                }
                out.insert(key, link);
            }
            (_, other) => {
                warnings.push(format!("{} is not a member of a describe block (title, description, docsLink)", key));
                out.insert(key, other);
            }
        }
    }
    (out, warnings)
}

/// The describe block of a `.api` text, checked, without running anything it
/// names: includes are not opened and imports not fetched. Placement is
/// judged as the batch parser judges it (`DescribePlacement`), so a block
/// that would stop a run is an error here too.
fn scan_describe_block(contents: &str) -> Result<Option<(DescribeBlock, Vec<String>)>, String> {
    let mut place = DescribePlacement::default();
    let mut current = String::new();
    let mut describing = false;
    let mut found = None;
    for line in contents.lines() {
        let trimmed = line.trim();
        if current.is_empty() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                place.gap();
                continue;
            }
            describing = place.begin(trimmed)?;
            current.push_str(line);
        } else {
            current.push('\n');
            current.push_str(line);
        }
        let (cleaned, depth) = strip_body_comments_and_count(&current);
        if depth <= 0 {
            let assembled = escape_newlines_in_strings(&cleaned);
            if describing {
                found = Some(check_describe_block(parse_describe_block(&assembled)?));
                place.described = true;
            } else {
                place.request(if split_request_chain(&assembled).len() > 1 { "" } else { &assembled });
            }
            current.clear();
        }
    }
    if describing && !current.trim().is_empty() {
        let (_, depth) = strip_body_comments_and_count(&current);
        return Err(format!("unclosed describe block (depth {})", depth));
    }
    Ok(found)
}

/// A file's text without the byte order mark some editors (Windows Notepad)
/// put in front of it, which would otherwise be read as part of the first line.
fn strip_bom(mut text: String) -> String {
    if text.starts_with('\u{feff}') {
        text.drain(..'\u{feff}'.len_utf8());
    }
    text
}

/// A `.api` file named on the command line, with the directory its includes
/// start from. `-` is stdin, `~/` the home directory.
fn read_api_file(file: &str) -> Result<(String, Option<PathBuf>), String> {
    if file == "-" {
        let mut contents = String::new();
        io::stdin().read_to_string(&mut contents).map_err(|_| "could not read stdin".to_string())?;
        return Ok((strip_bom(contents), None));
    }
    let path = expand_home(file);
    let contents = fs::read_to_string(&path).map_err(|e| format!("could not read {}: {}", path, e))?;
    Ok((strip_bom(contents), std::path::Path::new(&path).parent().map(|p| p.to_path_buf())))
}

/// JSON for stdout: indented, or on one line with `-r`.
fn print_json_document(value: &serde_json::Value, raw: bool) {
    let text = if raw { serde_json::to_string(value) } else { serde_json::to_string_pretty(value) };
    outln!("{}", text.unwrap_or_else(|_| "null".to_string()));
}

/// `--describe <file>`: the file's describe block on stdout, `null` when it
/// has none. Returns the exit code.
fn print_describe_block(file: &str, raw: bool) -> i32 {
    let found = read_api_file(file).and_then(|(contents, _)| scan_describe_block(&contents));
    match found {
        Ok(found) => {
            let (block, warnings) = found.map_or((serde_json::Value::Null, Vec::new()), |(b, w)| (b.into(), w));
            for warning in warnings {
                eprintln!("warning: describe block: {}", warning);
            }
            print_json_document(&block, raw);
            0
        }
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    }
}

/// The describe block of the one `.api` file a one-shot line names, if that
/// is all the line is.
fn describe_block_of_named_file(line: &str) -> Option<DescribeBlock> {
    let file = line.trim();
    if !names_api_file(file) || file.contains(char::is_whitespace) || file.contains(['*', '?', '[']) {
        return None;
    }
    let (contents, _) = read_api_file(file).ok()?;
    scan_describe_block(&contents).ok()?.map(|(block, _)| block)
}

/// The locale the user reads, from the environment (`LC_ALL`, `LC_MESSAGES`,
/// `LANG`: `sv_SE.UTF-8` is `sv-SE`). None for `C`, `POSIX` or nothing set.
fn user_locale() -> Option<String> {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.is_empty())
        .and_then(|value| {
            let name = value.split(['.', '@']).next().unwrap_or("").replace('_', "-");
            canonical_locale(&name)
        })
}

/// The text of a `title` or `description` to show a reader of `locale`: that
/// locale's, else one in the same language, else English, else the first.
fn localized_text<'a>(texts: Option<&'a serde_json::Value>, locale: Option<&str>) -> Option<&'a str> {
    let texts: Vec<(&str, &str)> = texts?
        .as_object()?
        .iter()
        .filter_map(|(key, text)| Some((key.as_str(), text.as_str()?)))
        .collect();
    let language = |key: &str| key.split('-').next().unwrap_or("").to_ascii_lowercase();
    let exact = locale.and_then(|l| texts.iter().find(|(key, _)| key.eq_ignore_ascii_case(l)));
    let same_language = locale.and_then(|l| texts.iter().find(|(key, _)| language(key) == language(l)));
    let english = texts.iter().find(|(key, _)| language(key) == "en");
    exact.or(same_language).or(english).or(texts.first()).map(|(_, text)| *text)
}

/// Break `text` into lines of at most `width` characters at its spaces,
/// keeping the line breaks it has.
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.lines() {
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
                lines.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        lines.push(line);
    }
    lines
}

/// The lines `-m` prints for a describe block: the title, the description
/// wrapped to `width`, and the link.
fn describe_first_lines(block: &DescribeBlock, locale: Option<&str>, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(title) = localized_text(block.get("title"), locale) {
        lines.push(title.bold().to_string());
    }
    if let Some(description) = localized_text(block.get("description"), locale) {
        lines.extend(wrap_words(description, width));
    }
    if let Some(link) = block.get("docsLink").and_then(|l| l.as_str()) {
        lines.push(link.dimmed().to_string());
    }
    lines
}

/// `-m`: say on stderr what the file about to run is, from its describe
/// block, with an empty line under it.
fn print_describe_first(block: &DescribeBlock) {
    let width = if io::stderr().is_terminal() {
        colored::control::set_override(true);
        terminal::size().map(|(w, _)| w as usize).unwrap_or(80)
    } else {
        80
    };
    let lines = describe_first_lines(block, user_locale().as_deref(), width.max(20));
    if lines.is_empty() {
        return;
    }
    for line in lines {
        eprintln!("{}", line);
    }
    eprintln!();
}

/// Whether a request URI is the `/assert` endpoint of an API version.
fn is_assert_uri(api_path: &str, uri: &str) -> bool {
    let uri = split_uri_outfile(uri).0.trim();
    let path = resolve_request_path(api_path, uri);
    let Some(prefix) = path.trim_end_matches('/').strip_suffix("/assert") else {
        return false;
    };
    let version = prefix.rsplit('/').next().unwrap_or("");
    prefix.starts_with("/api/")
        && version.strip_prefix('v').is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

/// The body of every `PUT /assert` a program sends, in the order it sends
/// them and each as it is written: one element per request, so two requests
/// that assert the same path stay two.
fn collect_assertions(program: &BulkProgram, api_path: &str) -> Result<Vec<serde_json::Value>, String> {
    let requests = program.steps.iter().flat_map(|step| match step {
        BulkStep::Request(request) => vec![request.as_str()],
        BulkStep::Chain(segments) => segments.iter().map(|(_, request)| request.as_str()).collect(),
        _ => Vec::new(),
    });
    let mut assertions = Vec::new();
    for request in requests {
        let Some((method, uri, body)) = parse_request_line(request) else { continue };
        if method != "PUT" || !is_assert_uri(api_path, &uri) {
            continue;
        }
        let text = match body.strip_prefix('@') {
            Some(_) => {
                let (file_body, _) = parse_body_functions(&body);
                let file = file_body.trim_start_matches('@').trim().to_string();
                let contents = resolve_at_file_body(&file)?.contents;
                let text = String::from_utf8(contents).map_err(|_| format!("not UTF-8 text: @{}", file))?;
                normalize_request_text(&text).map_err(|e| format!("@{}: {}", file, e))?
            }
            None => body.clone(),
        };
        let value = serde_json::from_str(text.trim())
            .map_err(|e| format!("the body of `PUT {}` is not JSON: {}", split_uri_outfile(&uri).0.trim(), e))?;
        assertions.push(value);
    }
    Ok(assertions)
}

/// `--assert <file>`: what the file asserts, as one JSON array on stdout.
/// Returns the exit code.
fn print_assertions(file: &str, api_path: &str, raw: bool) -> i32 {
    let assertions = read_api_file(file).and_then(|(contents, base_dir)| {
        let program = split_bulk_requests(&contents, base_dir.as_deref()).map_err(|e| describe_program_error(&e))?;
        collect_assertions(&program, api_path)
    });
    match assertions {
        Ok(assertions) => {
            print_json_document(&serde_json::Value::Array(assertions), raw);
            0
        }
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    }
}

/// Evaluate every gate of a program: the batch's own `url` lines, then each
/// imported repository's. All of them must pass.
fn evaluate_program_gates(program: &BulkProgram, url: &str) -> Result<(), String> {
    evaluate_url_gate(&program.url_conditions, url)?;
    for gate in &program.import_gates {
        evaluate_url_gate(&gate.conditions, url).map_err(|e| format!("import {}: {}", gate.alias, e))?;
    }
    Ok(())
}

/// Resolve an include directive into the actual file paths to load.
fn resolve_include_paths(
    include_spec: &str,
    base_dir: Option<&std::path::Path>,
) -> Result<Vec<std::path::PathBuf>, String> {
    resolve_include_paths_as(include_spec, base_dir, include_spec)
}

/// `resolve_include_paths` for a path that was written another way: `path`
/// is looked up, `include_spec` is what the messages quote (`cl/sv.api` for a
/// file inside an imported repository).
fn resolve_include_paths_as(
    path: &str,
    base_dir: Option<&std::path::Path>,
    include_spec: &str,
) -> Result<Vec<std::path::PathBuf>, String> {
    let expanded = expand_home(path);

    let path_buf = std::path::PathBuf::from(&expanded);
    let resolved = if path_buf.is_absolute() {
        path_buf
    } else if let Some(base) = base_dir {
        base.join(&path_buf)
    } else {
        path_buf
    };

    let is_glob = expanded.chars().any(|c| c == '*' || c == '?' || c == '[');
    if is_glob {
        let pattern = resolved.to_string_lossy().to_string();
        let mut matches: Vec<std::path::PathBuf> = glob::glob_with(&pattern, glob_match_options())
            .map_err(|e| format!("invalid include glob '{}': {}", include_spec, e))?
            .filter_map(|r| r.ok())
            .filter(|p| p.is_file() && !is_os_junk(p))
            .collect();
        if matches.is_empty() {
            return Err(format!("no files match include glob: {}", include_spec));
        }
        matches.sort();
        Ok(matches)
    } else {
        if !resolved.is_file() {
            return Err(format!("include not found: {}", include_spec));
        }
        Ok(vec![resolved])
    }
}

/// Internal recursive worker for `split_bulk_requests`. Tracks the current chain
/// of included files to detect loops.
fn split_bulk_requests_inner(
    contents: &str,
    base_dir: Option<&std::path::Path>,
    // The repository this file was imported from, if it was.
    within: Option<&ImportedRepo>,
    // The aliases this file has declared so far.
    aliases: &mut ImportAliases,
    chain: &mut std::collections::HashSet<std::path::PathBuf>,
    program: &mut BulkProgram,
    // The export mode this text starts in: none for a file, the session's
    // for a line typed at the prompt. Returns the one it ends in.
    mut export: Option<String>,
    // The included or imported file this text is, as its include line names
    // it; none for the file being run, whose describe block is the program's.
    included_as: Option<&str>,
) -> Result<Option<String>, String> {
    // Whatever the text came from (a file, an include, stdin), a byte order
    // mark in front of it is not part of its first line.
    let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    let mut current = String::new();
    let mut place = DescribePlacement::default();
    // Whether `current` is a describe block.
    let mut describing = false;
    // Whether `current` is an `import` directive rather than a request. Its
    // JSON may span lines, so it is assembled the way a request body is.
    let mut importing = false;
    let mut declared = std::collections::HashSet::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if current.is_empty() {
            // Between requests: skip blank lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                place.gap();
                continue;
            }
            // Decide: describe block, request line, directive (sleep/url), or include?
            describing = place.begin(trimmed)?;
            let first_word = trimmed.split_whitespace().next().unwrap_or("");
            importing = first_word.eq_ignore_ascii_case("import");
            if !describing && !importing && !starts_a_request(first_word) {
                // `sleep N` — timing directive.
                if first_word.eq_ignore_ascii_case("sleep") {
                    let rest = trimmed["sleep".len()..].trim();
                    let step = parse_sleep_step(rest)?;
                    program.steps.push(match within {
                        Some(repo) => rebase_step(step, base_dir, repo)?,
                        None => step,
                    });
                    continue;
                }
                // `assert [not] <request>` — pre-check directive.
                if first_word.eq_ignore_ascii_case("assert") {
                    let rest = trimmed["assert".len()..].trim();
                    let step = parse_assert_step(rest)?;
                    program.steps.push(match within {
                        Some(repo) => rebase_step(step, base_dir, repo)?,
                        None => step,
                    });
                    continue;
                }
                // `confirm [message]` — ask for user confirmation.
                if first_word.eq_ignore_ascii_case("confirm") {
                    let rest = trimmed["confirm".len()..].trim();
                    program.steps.push(parse_confirm_step(rest)?);
                    continue;
                }
                // `export <name>` / `export off` — export mode for the rest
                // of this file, and for this file only.
                if first_word.eq_ignore_ascii_case("export") {
                    let step = parse_export_step(trimmed["export".len()..].trim())?;
                    if let BulkStep::Export { name, .. } = &step {
                        export = name.clone();
                    }
                    program.steps.push(step);
                    continue;
                }
                // `url has`/`url is` — environment gate, collected globally.
                if first_word.eq_ignore_ascii_case("url") {
                    if let Some(cond) = parse_url_condition(trimmed)? {
                        // An imported file's gate is its repository's own:
                        // it can stop the batch, but not allow it.
                        match within {
                            Some(repo) => program.import_gate(repo).push(cond),
                            None => program.url_conditions.push(cond),
                        }
                        continue;
                    }
                }
                // Otherwise treat as include directive (load and inline another file).
                // `alias/…` names a file in an imported repository; anything
                // else is a path next to this file.
                let (paths, repo) = match alias_include(trimmed, aliases) {
                    Some((repo, rest)) => (
                        resolve_include_paths_as(rest, Some(&repo.root), trimmed)?,
                        Some(repo.clone()),
                    ),
                    None => (resolve_include_paths(trimmed, base_dir)?, within.cloned()),
                };
                for path in paths {
                    if let Some(repo) = &repo {
                        ensure_inside_import(&path, repo, trimmed)?;
                    }
                    let canonical = path.canonicalize().unwrap_or(path.clone());
                    if chain.contains(&canonical) {
                        return Err(format!("include loop detected: {}", path.display()));
                    }
                    let included = fs::read_to_string(&canonical)
                        .map_err(|e| format!("could not read include {}: {}", path.display(), e))?;
                    chain.insert(canonical.clone());
                    let new_base = canonical.parent().map(|p| p.to_path_buf());
                    // This file's export mode is not the included file's:
                    // that one starts without, and what it sets ends with it.
                    if export.is_some() {
                        program.steps.push(BulkStep::Export { name: None, written: false });
                    }
                    let left_in = split_bulk_requests_inner(
                        &included,
                        new_base.as_deref(),
                        repo.as_ref(),
                        &mut ImportAliases::new(),
                        chain,
                        program,
                        None,
                        Some(trimmed),
                    )?;
                    if export.is_some() || left_in.is_some() {
                        program.steps.push(BulkStep::Export { name: export.clone(), written: false });
                    }
                    chain.remove(&canonical);
                }
                continue;
            }
            current.push_str(line);
        } else {
            current.push('\n');
            current.push_str(line);
        }
        // Strip JSONC comments inside bodies and check bracket balance
        let (cleaned, depth) = strip_body_comments_and_count(&current);
        if depth <= 0 {
            // Split on `&&` here, once the whole request (multi-line bodies
            // included) has been assembled, so a chained segment can carry a
            // multi-line body of its own.
            let assembled = escape_newlines_in_strings(&cleaned);
            if describing {
                describing = false;
                current.clear();
                let (block, warnings) = check_describe_block(parse_describe_block(&assembled)?);
                place.described = true;
                program.describe_warnings.extend(warnings.into_iter().map(|w| match included_as {
                    Some(file) => format!("describe block in {}: {}", file, w),
                    None => format!("describe block: {}", w),
                }));
                if included_as.is_none() {
                    program.describe = Some(block);
                }
                continue;
            }
            if importing {
                importing = false;
                current.clear();
                declare_import(&assembled, base_dir, within, aliases, &mut declared, program)?;
                continue;
            }
            let mut segments = split_request_chain(&assembled);
            // A file body in an imported file is a file in its repository.
            if let Some(repo) = within {
                for (_, segment) in segments.iter_mut() {
                    *segment = rebase_at_body(segment, base_dir, repo)?;
                }
            }
            if segments.len() > 1 {
                // A directive can't be chained: it would otherwise be dropped
                // on the quiet, or worse, taken for the previous request.
                if let Some((_, bad)) = segments.iter().find(|(_, s)| parse_request_line(s).is_none()) {
                    return Err(format!("chain segment is not a request: `{}`", bad.trim()));
                }
            }
            for (_, segment) in &segments {
                refuse_request(segment)?;
            }
            place.request(if segments.len() > 1 { "" } else { &assembled });
            program.steps.push(if segments.len() > 1 {
                BulkStep::Chain(segments)
            } else {
                match (within, segments.pop()) {
                    (Some(_), Some((_, rebased))) => BulkStep::Request(rebased),
                    _ => BulkStep::Request(assembled),
                }
            });
            current.clear();
        }
    }

    if !current.trim().is_empty() {
        let (_, depth) = strip_body_comments_and_count(&current);
        if describing {
            return Err(format!("unclosed describe block (depth {})", depth));
        }
        return Err(format!(
            "unclosed body at end of bulk file (depth {})",
            depth
        ));
    }

    Ok(export)
}

/// Split a multi-line bulk file into an ordered program of requests and `sleep`
/// steps, plus globally-collected `url has`/`url is` gate conditions. Each request
/// can span multiple lines when its body has unbalanced `{}` / `[]` brackets
/// (string-aware). Lines that aren't requests, directives, comments, or blank are
/// treated as include directives — the named file (or glob) is loaded and inlined.
fn split_bulk_requests(
    contents: &str,
    base_dir: Option<&std::path::Path>,
) -> Result<BulkProgram, String> {
    split_bulk_requests_with(contents, base_dir, &mut ImportAliases::new(), None)
}

/// `split_bulk_requests` starting from `aliases`, which also receives the
/// ones the text declares.
fn split_bulk_requests_with(
    contents: &str,
    base_dir: Option<&std::path::Path>,
    aliases: &mut ImportAliases,
    export: Option<String>,
) -> Result<BulkProgram, String> {
    let mut program = BulkProgram::default();
    let mut chain = std::collections::HashSet::new();
    split_bulk_requests_inner(contents, base_dir, None, aliases, &mut chain, &mut program, export, None)?;
    Ok(program)
}

/// `split_bulk_requests` for a line typed at the prompt: an alias imported
/// there stays for the session, so a later line can include from it. The
/// prompt is the file here: `export` is the mode an earlier line left on, and
/// a file run from the line is kept out of it like any included file.
fn split_bulk_requests_in_session(contents: &str, export: Option<String>) -> Result<BulkProgram, String> {
    // Each line asks the remote afresh: an `import` typed again after a push
    // gets the new commit, where a batch resolves a ref once per run.
    forget_resolved_imports();
    let mut aliases = session_imports().lock().unwrap().clone();
    let program = split_bulk_requests_with(contents, None, &mut aliases, export)?;
    *session_imports().lock().unwrap() = aliases;
    Ok(program)
}

/// Format a single request as `METHOD URI [body]` for preview display.
/// The body is compacted (JSON re-serialized without whitespace) when possible,
/// matching the bulk-silent status-line format.
fn format_request_preview(method: &str, uri: &str, body: &str) -> String {
    let display_body = compact_body_for_display(&body_as_written(body));
    if display_body.is_empty() {
        return format!("{} {}", method, uri);
    }
    // `parse_request_line` hands the ` > outfile` back on the URI. It is shown
    // where it is written and where the prompt's log has it: behind the body.
    let (uri, redirect) = split_uri_outfile(uri);
    format!("{} {} {}{}", method, uri, display_body, redirect)
}

/// Format the request line echoed above a response in the TUI log:
/// `METHOD /uri [body] [> outfile]`, always exactly one terminal row.
///
/// Every part keeps the terminal's default foreground — nothing here is styled.
/// `METHOD /uri` and the outfile are never cut: they identify the request, so
/// the body (or `@file` reference) absorbs the whole shortfall, collapsed to one
/// line and fitted to whatever columns are left. When too few remain to say
/// anything useful the body is dropped rather than stubbed. `parse_input` strips
/// ` > outfile` off the input before the URI is set, so it's re-appended here.
fn format_request_log_line(
    method: &str,
    uri: &str,
    body: &str,
    display_outfile: &str,
    outfile_append: bool,
    width: usize,
) -> String {
    let mut line = format!("{} {}", method, uri);
    let suffix = if display_outfile.is_empty() {
        String::new()
    } else {
        format!(" {} {}", if outfile_append { ">>" } else { ">" }, display_outfile)
    };

    if !body.is_empty() {
        // What's left of the row once the prefix, the outfile suffix, and the
        // space separating the body are accounted for. Saturating throughout, so
        // a URI already wider than the terminal just drops the body.
        let budget = width
            .saturating_sub(char_len(&line))
            .saturating_sub(char_len(&suffix))
            .saturating_sub(1);
        if budget >= MIN_INLINE_BODY_CHARS {
            line.push(' ');
            line.push_str(&fit_body_to_width(body, budget));
        }
    }

    line.push_str(&suffix);
    line
}

/// How many request/response blocks are kept for redraw on resize.
const OUTPUT_HISTORY_LIMIT: usize = 10;

/// One logged request/response block, kept as parts rather than rendered text so
/// a resize can re-fit the request line to the new terminal width.
///
/// Only the request line is width-dependent — `head` and `tail` are stored as
/// printed and replayed verbatim, since the terminal wraps them itself.
#[derive(Clone, Default)]
struct OutputBlock {
    method: String,
    uri: String,
    body: String,
    display_outfile: String,
    /// The outfile was `>>` (append) rather than `>` — affects only display.
    outfile_append: bool,
    /// Status line plus any `> outfile` note — what ctrl+j keeps.
    head: String,
    /// The response body block, or empty — what ctrl+j erases.
    tail: String,
    /// A directive log line (`sleep 2s`, `confirm Ready? y`) printed verbatim
    /// in place of the request line. Not width-dependent.
    raw_line: Option<String>,
    /// What stood before the request on the line it came from (`assert `,
    /// `assert not `), so the log shows the check and not just its request.
    prefix: String,
}

impl OutputBlock {
    /// A block for a directive line typed at the prompt: the line itself, then
    /// one blank line so it doesn't run into the next block.
    fn directive(line: String) -> Self {
        OutputBlock {
            raw_line: Some(line),
            head: "\n".to_string(),
            ..Default::default()
        }
    }

    /// The full block as printed: request line fitted to `width`, then the
    /// stored head and tail. Always ends with the newline that closes the
    /// request line, so blocks concatenate cleanly.
    fn render(&self, width: usize) -> String {
        let line = match &self.raw_line {
            Some(raw) => raw.clone(),
            None => format!(
                "{}{}",
                self.prefix,
                format_request_log_line(
                    &self.method,
                    &self.uri,
                    &self.body,
                    &self.display_outfile,
                    self.outfile_append,
                    width.saturating_sub(char_len(&self.prefix)),
                )
            ),
        };
        format!("{}\n{}{}", line, self.head, self.tail)
    }

    /// Add a note under the status line — the verdict of a check, say — before
    /// the blank line that closes the block, so it reads as part of the block.
    fn push_note(&mut self, note: &str) {
        let closed = self.tail.is_empty() && self.head.ends_with("\n\n");
        if closed {
            self.head.pop();
        }
        self.head.push_str(note);
        self.head.push('\n');
        if closed {
            self.head.push('\n');
        }
    }

    fn has_body(&self) -> bool {
        !self.tail.is_empty()
    }

    fn strip_body(&mut self) {
        self.tail.clear();
    }
}

/// The response body as an `OutputBlock` tail: straight under the status line,
/// with one blank line below to separate it from the next block.
///
/// The payload's own trailing newline is dropped so this spacing is the only
/// thing that decides it. Whether a body carries one varies by content type,
/// status, and streaming — pretty-printing drops it, `-r` and NDJSON keep it,
/// streamed JSON and error bodies arrive without one — and that difference
/// otherwise surfaced as an extra blank line under the response.
fn format_body_block(output: &str) -> String {
    format!("{}\n\n", output.trim_end_matches('\n'))
}

/// Push a finished block, evicting the oldest past `OUTPUT_HISTORY_LIMIT`.
fn push_output_block(state: &mut AppState, block: OutputBlock) {
    state.output_history.push(block);
    if state.output_history.len() > OUTPUT_HISTORY_LIMIT {
        state.output_history.remove(0);
    }
}

/// Print an already-rendered block above the input area and redraw the area
/// below it, all in raw mode so nothing flashes: clear the input block, print
/// the output, lay down placeholder rows, then `render` the input block.
fn print_output_and_rerender(
    state: &mut AppState,
    stdout: &mut io::Stdout,
    display_output: &str,
) -> io::Result<()> {
    print_above_input(state, stdout, display_output, 0)
}

/// `print_output_and_rerender`, first taking back `reclaim` rows of what was
/// printed last — the blank line closing a block, when a note is to go there.
fn print_above_input(
    state: &mut AppState,
    stdout: &mut io::Stdout,
    display_output: &str,
    reclaim: u16,
) -> io::Result<()> {
    let clear_lines = 2 + state.prev_input_lines + reclaim;
    queue!(
        stdout,
        cursor::Hide,
        cursor::MoveUp(clear_lines.min(state.height.saturating_sub(1))),
        cursor::MoveToColumn(0),
        Clear(ClearType::FromCursorDown)
    )?;
    // Raw mode needs \r\n line endings.
    let raw_output = display_output.replace('\n', "\r\n");
    queue!(stdout, Print(&raw_output))?;
    let input_lines = visual_line_count(&state.input, state.width as usize);
    for _ in 0..(2 + input_lines) {
        queue!(stdout, Print("\r\n"))?;
    }
    state.prev_input_lines = input_lines;
    // No flush here — render() flushes everything atomically.
    render(stdout, state)
}

/// Log a directive line (`sleep 2s`, `confirm Ready? y`) to the output area,
/// kept in history so a resize replays it.
fn log_directive_line(state: &mut AppState, stdout: &mut io::Stdout, line: String) -> io::Result<()> {
    let block = OutputBlock::directive(line);
    let display_output = block.render(state.width as usize);
    push_output_block(state, block);
    print_output_and_rerender(state, stdout, &display_output)
}

/// Put a note under the block just printed (`↳ assertion failed (null)`),
/// on screen and in the history a resize replays. The block's closing blank
/// line is taken back so the note sits right under the status line.
fn note_last_block(state: &mut AppState, stdout: &mut io::Stdout, note: &str) -> io::Result<()> {
    let Some(block) = state.output_history.last_mut() else {
        return Ok(());
    };
    let closed = block.tail.is_empty() && block.head.ends_with("\n\n");
    block.push_note(note);
    let output = if closed { format!("{}\n\n", note) } else { format!("{}\n", note) };
    print_above_input(state, stdout, &output, closed as u16)
}

/// Ask the user a yes/no question and return true if they confirm (Y/yes/empty).
/// Prompt is printed to stderr; answer read from /dev/tty (falling back to stdin)
/// so it works when stdin is piped.
///
/// An empty *line* is Enter and accepts. End of input is not an answer: with no
/// terminal and nothing on stdin (CI, cron, a closed or empty pipe), or ctrl+D
/// at a terminal, nobody agreed. That, like a read error, prints an abort
/// message and exits 1 with nothing sent. A decline returns false (exit 0).
/// The terminal a question is asked on when there is one, whatever stdin is:
/// `/dev/tty`, or `CONIN$` on Windows. Without it the answer is read from
/// stdin.
fn open_answer_terminal() -> io::Result<fs::File> {
    // The console's input, whatever stdin was redirected to.
    fs::File::open(if cfg!(windows) { "CONIN$" } else { "/dev/tty" })
}

/// Whether a `confirm` or a `-p` can be answered at a terminal, so that stdin
/// is free to be something else.
fn terminal_can_answer() -> bool {
    open_answer_terminal().is_ok()
}

fn ask_yes_no(prompt: &str) -> bool {
    eprint!("{} ", prompt.bold());
    let _ = io::stderr().flush();

    // Read a single line of input, preferring /dev/tty so a piped stdin
    // (e.g. `-a -`) does not consume the request data as the answer.
    let mut answer = String::new();
    let read = match open_answer_terminal() {
        Ok(tty) => io::BufReader::new(tty).read_line(&mut answer),
        Err(_) => io::stdin().read_line(&mut answer),
    };
    // `Ok(0)` is end of input: no line was read, not even an empty one.
    if !matches!(read, Ok(n) if n > 0) {
        // The prompt is still open on its line; end it before the message.
        eprintln!();
        eprintln!("aborted (could not read confirmation)");
        exit_process(1);
    }
    let a = answer.trim().to_lowercase();
    let proceed = a.is_empty() || a == "y" || a == "yes";
    if !proceed {
        eprintln!("aborted");
    }
    proceed
}

/// Show a preview of the request line(s) and ask the user to confirm before
/// sending. Output and prompt go to stderr so piped stdout stays clean. Reads
/// the answer from /dev/tty (falling back to stdin) so it works even when stdin
/// is a piped bulk file. Defaults to yes: an empty line (Enter) accepts.
/// Returns true to proceed, false to abort.
fn confirm_preview(lines: &[String], base_uri: &str) -> bool {
    if io::stderr().is_terminal() {
        colored::control::set_override(true);
    }
    // Count and summarize only actual request lines (first token is an HTTP
    // method). Non-request preview lines like `sleep 2s` are still displayed but
    // don't inflate the count or appear in the method summary.
    let http_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    let mut methods: Vec<String> = Vec::new();
    let mut request_count = 0usize;
    for line in lines {
        // Chained segments are shown as `&& METHOD /uri`; drop the marker so they
        // count and contribute their method like any other request.
        let trimmed_line = line.trim_start();
        let line = trimmed_line
            .strip_prefix("&&")
            .or_else(|| trimmed_line.strip_prefix("||"))
            .unwrap_or(line);
        if let Some(m) = line.split_whitespace().next() {
            if http_methods.contains(&m.to_uppercase().as_str()) {
                request_count += 1;
                if !methods.iter().any(|x| x == m) {
                    methods.push(m.to_string());
                }
            }
        }
    }
    let count_text = if request_count == 1 {
        "Preview — 1 request".to_string()
    } else {
        format!("Preview — {} requests", request_count)
    };
    let header = if methods.is_empty() {
        count_text
    } else {
        format!("{} | {}", count_text, methods.join(" "))
    };

    if base_uri.is_empty() {
        eprintln!("{}", header.bold());
    } else {
        eprintln!("{} {}", header.bold(), format!("[{}]", base_uri).dimmed());
    }
    for line in lines {
        eprintln!("  {}", line);
    }
    ask_yes_no("Run? [Y/n]")
}

fn run_bulk_from_str(config: &mut Config, contents: &str, base_dir: Option<&std::path::Path>) {
    require_base_uri(config);

    // Silent + bulk: enable "silent bulk mode" — show request line + status, skip body.
    // We clear silent so status line still prints; bulk_silent suppresses body output.
    if config.silent {
        config.silent = false;
        config.bulk_silent = true;
    }

    let program = match split_bulk_requests(contents, base_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {}", describe_program_error(&e));
            exit_process(1);
        }
    };

    // URL gate: validate the configured base URI against all collected conditions
    // before any output or requests, so test data can't reach the wrong environment.
    if let Err(e) = evaluate_program_gates(&program, &config.base_uri) {
        eprintln!("error: {}", e);
        exit_process(1);
    }

    for warning in &program.describe_warnings {
        eprintln!("warning: {}", warning);
    }
    // `-m`: say what the file is before the preview asks whether to run it.
    if config.describe_first {
        if let Some(block) = &program.describe {
            print_describe_first(block);
        }
    }

    // Preview: show all resolved requests (and sleeps) and confirm once before
    // sending. Done before any stdout output so a declined run leaves stdout clean.
    if config.preview {
        let preview_lines: Vec<String> = program
            .import_notes
            .iter()
            .map(|note| note.text.clone())
            .chain(program.steps.iter().flat_map(|step| match step {
                BulkStep::Request(r) => parse_request_line(r)
                    .map(|(method, uri, body)| format_request_preview(&method, &uri, &body))
                    .into_iter()
                    .collect::<Vec<_>>(),
                // Show every segment, marked with its operator so it's clear the
                // later ones are conditional on the earlier ones.
                BulkStep::Chain(segments) => segments
                    .iter()
                    .enumerate()
                    .filter_map(|(i, (op, r))| {
                        parse_request_line(r).map(|(method, uri, body)| {
                            let line = format_request_preview(&method, &uri, &body);
                            if i == 0 { line } else { format!("{} {}", op.as_str(), line) }
                        })
                    })
                    .collect::<Vec<_>>(),
                BulkStep::Sleep(d) => vec![format!("sleep {}", format_duration(*d))],
                BulkStep::SleepWhile { interval, negate, request } => {
                    vec![format_sleep_while(*interval, *negate, request)]
                }
                BulkStep::Assert { negate, request } => vec![format_assert(*negate, request)],
                BulkStep::Confirm(message) => vec![format_confirm(message)],
                BulkStep::Export { name, written: true } => vec![format_export(name)],
                BulkStep::Export { .. } => Vec::new(),
            }))
            .collect();
        if !confirm_preview(&preview_lines, &config.base_uri) {
            return;
        }
        // Confirmed for the whole batch — avoid re-prompting per request.
        config.preview = false;
    }

    if config.bulk_silent && !config.base_uri.is_empty() {
        // Ensure colors work even when stdout is piped
        if io::stderr().is_terminal() {
            colored::control::set_override(true);
        }
        outln!("{}", format!("[{}]", config.base_uri).dimmed());
    }

    // The log says which commit each import was, since a branch moves. Outside
    // the log only a cached copy standing in for the remote is worth a line.
    for note in &program.import_notes {
        if config.bulk_silent {
            outln!("{}", note.text.dimmed());
        } else if note.stale {
            eprintln!("warning: {}", note.text);
        }
    }

    for step in &program.steps {
        match step {
            BulkStep::Sleep(d) => {
                if config.bulk_silent {
                    outln!("{}", format!("sleep {}", format_duration(*d)).dimmed());
                }
                thread::sleep(*d);
            }
            BulkStep::Request(request) => {
                run_bulk_request(config, request);
            }
            BulkStep::SleepWhile { interval, negate, request } => {
                if !run_sleep_while(config, *interval, *negate, request) {
                    return;
                }
            }
            BulkStep::Assert { negate, request } => {
                if !run_assert(config, *negate, request) {
                    return;
                }
            }
            BulkStep::Confirm(message) => {
                if !run_confirm(config, message) {
                    return;
                }
            }
            BulkStep::Export { name, written } => {
                let applied = apply_export_step(config, name);
                if *written && config.bulk_silent {
                    outln!("{}", format_export(name).dimmed());
                    if !applied {
                        let pinned = config.export_id.as_deref().unwrap_or_default();
                        outln!("{}", format!("↳ ignored: --export {} is set", pinned).dimmed());
                    }
                }
            }
            BulkStep::Chain(segments) => {
                // Outcome of the last EXECUTED segment; skipped segments leave
                // it alone (that's what makes `a && b || c` an if-then-else).
                let mut prev: Option<RequestOutcome> = None;
                let mut skipped = 0usize;
                for (i, (op, segment)) in segments.iter().enumerate() {
                    if !chain_segment_should_run(prev, *op) {
                        skipped += 1;
                        continue;
                    }
                    // A segment with something after it is a condition, and a
                    // condition may answer "no". The last one is just a request.
                    config.expect_falsy = i + 1 < segments.len();
                    let outcome = run_bulk_request(config, segment);
                    config.expect_falsy = false;
                    match outcome {
                        // Unparseable segment (comment-like or malformed): skipped,
                        // matching how a standalone bad line is tolerated. Doesn't
                        // count as executed, so it doesn't update the outcome.
                        None => {}
                        Some(o @ (RequestOutcome::Truthy | RequestOutcome::Falsy)) => {
                            prev = Some(o);
                        }
                        // 401/403/5xx/timeouts mean the condition was never
                        // answered — abort the run rather than quietly skipping
                        // the write, which is what a false would have done. A
                        // following `||` does NOT catch this.
                        Some(RequestOutcome::Errored) => exit_process(1),
                        // Preview declined — the user said no, so it isn't a failure.
                        Some(RequestOutcome::Aborted) => break,
                    }
                }
                note_skipped_chain(config, skipped);
            }
        }
    }
}

/// Run an `assert [not] <request>` step. The request goes out like any other
/// (echoed in `-sa`, status line printed) but its body is never shown — the
/// answer is pass/fail. A failed assertion exits 1 with the reason (`404 Not
/// Found`, or the falsy body such as `0`); an error status exits 1 through the
/// usual path, since a pre-check that couldn't be answered mustn't let the
/// batch proceed. Returns `false` only when the user aborted at the preview.
fn run_assert(config: &mut Config, negate: bool, request: &str) -> bool {
    // Validated at parse time; a None here would be a parser bug.
    let Some((method, uri, body)) = parse_request_line(request) else {
        eprintln!("error: {} is not a request", request);
        exit_process(1);
    };
    let line = format_assert(negate, request);
    if config.bulk_silent {
        outln!("{}", line);
    }

    config.check_only = true;
    // `assert not` is asking for a "no", so the 404 that satisfies it isn't
    // an alarm.
    config.expect_falsy = negate;
    config.last_response = None;
    let outcome = run_non_interactive(config, &method, &uri, &body);
    config.check_only = false;
    config.expect_falsy = false;
    let response = config.last_response.take();

    match outcome {
        RequestOutcome::Truthy if !negate => true,
        RequestOutcome::Falsy if negate => true,
        RequestOutcome::Truthy | RequestOutcome::Falsy => {
            let why = response
                .map(|(status, body)| describe_check_response(status, &body))
                .unwrap_or_default();
            eprintln!("error: assertion failed: {} ({})", line, why);
            exit_process(1);
        }
        RequestOutcome::Errored => {
            eprintln!("error: {} — could not be evaluated, aborting", line);
            config.last_response = response;
            exit_on_unjudged_check(config);
        }
        RequestOutcome::Aborted => false,
    }
}

/// Execute a `confirm [message]` step. Displays the confirm line in `-sa` mode
/// and asks the user for confirmation. Returns true if they confirm (Y/yes/empty),
/// false (exit 0 with `aborted` message) if they decline. When the question
/// can't be answered (end of input, read error) the process exits 1.
fn run_confirm(config: &Config, message: &Option<String>) -> bool {
    let line = format_confirm(message);
    if config.bulk_silent {
        outln!("{}", line);
    }
    ask_yes_no(&format!("{} [Y/n]", confirm_prompt_text(message)))
}

/// Poll `request` every `interval` until it stops being truthy (falsy, when
/// `negate`). The first check is immediate. Polls print nothing themselves; in
/// `-sa` mode the loop logs one line when it starts and one when it ends, so a
/// long wait is explained and a stalled one is diagnosable. An error outcome
/// (401/403/5xx/timeout) aborts the run like it would in a chain — retrying an
/// unanswerable question forever is the worst thing a poll could do. Returns
/// `false` only when the user aborted, so the caller stops the batch.
fn run_sleep_while(config: &mut Config, interval: Duration, negate: bool, request: &str) -> bool {
    let line = format_sleep_while(interval, negate, request);
    if config.bulk_silent {
        outln!("{}", line.dimmed());
    }
    // Validated at parse time; a None here would be a parser bug.
    let Some((method, uri, body)) = parse_request_line(request) else {
        eprintln!("error: {} is not a request", request);
        exit_process(1);
    };

    let start = Instant::now();
    let mut checks = 0usize;
    loop {
        checks += 1;
        config.quiet = true;
        config.last_response = None;
        let outcome = run_non_interactive(config, &method, &uri, &body);
        config.quiet = false;
        match outcome {
            RequestOutcome::Truthy if negate => break,
            RequestOutcome::Falsy if !negate => break,
            RequestOutcome::Truthy | RequestOutcome::Falsy => {}
            RequestOutcome::Errored => {
                eprintln!(
                    "error: {} — condition could not be evaluated (check {}), aborting",
                    line, checks
                );
                exit_on_unjudged_check(config);
            }
            RequestOutcome::Aborted => return false,
        }
        thread::sleep(interval);
    }

    if config.bulk_silent {
        let plural = if checks == 1 { "check" } else { "checks" };
        outln!(
            "{}",
            format!("↳ waited {} ({} {})", format_elapsed(start.elapsed()), checks, plural).dimmed()
        );
    }
    true
}

/// Run one bulk request line, echoing it first in `-a` mode. `None` when the
/// line isn't a request at all.
fn run_bulk_request(config: &mut Config, request: &str) -> Option<RequestOutcome> {
    let (method, uri, body) = parse_request_line(request)?;
    if config.bulk_silent {
        // The line as the preview shows it: the body compacted, the outfile
        // last. Unstyled, like the TUI log.
        outln!("{}", format_request_preview(&method, &uri, &body));
    }
    Some(run_non_interactive(config, &method, &uri, &body))
}

/// Report that a falsy condition cut a chain short, so a skipped write is never
/// silent. Goes to whichever stream carries that run's log.
fn note_skipped_chain(config: &Config, skipped: usize) {
    if skipped == 0 {
        return;
    }
    let plural = if skipped == 1 { "request" } else { "requests" };
    let note = format!("↳ skipped {} {}", skipped, plural).dimmed().to_string();
    if config.bulk_silent {
        outln!("{}", note);
    } else {
        eprintln!("{}", note);
    }
}

/// A `sleep` interval as the file would write it: whole seconds as `Ns`,
/// sub-second as `Nms`, anything in between with its fraction (`1.5s`).
fn format_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms % 1000 == 0 {
        format!("{}s", ms / 1000)
    } else if ms < 1000 {
        format!("{}ms", ms)
    } else {
        let s = format!("{:.3}", d.as_secs_f64());
        format!("{}s", s.trim_end_matches('0').trim_end_matches('.'))
    }
}

fn run_bulk(config: &mut Config, file_path: &str) {
    let (contents, base_dir) = match read_api_file(file_path) {
        Ok(read) => read,
        Err(e) => {
            eprintln!("error: {}", e);
            exit_process(1);
        }
    };
    run_bulk_from_str(config, &contents, base_dir.as_deref());
}

/// What one request is made of, apart from the connection it is sent on. It
/// is what `build_request` turns into a request, as many times as needed: the
/// first attempt, and the one after a token was renewed, are the same.
#[derive(Debug, Clone)]
struct RequestParts {
    method: String,
    /// The URI as written, without its ` > outfile`.
    uri: String,
    /// The body as written: JSON text, or `@file` with its `~map()`.
    body: String,
    /// Where the response goes, when it goes to a file: the extension asks
    /// for a format.
    outfile: Option<String>,
    /// Ask the server to stream (`;stream=true`).
    streaming: bool,
}

/// What an outfile's extension says the file holds. Read in any case, so
/// `out.CSV` is a CSV file to `Accept` as it is to `>>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutFormat {
    Json,
    Ndjson,
    Csv,
    Sql,
}

fn outfile_format(path: &str) -> OutFormat {
    let lower = path.to_lowercase();
    if lower.ends_with(".ndjson") || lower.ends_with(".njson") {
        OutFormat::Ndjson
    } else if lower.ends_with(".csv") {
        OutFormat::Csv
    } else if lower.ends_with(".sql") {
        OutFormat::Sql
    } else {
        OutFormat::Json
    }
}

/// The `Accept` an outfile asks for, when its extension asks for one.
fn accept_for_outfile(path: &str) -> Option<&'static str> {
    match outfile_format(path) {
        OutFormat::Ndjson => Some("application/x-ndjson"),
        OutFormat::Csv => Some("text/csv"),
        OutFormat::Sql => Some("application/sql"),
        OutFormat::Json => None,
    }
}

/// The `Authorization` header for a connection: a token is Bearer, and so is
/// a key that has the shape of a JWT; any other key is Basic with an empty
/// user name. Every request the client makes gets its header here, so a key
/// is never Bearer for one call and Basic for another.
fn auth_header(config: &Config) -> Option<String> {
    if !config.token.is_empty() {
        Some(format!("Bearer {}", config.token))
    } else if config.api_key.is_empty() {
        None
    } else if config.api_key.starts_with("ey") && config.api_key.len() > 180 {
        Some(format!("Bearer {}", config.api_key))
    } else {
        Some(format!("Basic {}", BASE64.encode(format!(":{}", config.api_key))))
    }
}

/// `~/x` as a path in the home directory (`~\\x` too on Windows); anything
/// else as it is.
fn expand_home(path: &str) -> String {
    match (home_relative(path, cfg!(windows)), dirs::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest).to_string_lossy().into_owned(),
        _ => path.to_string(),
    }
}

/// What follows the `~/` of a path in the home directory, or the `~\` where
/// `\` separates a path too (Windows). `None` for any other path: a `~`
/// elsewhere in a path, or `~user`, is not expanded.
fn home_relative(path: &str, backslash_separates: bool) -> Option<&str> {
    path.strip_prefix("~/")
        .or_else(|| if backslash_separates { path.strip_prefix("~\\") } else { None })
}

/// A request ready to send, and the `Accept` it carries (which says how the
/// response is to be read).
struct BuiltRequest {
    request: reqwest::blocking::RequestBuilder,
    accept: String,
}

/// Build the request for `parts` on the connection in `config`: method, URL,
/// authorization, `Content-Type` and `Accept`, the `~map()` header and the
/// body. The batch, the prompt and the retry after a renewed token all build
/// here. `Err` is an `@file` body that could not be read; nothing is sent.
fn build_request(config: &Config, parts: &RequestParts) -> Result<BuiltRequest, String> {
    let client = build_request_client(config.timeout_secs);
    let url = format!("{}{}", config.base_uri, resolve_request_path(&config.api_path, &parts.uri));

    let mut request = match parts.method.as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "PATCH" => client.patch(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, &url),
        _ => client.get(&url),
    };

    if let Some(authorization) = auth_header(config) {
        request = request.header("Authorization", authorization);
    }

    let mut content_type = "application/json".to_string();
    let mut accept = "application/json".to_string();
    if config.ndjson {
        content_type = "application/x-ndjson".to_string();
        accept = "application/x-ndjson".to_string();
    }

    if parts.body.starts_with('@') {
        // `~func(arg)` suffixes (`~map(name)`) are for `@file` bodies only.
        let (file_body, extra_headers) = parse_body_functions(&parts.body);
        for (name, value) in &extra_headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let file_path_raw = file_body.trim_start_matches("@ ").trim_start_matches('@').trim();
        let file = resolve_at_file_body(file_path_raw)?;
        if let Some(ct) = file.content_type {
            content_type = ct;
        }
        if let Some(ac) = file.accept_type {
            accept = ac;
        }
        request = request.body(file.contents);
    } else if !parts.body.is_empty() {
        request = request.body(parts.body.clone());
    }

    if let Some(asked) = parts.outfile.as_deref().and_then(accept_for_outfile) {
        accept = asked.to_string();
    }
    if parts.streaming {
        content_type.push_str(";stream=true");
        accept.push_str(";stream=true");
    }
    if config.include_nulls {
        accept.push_str(";skipNulls=false");
    }

    let request = request.header("Content-Type", &content_type).header("Accept", &accept);
    Ok(BuiltRequest { request, accept })
}

/// A response, and the token that was fetched to get it, if one was.
struct Sent {
    response: reqwest::blocking::Response,
    /// A renewed OAuth2 token, for the caller to keep for the next request.
    new_token: Option<String>,
}

/// Send a built request. A 401 on a connection that has OAuth2 client
/// credentials means the token ran out: a new one is fetched, once, and the
/// same request (`parts`, built again with the new token) is sent again. The
/// second answer is the answer, 401 or not.
fn send_request(config: &Config, parts: &RequestParts, built: BuiltRequest) -> Result<Sent, reqwest::Error> {
    let response = built.request.send()?;
    let renewable = response.status().as_u16() == 401
        && !config.oauth2_client_id.is_empty()
        && !config.oauth2_client_secret.is_empty();
    if renewable {
        let exchanged = oauth2_token_exchange(&config.base_uri, &config.oauth2_client_id, &config.oauth2_client_secret);
        if let Ok((token, _)) = exchanged {
            let mut renewed = config.clone();
            renewed.token = token.clone();
            if let Ok(again) = build_request(&renewed, parts) {
                return Ok(Sent { response: again.request.send()?, new_token: Some(token) });
            }
        }
    }
    Ok(Sent { response, new_token: None })
}

/// Why a response streamed to an outfile did not get there.
enum StreamFailure {
    /// The file could not be created or put in place: a local problem.
    Write(io::Error),
    /// The body stopped or the transfer failed partway.
    Body(io::Error),
}

/// Stream a response body to `path`. The bytes go to `<path>.part` and the
/// file takes its name only once the body has ended, so a transfer that
/// fails leaves no file that looks complete: the target is as it was.
fn stream_to_outfile(resp: impl IoRead, path: &str) -> Result<StreamedBody, StreamFailure> {
    let part = format!("{}.part", path);
    let file = fs::File::create(&part).map_err(StreamFailure::Write)?;
    let mut writer = io::BufWriter::new(file);
    let streamed = stream_to_sink(resp, &mut writer);
    drop(writer);
    let result = match streamed {
        Ok(body) => fs::rename(&part, path).map(|()| body).map_err(StreamFailure::Write),
        Err(e) => Err(StreamFailure::Body(e)),
    };
    if result.is_err() {
        let _ = fs::remove_file(&part);
    }
    result
}

/// A buffered body as it is written to a file or the clipboard: JSON is
/// indented, unless `-r` or `--ndjson` asked for it as it came. Anything
/// that is not JSON (CSV, SQL, NDJSON of several lines) is left alone.
fn outfile_text(config: &Config, body: &str) -> String {
    if config.raw || config.ndjson {
        return body.to_string();
    }
    match serde_json::from_str::<Value>(body) {
        Ok(json) => serde_json::to_string_pretty(&json).unwrap_or_else(|_| body.to_string()),
        Err(_) => body.to_string(),
    }
}

/// Where a response goes instead of the screen.
struct OutTarget<'a> {
    /// The path to write, `~/` expanded.
    path: &'a str,
    /// The path as written, for messages.
    display: &'a str,
    append: bool,
}

impl OutTarget<'_> {
    fn is_clipboard(&self) -> bool {
        is_clipboard_target(self.display)
    }

    /// Put `text` there and say how many bytes that added.
    fn deliver(&self, text: &str) -> io::Result<u64> {
        if self.is_clipboard() {
            return cli_clipboard::set_contents(text.to_string())
                .map(|()| text.len() as u64)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));
        }
        if self.append {
            let before = file_len(self.path);
            append_to_outfile(self.path, text).map(|()| file_len(self.path).saturating_sub(before))
        } else {
            write_outfile(self.path, text)
        }
    }

    /// What to say when `deliver` failed.
    fn failure(&self, e: &io::Error) -> String {
        if self.is_clipboard() {
            format!("clipboard unavailable: {}", e)
        } else {
            format!("Error writing to {}: {}", self.path, e)
        }
    }

    /// The `> file (size)` line under the status line.
    fn marker(&self, bytes: u64) -> String {
        let name = if self.is_clipboard() { "clipboard" } else { self.display };
        outfile_marker(name, bytes, self.append)
    }
}

/// A response body that stopped before its end, or took longer than the
/// timeout, in words.
fn describe_body_failure(e: &io::Error, timeout_secs: u64) -> String {
    if io_error_is_timeout(e) {
        format!(
            "Timed out after {} — raise it with --timeout <seconds> (0 = no timeout)",
            describe_timeout(timeout_secs)
        )
    } else {
        format!("The response was cut short: {}", e)
    }
}

/// A batch or a one-shot got a response it could not read to the end. That
/// is no answer at all, like a request that got no response: the run ends
/// with exit 1, with or without `-f`, from a plain line, a chain or a check.
fn exit_on_body_failure(config: &Config, e: &io::Error) -> ! {
    eprintln!();
    eprintln!("{}\n", describe_body_failure(e, config.timeout_secs));
    exit_process(1);
}

/// A batch or a one-shot could not write what a request was to leave behind
/// (an outfile, the clipboard). The message is out. For a single request and
/// under `-f` that ends the run; otherwise the batch goes on as it does past
/// a failed request, and a chain stops there.
fn local_write_failed(config: &Config) -> RequestOutcome {
    if config.fail_fast || config.one_shot {
        exit_process(1);
    }
    RequestOutcome::Errored
}

/// Send one request and report what it means for a `&&` chain. Errors are
/// printed here; deciding whether they end the run is the caller's business
/// (bulk exits 1, the TUI stops the chain and stays open).
fn run_non_interactive(config: &mut Config, method: &str, uri: &str, body: &str) -> RequestOutcome {
    let is_tty = io::stdout().is_terminal();

    // Ensure colors work on stderr even when stdout is piped
    if io::stderr().is_terminal() {
        colored::control::set_override(true);
    }

    require_base_uri(config);

    // Preview: show the request and confirm before sending (and before any
    // network call such as the feature-flag fetch below).
    if config.preview {
        let line = format_request_preview(method, uri, body);
        if !confirm_preview(&[line], &config.base_uri) {
            // Declined before sending — nothing ran, so a chain must not continue.
            return RequestOutcome::Aborted;
        }
        config.preview = false;
    }

    // The ` > outfile` / ` >> outfile` that `parse_request_line` left on the URI.
    let (actual_uri, redirect) = split_uri_outfile(uri);
    let actual_uri = actual_uri.trim();
    let outfile_append = redirect.starts_with(" >>");
    let display_outfile: Option<String> = (!redirect.is_empty())
        .then(|| redirect.trim_start_matches([' ', '>']).trim().to_string());
    let outfile: Option<String> = display_outfile.as_deref().map(expand_home);
    let target = match (&outfile, &display_outfile) {
        (Some(path), Some(display)) => Some(OutTarget { path, display, append: outfile_append }),
        _ => None,
    };
    let is_clipboard = target.as_ref().is_some_and(|t| t.is_clipboard());

    // Streaming is opt-in and already resolved from --stream/API_STREAMING, so
    // there is no per-request feature-flag round trip here. A server that
    // doesn't stream ignores the unknown `;stream=true` media-type parameter.
    // `--export` rewrites the whole body, so it is read whole: streaming is
    // not asked for, and an error then arrives as a status, not mid-payload.
    config.streaming = config.stream_requested && config.export_id.is_none();

    let parts = RequestParts {
        method: method.to_string(),
        uri: actual_uri.to_string(),
        body: body.to_string(),
        outfile: outfile.clone(),
        streaming: config.streaming,
    };
    let built = match build_request(config, &parts) {
        Ok(built) => built,
        Err(e) => {
            eprintln!("{}", e);
            exit_process(1);
        }
    };
    let accept = built.accept.clone();

    let start = Instant::now();

    // Drawn on stderr, so it needs a terminal there; a poll prints nothing at all.
    let progress = TransferProgress::new();
    let mut ticker = ProgressTicker::start(
        Arc::clone(&progress),
        io::stderr().is_terminal() && !config.silent && !config.quiet,
    );

    let resp = match send_request(config, &parts, built) {
        Ok(sent) => {
            if let Some(token) = sent.new_token {
                config.token = token;
            }
            sent.response
        }
        Err(e) => {
            ticker.stop();
            eprintln!();
            if e.is_timeout() {
                eprintln!(
                    "Timed out after {} — raise it with --timeout <seconds> (0 = no timeout)\n",
                    describe_timeout(config.timeout_secs)
                );
            } else if let Some(tls) = tls_failure(&e) {
                eprintln!("{}\n", describe_tls_failure(tls, host_of(&config.base_uri)));
            } else {
                eprintln!("Is COS running on {}? 🤔\n", host_of(&config.base_uri));
            }
            exit_process(1);
        }
    };

    let status = resp.status();
    let elapsed = start.elapsed();
    progress.headers_arrived(&resp);

    // Streaming needs a sink that accepts bytes as they arrive, which
    // rules out everything that must see the whole body first: pretty
    // printing, `>>` merging, and the clipboard. Non-2xx buffers too, so
    // an error payload never streams into an outfile.
    let stream_body = config.streaming
        && status.is_success()
        && !config.quiet
        && !config.check_only
        && !is_clipboard
        && !outfile_append
        && (outfile.is_some() || config.bulk_silent || config.raw || config.ndjson || !is_tty);

    // Print status. A quiet poll only speaks up when the status is an
    // error, so the abort that follows has a reason next to it.
    if !config.silent && (!config.quiet || status_is_error(status.as_u16())) {
        let status_str = format_status(status, config.expect_falsy);

        ticker.interrupt(|| {
            if config.bulk_silent {
                // Bulk silent mode: print compact status to stdout with box-draw prefix
                outln!(
                    "{}HTTP/1.1 {} {}",
                    "└─".dimmed(),
                    status_str,
                    format_latency(elapsed).dimmed()
                );
            } else {
                eprintln!(
                    "HTTP/1.1 {} {}",
                    status_str,
                    format_latency(elapsed).dimmed()
                );
                // The body follows straight under the status line; the
                // "> outfile" line, when there is one, takes its place.
            }
        });
    }

    if stream_body {
        // A body printed live to the terminal would fight the progress
        // line for the same screen.
        if outfile.is_none() && !config.bulk_silent && is_tty {
            ticker.stop();
        }
        let resp = CountingReader::new(resp, &progress);
        let streamed = if let Some(target) = &target {
            let res = stream_to_outfile(resp, target.path);
            ticker.stop();
            match res {
                Ok(body) => {
                    if !config.silent && !config.bulk_silent {
                        // Match the buffered path: status line, then `> outfile`.
                        eprintln!("{}", target.marker(body.bytes).dimmed());
                    }
                    Ok(body)
                }
                Err(StreamFailure::Write(e)) => {
                    eprintln!("{}", target.failure(&e));
                    return local_write_failed(config);
                }
                Err(StreamFailure::Body(e)) => Err(e),
            }
        } else if config.bulk_silent {
            // Bodies are suppressed here, but the response still has to be
            // drained before the next request reuses the connection.
            stream_to_sink(resp, &mut io::sink())
        } else {
            let mut lock = Out;
            let res = stream_to_sink(resp, &mut lock);
            ticker.stop();
            // Match the buffered path's trailing newline (and the blank
            // separator line on a TTY) so piping gives identical bytes.
            if let Ok(ref body) = res {
                if !matches!(body.last_byte, Some(b'\n') | None) {
                    let _ = writeln!(lock);
                }
                let _ = lock.flush();
                if is_tty && !config.silent {
                    eprintln!();
                }
            }
            res
        };

        ticker.stop();
        return match streamed {
            Ok(body) => classify_streamed(status.as_u16(), &body.prefix, body.overflowed),
            // The body broke off partway. Nothing of it is left in the
            // outfile, and the run ends: this was no answer.
            Err(e) => exit_on_body_failure(config, &e),
        };
    }

    // Read once, up front: the outcome depends on the body, and the
    // branches below each need it (or would drain it anyway). A body that
    // can't be read to its end is not an empty body.
    let body_text = match read_body_text(resp, &progress) {
        Ok(text) => text,
        Err(e) => {
            ticker.stop();
            exit_on_body_failure(config, &e);
        }
    };
    ticker.stop();
    let outcome = classify_response(status.as_u16(), &body_text);

    // A poll or assert wants the verdict only; the body has been drained
    // above. Keep it so the caller can explain a failed check.
    if config.quiet || config.check_only {
        config.last_response = Some((status.as_u16(), body_text));
        return outcome;
    }

    // `-f`: this response ends the run. Nothing is written to an
    // outfile; the error is not the data the file was meant to hold.
    if fail_fast_trips(config, status.as_u16()) {
        fail_fast_exit(&body_text);
    }

    // `--export`: what is printed, written or copied from here on is
    // the seed data. The chain's verdict above was taken from what the
    // server said, and an error body is left as it came.
    let body_text = match &config.export_id {
        Some(id_key) if status.is_success() => {
            let exported = export_body(
                &body_text,
                id_key,
                accept.starts_with("application/x-ndjson"),
                config.raw,
            );
            if let Some(warning) = export_warning(&exported) {
                eprintln!("{}", warning);
            }
            exported.text
        }
        _ => body_text,
    };

    if let Some(target) = &target {
        // To a file or the clipboard; in `-sa` mode too, where bodies are
        // otherwise not shown.
        match target.deliver(&outfile_text(config, &body_text)) {
            Ok(written) => {
                // Match interactive output: status line already printed,
                // now ">/>> outfile (size)" (dimmed) on the next line.
                if !config.silent && !config.bulk_silent {
                    eprintln!("{}", target.marker(written).dimmed());
                }
            }
            Err(e) => {
                eprintln!("{}", target.failure(&e));
                return local_write_failed(config);
            }
        }
    } else if !config.bulk_silent {
        let output = if config.raw || config.ndjson || !is_tty {
            // As it came: for `-r`, and for a pipe.
            body_text
        } else {
            outfile_text(config, &body_text)
        };
        out!("{}", output);
        if !output.ends_with('\n') {
            outln!();
        }
        if is_tty && !config.silent {
            eprintln!();
        }
    }

    outcome
}

fn run_interactive(config: Config, op_selector: Option<String>, from_setup: bool, connection_alias: String, connecting_to: Option<String>, oauth2_creds: Option<(String, String)>, startup_preloaded: Option<BackgroundLoadResult>, from_cli_auth: bool) -> io::Result<()> {
    // Get initial terminal size
    let (width, height) = terminal::size()?;

    let is_1p = op_selector.is_some();
    let is_connecting = connecting_to.is_some();

    // For non-1P (unless connecting from picker): load synchronously before showing UI
    // For 1P or connecting: show UI immediately with loading spinner
    let (preloaded, config) = if let Some(pre) = startup_preloaded {
        // Already preloaded from connection flow - skip duplicate requests
        (Some(pre), config)
    } else if !is_1p && !is_connecting {
        if config.base_uri.is_empty() {
            eprintln!("{}", "Error: no base URL specified. Use -b <url> or -c <connection>.".red());
            exit_process(1);
        }
        let result = background_load(&config, None);
        if let Some(err) = &result.error {
            // Auth error (401/403)
            if err.contains("401") || err.contains("403") {
                // If explicit -b and -k were provided, or localhost, show error and exit
                let is_localhost = config.base_uri.contains("localhost")
                    || config.base_uri.contains("127.0.0.1")
                    || config.base_uri.contains("[::1]");
                if from_cli_auth || is_localhost {
                    eprintln!("{}", err);
                    exit_process(1);
                }
                // Otherwise launch connection flow with picker
                let (term_width, _) = terminal::size().unwrap_or((80, 24));
                let envs = list_connections();
                let mut flow = ConnectionFlow::for_startup(&envs, term_width, true);
                // Pre-fill URL from -b arg so user only needs to provide auth
                if !config.base_uri.is_empty() {
                    flow.setup_url = config.base_uri.clone();
                    flow.setup_active_field = SetupField::Auth;
                    flow.in_setup = true;
                }

                let mut stdout = io::stdout();
                terminal::enable_raw_mode().unwrap();
                execute!(stdout, cursor::Hide).unwrap();

                match flow.run(&mut stdout) {
                    Ok(ConnectionFlowResult::Connected(env, preloaded, resolved_config)) => {
                        // The session's flags stay; only the connection is new.
                        // A failed token exchange shows when the load below fails.
                        let mut new_config = config.clone();
                        let _ = connect(&mut new_config, &env, resolved_config);
                        // Stay on form with animated spinner while loading
                        let new_result = if let Some(pre) = preloaded {
                            pre
                        } else {
                            let bg_config = new_config.clone();
                            let (tx, rx) = std::sync::mpsc::channel();
                            thread::spawn(move || { let _ = tx.send(background_load(&bg_config, None)); });
                            let mut frame = 0usize;
                            loop {
                                if let Ok(r) = rx.try_recv() {
                                    break r;
                                }
                                flow.setup_status = format!("{} loading...", SPINNER_FRAMES[frame % SPINNER_FRAMES.len()]).dimmed().to_string();
                                flow.render(&mut stdout, false).ok();
                                thread::sleep(Duration::from_millis(80));
                                frame += 1;
                            }
                        };
                        if let Some(new_err) = &new_result.error {
                            eprintln!("{}", new_err);
                            exit_process(1);
                        }

                        let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                        execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                        terminal::disable_raw_mode().unwrap();
                        execute!(stdout, cursor::Show).unwrap();

                        (Some(new_result), new_config)
                    }
                    Ok(ConnectionFlowResult::Cancelled) | Ok(ConnectionFlowResult::Quit) => {
                        let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                        execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                        terminal::disable_raw_mode().unwrap();
                        execute!(stdout, cursor::Show).unwrap();
                        exit_process(0);
                    }
                    Err(e) => {
                        let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                        execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                        terminal::disable_raw_mode().unwrap();
                        execute!(stdout, cursor::Show).unwrap();
                        eprintln!("Error: {}", e);
                        exit_process(1);
                    }
                }
            } else {
                eprintln!("{}", err);
                exit_process(1);
            }
        } else if !result.connected && !from_setup {
            // Connection failed - exit
            let host = config.base_uri.trim_start_matches("https://").trim_start_matches("http://");
            eprintln!("{}", format!("Could not connect to {}", host).red());
            exit_process(1);
        } else {
            (Some(result), config)
        }
    } else {
        (None, config)
    };

    // Print splash (skip when from_setup - connection flow already showed splash)
    if !from_setup {
        if is_1p || is_connecting {
            // Blank URL while loading
            print_splash_loading(&config, width);
        } else {
            print_splash_with_width(&config, width);
        }
        io::stdout().flush().ok();
    }

    // Enter raw mode. From here on every way out restores the terminal.
    let _terminal_guard = TerminalGuard;
    terminal::enable_raw_mode()?;

    let mut stdout = io::stdout();

    // Enable kitty keyboard protocol for Shift+Enter, Alt+Enter detection
    // Only if the terminal actually supports it (iTerm2, Kitty, WezTerm, Ghostty, etc.)
    let enhanced_keyboard = crossterm::terminal::supports_keyboard_enhancement()
        .unwrap_or(false);
    if enhanced_keyboard {
        let _ = execute!(
            stdout,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        );
        KEYBOARD_FLAGS_PUSHED.store(true, Ordering::SeqCst);
    }

    // Enable bracketed paste so multi-character pastes arrive as one Event::Paste —
    // lets us recognize and expand pasted JSON identifier structures.
    let _ = execute!(stdout, EnableBracketedPaste);
    BRACKETED_PASTE_ON.store(true, Ordering::SeqCst);

    let mut state = AppState::new(config.clone());
    state.width = width;
    state.height = height;
    state.history = load_history();

    state.connection_alias = connection_alias.clone();

    // Store OAuth2 credentials for token refresh
    if let Some((client_id, client_secret)) = oauth2_creds {
        // From setup flow or passed explicitly
        state.config.oauth2_client_id = client_id;
        state.config.oauth2_client_secret = client_secret;
    } else if !connection_alias.is_empty() {
        // From saved connection
        if let Some(env) = load_connection(&connection_alias) {
            if env.auth_type == "oauth2" {
                state.config.oauth2_client_id = env.client_id.clone();
                state.config.oauth2_client_secret = env.credential.clone();
            }
        }
    }

    if from_setup && connection_alias.is_empty() {
        state.status_msg = "ctrl+s to save this connection".to_string();
        state.status_msg_at = Some(Instant::now());
    } else if from_setup && !connection_alias.is_empty() {
        // From picker - show connected message
        state.status_msg = format!("connected to: {}", connection_alias);
        state.status_msg_at = Some(Instant::now());
    } else {
        // Splash was printed at startup, mark it for consecutive env switch optimization
        state.last_was_splash = true;
        // Show connection status (skip if async loading will provide it)
        if !is_connecting {
            let connected = preloaded.as_ref().map(|r| r.connected).unwrap_or(false);
            if !connection_alias.is_empty() {
                if connected {
                    state.status_msg = format!("connected to: {}", connection_alias);
                } else {
                    state.status_msg = format!("{}: {}", connection_alias, "connection failed".red());
                }
                state.status_msg_at = Some(Instant::now());
            } else if !connected && preloaded.is_some() {
                // No env alias but explicit -b flag and connection failed
                state.status_msg = "connection failed".red().to_string();
                state.status_msg_at = Some(Instant::now());
            }
        }
    }

    // Apply preloaded results if available (non-1P mode)
    if let Some(result) = preloaded {
        apply_background_result(&mut state, result);
    }

    // Print initial placeholder lines so first render can move up
    execute!(stdout, Print("\r\n\r\n\r\n"))?;

    // Initial render
    render(&mut stdout, &mut state)?;

    // For 1P or connecting from picker: start background loading
    let mut bg_rx: Option<std::sync::mpsc::Receiver<BackgroundLoadResult>> = None;
    if is_1p || is_connecting {
        state.loading = true;
        state.loading_connection_name = connecting_to.clone().or(op_selector.clone());
        let bg_config = config.clone();
        let (tx, rx) = std::sync::mpsc::channel::<BackgroundLoadResult>();
        bg_rx = Some(rx);
        thread::spawn(move || {
            let result = background_load(&bg_config, op_selector);
            let _ = tx.send(result);
        });
    }

    loop {
        // A resize that arrived during a wait is drawn now.
        if state.resize_pending {
            let (w, h) = (state.width, state.height);
            redraw_after_resize(&mut state, &mut stdout, w, h)?;
        }
        // Poll for events with timeout for resize handling
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key_event) if key_event.kind == event::KeyEventKind::Press => {
                    if state.loading {
                        // Only allow ctrl+c while loading
                        if key_event.modifiers == KeyModifiers::CONTROL && key_event.code == KeyCode::Char('c') {
                            break;
                        }
                    } else {
                        let (should_exit, new_rx) = handle_key_event(&mut state, key_event, &mut stdout)?;
                        if let Some(rx) = new_rx {
                            bg_rx = Some(rx);
                        }
                        if should_exit {
                            break;
                        }
                    }
                }
                Event::Paste(s) if !state.loading => {
                    handle_paste(&mut state, &s, &mut stdout)?;
                }
                Event::Resize(w, h) => {
                    redraw_after_resize(&mut state, &mut stdout, w, h)?;
                }
                _ => {}
            }
        }
        // Check for background load completion
        if let Some(ref rx) = bg_rx {
        if let Ok(result) = rx.try_recv() {
            if let Some(err) = &result.error {
                state.loading = false;
                // If from picker (is_connecting), show error message instead of exiting
                if is_connecting {
                    if let Some(ref env_name) = state.loading_connection_name {
                        if err.contains("401") {
                            state.status_msg = format!("{}: {}", env_name, "unauthorized".red());
                        } else if err.contains("403") {
                            state.status_msg = format!("{}: {}", env_name, "forbidden".red());
                        } else {
                            state.status_msg = format!("{}: {}", env_name, "auth failed".red());
                        }
                        state.status_msg_at = Some(Instant::now());
                    }
                    state.loading_connection_name = None;
                    bg_rx = None;  // Clear the receiver
                    // Continue running - user can delete the env or try another
                } else {
                    // Fatal error (e.g., 1Password failed) — clean up and exit
                    let err_msg = err.clone();

                    // Restore terminal
                    leave_prompt_modes();
                    // Move up to top of splash and clear from there down:
                    // hint + input + ruler, then the splash itself.
                    let total_up = 2 + state.prev_input_lines + splash_line_count(state.width);
                    execute!(
                        stdout,
                        cursor::MoveUp(total_up.min(state.height.saturating_sub(1))),
                        cursor::MoveToColumn(0),
                        Clear(ClearType::FromCursorDown),
                        cursor::Show
                    )?;
                    terminal::disable_raw_mode()?;
                    if err_msg.starts_with("HTTP/") {
                        eprintln!("{}", err_msg);
                    } else {
                        eprintln!("Error: {}", err_msg);
                    }
                    exit_process(1);
                }
            } else {
                state.loading = false;
                // Show status message based on connection result
                if let Some(ref env_name) = state.loading_connection_name {
                    if result.connected {
                        state.status_msg = format!("connected to: {}", env_name);
                    } else {
                        state.status_msg = format!("{}: {}", env_name, "connection failed".red());
                    }
                    state.status_msg_at = Some(Instant::now());
                }
                state.loading_connection_name = None;
                apply_background_result(&mut state, result);
            }

            // Update the splash URL line after the background load completes:
            // when the splash is the box that has such a line. On a terminal
            // too narrow for the box the splash is one blank row, and the
            // rewrite would land on a row that is not its own.
            if splash_line_count(state.width) == 5 {
                // Loading resolved — update just the splash URL line in place
                // From cursor (bottom of input area), the URL line is:
                //   hint + input_lines + ruler + blank_after_splash + bottom_border
                let url_line_offset = 2 + state.prev_input_lines + 3;
                let host = state.config.base_uri.as_str();
                let full_width = 60usize;
                let hint_section_width = 20usize;
                let term_w = state.width as usize;
                let show_hint = term_w >= full_width;
                let actual_width = if show_hint {
                    full_width
                } else {
                    term_w.max(36).min(full_width - hint_section_width + 2)
                };
                let url_line = if show_hint {
                    let hint = "ctrl+b for docs";
                    let host_space = actual_width - 7 - hint.len();
                    let host_display = head_chars(host, host_space);
                    let host_padded = format!("{:width$}", host_display, width = host_space);
                    format!("{}{}{}{}{}", "│ ".dimmed(), host_padded.dimmed(), " │ ".dimmed(), hint.dimmed(), " │".dimmed())
                } else {
                    let host_space = actual_width.saturating_sub(4);
                    let host_display = head_chars(host, host_space);
                    let host_padded = format!("{:width$}", host_display, width = host_space);
                    format!("{}{}{}", "│ ".dimmed(), host_padded.dimmed(), " │".dimmed())
                };
                execute!(
                    stdout,
                    cursor::SavePosition,
                    cursor::MoveUp(url_line_offset.min(state.height.saturating_sub(1))),
                    cursor::MoveToColumn(0),
                    Clear(ClearType::CurrentLine),
                    Print(url_line),
                    cursor::RestorePosition
                )?;
            }
            render(&mut stdout, &mut state)?;
        }
        }
        // Animate loading spinner
        if state.loading {
            state.loading_frame += 1;
            render(&mut stdout, &mut state)?;
        }
        // Auto-clear status message after its 3 seconds, animate spinner while active
        if let Some(at) = state.status_msg_at {
            if at.elapsed() >= STATUS_MSG_TTL {
                state.status_msg.clear();
                state.status_msg_at = None;
                state.ctrl_c_pending = false;
                state.ctrl_c_at = None;
            }
            render(&mut stdout, &mut state)?;
        }
        // Repaint while the indicator pulses, then let it settle to dimmed.
        if let Some(at) = state.streaming_flash_at {
            if at.elapsed() >= Duration::from_millis(400) {
                state.streaming_flash_at = None;
            }
            render(&mut stdout, &mut state)?;
        }
    }

    // Clear input area before exiting (move up and clear to end). When nothing
    // was ever printed, the splash is all that sits above it: take that too,
    // so a session that only opened and closed leaves the shell as it found it.
    let help_lines: u16 = help_line_count(&state);
    let mut lines_to_clear: u16 = if state.show_help { help_lines } else { 2 + state.prev_input_lines };
    if state.output_history.is_empty() {
        lines_to_clear += splash_line_count(state.width);
    }
    execute!(
        stdout,
        cursor::MoveUp(lines_to_clear.min(state.height.saturating_sub(1))),
        cursor::MoveToColumn(0),
        Clear(ClearType::FromCursorDown),
        cursor::Show
    )?;

    // Restore terminal
    leave_prompt_modes();
    terminal::disable_raw_mode()?;

    Ok(())
}

/// Draw the whole screen again for a terminal that is now `w` by `h`: the
/// splash, what has been printed (each request line fitted to the new
/// width), and the command area.
fn redraw_after_resize(state: &mut AppState, stdout: &mut io::Stdout, w: u16, h: u16) -> io::Result<()> {
    state.width = w;
    state.height = h;
    state.resize_pending = false;

    // Disable raw mode first (same as original working code)
    terminal::disable_raw_mode()?;

    // Clear screen and scrollback, move cursor to home
    out!("\x1b[2J\x1b[3J\x1b[H");
    io::stdout().flush().ok();

    // Re-print splash with current terminal width
    print_splash_with_width(&state.config, w);

    // Re-print previous output, re-fitting each request line to the
    // new width rather than replaying it at the old one.
    for block in &state.output_history {
        out!("{}", block.render(w as usize));
    }

    // Placeholder lines for input area (match actual input height)
    let input_lines = state.input.split('\n').count() as u16;
    let placeholder_count = 2 + input_lines; // ruler + input lines + hint
    for _ in 0..placeholder_count {
        outln!();
    }
    io::stdout().flush().ok();

    // Re-enable raw mode
    terminal::enable_raw_mode()?;

    // Reset prev_input_lines so render clears the right amount
    state.prev_input_lines = input_lines;

    // Render input area
    render(stdout, state)
}

/// A resize that arrived while the prompt was waiting (for a response, a
/// `sleep`, an answer): the new size is taken at once, so what is drawn
/// during the wait fits, and the screen is drawn again when the wait ends.
fn note_resize(state: &mut AppState, event: &Event) {
    if let Event::Resize(w, h) = event {
        state.width = *w;
        state.height = *h;
        state.resize_pending = true;
    }
}

fn handle_key_event(
    state: &mut AppState,
    key: KeyEvent,
    stdout: &mut io::Stdout,
) -> io::Result<(bool, Option<std::sync::mpsc::Receiver<BackgroundLoadResult>>)> {
    // Body input mode: intercept all keys
    if state.body_input_mode {
        match (key.modifiers, key.code) {
            // Ctrl+D: finish body input and execute request
            (KeyModifiers::CONTROL, KeyCode::Char('d')) => {
                let body = state.body_input_buffer.trim().to_string();
                let method = state.body_input_method.clone();
                let uri = state.body_input_uri.clone();
                state.body_input_mode = false;
                state.body_input_buffer.clear();
                state.body_input_method.clear();
                state.body_input_uri.clear();

                let input = if body.is_empty() {
                    format!("{} {}", method, uri)
                } else {
                    format!("{} {} {}", method, uri, body)
                };
                // Comments and raw newlines, as a `.api` file would have them.
                let input = normalize_request_text(&input).unwrap_or(input);
                parse_input(state, &input);
                state.history.push(input.clone());
                append_history(&input);
                state.history_idx = -1;
                execute_request(state, stdout)?;

                state.input = format!("{} {}", state.method, state.uri);
                state.cursor_pos = char_len(&state.input);
                render(stdout, state)?;
            }
            // Esc or Ctrl+C: cancel body input
            (_, KeyCode::Esc) | (KeyModifiers::CONTROL, KeyCode::Char('c')) => {
                state.body_input_mode = false;
                state.body_input_buffer.clear();
                state.body_input_method.clear();
                state.body_input_uri.clear();
                render(stdout, state)?;
            }
            // Enter: newline in body buffer
            (KeyModifiers::NONE, KeyCode::Enter) => {
                state.body_input_buffer.push('\n');
                render(stdout, state)?;
            }
            // Backspace
            (_, KeyCode::Backspace) => {
                state.body_input_buffer.pop();
                render(stdout, state)?;
            }
            // Regular character input
            (KeyModifiers::NONE | KeyModifiers::SHIFT, KeyCode::Char(c)) => {
                state.body_input_buffer.push(c);
                render(stdout, state)?;
            }
            _ => {}
        }
        return Ok((false, None));
    }

    // Reset completion state on any key except Tab, BackTab, Esc
    let dominated_by_completions = key.code == KeyCode::Tab
        || key.code == KeyCode::BackTab
        || key.code == KeyCode::Esc;
    if !dominated_by_completions {
        state.completions.clear();
        state.completion_idx = 0;
        state.last_tab_input.clear();
        state.completion_uri_suffix.clear();
    }

    // If help is showing, close it on any key except esc/ctrl+h/ctrl+c, then process the key
    if state.show_help {
        let is_help_key = key.code == KeyCode::Esc
            || (key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('h'))
            || (key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c'));
        if !is_help_key {
            state.show_help = false;
            render(stdout, state)?;
        }
    }

    // Reset ctrl+c pending on any non-ctrl+c key
    if !(key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c')) {
        if state.ctrl_c_pending {
            state.ctrl_c_pending = false;
            state.ctrl_c_at = None;
            state.status_msg.clear();
            state.status_msg_at = None;
            render(stdout, state)?;
        }
    }

    match (key.modifiers, key.code) {
        // Quit (ctrl+c double-press)
        (KeyModifiers::CONTROL, KeyCode::Char('c')) => {
            if state.ctrl_c_pending {
                // Second press — exit
                return Ok((true, None));
            }
            // First press — show hint
            state.ctrl_c_pending = true;
            state.ctrl_c_at = Some(std::time::Instant::now());
            state.status_msg = "ctrl+c again to exit".to_string();
            state.status_msg_at = Some(std::time::Instant::now());
            render(stdout, state)?;
        }

        // Esc: close completions, close help, or do nothing
        (_, KeyCode::Esc) => {
            if !state.completions.is_empty() {
                state.completions.clear();
                state.completion_idx = 0;
                state.last_tab_input.clear();
                state.completion_uri_suffix.clear();
                render(stdout, state)?;
            } else if state.show_help {
                state.show_help = false;
                render(stdout, state)?;
            }
        }

        // Toggle help
        (KeyModifiers::CONTROL, KeyCode::Char('h')) => {
            state.show_help = !state.show_help;
            render(stdout, state)?;
        }

        // Shift+Tab: reverse autocomplete
        (KeyModifiers::SHIFT, KeyCode::BackTab) | (_, KeyCode::BackTab) => {
            if !state.completions.is_empty() {
                if extract_file_path_context(&state.input, state.cursor_pos).is_some() {
                    handle_file_tab_completion_reverse(state);
                } else if state.config.experimental && cursor_inside_brackets(&state.input, state.cursor_pos) {
                    with_chain_segment_view(state, |state| handle_json_tab_completion(state, true, true));
                } else if state.config.complete {
                    with_chain_segment_view(state, handle_tab_completion_reverse);
                }
                render(stdout, state)?;
            }
        }

        // Tab: autocomplete only
        (_, KeyCode::Tab) => {
            // Check if we're in file completion mode (after > or @) and cursor is in the file path region
            if extract_file_path_context(&state.input, state.cursor_pos).is_some_and(|ctx| {
                let path_char_start = state.input[..ctx.path_start].chars().count();
                state.cursor_pos >= path_char_start
            }) {
                handle_file_tab_completion(state);
                render(stdout, state)?;
            } else if !state.config.complete {
                state.status_msg = "completion not available on this server".to_string();
                state.status_msg_at = Some(std::time::Instant::now());
                render(stdout, state)?;
            } else if state.config.experimental && cursor_inside_brackets(&state.input, state.cursor_pos) {
                // Check for closing bracket ghost before JSON key/value completion
                let closing = get_closing_brackets_ghost(&state.input, state.cursor_pos);
                if !closing.is_empty() {
                    let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
                    let is_multiline = state.input[..byte_idx].contains('\n');
                    if is_multiline {
                        let depth = bracket_depth_at(&state.input, state.cursor_pos) as usize;
                        let dedent = depth.saturating_sub(1);
                        let indent = "  ".repeat(dedent);
                        // Check if cursor is on a blank/whitespace-only line — reuse it
                        let line_start = state.input[..byte_idx].rfind('\n')
                            .map_or(0, |p| p + 1);
                        let line_before = &state.input[line_start..byte_idx];
                        if line_before.chars().all(|c| c == ' ') {
                            // Replace current blank line content with proper indent + bracket
                            let replacement = format!("{}{}", indent, &closing[..1]);
                            state.input.replace_range(line_start..byte_idx, &replacement);
                            state.cursor_pos = char_len(&state.input[..line_start]) + dedent * 2 + 1;
                        } else {
                            let insert = format!("\n{}{}", indent, &closing[..1]);
                            state.input.insert_str(byte_idx, &insert);
                            state.cursor_pos += 1 + dedent * 2 + 1;
                        }
                    } else {
                        state.input.insert_str(byte_idx, &closing[..1]);
                        state.cursor_pos += 1;
                    }
                    state.completions.clear();
                    state.last_tab_input.clear();
                } else {
                    // JSON body tab completion — viewed per segment, so a chain's
                    // second body completes against its own text, not segment 1's.
                    with_chain_segment_view(state, |state| handle_json_tab_completion(state, false, true));
                }
                render(stdout, state)?;
            } else {
                // URI/body-bracket completion, on the cursor's `&&` segment: every
                // check below parses the input as a single request line, so hand it
                // one segment. Renders happen after the view is restored.
                let needs_render = with_chain_segment_view(state, |state| {
                    // If input already has body content (brackets), don't fall through to URI completion
                    let has_body_content = find_body_start(&state.input)
                        .map_or(false, |bs| state.input[bs..].trim().starts_with(|c: char| c == '[' || c == '{'));
                    if has_body_content {
                        // Tab at end of body — ignore
                        return false;
                    }
                    let had_completions = !state.completions.is_empty();
                    let parts: Vec<&str> = state.input.split_whitespace().collect();
                    let uri = if parts.len() >= 2 { parts[1] } else if parts.len() == 1 && parts[0].starts_with('/') { parts[0] } else { "" };

                    // Try body bracket completion first (e.g., Tab after "PUT /people ")
                    let bracket_ghost = if state.config.experimental { get_body_bracket_ghost(state, &parts, uri) } else { String::new() };
                    if !bracket_ghost.is_empty() {
                        // Expand brackets to multiline block with matching closers on one line
                        // e.g. "[{ " → "[{\n  \n}]"  or "{ " → "{\n  \n}"
                        // Brackets on the same line count as one indent level
                        let ins_byte = char_to_byte_idx(&state.input, state.cursor_pos);
                        let trimmed = bracket_ghost.trim();
                        let bracket_count = trimmed.len();
                        // Build closers: reverse of openers on a single line (mirrors the openers)
                        let closers: String = trimmed.chars().rev()
                            .map(|ch| if ch == '[' { ']' } else { '}' })
                            .collect();
                        let expanded = format!("{}\n  \n{}", trimmed, closers);
                        let cursor_offset = bracket_count + 1 + 2; // brackets + \n + 2-space indent
                        state.input.insert_str(ins_byte, &expanded);
                        state.cursor_pos += cursor_offset;
                        return true;
                    }
                    // Complete if URI contains a delimiter (we're typing after /, (, or ~)
                    let has_delim = uri.rfind(|c| c == '/' || c == '(' || c == '~').is_some();
                    let should_complete = has_delim || had_completions;

                    if !state.endpoints.is_empty() && should_complete {
                        handle_tab_completion(state);
                        return true;
                    }
                    false
                });
                if needs_render {
                    render(stdout, state)?;
                }
            }
        }

        // Cycle method (ctrl+space)
        (KeyModifiers::CONTROL, KeyCode::Char(' ')) => {
            cycle_method(state);
            render(stdout, state)?;
        }

        // Quick GET
        (KeyModifiers::CONTROL, KeyCode::Char('g')) => {
            // GET the URI on the line, whatever method, body or outfile the
            // line has: a look at the resource being written to. The line
            // itself is left as it was typed.
            let typed = (state.input.clone(), state.cursor_pos);
            let line = if state.input.trim().is_empty() { "GET /".to_string() } else { state.input.trim().to_string() };
            match classify_prompt_line(&line, typed_export(&state.config)) {
                PromptLine::Request(request) => {
                    parse_input(state, &request);
                    state.method = "GET".to_string();
                    state.body.clear();
                    state.config.outfile.clear();
                    state.config.outfile_append = false;
                    state.display_outfile.clear();
                    state.method_auto_promoted = false;
                    execute_request(state, stdout)?;

                    (state.input, state.cursor_pos) = typed;
                    render(stdout, state)?;
                }
                // A chain, a directive, a file: there is no one URI to GET.
                _ => {
                    state.status_msg = "not a request".to_string();
                    state.status_msg_at = Some(Instant::now());
                    render(stdout, state)?;
                }
            }
        }

        // Clear body
        (KeyModifiers::CONTROL, KeyCode::Char('x')) => {
            let parts: Vec<&str> = state.input.split_whitespace().collect();
            if parts.len() >= 2 {
                state.input = format!("{} {}", parts[0], parts[1]);
                state.cursor_pos = char_len(&state.input);
            }
            auto_revert_method_on_body_clear(state);
            render(stdout, state)?;
        }

        // Clear full
        (KeyModifiers::CONTROL, KeyCode::Char('f')) => {
            state.input = "GET /".to_string();
            state.cursor_pos = 5;
            state.method = "GET".to_string();
            state.uri = "/".to_string();
            state.body.clear();
            state.method_auto_promoted = false;
            render(stdout, state)?;
        }

        // Clear entire input line (ctrl+u)
        (KeyModifiers::CONTROL, KeyCode::Char('u')) => {
            state.input.clear();
            state.cursor_pos = 0;
            state.method.clear();
            state.uri.clear();
            state.body.clear();
            state.method_auto_promoted = false;
            render(stdout, state)?;
        }

        // Open docs
        (KeyModifiers::CONTROL, KeyCode::Char('b')) => {
            let url = api_docs_url(&state.config.base_uri);
            let _ = open_external(&url);
        }

        // Open last file
        (KeyModifiers::CONTROL, KeyCode::Char('o')) => {
            if !state.last_outfile.is_empty() && !open_external(&state.last_outfile) {
                let name = std::path::Path::new(&state.last_outfile)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| state.last_outfile.clone());
                state.status_msg = format!("could not open {}", name);
                state.status_msg_at = Some(Instant::now());
                render(stdout, state)?;
            }
        }

        // Copy curl
        (KeyModifiers::CONTROL, KeyCode::Char('y')) => {
            if copy_curl(state) {
                state.status_msg = "curl command copied to clipboard".to_string();
                state.status_msg_at = Some(std::time::Instant::now());
                render(stdout, state)?;
                // Clear status after delay (status will clear on next action)
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_secs(3));
                });
            }
        }

        // Toggle response streaming (ctrl+t)
        (KeyModifiers::CONTROL, KeyCode::Char('t')) => {
            if state.config.streaming {
                state.config.streaming = false;
                state.config.stream_requested = false;
                state.streaming_flash_at = None;
                clear_streaming_info(state);
            } else if state.config.server_streaming {
                state.config.streaming = true;
                state.config.stream_requested = true;
                state.streaming_flash_at = Some(Instant::now());
                show_streaming_info(state);
            } else {
                state.status_msg = "streaming not available on this server".to_string();
                state.status_msg_at = Some(Instant::now());
            }
            render(stdout, state)?;
        }

        // Toggle export mode (ctrl+r)
        (KeyModifiers::CONTROL, KeyCode::Char('r')) => {
            if handle_export_toggle(state, stdout)? {
                return Ok((true, None));
            }
        }

        // Save connection (ctrl+s)
        (KeyModifiers::CONTROL, KeyCode::Char('s')) => {
            if handle_save_connection(state, stdout)? {
                return Ok((true, None));
            }
        }

        // Clear all output (ctrl+l)
        (KeyModifiers::CONTROL, KeyCode::Char('l')) => {
            if !state.output_history.is_empty() {
                state.output_history.clear();

                terminal::disable_raw_mode()?;
                out!("\x1b[2J\x1b[3J\x1b[H");
                io::stdout().flush().ok();
                print_splash_with_width(&state.config, state.width);
                let input_lines = state.input.split('\n').count() as u16;
                for _ in 0..(2 + input_lines) { outln!(); }
                io::stdout().flush().ok();
                terminal::enable_raw_mode()?;
                state.prev_input_lines = input_lines;
                render(stdout, state)?;
            }
        }

        // Erase last response body only, keep request+status headers (ctrl+j) — full redraw
        (KeyModifiers::CONTROL, KeyCode::Char('j')) => {
            if state.output_history.last().is_some_and(|b| b.has_body()) {
                state.output_history.last_mut().unwrap().strip_body();

                terminal::disable_raw_mode()?;
                out!("\x1b[2J\x1b[3J\x1b[H");
                io::stdout().flush().ok();
                print_splash_with_width(&state.config, state.width);
                for block in &state.output_history {
                    out!("{}", block.render(state.width as usize));
                }
                let input_lines = state.input.split('\n').count() as u16;
                for _ in 0..(2 + input_lines) { outln!(); }
                io::stdout().flush().ok();
                terminal::enable_raw_mode()?;
                state.prev_input_lines = input_lines;
                render(stdout, state)?;
            }
        }

        // Switch connection (ctrl+q)
        (KeyModifiers::CONTROL, KeyCode::Char('q')) => {
            if let Some(rx) = handle_switch_connection(state, stdout)? {
                return Ok((false, Some(rx)));
            }
        }

        // Up — line navigation in multiline, history from top line
        (_, KeyCode::Up) => {
            let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
            let on_first_line = !state.input[..byte_idx].contains('\n');
            if !on_first_line {
                // Move cursor to same column on previous line
                state.cursor_pos = cursor_line_up(&state.input, state.cursor_pos);
                render(stdout, state)?;
            } else if !state.history.is_empty() && state.history_idx < state.history.len() as i32 - 1 {
                if state.history_idx == -1 {
                    state.history_stash = state.input.clone();
                }
                state.history_idx += 1;
                let idx = state.history.len() - 1 - state.history_idx as usize;
                state.input = state.history[idx].clone();
                state.cursor_pos = char_len(&state.input);
                render(stdout, state)?;
            }
        }

        // Down — line navigation in multiline, history when browsing
        (_, KeyCode::Down) => {
            let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
            let on_last_line = !state.input[byte_idx..].contains('\n');
            if !on_last_line && state.history_idx == -1 {
                // Move cursor to same column on next line
                state.cursor_pos = cursor_line_down(&state.input, state.cursor_pos);
                render(stdout, state)?;
            } else if state.history_idx > 0 {
                state.history_idx -= 1;
                let idx = state.history.len() - 1 - state.history_idx as usize;
                state.input = state.history[idx].clone();
                state.cursor_pos = char_len(&state.input);
                render(stdout, state)?;
            } else if state.history_idx == 0 {
                state.history_idx = -1;
                state.input = state.history_stash.clone();
                state.cursor_pos = char_len(&state.input);
                render(stdout, state)?;
            }
        }

        // Newline insertion
        // Alt/Option+Enter (works in Terminal.app with "Use Option as Meta key" enabled, and in kitty-protocol terminals)
        (KeyModifiers::ALT, KeyCode::Enter) |
        // Ctrl+N (universal fallback, works in all terminals)
        (KeyModifiers::CONTROL, KeyCode::Char('n')) |
        // Shift+Enter (requires kitty keyboard protocol — iTerm2, Kitty, WezTerm, Ghostty)
        (KeyModifiers::SHIFT, KeyCode::Enter) => {
            let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
            state.input.insert(byte_idx, '\n');
            state.cursor_pos += 1;
            render(stdout, state)?;
        }

        // Enter - auto-indented newline if inside brackets/braces, otherwise execute request
        (KeyModifiers::NONE, KeyCode::Enter) => {
            if state.config.experimental && cursor_inside_brackets(&state.input, state.cursor_pos) {
                // Check if body is currently single-line — if so, reformat to multi-line
                if let Some(bs) = find_body_start(&state.input) {
                    let body = &state.input[bs..];
                    if !body.contains('\n') {
                        // Body is single-line — reformat it to multi-line
                        let prefix = state.input[..bs].trim_end();
                        let cursor_in_body = state.cursor_pos.saturating_sub(char_len(&state.input[..bs]));
                        let (formatted, new_body_cursor) = reformat_json_multiline(body, cursor_in_body);
                        let prefix_char_len = char_len(prefix);
                        state.input = format!("{}\n{}", prefix, formatted);
                        // +1 for the newline between prefix and body
                        state.cursor_pos = prefix_char_len + 1 + new_body_cursor;

                        // The reformat already placed the cursor on a new indented line
                        // after the comma/bracket. Only insert an additional newline if
                        // the cursor is NOT already on a fresh indented line (i.e., when
                        // the cursor sits right after content, not after whitespace-only).
                        let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
                        let current_line_start = state.input[..byte_idx].rfind('\n')
                            .map_or(0, |p| p + 1);
                        let line_before_cursor = &state.input[current_line_start..byte_idx];
                        let on_blank_indented_line = line_before_cursor.chars().all(|c| c == ' ');

                        if !on_blank_indented_line {
                            let depth = bracket_depth_at(&state.input, state.cursor_pos) as usize;
                            let last_nws = state.input[..byte_idx].chars().rev()
                                .find(|c| !c.is_whitespace());

                            if matches!(last_nws, Some(',') | Some('{') | Some('[') | Some(':')) {
                                let indent = "  ".repeat(depth);
                                let insert = format!("\n{}", indent);
                                state.input.insert_str(byte_idx, &insert);
                                state.cursor_pos += 1 + depth * 2;
                            } else {
                                let dedent = depth.saturating_sub(1);
                                let indent = "  ".repeat(dedent);
                                let insert = format!("\n{}", indent);
                                state.input.insert_str(byte_idx, &insert);
                                state.cursor_pos += 1 + dedent * 2;
                            }
                        }

                        render(stdout, state)?;
                    } else {
                        // Body is already multi-line — normal Enter behavior
                        let depth = bracket_depth_at(&state.input, state.cursor_pos) as usize;
                        let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);

                        let char_before = if state.cursor_pos > 0 {
                            state.input.chars().nth(state.cursor_pos - 1)
                        } else { None };
                        let char_after = state.input.chars().nth(state.cursor_pos);
                        let between_brackets = matches!(
                            (char_before, char_after),
                            (Some('{'), Some('}')) | (Some('['), Some(']'))
                        );

                        let last_nws = state.input[..byte_idx].chars().rev()
                            .find(|c| !c.is_whitespace());

                        if between_brackets {
                            let indent = "  ".repeat(depth);
                            let closing_indent = "  ".repeat(depth.saturating_sub(1));
                            let insert = format!("\n{}\n{}", indent, closing_indent);
                            state.input.insert_str(byte_idx, &insert);
                            state.cursor_pos += 1 + depth * 2;
                        } else if matches!(last_nws, Some(',') | Some('{') | Some('[') | Some(':')) {
                            let indent = "  ".repeat(depth);
                            let insert = format!("\n{}", indent);
                            state.input.insert_str(byte_idx, &insert);
                            state.cursor_pos += 1 + depth * 2;
                        } else {
                            // After a closing bracket without comma, de-indent to
                            // the enclosing bracket's level (ready to close it too)
                            let extra = if matches!(last_nws, Some('}') | Some(']')) { 2 } else { 1 };
                            let dedent = depth.saturating_sub(extra);
                            let indent = "  ".repeat(dedent);
                            let insert = format!("\n{}", indent);
                            state.input.insert_str(byte_idx, &insert);
                            state.cursor_pos += 1 + dedent * 2;
                        }
                        render(stdout, state)?;
                    }
                } else {
                    // No body found — just insert newline
                    let depth = bracket_depth_at(&state.input, state.cursor_pos) as usize;
                    let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
                    let indent = "  ".repeat(depth);
                    let insert = format!("\n{}", indent);
                    state.input.insert_str(byte_idx, &insert);
                    state.cursor_pos += 1 + depth * 2;
                    render(stdout, state)?;
                }
            } else {
                let input = state.input.trim().to_string();
                let input = if input.is_empty() { "GET /".to_string() } else { input };

                // The line is read the way a `.api` file is read, so the same
                // text means the same thing here. One request keeps the
                // prompt's own handling (the body editor); a chain runs as a
                // chain; anything else — a directive, an include, several
                // lines at once, a typo — runs as a program.
                let (request, segments) = match classify_prompt_line(&input, typed_export(&state.config)) {
                    PromptLine::Request(r) => (r, Vec::new()),
                    PromptLine::Chain(s) => (s[0].1.clone(), s),
                    PromptLine::Program => {
                        state.history.push(input.clone());
                        append_history(&input);
                        state.history_idx = -1;
                        run_program_line(state, stdout, &input)?;
                        return Ok((false, None));
                    }
                };
                {
                    let is_chain = !segments.is_empty();

                    parse_input(state, &request);

                    // If method expects a body but none provided and no infile, enter body input mode.
                    // Never mid-chain: opening the multi-line editor between segments
                    // would strand the rest of the chain.
                    if !is_chain
                        && state.body.is_empty()
                        && state.config.outfile.is_empty()
                        && ["POST", "PUT", "PATCH"].contains(&state.method.as_str())
                    {
                        state.body_input_mode = true;
                        state.body_input_buffer.clear();
                        state.body_input_method = state.method.clone();
                        state.body_input_uri = state.uri.clone();
                        render(stdout, state)?;
                    } else {
                        // History keeps the whole chain, so up-arrow returns what was typed.
                        state.history.push(input.clone());
                        append_history(&input);
                        state.history_idx = -1;

                        if is_chain {
                            // The per-segment restore keeps the full chain on the
                            // input line throughout, so it can be re-sent or edited
                            // without retyping — no post-hoc restore needed.
                            execute_request_chain(state, stdout, &segments, &input)?;
                        } else {
                            execute_request(state, stdout)?;
                        }
                    }
                }
            }
        }

        // Backspace
        // Delete word backward (alt+backspace or ctrl+w)
        (KeyModifiers::ALT, KeyCode::Backspace) | (KeyModifiers::CONTROL, KeyCode::Char('w')) => {
            if state.cursor_pos > 0 {
                let new_pos = word_boundary_back(&state.input, state.cursor_pos);
                let start_byte = char_to_byte_idx(&state.input, new_pos);
                let end_byte = char_to_byte_idx(&state.input, state.cursor_pos);
                state.input.drain(start_byte..end_byte);
                state.cursor_pos = new_pos;
                auto_revert_method_on_body_clear(state);
                render(stdout, state)?;
            }
        }

        (_, KeyCode::Backspace) => {
            if state.cursor_pos > 0 {
                let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos - 1);
                state.input.remove(byte_idx);
                state.cursor_pos -= 1;
                auto_revert_method_on_body_clear(state);
                render(stdout, state)?;
            }
        }

        // Delete word forward (alt+d)
        (KeyModifiers::ALT, KeyCode::Char('d')) => {
            let input_char_len = char_len(&state.input);
            if state.cursor_pos < input_char_len {
                let new_pos = word_boundary_forward(&state.input, state.cursor_pos);
                let start_byte = char_to_byte_idx(&state.input, state.cursor_pos);
                let end_byte = char_to_byte_idx(&state.input, new_pos);
                state.input.drain(start_byte..end_byte);
                auto_revert_method_on_body_clear(state);
                render(stdout, state)?;
            }
        }

        // Delete
        (_, KeyCode::Delete) => {
            let input_char_len = char_len(&state.input);
            if state.cursor_pos < input_char_len {
                let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
                state.input.remove(byte_idx);
                auto_revert_method_on_body_clear(state);
                render(stdout, state)?;
            }
        }

        // Kill to end of line (ctrl+k)
        (KeyModifiers::CONTROL, KeyCode::Char('k')) => {
            let input_char_len = char_len(&state.input);
            if state.cursor_pos < input_char_len {
                let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
                state.input.truncate(byte_idx);
                auto_revert_method_on_body_clear(state);
                render(stdout, state)?;
            }
        }

        // Word navigation back (ctrl+left, alt+left or alt+b)
        (KeyModifiers::CONTROL, KeyCode::Left) | (KeyModifiers::ALT, KeyCode::Left) | (KeyModifiers::ALT, KeyCode::Char('b')) => {
            state.cursor_pos = word_boundary_back(&state.input, state.cursor_pos);
            render(stdout, state)?;
        }

        // Word navigation forward (ctrl+right, alt+right or alt+f)
        (KeyModifiers::CONTROL, KeyCode::Right) | (KeyModifiers::ALT, KeyCode::Right) | (KeyModifiers::ALT, KeyCode::Char('f')) => {
            state.cursor_pos = word_boundary_forward(&state.input, state.cursor_pos);
            render(stdout, state)?;
        }

        // Left arrow
        (_, KeyCode::Left) => {
            if state.cursor_pos > 0 {
                state.cursor_pos -= 1;
                render(stdout, state)?;
            }
        }

        // Right arrow
        (_, KeyCode::Right) => {
            let input_char_len = char_len(&state.input);
            if state.cursor_pos < input_char_len {
                state.cursor_pos += 1;
                render(stdout, state)?;
            }
        }

        // Home
        (_, KeyCode::Home) | (KeyModifiers::CONTROL, KeyCode::Char('a')) => {
            state.cursor_pos = 0;
            render(stdout, state)?;
        }

        // End
        (_, KeyCode::End) | (KeyModifiers::CONTROL, KeyCode::Char('e')) => {
            state.cursor_pos = char_len(&state.input);
            render(stdout, state)?;
        }

        // Regular character input
        (KeyModifiers::NONE | KeyModifiers::SHIFT, KeyCode::Char(c)) => {
            // Smart closing bracket: remove trailing comma and fix indentation
            if (c == '}' || c == ']') && state.config.experimental && cursor_inside_brackets(&state.input, state.cursor_pos) {
                let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
                let before = &state.input[..byte_idx];

                // Find and remove trailing comma before this closing bracket
                // Look backwards past whitespace for a comma
                let trimmed = before.trim_end();
                let has_trailing_comma = trimmed.ends_with(',');
                let mut new_before = if has_trailing_comma {
                    let comma_pos = trimmed.len() - 1;
                    format!("{}{}", &before[..comma_pos], &before[trimmed.len()..])
                } else {
                    before.to_string()
                };

                // Fix indentation: remove whitespace on current line, replace with proper indent
                // Find the start of the current line
                let line_start = new_before.rfind('\n').map(|p| p + 1).unwrap_or(0);
                let line_content = &new_before[line_start..];
                if line_content.chars().all(|ch| ch == ' ' || ch == '\t') {
                    // Current line is only whitespace — replace with proper dedented indent
                    let depth_after = bracket_depth_at(&new_before, char_len(&new_before)).saturating_sub(1) as usize;
                    let indent = "  ".repeat(depth_after);
                    new_before = format!("{}{}", &new_before[..line_start], indent);
                }

                let after = &state.input[byte_idx..];
                state.input = format!("{}{}{}", new_before, c, after);
                state.cursor_pos = char_len(&new_before) + 1;
            } else {
                let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
                let inside_brackets = cursor_inside_brackets(&state.input, state.cursor_pos);
                state.input.insert(byte_idx, c);
                state.cursor_pos += 1;

                // Auto-trigger JSON completion for ghost text when typing a key name
                if state.config.experimental && inside_brackets {
                    if let Some(ctx) = json_context_at_cursor(state) {
                        let (_schema, partial, is_value, _key, _existing) = ctx;
                        // Only trigger when actually in a key string: either just opened " or typing chars inside it
                        if !is_value && (!partial.is_empty() || c == '"') {
                            handle_json_tab_completion(state, false, false);
                        }
                    }
                }
            }
            // Typing a body promotes GET to PUT (a body implies a write).
            auto_promote_method_on_body_start(state, c);
            // On an array endpoint, prepend `[` so the body matches the array shape.
            auto_wrap_array_body(state, c);
            state.status_msg.clear();
            state.status_msg_at = None;
            render(stdout, state)?;
        }

        _ => {}
    }

    Ok((false, None))
}

/// Cycling window for re-pasting the same JSON to advance through its identifiers.
const PASTE_CYCLE_WINDOW: Duration = Duration::from_secs(10);

/// `@`-prefixed keys are JSON-LD metadata (e.g. `@type`), never identifiers.
fn is_identifier_key(k: &str) -> bool {
    !k.starts_with('@')
}

/// Parse a pasted JSON fragment, tolerating the artifacts of lifting a slice out
/// of a larger document:
/// - a trailing comma left behind by copying one entry of an object/array
/// - a leading `"identifiers":` property label, when the selection included the
///   key the identifiers were nested under (`"identifiers": { … },`)
///
/// The strictest reading is tried first and only relaxed on failure, so valid
/// JSON is never reinterpreted.
fn parse_pasted_json_fragment(s: &str) -> Option<Value> {
    let trimmed = s.trim();
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        return Some(v);
    }

    // Drop trailing commas (and the whitespace around them) left by the copy.
    let no_comma = trimmed.trim_end_matches(|c: char| c == ',' || c.is_whitespace());
    if no_comma.is_empty() {
        return None;
    }
    if no_comma != trimmed {
        if let Ok(v) = serde_json::from_str::<Value>(no_comma) {
            return Some(v);
        }
    }

    // A fragment labelled with the `identifiers` key is a bare property — brace
    // it back into an object: `"identifiers": { … }` → `{"identifiers": { … }}`.
    // Only that one key is repaired; any other bare property stays unparsed and
    // is pasted verbatim.
    if no_comma.starts_with("\"identifiers\"") {
        if let Ok(v) = serde_json::from_str::<Value>(&format!("{{{}}}", no_comma)) {
            return Some(v);
        }
    }

    None
}

/// Every string-valued, non-metadata entry of `obj`, in insertion order.
fn string_pairs(obj: &Map<String, Value>) -> Vec<(String, String)> {
    obj.iter()
        .filter(|(k, _)| is_identifier_key(k))
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect()
}

/// Pull `(key, value)` pairs out of pasted JSON, in insertion order.
///
/// Recognizes two shapes:
/// 1. An object with an `"identifiers"` field that is itself an object — uses
///    every string-valued key inside it (no dot requirement, because the user
///    has explicitly nested them under `identifiers`). Since
///    `parse_pasted_json_fragment` braces a bare property back into an object,
///    this also covers a paste of just `"identifiers": { … },`. Only that one
///    key unwraps — an object nested under any other name is not searched.
/// 2. A flat object where every (non-metadata) value is a string — uses every key.
///
/// A top-level array holding exactly one object is unwrapped first, so a
/// list-endpoint body like `[{ "identifiers": { … } }]` addresses the same
/// index slot as the bare object would. Arrays with zero, several, or
/// non-object elements can't name a single index slot and are left alone.
///
/// Returns an empty vec when the paste isn't JSON, isn't an object, or doesn't
/// match either shape. Order follows the source JSON because `serde_json` is
/// built with the `preserve_order` feature.
fn extract_identifier_pairs(s: &str) -> Vec<(String, String)> {
    let value = match parse_pasted_json_fragment(s) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let value = match value.as_array() {
        Some(items) if items.len() == 1 => &items[0],
        Some(_) => return Vec::new(),
        None => &value,
    };
    let obj = match value.as_object() {
        Some(o) => o,
        None => return Vec::new(),
    };

    // Case 1: explicit "identifiers" child object.
    if let Some(idents) = obj.get("identifiers").and_then(|v| v.as_object()) {
        let pairs = string_pairs(idents);
        if !pairs.is_empty() {
            return pairs;
        }
    }

    // Case 2: flat object, every (non-metadata) value is a string.
    let non_meta: Vec<(&String, &Value)> = obj.iter().filter(|(k, _)| is_identifier_key(k)).collect();
    if !non_meta.is_empty() && non_meta.iter().all(|(_, v)| v.is_string()) {
        return string_pairs(obj);
    }

    Vec::new()
}

/// Place an expanded `identifier=value` (`kv`) into the URI's index slot — the
/// last path segment of `before` (the text up to the cursor) — replacing or
/// appending so repeated identifier pastes never accumulate:
/// - segment empty (`before` ends with `/`)        → append:  `before + kv`
/// - segment is already an identifier (has `=`)     → replace: drop it, keep the `/`, add `kv`
/// - segment is a collection / other (no `=`)       → append:  `before + "/" + kv`
///
/// Examples (kv = `com.foo=1`):
/// - `GET /people`                  → `GET /people/com.foo=1`     (enter indexing)
/// - `GET /people/`                 → `GET /people/com.foo=1`     (no double slash)
/// - `GET /people/com.bar=9`        → `GET /people/com.foo=1`     (replace the slot)
fn apply_identifier_index(before: &str, kv: &str) -> String {
    match before.rfind('/') {
        Some(p) => {
            let segment = &before[p + 1..];
            // A segment counts as a replaceable identifier slot only when it's a
            // plain `key=value` — an `=` inside an operator expression (e.g.
            // `people~where(name=Joe)`) must not be replaced, only appended to.
            let is_identifier_slot =
                segment.contains('=') && !segment.contains('~') && !segment.contains('(');
            if segment.is_empty() {
                format!("{}{}", before, kv)
            } else if is_identifier_slot {
                format!("{}{}", &before[..=p], kv)
            } else {
                format!("{}/{}", before, kv)
            }
        }
        // No slash before the cursor (unusual for a URI) — add a separating one.
        None => format!("{}/{}", before, kv),
    }
}

/// True when a paste at `cursor_pos` should expand identifier JSON into the
/// URI's index slot: the cursor is not inside a JSON body and is attached to a
/// URI path token (the current whitespace-delimited token contains a `/`).
/// A cursor past the URI's separating space (body position, e.g. `PUT /people |`)
/// is NOT index mode — the paste is then a request body and inserted verbatim.
fn paste_in_index_mode(input: &str, cursor_pos: usize) -> bool {
    if cursor_inside_brackets(input, cursor_pos) {
        return false;
    }
    let byte_idx = char_to_byte_idx(input, cursor_pos);
    // The cursor must sit at the END of its token (next char is whitespace or
    // end of input) — expanding mid-token would splice text into the URI.
    if !input[byte_idx..].chars().next().map_or(true, |c| c.is_whitespace()) {
        return false;
    }
    let before_cursor = &input[..byte_idx];
    let current_token = before_cursor.rsplit(char::is_whitespace).next().unwrap_or("");
    current_token.contains('/')
}

/// Terminals hand a pasted newline over as a carriage return — xterm.js,
/// Terminal.app and iTerm2 all rewrite `\n` to `\r` inside a bracketed paste —
/// so `\r\n` and a lone `\r` are both read as line breaks. Left in, a `\r` is
/// an invisible character that sends the terminal cursor back to column 0 when
/// the line is drawn.
fn normalize_paste_newlines(paste: &str) -> String {
    paste.replace("\r\n", "\n").replace('\r', "\n")
}

/// True if `paste` begins with an HTTP method token followed by whitespace
/// (e.g. "GET /people...").
fn paste_starts_with_method(paste: &str) -> bool {
    let trimmed = paste.trim_start();
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    match trimmed.split_once(|c: char| c.is_whitespace()) {
        Some((first, _rest)) => methods.contains(&first.to_uppercase().as_str()),
        None => false,
    }
}

/// True if `paste` is `.api` text that stands on its own, so it replaces the
/// input rather than being inserted at the cursor: a full request line
/// (`GET /people`), a directive (`assert /x`, `confirm`, `sleep 2`, `url has`),
/// a comment, a `.api` file to run, or a block of several lines. Pasted over the
/// `GET /` the prompt starts with, such text would otherwise end up as
/// `GET /assert GET /x`. A body (`{…`, `[…`, `@file`), a redirect (`> file`), and
/// a bare `/path` are not program text and are inserted where the cursor is,
/// however many lines they span.
fn paste_is_api_text(paste: &str) -> bool {
    if paste_starts_with_method(paste) {
        return true;
    }
    let trimmed = paste.trim_start();
    let Some(first) = trimmed.split_whitespace().next() else {
        return false;
    };
    first.starts_with('#')
        || DIRECTIVES.iter().any(|d| first.eq_ignore_ascii_case(d))
        || names_api_file(first)
        || (first.starts_with('/') && trimmed.trim_end().contains('\n'))
        || (first.starts_with('{') && describe_block_leads(trimmed))
}

/// True if `text` is a JSON object with more lines under it: a `.api` file
/// that opens with its describe block, where an object alone is a body.
fn describe_block_leads(text: &str) -> bool {
    let mut current = String::new();
    let mut lines = text.lines();
    for line in lines.by_ref() {
        current.push_str(line);
        current.push('\n');
        if strip_body_comments_and_count(&current).1 <= 0 {
            return lines.any(|rest| !rest.trim().is_empty());
        }
    }
    false
}

/// Uppercase the leading method token of a request line (e.g. `get /x` →
/// `GET /x`), matching how typed promotion always writes uppercase methods.
fn uppercase_method_token(line: &str) -> String {
    let mut out = line.to_string();
    let trimmed = out.trim_start();
    let offset = out.len() - trimmed.len();
    let end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let upper = trimmed[..end].to_uppercase();
    out.replace_range(offset..offset + end, &upper);
    out
}

/// Handle a bracketed-paste event into the URL/input field.
///
/// When the cursor sits outside any open `{}`/`[]` body, we try to expand the
/// paste into an `identifier=value` form so users can paste API JSON straight
/// into a URL. Re-pasting the same JSON within `PASTE_CYCLE_WINDOW` cycles
/// through multiple identifiers (first → last, wrapping).
///
/// In every other case the paste is inserted verbatim — so writing real JSON
/// request bodies still works exactly as before.
fn handle_paste<W: Write>(
    state: &mut AppState,
    paste: &str,
    stdout: &mut W,
) -> io::Result<()> {
    // In the body editor the paste is body text: it goes into the body being
    // written, as it is. The line under the editor is not what is on screen.
    if state.body_input_mode {
        state.body_input_buffer.push_str(&normalize_paste_newlines(paste));
        return render(stdout, state);
    }

    let inside_body = cursor_inside_brackets(&state.input, state.cursor_pos);

    let normalized = normalize_paste_newlines(paste);
    // A copied line usually brings its newline along. Outside a body it would
    // only leave the cursor on an empty second line, so it goes; a paste never
    // sends anything by itself, Enter still does that. Inside a body every
    // newline is content.
    let paste = if inside_body { normalized.as_str() } else { normalized.trim_end_matches('\n') };

    // Pasting `.api` text (a request line, a directive, a block of lines)
    // outside a JSON body replaces the entire input rather than inserting at
    // the cursor — so pasting "GET /people..." or "assert /x" over a "GET /"
    // prompt yields the pasted text, not "GET /assert /x". Detection is skipped
    // inside a body so a JSON string beginning with "GET " is pasted verbatim.
    if !inside_body && paste_is_api_text(paste) {
        // Normalize the method to uppercase, like typed promotion does.
        state.input = if paste_starts_with_method(paste) {
            uppercase_method_token(paste.trim_end())
        } else {
            paste.trim_end().to_string()
        };
        state.cursor_pos = char_len(&state.input);
        // Pasting a full request line is an explicit method choice.
        state.method_auto_promoted = false;
        state.status_msg.clear();
        state.status_msg_at = None;
        render(stdout, state)?;
        return Ok(());
    }

    let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
    let before_cursor = &state.input[..byte_idx];

    // Identifier expansion only applies in "indexing mode"; pasting an
    // `identifiers` JSON then replaces/appends the URI's index slot rather than
    // inserting at the cursor, so it never accumulates duplicate segments.
    let in_index_mode = paste_in_index_mode(&state.input, state.cursor_pos);
    if in_index_mode {
        let pairs = extract_identifier_pairs(paste);
        if !pairs.is_empty() {
            let same_as_last = state.last_paste_raw == paste;
            let within_window = state
                .last_paste_at
                .map(|t| t.elapsed() < PASTE_CYCLE_WINDOW)
                .unwrap_or(false);

            // Re-pasting the same JSON within the window cycles to the next
            // identifier; a fresh paste starts at the first.
            let idx = if same_as_last && within_window {
                (state.last_paste_cycle_idx + 1) % pairs.len()
            } else {
                0
            };

            let (k, v) = &pairs[idx];
            let kv = format!("{}={}", k, v);
            let note = if pairs.len() > 1 {
                format!("paste: {} ({}/{})", kv, idx + 1, pairs.len())
            } else {
                format!("paste: {}", kv)
            };

            state.last_paste_raw = paste.to_string();
            state.last_paste_cycle_idx = idx;
            state.last_paste_at = Some(Instant::now());

            // Replace/append the index slot in the text before the cursor; keep
            // whatever followed the cursor intact.
            let after_cursor = &state.input[byte_idx..];
            let new_before = apply_identifier_index(before_cursor, &kv);
            state.cursor_pos = char_len(&new_before);
            state.input = format!("{}{}", new_before, after_cursor);

            state.status_msg = note;
            state.status_msg_at = Some(Instant::now());
            render(stdout, state)?;
            return Ok(());
        }
    }

    // Verbatim insert (non-identifier paste, or paste inside a JSON body).
    let insert_text = if !inside_body && paste.starts_with('/') && before_cursor.ends_with('/') {
        // Avoid a double slash when pasting "/products/..." right after an
        // existing trailing "/" (e.g. prompt "GET /"). JSON bodies are untouched.
        paste[1..].to_string()
    } else {
        paste.to_string()
    };

    state.input.insert_str(byte_idx, &insert_text);
    state.cursor_pos += char_len(&insert_text);

    // Pasting a body at the first-body position promotes GET → PUT, matching the
    // typing behavior (`>` redirects and `&` chain separators excluded — pasting
    // `&& GET /b` after a GET must not turn that GET into a PUT). The paste's own
    // leading whitespace can serve as the URI/body separator. On an array
    // endpoint, a complete pasted JSON body is then wrapped in `[` … `]` (both
    // brackets — unlike typing, a pasted body isn't still being composed).
    if !inside_body {
        let lead_ws = insert_text.len() - insert_text.trim_start().len();
        if let Some(first) = insert_text.trim_start().chars().next() {
            if first != '>' && first != '&' && first != '|' {
                let delta = promote_method_prefix(state, byte_idx + lead_ws);
                state.cursor_pos = (state.cursor_pos as i64 + delta).max(0) as usize;
                // Method tokens are ASCII, so the char delta equals the byte
                // delta — shift the pasted span by it and try the array wrap.
                let body_start = (byte_idx + lead_ws) as i64 + delta;
                let body_end = (byte_idx + insert_text.len()) as i64 + delta;
                if body_start >= 0 && body_end > body_start {
                    wrap_pasted_array_body(state, body_start as usize, body_end as usize);
                }
            }
        }
    }

    state.status_msg.clear();
    state.status_msg_at = None;

    render(stdout, state)?;
    Ok(())
}

fn parse_input(state: &mut AppState, input: &str) {
    let mut input = input.to_string();

    // Parse > / >> outfile from the end (space required before >, optional after;
    // `>>` appends instead of overwriting)
    state.config.outfile.clear();
    state.config.outfile_append = false;
    state.display_outfile.clear();
    if let Some(idx) = outfile_marker_at(&input) {
        let mut after_gt = &input[idx + 2..];
        let append = after_gt.starts_with('>');
        if append {
            after_gt = &after_gt[1..];
        }
        let outfile_raw = after_gt.trim_start().trim_end().to_string();
        if !outfile_raw.is_empty() {
            state.display_outfile = outfile_raw.clone();
            state.config.outfile = outfile_raw;
            state.config.outfile_append = append;
            state.config.outfile = expand_home(&state.config.outfile);
            input = input[..idx].trim().to_string();
        }
    }

    // Extract method and URI using whitespace splitting, but preserve body verbatim
    let trimmed = input.trim_start();
    if trimmed.is_empty() {
        return;
    }

    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

    // Find first whitespace-delimited word
    let first_end = trimmed.find(|c: char| c.is_whitespace()).unwrap_or(trimmed.len());
    let first_word = &trimmed[..first_end];
    let first_upper = first_word.to_uppercase();

    if methods.contains(&first_upper.as_str()) {
        state.method = first_upper;
        // Find URI (second word)
        let after_method = &trimmed[first_end..];
        let after_method_trimmed = after_method.trim_start();
        if after_method_trimmed.is_empty() {
            state.uri = "/".to_string();
            state.body = String::new();
        } else {
            let uri_end = uri_end(after_method_trimmed);
            state.uri = after_method_trimmed[..uri_end].to_string();
            // Body is everything after URI; trim leading spaces/tabs but preserve newlines
            let after_uri = &after_method_trimmed[uri_end..];
            let body = after_uri.trim_start_matches(|c: char| c == ' ' || c == '\t');
            state.body = if body.trim().is_empty() { String::new() } else { body.to_string() };
        }
    } else if starts_a_request(first_word) {
        state.method = "GET".to_string();
        let first_end = uri_end(trimmed);
        state.uri = trimmed[..first_end].to_string();
        // Body is everything after URI; trim leading spaces/tabs but preserve newlines
        let after_uri = &trimmed[first_end..];
        let body = after_uri.trim_start_matches(|c: char| c == ' ' || c == '\t');
        state.body = if body.trim().is_empty() { String::new() } else { body.to_string() };
    }
}

/// Restore the input line after a request has been sent: normally the request
/// that just ran (method, URI, body, and the `>`/`>>` outfile as typed); inside
/// a `&&` chain, the FULL chain — otherwise the input area would show segment 1
/// alone while segment 2 runs, then snap to the chain at the end. Also clears
/// completion state so no stale ghost flashes.
fn restore_input_after_send(state: &mut AppState) {
    if let Some(chain) = state.chain_input.clone() {
        state.input = chain;
    } else {
        state.input = format!("{} {}", state.method, state.uri);
        if !state.body.is_empty() {
            state.input.push_str(&format!(" {}", state.body));
        }
        if !state.display_outfile.is_empty() {
            // Keep the marker the user typed — restoring `>>` as `>` would
            // silently turn an append into an overwrite on re-send.
            let marker = if state.config.outfile_append { ">>" } else { ">" };
            state.input.push_str(&format!(" {} {}", marker, state.display_outfile));
        }
    }
    state.cursor_pos = char_len(&state.input);
    // Clear stale completion state to prevent ghost text flash
    state.completions.clear();
    state.last_tab_input.clear();
}

/// Send the request currently in `state` and report what it means for a `&&`
/// chain. See `classify_response`.
fn execute_request(state: &mut AppState, stdout: &mut io::Stdout) -> io::Result<RequestOutcome> {
    // Clear stashed body since a request was sent
    state.stashed_body.clear();
    // A sent request finalizes the method choice — no auto-revert afterwards.
    state.method_auto_promoted = false;
    // Clear splash tracking since we're printing output
    state.last_was_splash = false;

    // Flash rulers on send
    flash_rulers(stdout, state, "\x1b[38;5;242m", 120)?;

    // The block accumulates what's printed below the request line, so history and
    // screen can't drift apart; the request line itself is re-fitted per width.
    let mut block = OutputBlock {
        method: state.method.clone(),
        uri: state.uri.clone(),
        body: body_as_written(&state.body),
        display_outfile: state.display_outfile.clone(),
        outfile_append: state.config.outfile_append,
        prefix: std::mem::take(&mut state.log_prefix),
        ..Default::default()
    };

    // No status yet: one left from the request before would otherwise be
    // read as this one's if it is aborted or never sent.
    state.config.last_status = None;

    // This is the last request now, for ctrl+y, however it came to be sent:
    // typed, a segment of a chain, a line of a file, ctrl+g. A poll is not
    // something anyone sent by hand.
    if !state.config.quiet {
        state.prev_method = state.method.clone();
        state.prev_uri = state.uri.clone();
        state.prev_body = state.body.clone();
        state.prev_outfile = state.config.outfile.clone();
        state.prev_display_outfile = state.display_outfile.clone();
        state.prev_outfile_append = state.config.outfile_append;
    }

    // `--export` rewrites the whole body, so it is read whole.
    let streaming = state.config.streaming && state.config.export_id.is_none();
    let parts = RequestParts {
        method: state.method.clone(),
        uri: state.uri.clone(),
        body: state.body.clone(),
        outfile: (!state.config.outfile.is_empty()).then(|| state.config.outfile.clone()),
        streaming,
    };
    // The request is built by the function the batch uses, so a line means
    // the same request here as in a file.
    let built = match build_request(&state.config, &parts) {
        Ok(built) => built,
        Err(err) => {
            // The @file couldn't be read, so nothing is sent.
            block.head = format!("\n{}\n\n", err);
            let display_output = block.render(state.width as usize);
            push_output_block(state, block);

            // Update input with last command (chain-aware, outfile marker included)
            restore_input_after_send(state);
            print_output_and_rerender(state, stdout, &display_output)?;
            return Ok(RequestOutcome::Errored);
        }
    };
    let accept = built.accept.clone();

    let start = Instant::now();

    // With no outfile the renderer owns the screen, so there's nothing to stream
    // into and the body stays buffered. `>>` and clipboard both need the whole
    // body, and a non-2xx buffers so an error payload never lands in the file.
    let stream_outfile: Option<String> = if streaming
        && !state.config.outfile.is_empty()
        && !state.config.outfile_append
        && !is_clipboard_target(&state.display_outfile)
    {
        Some(state.config.outfile.clone())
    } else {
        None
    };

    // Run HTTP request + body read in a thread so we can handle spinner and ctrl+c
    // Both send() and text() can block — send() waits for headers, text() reads the full body
    let response_result: Arc<std::sync::Mutex<Option<Result<(reqwest::StatusCode, String, BodyDelivery), RequestFailure>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let response_result_clone = Arc::clone(&response_result);
    let progress = TransferProgress::new();
    let thread_progress = Arc::clone(&progress);
    let failure_base_uri = state.config.base_uri.clone();
    // A token renewed on a 401, handed back for the requests that follow.
    let renewed_token: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let thread_renewed = Arc::clone(&renewed_token);
    let thread_config = state.config.clone();
    let request_handle = thread::spawn(move || {
        let sent = send_request(&thread_config, &parts, built).map_err(|e| RequestFailure::of(e, &failure_base_uri));
        let result = sent.and_then(|sent| {
            *thread_renewed.lock().unwrap() = sent.new_token;
            let resp = sent.response;
            let status = resp.status();
            thread_progress.headers_arrived(&resp);
            if let Some(path) = stream_outfile {
                if status.is_success() {
                    // Stream straight to the file. A failure here is
                    // reported through BodyDelivery — it isn't a request error.
                    let streamed = stream_to_outfile(CountingReader::new(resp, &thread_progress), &path);
                    return Ok(match streamed {
                        Ok(body) => (
                            status,
                            body.prefix,
                            BodyDelivery::Streamed {
                                overflowed: body.overflowed,
                                error: None,
                                bytes: body.bytes,
                            },
                        ),
                        Err(failure) => (
                            status,
                            String::new(),
                            BodyDelivery::Streamed {
                                overflowed: false,
                                error: Some(match failure {
                                    StreamFailure::Write(e) => format!("Error writing to {}: {}", path, e),
                                    StreamFailure::Body(e) => describe_body_failure(&e, thread_config.timeout_secs),
                                }),
                                bytes: 0,
                            },
                        ),
                    });
                }
            }
            let body = read_body_text(resp, &thread_progress)?;
            Ok((status, body, BodyDelivery::Buffered))
        });
        *response_result_clone.lock().unwrap() = Some(result);
    });

    // Poll for completion, show spinner after 3 seconds, handle ctrl+c
    let mut frame_idx = 0;
    let mut showing_spinner = false;
    let mut aborted = false;
    let mut stream_pulse = StreamPulse::new();

    loop {
        // Check if request completed
        {
            let guard = response_result.lock().unwrap();
            if guard.is_some() {
                break;
            }
        }

        // Check for ctrl+c to abort (short poll to stay responsive). Any
        // other key, and a paste, is dropped: the prompt is not there to
        // take it while a request is on its way.
        if event::poll(Duration::from_millis(80))? {
            let event = event::read()?;
            note_resize(state, &event);
            if let Event::Key(key) = event {
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    aborted = true;
                    break;
                }
                if key.code == KeyCode::Esc {
                    aborted = true;
                    break;
                }
            }
        }

        // Show progress after 0.5 seconds in the hint area (bottom line)
        if start.elapsed() >= PROGRESS_DELAY {
            showing_spinner = true;
            let frame = SPINNER_FRAMES[frame_idx % SPINNER_FRAMES.len()];
            let snapshot = progress.snapshot();
            let text = format!("{} {}", frame, progress_text(&snapshot, start.elapsed(), true));
            let pulse = stream_pulse.observe(snapshot.received, Instant::now());
            // Overwrite the hint line with the progress
            execute!(
                stdout,
                cursor::MoveToColumn(0),
                Clear(ClearType::CurrentLine),
                Print(transient_hint_line(state, &text, pulse))
            )?;
            stdout.flush()?;
            frame_idx += 1;
        }
    }

    // Handle abort — detach thread and return immediately
    if aborted {
        drop(request_handle);
        state.status_msg = "request aborted".to_string();
        state.status_msg_at = Some(std::time::Instant::now());
        // Restore hint area with abort message
        execute!(
            stdout,
            cursor::MoveToColumn(0),
            Clear(ClearType::CurrentLine),
            Print(transient_hint_line(state, &state.status_msg, None))
        )?;
        stdout.flush()?;
        return Ok(RequestOutcome::Aborted);
    }

    // Clear spinner from hint line
    if showing_spinner {
        execute!(
            stdout,
            cursor::MoveToColumn(0),
            Clear(ClearType::CurrentLine)
        )?;
    }

    // Wait for request thread to finish
    let _ = request_handle.join();

    // Get the response
    let response_opt = response_result.lock().unwrap().take();

    // A token that ran out was renewed on the way: keep the new one.
    if let Some(token) = renewed_token.lock().unwrap().take() {
        state.config.token = token;
    }

    // What this request means for a `&&` chain. Captured before the body is
    // consumed by the outfile/clipboard branches below.
    let mut outcome = match &response_opt {
        // A streamed body only left its prefix behind, and a write that failed
        // partway is an error however truthy the bytes looked.
        Some(Ok((_, _, BodyDelivery::Streamed { error: Some(_), .. }))) => RequestOutcome::Errored,
        Some(Ok((status, prefix, BodyDelivery::Streamed { overflowed, .. }))) => {
            classify_streamed(status.as_u16(), prefix, *overflowed)
        }
        Some(Ok((status, body_text, BodyDelivery::Buffered))) => {
            classify_response(status.as_u16(), body_text)
        }
        Some(Err(_)) | None => RequestOutcome::Errored,
    };

    state.config.last_status = match &response_opt {
        Some(Ok((status, _, _))) => Some(status.as_u16()),
        _ => None,
    };

    // A check (`assert`, `sleep while`) may need to say why it failed.
    if state.config.check_only || state.config.quiet {
        state.config.last_response = match &response_opt {
            Some(Ok((status, body, _))) => Some((status.as_u16(), body.clone())),
            _ => None,
        };
    }

    // What `--export` has to say about this response, for the hint line.
    let mut export_note: Option<String> = None;

    match response_opt {
        Some(Ok((status, body_text, delivery))) => {
            let elapsed = start.elapsed();

            let status_str = format_status(status, state.config.expect_falsy);

            // `--export`: the body shown, written or copied is the seed data.
            // The verdict above was taken from what the server said.
            let body_text = match &state.config.export_id {
                Some(id_key) if status.is_success() && matches!(delivery, BodyDelivery::Buffered) => {
                    let exported = export_body(
                        &body_text,
                        id_key,
                        accept.starts_with("application/x-ndjson"),
                        state.config.raw,
                    );
                    export_note = export_warning(&exported);
                    exported.text
                }
                _ => body_text,
            };

            // To a file or the clipboard. Under `-f` an error is not what
            // the outfile was meant to hold: the file is left alone and the
            // body is shown, as a batch does it.
            let to_target = !state.config.outfile.is_empty() && !fail_fast_trips(&state.config, status.as_u16());
            if to_target {
                let target = OutTarget {
                    path: &state.config.outfile,
                    display: &state.display_outfile,
                    append: state.config.outfile_append,
                };
                // A streamed body is already on disk — only its failure, if
                // any, is still to be reported.
                let delivered: Result<u64, String> = match delivery {
                    BodyDelivery::Streamed { error: Some(ref e), .. } => Err(e.clone()),
                    BodyDelivery::Streamed { bytes, .. } => Ok(bytes),
                    BodyDelivery::Buffered => target
                        .deliver(&outfile_text(&state.config, &body_text))
                        .map_err(|e| target.failure(&e)),
                };
                match delivered {
                    Err(message) => {
                        block.head = format!("{}\n", message);
                        // What the request was to leave behind is not there:
                        // a chain stops here.
                        outcome = RequestOutcome::Errored;
                    }
                    Ok(written) => {
                        if !state.config.silent {
                            block.head = format!(
                                "HTTP/1.1 {} {}\n{}\n\n",
                                status_str,
                                format_latency(elapsed).dimmed(),
                                target.marker(written).dimmed()
                            );
                        }
                        if target.is_clipboard() {
                            state.status_msg = "copied to clipboard".to_string();
                        } else {
                            state.last_outfile = state.config.outfile.clone();
                            state.last_display_outfile = state.display_outfile.clone();
                            state.status_msg = "ctrl+o to open file".to_string();
                        }
                        state.status_msg_at = Some(Instant::now());
                    }
                }
            } else {
                // Build status line
                if !state.config.silent {
                    block.head = format!(
                        "HTTP/1.1 {} {}\n",
                        status_str,
                        format_latency(elapsed).dimmed()
                    );
                }

                // Build body. The trailing blank line belongs to the head when
                // there's no body, so `has_body()` stays false and ctrl+j
                // correctly finds nothing to erase.
                if !body_text.is_empty() {
                    let output = outfile_text(&state.config, &body_text);
                    block.tail = format_body_block(&output);
                } else {
                    block.head.push('\n');
                }
            }
        }
        Some(Err(e)) => {
            block.head = if e.timed_out {
                format!(
                    "\nTimed out after {} — raise it with --timeout <seconds> (0 = no timeout)\n\n",
                    describe_timeout(state.config.timeout_secs)
                )
            } else if let Some(tls) = &e.tls {
                format!("\n{}\n\n", tls)
            } else {
                format!("\nIs COS running on {}? 🤔\n\n", host_of(&state.config.base_uri))
            };
        }
        None => {
            // Request was aborted or something went wrong
            block.head = "\nRequest failed\n".to_string();
        }
    }

    // Said last, so it is what the hint line shows under the response.
    if let Some(note) = export_note.filter(|_| !state.config.quiet && !state.config.check_only) {
        state.status_msg = note;
        state.status_msg_at = Some(Instant::now());
    }

    // Refresh mapped type names after mutating /mapped-types
    if state.uri.starts_with("/mapped-types")
        && matches!(state.method.as_str(), "PUT" | "POST" | "PATCH")
    {
        let config = state.config.clone();
        let names = fetch_mapped_type_names(&config);
        state.mapped_types = names;
    }

    // A `sleep while` poll prints nothing unless it errored — then the block
    // is the explanation of why the wait stopped. `assert` keeps the request
    // and status lines but never the body: the answer is a verdict, not data.
    if state.config.quiet && outcome != RequestOutcome::Errored {
        restore_input_after_send(state);
        // Clear any spinner left in the hint line.
        render(stdout, state)?;
        return Ok(outcome);
    }
    if state.config.check_only && block.has_body() {
        block.strip_body();
        block.head.push('\n');
    }

    // Render once, then store the parts so a resize can re-fit the request line.
    let display_output = block.render(state.width as usize);
    push_output_block(state, block);

    // Update input with last command — or, mid-chain, keep the full chain on
    // the line so it doesn't flash the just-sent segment between requests.
    restore_input_after_send(state);
    print_output_and_rerender(state, stdout, &display_output)?;

    Ok(outcome)
}

/// Run a `&&` chain in the TUI: each segment sends only if the previous was
/// truthy. Returns once the chain finishes or is cut short.
///
/// Each segment prints its own block, so the log reads the same as if the
/// requests had been sent one at a time.
///
/// Returns `false` when a segment errored or was aborted — the chain was cut
/// short rather than answered — so a program running it can stop too.
fn execute_request_chain(
    state: &mut AppState,
    stdout: &mut io::Stdout,
    segments: &[(ChainOp, String)],
    full_chain: &str,
) -> io::Result<bool> {
    // Published so every per-segment input restore shows the whole chain.
    state.chain_input = Some(full_chain.to_string());
    let result: io::Result<(usize, bool, bool)> = (|| {
        // Outcome of the last EXECUTED segment; skipped segments leave it
        // alone (that's what makes `a && b || c` an if-then-else).
        let mut prev: Option<RequestOutcome> = None;
        let mut skipped = 0usize;
        let mut cut_short = false;
        let mut fail_fast = false;
        for (i, (op, segment)) in segments.iter().enumerate() {
            if !chain_segment_should_run(prev, *op) {
                skipped += 1;
                continue;
            }
            parse_input(state, segment);
            // A segment with something after it is a condition, and a
            // condition may answer "no". The last one is just a request.
            state.config.expect_falsy = i + 1 < segments.len();
            let outcome = execute_request(state, stdout);
            let tripped = fail_fast_tripped_at_prompt(&state.config);
            state.config.expect_falsy = false;
            let outcome = outcome?;
            if tripped {
                // `-f`: the chain's last request failed, so the program this
                // chain is part of stops here.
                cut_short = true;
                fail_fast = true;
                break;
            }
            match outcome {
                RequestOutcome::Truthy | RequestOutcome::Falsy => prev = Some(outcome),
                // Errored or aborted ends the chain — a following `||` does
                // NOT catch it. The reason is already on screen.
                RequestOutcome::Errored | RequestOutcome::Aborted => {
                    skipped += segments.len() - i - 1;
                    cut_short = true;
                    break;
                }
            }
        }
        Ok((skipped, cut_short, fail_fast))
    })();
    // Cleared on every exit, including an Err from execute_request — a stale
    // Some() would make the NEXT single request restore the old chain.
    state.chain_input = None;
    let (skipped, cut_short, fail_fast) = result?;
    if fail_fast {
        show_fail_fast_stop(state, stdout)?;
    } else if skipped > 0 {
        let plural = if skipped == 1 { "request" } else { "requests" };
        state.status_msg = format!("↳ skipped {} {}", skipped, plural);
        state.status_msg_at = Some(Instant::now());
        render(stdout, state)?;
    }
    Ok(!cut_short)
}

/// What a prompt line is once read as `.api` syntax.
enum PromptLine {
    /// Exactly one request, its text normalised as a file's would be.
    Request(String),
    /// Exactly one `&&`/`||` chain.
    Chain(Vec<(ChainOp, String)>),
    /// Anything else, including a line that doesn't parse — `run_program_line`
    /// reports that.
    Program,
}

/// The export mode an `export` line typed at the prompt left on, which the
/// next line starts in. A mode set for the whole session (`--export`,
/// ctrl+r) is not a line's: no step touches it, and nothing is kept out of it.
fn typed_export(config: &Config) -> Option<String> {
    if config.export_pinned { None } else { config.export_id.clone() }
}

fn classify_prompt_line(input: &str, export: Option<String>) -> PromptLine {
    // An import fetches, and its alias belongs to the session: both are
    // `run_program_line`'s to do.
    let imports = input
        .lines()
        .any(|l| l.split_whitespace().next().is_some_and(|w| w.eq_ignore_ascii_case("import")));
    if imports {
        return PromptLine::Program;
    }
    // Read in the export mode the prompt is in: a file named on the line is
    // then more than its one request, since it has to be kept out of that
    // mode, and runs as the program it is.
    match split_bulk_requests_with(input, None, &mut ImportAliases::new(), export) {
        Ok(mut program) if program.url_conditions.is_empty() && program.steps.len() == 1 => {
            match program.steps.pop() {
                Some(BulkStep::Request(r)) => PromptLine::Request(r),
                Some(BulkStep::Chain(s)) => PromptLine::Chain(s),
                _ => PromptLine::Program,
            }
        }
        _ => PromptLine::Program,
    }
}

/// Whether a prompt line is `.api` program syntax rather than a request: its
/// first word is neither an HTTP method nor a `/path`. Such a line goes
/// through the bulk parser, so directives (`confirm`, `sleep`, `assert`,
/// `url`) and includes work at the prompt exactly as they do in a file.
fn is_program_line(input: &str) -> bool {
    match input.split_whitespace().next() {
        None => false,
        Some(first) => !starts_a_request(first),
    }
}

/// A parse error as reported to the user, wherever the line came from. An
/// unknown word falls through to include handling, whose "not found" would
/// suggest the user meant a file; unless the word looks like one, they
/// mistyped a request.
fn describe_program_error(err: &str) -> String {
    let first_word = err
        .strip_prefix("include not found: ")
        .and_then(|spec| spec.split_whitespace().next());
    match first_word {
        Some(word) if !looks_like_a_path(word) => {
            format!("not a request or .api file: {}", word)
        }
        _ => err.to_string(),
    }
}

fn looks_like_a_path(word: &str) -> bool {
    names_api_file(word)
        || word.contains('/')
        || word.contains('\\')
        || word.starts_with('~')
        || word.starts_with('.')
}

/// Run a `.api` program typed at the prompt: parse the line with the bulk
/// parser (so includes expand), gate on `url`, then execute every step in
/// order with the interactive sender. The typed line stays on the input line
/// throughout and is restored afterwards, like a `&&` chain. A failed assert,
/// a declined confirm, an errored request, or esc stops the remaining steps.
fn run_program_line(state: &mut AppState, stdout: &mut io::Stdout, line: &str) -> io::Result<()> {
    // A fetch can take a moment; say what the prompt is busy with.
    if matches!(classify_prompt_line(line, None), PromptLine::Program) && line.to_ascii_lowercase().contains("import") {
        show_program_status(state, stdout, "importing…".to_string())?;
    }
    let program = match split_bulk_requests_in_session(line, typed_export(&state.config)) {
        Ok(p) => p,
        Err(e) => return show_program_status(state, stdout, describe_program_error(&e)),
    };
    if program.only_describes() {
        return show_program_status(state, stdout, DESCRIBE_ALONE.to_string());
    }
    if let Err(e) = evaluate_program_gates(&program, &state.config.base_uri) {
        return show_program_status(state, stdout, e);
    }
    for warning in &program.describe_warnings {
        log_directive_line(state, stdout, format!("warning: {}", warning).dimmed().to_string())?;
    }
    for note in &program.import_notes {
        log_directive_line(state, stdout, note.text.dimmed().to_string())?;
    }

    // Published so every per-request input restore shows the typed line.
    state.chain_input = Some(line.to_string());
    let result = run_program_steps(state, stdout, &program.steps);
    state.chain_input = None;
    state.config.quiet = false;
    state.config.check_only = false;
    result?;

    state.input = line.to_string();
    state.cursor_pos = char_len(&state.input);
    state.completions.clear();
    state.last_tab_input.clear();
    render(stdout, state)
}

/// Whether the response the prompt just received ends a program under `-f`.
/// Read before `expect_falsy` is reset, so a chain's condition is exempt.
fn fail_fast_tripped_at_prompt(config: &Config) -> bool {
    config.last_status.is_some_and(|status| fail_fast_trips(config, status))
}

/// Say in the hint line why the rest of a program did not run.
fn show_fail_fast_stop(state: &mut AppState, stdout: &mut io::Stdout) -> io::Result<()> {
    let status = state.config.last_status.unwrap_or_default();
    show_program_status(state, stdout, format!("stopped at {} (--fail-fast)", status))
}

/// Put a one-line verdict in the hint line and redraw.
fn show_program_status(state: &mut AppState, stdout: &mut io::Stdout, msg: String) -> io::Result<()> {
    state.status_msg = msg;
    state.status_msg_at = Some(Instant::now());
    render(stdout, state)
}

/// The step loop of `run_program_line`. Returns as soon as a step says stop.
fn run_program_steps(state: &mut AppState, stdout: &mut io::Stdout, steps: &[BulkStep]) -> io::Result<()> {
    for step in steps {
        let keep_going = match step {
            BulkStep::Request(request) => {
                parse_input(state, request);
                let answered = matches!(
                    execute_request(state, stdout)?,
                    RequestOutcome::Truthy | RequestOutcome::Falsy
                );
                // `-f` at the prompt stops the program, not the session.
                let tripped = fail_fast_tripped_at_prompt(&state.config);
                if tripped {
                    show_fail_fast_stop(state, stdout)?;
                }
                answered && !tripped
            }
            BulkStep::Chain(segments) => {
                let full = state.chain_input.clone().unwrap_or_default();
                let ok = execute_request_chain(state, stdout, segments, &full)?;
                // The chain runner clears this on exit; the program still needs it.
                state.chain_input = Some(full);
                ok
            }
            BulkStep::Sleep(d) => {
                log_directive_line(state, stdout, format!("sleep {}", format_duration(*d)).dimmed().to_string())?;
                wait_interruptible(state, stdout, *d, "sleeping")?
            }
            BulkStep::SleepWhile { interval, negate, request } => {
                run_sleep_while_interactive(state, stdout, *interval, *negate, request)?
            }
            BulkStep::Assert { negate, request } => {
                run_assert_interactive(state, stdout, *negate, request)?
            }
            BulkStep::Confirm(message) => {
                let prompt = confirm_prompt_text(message);
                let yes = confirm_in_hint(state, stdout, &prompt)?;
                let answer = if yes { "y" } else { "n" };
                log_directive_line(
                    state,
                    stdout,
                    format!("{} {}", format_confirm(message), answer.dimmed()),
                )?;
                if !yes {
                    state.status_msg = "aborted".to_string();
                    state.status_msg_at = Some(Instant::now());
                    render(stdout, state)?;
                }
                yes
            }
            BulkStep::Export { name, written } => {
                let applied = apply_export_step(&mut state.config, name);
                if *written {
                    log_directive_line(state, stdout, format_export(name).dimmed().to_string())?;
                    let said = match (applied, name) {
                        (true, Some(name)) => format!("export on: {}", name),
                        (true, None) => "export off".to_string(),
                        // Set for the session with --export or ctrl+r, which a line doesn't undo.
                        (false, _) => format!(
                            "export stays {}: set for the session (ctrl+r turns it off)",
                            state.config.export_id.as_deref().unwrap_or_default()
                        ),
                    };
                    show_program_status(state, stdout, said)?;
                }
                true
            }
        };
        if !keep_going {
            break;
        }
    }
    Ok(())
}

/// The question a `confirm [message]` asks, without the `[Y/n]` marker — the
/// caller adds whichever marker fits its prompt style.
fn confirm_prompt_text(message: &Option<String>) -> String {
    match message {
        Some(msg) if msg.ends_with('?') => msg.clone(),
        Some(msg) => format!("{}?", msg),
        None => "Continue?".to_string(),
    }
}

/// `assert` at the prompt: the request and status lines are logged, the body
/// isn't. A failure or an unanswerable request goes in the hint line and
/// stops the program.
fn run_assert_interactive(
    state: &mut AppState,
    stdout: &mut io::Stdout,
    negate: bool,
    request: &str,
) -> io::Result<bool> {
    let line = format_assert(negate, request);
    parse_input(state, request);
    // The log shows the check as typed, `assert GET /x`, not a bare GET.
    state.log_prefix = if negate { "assert not " } else { "assert " }.to_string();
    state.config.check_only = true;
    state.config.expect_falsy = negate;
    state.config.last_response = None;
    let outcome = execute_request(state, stdout);
    state.log_prefix.clear();
    state.config.check_only = false;
    state.config.expect_falsy = false;
    let outcome = outcome?;
    let response = state.config.last_response.take();

    // The verdict goes in the hint line for the moment and under the status
    // line for good: the hint fades in seconds, and without the note a
    // failed assert would leave nothing but a 200 OK in the scrollback.
    let (verdict, note) = match outcome {
        RequestOutcome::Truthy if !negate => return Ok(true),
        RequestOutcome::Falsy if negate => return Ok(true),
        RequestOutcome::Truthy | RequestOutcome::Falsy => {
            let why = response
                .map(|(status, body)| describe_check_response(status, &body))
                .unwrap_or_default();
            (format!("assertion failed: {} ({})", line, why), format!("↳ assertion failed ({})", why))
        }
        RequestOutcome::Errored => (
            format!("{} — could not be evaluated", line),
            "↳ could not be evaluated".to_string(),
        ),
        RequestOutcome::Aborted => return Ok(false),
    };
    note_last_block(state, stdout, &note.red().to_string())?;
    show_program_status(state, stdout, verdict)?;
    Ok(false)
}

/// `sleep while` at the prompt: polls print nothing; one line when the wait
/// starts and one when it ends, like `-sa`. Esc cancels; an errored poll
/// prints its block (the reason) and stops.
fn run_sleep_while_interactive(
    state: &mut AppState,
    stdout: &mut io::Stdout,
    interval: Duration,
    negate: bool,
    request: &str,
) -> io::Result<bool> {
    log_directive_line(state, stdout, format_sleep_while(interval, negate, request).dimmed().to_string())?;
    let start = Instant::now();
    let mut checks = 0usize;
    loop {
        checks += 1;
        parse_input(state, request);
        state.config.quiet = true;
        let outcome = execute_request(state, stdout)?;
        state.config.quiet = false;
        let done = match outcome {
            RequestOutcome::Truthy => negate,
            RequestOutcome::Falsy => !negate,
            RequestOutcome::Errored => {
                return show_program_status(
                    state,
                    stdout,
                    format!("{} — could not be evaluated", format_sleep_while(interval, negate, request)),
                )
                .map(|_| false);
            }
            RequestOutcome::Aborted => return Ok(false),
        };
        if done {
            break;
        }
        if !wait_interruptible(state, stdout, interval, "waiting")? {
            return Ok(false);
        }
    }
    let plural = if checks == 1 { "check" } else { "checks" };
    log_directive_line(
        state,
        stdout,
        format!("↳ waited {} ({} {})", format_elapsed(start.elapsed()), checks, plural)
            .dimmed()
            .to_string(),
    )?;
    Ok(true)
}

/// Sleep for `d` while staying responsive: esc or ctrl+c cancels (returns
/// false, with a note in the hint line). After half a second a spinner with
/// `label` takes over the hint line, like a slow request's.
fn wait_interruptible(
    state: &mut AppState,
    stdout: &mut io::Stdout,
    d: Duration,
    label: &str,
) -> io::Result<bool> {
    let start = Instant::now();
    let mut frame_idx = 0usize;
    let mut showing_spinner = false;
    while start.elapsed() < d {
        let remaining = d - start.elapsed();
        if event::poll(remaining.min(Duration::from_millis(80)))? {
            let event = event::read()?;
            note_resize(state, &event);
            if let Event::Key(key) = event {
                let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
                if ctrl_c || key.code == KeyCode::Esc {
                    show_program_status(state, stdout, format!("{} cancelled", label))?;
                    return Ok(false);
                }
            }
        }
        if start.elapsed() >= Duration::from_millis(500) {
            showing_spinner = true;
            let frame = SPINNER_FRAMES[frame_idx % SPINNER_FRAMES.len()];
            execute!(
                stdout,
                cursor::MoveToColumn(0),
                Clear(ClearType::CurrentLine),
Print(transient_hint_line(
                    state,
                    &format!("{} {} {}...", frame, label, format_duration(d)),
                    None
                ))
            )?;
            stdout.flush()?;
            frame_idx += 1;
        }
    }
    if showing_spinner {
        render(stdout, state)?;
    }
    Ok(true)
}

/// Ask a yes/no question in the hint line (where the cursor rests after a
/// render) and wait for a key. Enter and y accept; n and esc decline. The
/// line is redrawn by whatever the caller prints next.
fn confirm_in_hint(state: &mut AppState, stdout: &mut io::Stdout, prompt: &str) -> io::Result<bool> {
    execute!(
        stdout,
        cursor::MoveToColumn(0),
        Clear(ClearType::CurrentLine),
        Print(format!("  {} ", format!("{} (Y/n)", prompt).bold()))
    )?;
    stdout.flush()?;
    loop {
        if event::poll(Duration::from_millis(100))? {
            let event = event::read()?;
            note_resize(state, &event);
            if let Event::Key(key) = event {
                if key.kind != event::KeyEventKind::Press {
                    continue;
                }
                if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
                    return Ok(false);
                }
                if let Some(answer) = yes_no_from_key(&key) {
                    return Ok(answer);
                }
            }
        }
    }
}

/// The key → answer mapping shared by every raw-mode yes/no prompt: enter/y
/// accept, n/esc decline, anything else is ignored.
fn yes_no_from_key(key: &KeyEvent) -> Option<bool> {
    match key.code {
        KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => Some(true),
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => Some(false),
        _ => None,
    }
}

/// Byte range `[start, end)` of the `&&` chain segment containing `byte_pos` —
/// the whole input when the line isn't chained. Separator bytes belong to
/// neither segment. Same scan semantics as `split_request_chain`: separators
/// inside JSON strings or brackets don't count. A `byte_pos` on a segment's end
/// boundary (just before ` &&`) belongs to that segment.
fn chain_segment_bounds_at(input: &str, byte_pos: usize) -> (usize, usize) {
    let mut seg_start = 0usize;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    let mut iter = input.char_indices().peekable();

    while let Some((i, ch)) = iter.next() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && in_string {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if !in_string {
            match ch {
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                c @ ('&' | '|') if depth <= 0 && iter.peek().map(|&(_, n)| n) == Some(c) => {
                    // The segment ending here contains byte_pos — done.
                    if byte_pos <= i {
                        return (seg_start, i);
                    }
                    iter.next();
                    seg_start = i + 2;
                }
                _ => {}
            }
        }
    }
    (seg_start, input.len())
}

/// Byte offset just past the final top-level `&&` of `input` — the start of the
/// chain's last segment (0 when the line isn't chained).
fn last_chain_segment_start(input: &str) -> usize {
    chain_segment_bounds_at(input, input.len()).0
}

/// Run `f` with the cursor's `&&` segment presented as if it were the whole
/// input line, then splice whatever `f` did to it back into the full line.
///
/// The URI completion and ghost machinery all parse `state.input` as a single
/// `METHOD /uri …` line; inside a chain that made them operate on segment 1's
/// URI wherever the cursor was. Rather than teach each of them about chains,
/// this hands them one segment — cursor made segment-relative on the way in,
/// text and cursor restored to absolute on the way out. Unchained lines call
/// `f` directly, so single-request behavior is bit-for-bit unchanged.
///
/// Completion-cycling state (`last_tab_input`, `completions`) naturally stores
/// segment-relative text while chained, which stays consistent because every
/// completion path runs under the same view.
fn with_chain_segment_view<R>(state: &mut AppState, f: impl FnOnce(&mut AppState) -> R) -> R {
    let cursor_byte = char_to_byte_idx(&state.input, state.cursor_pos.min(char_len(&state.input)));
    let (seg_start, seg_end) = chain_segment_bounds_at(&state.input, cursor_byte);
    if seg_start == 0 && seg_end == state.input.len() {
        return f(state);
    }

    // Trim the segment's leading whitespace (the space after `&&`), and — for a
    // segment followed by a separator — its trailing whitespace (the space
    // before ` &&`), so the view looks exactly like a normal input line and a
    // cursor at the segment's text end reads as "at end". The last segment
    // keeps trailing spaces: `PUT /b ` at line end is meaningful (body ghosts).
    let segment = &state.input[seg_start..seg_end];
    let lead_ws = segment.len() - segment.trim_start().len();
    let view_start = seg_start + lead_ws;
    let view_end = if seg_end < state.input.len() {
        view_start + segment.trim().len()
    } else {
        seg_end
    };

    let original_cursor = state.cursor_pos;
    let full = std::mem::take(&mut state.input);
    let prefix_chars = char_len(&full[..view_start]);
    state.input = full[view_start..view_end].to_string();
    let entry_view_cursor = original_cursor.saturating_sub(prefix_chars).min(char_len(&state.input));
    state.cursor_pos = entry_view_cursor;

    let result = f(state);

    // Splice the (possibly edited) segment back between the untouched prefix
    // and tail. If the closure left the cursor where it entered (read-only use,
    // e.g. ghost computation), restore the ORIGINAL cursor exactly — the entry
    // clamp must never move the user's cursor as a side effect of a render.
    let view_cursor = state.cursor_pos.min(char_len(&state.input));
    let mut restored = String::with_capacity(view_start + state.input.len() + (full.len() - view_end));
    restored.push_str(&full[..view_start]);
    restored.push_str(&state.input);
    restored.push_str(&full[view_end..]);
    state.input = restored;
    state.cursor_pos = if view_cursor == entry_view_cursor {
        original_cursor
    } else {
        prefix_chars + view_cursor
    };

    result
}

/// Core of body auto-promotion. If the text between the start of the line's LAST
/// `&&` segment and byte offset `body_start` is exactly `GET <uri> ` (method +
/// URI + separating whitespace) or `<uri> ` (URI-only, implicit GET), rewrite
/// that segment's method to PUT — replacing the GET token or prepending `PUT ` —
/// since a body implies a write. Promotion never touches earlier segments: only
/// the last method of a `&&` sequence is ever promoted, and editing an earlier
/// segment's body position does nothing.
///
/// Records the promoted URI so the revert can refuse to fire once the last
/// segment targets something else (see `auto_revert_method_on_body_clear`).
/// `state.method` and the ctrl+space cycle window are only updated when the
/// promoted segment is the first — both refer to the line's leading method
/// token, and arming the cycle for a later segment would let ctrl+space rewrite
/// segment 1. Returns the change in the input's char length (0 = no promotion).
fn promote_method_prefix(state: &mut AppState, body_start: usize) -> i64 {
    if body_start > state.input.len() {
        return 0;
    }
    let seg_start = last_chain_segment_start(&state.input);
    // Editing an earlier segment's body position never promotes.
    if body_start < seg_start {
        return 0;
    }
    let segment = &state.input[seg_start..body_start];
    // There must be separating whitespace between the URI and the body.
    if !segment.ends_with(char::is_whitespace) {
        return 0;
    }
    let tokens: Vec<String> = segment.split_whitespace().map(str::to_string).collect();
    // Where the segment's first token begins, in absolute bytes.
    let token_start = seg_start + (segment.len() - segment.trim_start().len());
    let (delta, promoted_uri): (i64, String) = match tokens.as_slice() {
        [method, uri] if method.to_uppercase() == "GET" => {
            // Replace the segment's method token (preserving its position) with PUT.
            state.input.replace_range(token_start..token_start + method.len(), "PUT");
            (3 - method.len() as i64, uri.clone())
        }
        [uri] if uri.starts_with('/') => {
            // URI-only segment (implicit GET): prepend an explicit PUT.
            state.input.insert_str(token_start, "PUT ");
            (4, uri.clone())
        }
        _ => return 0,
    };
    state.method_auto_promoted = true;
    state.method_auto_promoted_uri = promoted_uri;
    if seg_start == 0 {
        state.method = "PUT".to_string();
        state.last_method_cycle = Some(std::time::Instant::now());
    }
    delta
}

/// When the user starts typing a request body, automatically promote the method
/// from GET to PUT, since a body implies a write. Fires when `typed` is the first
/// non-whitespace character of the body section — i.e. the text before it is
/// exactly `GET <uri> ` (or `<uri> ` for a URI-only line). The `>` outfile
/// redirect operator is excluded, as it begins an output redirect, not a body.
/// `&` and `|` are excluded too: they begin `&&`/`||` chain separators, not a body — promoting
/// there would silently turn the GET the user just chained after into a PUT.
/// The `@` infile prefix DOES promote: at the body position it always denotes a
/// file-reference request body (`PUT /people @data.json`), which implies a write
/// just like a literal JSON body.
fn auto_promote_method_on_body_start(state: &mut AppState, typed: char) {
    // A body implies a write, so only something that could start one promotes.
    // `@` is a file reference, which is a body too; `>` (outfile), `&`/`|`
    // (chain separators), and stray keystrokes are not.
    if typed != '@' && !is_json_value_start(typed) {
        return;
    }
    if state.cursor_pos == 0 {
        return;
    }
    let typed_byte = char_to_byte_idx(&state.input, state.cursor_pos - 1);
    let delta = promote_method_prefix(state, typed_byte);
    state.cursor_pos = (state.cursor_pos as i64 + delta).max(0) as usize;
}

/// Revert an automatic GET→PUT promotion once the body is gone again: if the
/// last `&&` segment's PUT came from auto-promotion and nothing follows its URI
/// anymore, rewrite that method back to GET. Called after deletion/clear
/// operations. A manual method change (ctrl+space, ctrl+g, paste-replace, …)
/// clears the flag, so explicitly chosen methods are never reverted.
///
/// Guarded by the recorded promoted URI: the revert fires only while the last
/// segment still targets the URI that was promoted. Without this, deleting a
/// promoted trailing segment could leave an EXPLICITLY typed `PUT /a` as the
/// last segment with the flag still set — and a further deletion would rewrite
/// a method the user chose by hand. On any mismatch the flag is cleared and
/// nothing is touched.
fn auto_revert_method_on_body_clear(state: &mut AppState) {
    if !state.method_auto_promoted {
        return;
    }
    let seg_start = last_chain_segment_start(&state.input);
    let segment = &state.input[seg_start..];
    let tokens: Vec<String> = segment.split_whitespace().map(str::to_string).collect();
    if tokens.is_empty() {
        state.method_auto_promoted = false;
        return;
    }
    if tokens[0].to_uppercase() != "PUT" {
        // The method changed some other way; the promotion no longer applies.
        state.method_auto_promoted = false;
        return;
    }
    // The last segment no longer targets what was promoted — this PUT is not
    // the one the promotion created. Never touch it.
    if tokens.len() < 2 || tokens[1] != state.method_auto_promoted_uri {
        state.method_auto_promoted = false;
        return;
    }
    if tokens.len() > 2 {
        return; // body still present
    }
    // Replace the segment's PUT with GET (same length — cursor stays aligned).
    let token_start = seg_start + (segment.len() - segment.trim_start().len());
    let put_len = tokens[0].len();
    state.input.replace_range(token_start..token_start + put_len, "GET");
    if seg_start == 0 {
        state.method = "GET".to_string();
    }
    state.method_auto_promoted = false;
}

/// What the loaded OpenAPI spec says a body to `uri` should look like.
///
/// `Unknown` covers both "the spec describes neither an array nor an object"
/// and "no spec is loaded yet" — neither is grounds for reshaping what the user
/// types, so both must behave the same.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BodyShape {
    /// An array whose elements are objects: a body starts `[{`.
    ArrayOfObjects,
    /// An array of scalars: a body starts `[` plus a scalar.
    ArrayOfScalars,
    /// A single object: a body starts `{`.
    Object,
    Unknown,
}

impl BodyShape {
    fn is_array(self) -> bool {
        matches!(self, BodyShape::ArrayOfObjects | BodyShape::ArrayOfScalars)
    }

    fn is_object(self) -> bool {
        matches!(self, BodyShape::ArrayOfObjects | BodyShape::Object)
    }
}

/// Resolve `uri` against the spec: whether the endpoint carries an array, and
/// whether the element type has properties (i.e. is an object). Shared by the
/// body ghost and the `[` auto-wrap so the hint and the expansion can never
/// disagree about the shape of the same endpoint.
fn expected_body_shape(state: &AppState, uri: &str) -> BodyShape {
    let is_array = state.array_endpoints.contains(uri);
    let (schema, _, _) = resolve_type_at_path(state, &format!("{}/", uri.trim_end_matches('/')));
    let is_object = schema
        .as_ref()
        .and_then(|s| {
            if let Some(indexer) = state.indexer_info.get(s) {
                indexer.return_type.as_ref().map(|rt| rt.trim_end_matches('?').to_string())
            } else {
                Some(s.clone())
            }
        })
        .map_or(false, |s| state.schema_props.contains_key(&s));
    match (is_array, is_object) {
        (true, true) => BodyShape::ArrayOfObjects,
        (true, false) => BodyShape::ArrayOfScalars,
        (false, true) => BodyShape::Object,
        (false, false) => BodyShape::Unknown,
    }
}

/// Whether `c` could begin a JSON value, i.e. whether typing it at the body
/// position plausibly starts a body at all. The RFC 8259 set: `{`, `[`, `"`,
/// a number (`-` or a digit), and the literals `true`/`false`/`null`.
///
/// Both body auto-expansions gate on this so a stray keystroke at the body
/// position is left alone. `<` — a mistyped `>` — is the motivating case: it
/// used to expand to `PUT /x [<`, costing two backspaces to undo. Blocklisting
/// the characters seen in practice (`>`, `&`, `|`, `@`, whitespace) could never
/// cover this; an allowlist inverts the default so only a real body expands.
fn is_json_value_start(c: char) -> bool {
    matches!(c, '{' | '[' | '"' | '-') || c.is_ascii_digit() || matches!(c, 't' | 'f' | 'n')
}

/// When the user starts typing a body on a PUT/PATCH to an array endpoint, and
/// the first body character isn't already `[`, prepend an opening `[` so the
/// body matches the expected array shape (e.g. `PUT /people {` → `PUT /people [{`).
/// Fires when `typed` is the first non-whitespace character of the body section —
/// i.e. the text before it is exactly `METHOD URI ` (method + URI + a separating
/// space). Inserting only `[` is intentional; the matching `]` is left to tab
/// completion. Runs after `auto_promote_method_on_body_start`, so a `GET` that was
/// just promoted to `PUT` is handled in the same keystroke. The `@` infile prefix
/// is excluded, as a file reference already provides the full body shape.
fn auto_wrap_array_body(state: &mut AppState, typed: char) {
    // `[` is a body start but needs no wrapping — it's already an array.
    if typed == '[' {
        return;
    }
    if state.cursor_pos == 0 {
        return;
    }
    // The just-typed character must be the first non-whitespace char of the LAST
    // `&&` segment's body: exactly METHOD + URI before it (within that segment),
    // with a separating space. Like promotion, never fires in earlier segments.
    // Runs after promotion, so a segment promoted this keystroke wraps too.
    let typed_byte = char_to_byte_idx(&state.input, state.cursor_pos - 1);
    let seg_start = last_chain_segment_start(&state.input);
    if typed_byte < seg_start {
        return;
    }
    let before = &state.input[seg_start..typed_byte];
    if !before.ends_with(char::is_whitespace) {
        return;
    }
    let tokens: Vec<&str> = before.split_whitespace().collect();
    if tokens.len() != 2 {
        return;
    }
    let method = tokens[0].to_uppercase();
    if method != "PUT" && method != "PATCH" {
        return;
    }
    // What the spec says the endpoint carries decides what may expand. Only an
    // array wraps at all; an array of objects takes only `{`, so a stray `<` or
    // a `"` that could never be a valid element is left exactly as typed. With
    // no spec loaded the shape is `Unknown` and nothing expands, as before.
    match expected_body_shape(state, tokens[1]) {
        BodyShape::ArrayOfObjects if typed != '{' => return,
        BodyShape::ArrayOfScalars if !is_json_value_start(typed) => return,
        BodyShape::Object | BodyShape::Unknown => return,
        _ => {}
    }
    // Prepend `[` immediately before the typed body character, keeping the cursor
    // just after what was typed.
    state.input.insert(typed_byte, '[');
    state.cursor_pos += 1;
}

/// After a body has been PASTED at the first-body position of a PUT/PATCH to an
/// array endpoint, wrap the pasted body in `[` … `]`. Unlike the typing variant
/// (which inserts only the opening `[` because the user is still composing), a
/// pasted body is complete, so both brackets are added:
/// `GET /people ` + paste `{ "name": "Joe" }` → `PUT /people [{ "name": "Joe" }]`.
///
/// `body_start..body_end` is the byte span of the pasted text in `state.input`.
/// Wraps only when the span is the whole body (exactly `METHOD URI ` before it),
/// the method is PUT/PATCH, the URI is a known array endpoint, and the pasted
/// text parses as a complete non-array JSON value — so already-array pastes stay
/// untouched, and partial JSON or `@file` references are left alone.
/// The cursor ends just after the inserted `]`.
fn wrap_pasted_array_body(state: &mut AppState, body_start: usize, body_end: usize) {
    if body_start >= body_end || body_end > state.input.len() {
        return;
    }
    // Segment-aware like the typing variant: the span must be the whole body of
    // the LAST `&&` segment; a paste into an earlier segment is never wrapped.
    let seg_start = last_chain_segment_start(&state.input);
    if body_start < seg_start {
        return;
    }
    let before = &state.input[seg_start..body_start];
    if !before.ends_with(char::is_whitespace) {
        return;
    }
    let tokens: Vec<&str> = before.split_whitespace().collect();
    if tokens.len() != 2 {
        return;
    }
    let method = tokens[0].to_uppercase();
    if method != "PUT" && method != "PATCH" {
        return;
    }
    let shape = expected_body_shape(state, tokens[1]);
    if !shape.is_array() {
        return;
    }
    let body_trimmed = state.input[body_start..body_end].trim_end();
    if body_trimmed.is_empty() {
        return;
    }
    // Complete JSON only, and not already an array (covers `@file` too — it
    // doesn't parse as JSON). On an array of objects a pasted scalar is a
    // mistake, and wrapping it would only cement it.
    match serde_json::from_str::<Value>(body_trimmed) {
        Ok(v) if !v.is_array() => {
            if shape == BodyShape::ArrayOfObjects && !v.is_object() {
                return;
            }
        }
        _ => return,
    }
    let close_at = body_start + body_trimmed.len();
    state.input.insert(close_at, ']');
    state.input.insert(body_start, '[');
    // `[` insertion shifted the `]` one byte right; place the cursor after it.
    state.cursor_pos = char_len(&state.input[..close_at + 2]);
}

fn cycle_method(state: &mut AppState) {
    // Split into (method, uri, raw body) preserving the body verbatim — a
    // token-join here would flatten multi-line JSON bodies into one line.
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    let trimmed = state.input.trim_start();
    if trimmed.trim().is_empty() {
        return;
    }
    let first_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let first = &trimmed[..first_end];
    let first_upper = first.to_uppercase();

    let (current, uri, body) = if methods.contains(&first_upper.as_str()) {
        let after_method = trimmed[first_end..].trim_start();
        if after_method.is_empty() {
            (first_upper, "/".to_string(), String::new())
        } else {
            let uri_end = after_method.find(char::is_whitespace).unwrap_or(after_method.len());
            let uri = after_method[..uri_end].to_string();
            // Preserve the body verbatim; trim only the separating spaces/tabs.
            let body = after_method[uri_end..]
                .trim_start_matches(|c: char| c == ' ' || c == '\t')
                .to_string();
            (first_upper, uri, body)
        }
    } else if first.starts_with('/') {
        // URI-only line: implicit GET.
        let body = trimmed[first_end..]
            .trim_start_matches(|c: char| c == ' ' || c == '\t')
            .to_string();
        ("GET".to_string(), first.to_string(), body)
    } else {
        return;
    };
    let body = if body.trim().is_empty() { String::new() } else { body };

    // If not on GET and >5s since last cycle, reset to GET instead of cycling
    let stale = state.last_method_cycle
        .map_or(true, |t| t.elapsed() > Duration::from_secs(5));
    let new_method = if stale && current != "GET" {
        "GET"
    } else {
        match current.as_str() {
            "GET" => "PUT",
            "PUT" => "PATCH",
            "PATCH" => "POST",
            _ => "GET",
        }
    };

    // Switching TO GET: stash the body (verbatim) and hide it
    if new_method == "GET" && current != "GET" {
        if !body.is_empty() {
            state.stashed_body = body;
        }
        state.input = format!("{} {}", new_method, uri);
    }
    // Switching FROM GET: restore stashed body if available
    else if current == "GET" && !state.stashed_body.is_empty() {
        state.input = format!("{} {} {}", new_method, uri, state.stashed_body);
    }
    // Normal case: carry the body over verbatim
    else if body.is_empty() {
        state.input = format!("{} {}", new_method, uri);
    } else {
        state.input = format!("{} {} {}", new_method, uri, body);
    }

    state.last_method_cycle = Some(std::time::Instant::now());
    state.cursor_pos = char_len(&state.input);
    state.method = new_method.to_string();
    // Cycling is an explicit method choice — never auto-revert it.
    state.method_auto_promoted = false;
}

/// How an inline input ended.
#[derive(Debug, PartialEq)]
enum InlineInput {
    /// Enter, with what was typed.
    Entered(String),
    /// Esc.
    Cancelled,
    /// ctrl+c: the user wants out of the client, not just of the dialog. The
    /// caller puts the command area's rows back and passes this on, so the
    /// session ends the way it always does and clears what it drew. Exiting
    /// from in here left the top ruler (and an unused session's splash) in
    /// the shell, and the terminal's paste and keyboard modes switched on.
    Quit,
}

// Read a line of input in raw mode (already in raw mode when called from interactive)
fn read_inline_input(stdout: &mut io::Stdout, prompt: &str, mask: bool, prefill: &str) -> io::Result<InlineInput> {
    read_inline_input_within(stdout, prompt, mask, prefill, None, None)
}

/// The prompt and the value of an inline input as one line of at most `cols`
/// columns holds them, with a column kept for the cursor block and one free
/// at the margin. A value too long for the line shows its end. `None` for
/// `cols` leaves both as they are.
fn inline_input_line(prompt: &str, value: &str, cols: Option<usize>) -> (String, String) {
    let Some(cols) = cols else {
        return (prompt.to_string(), value.to_string());
    };
    let budget = cols.saturating_sub(2);
    let prompt = fit_to_width(prompt, budget);
    let value = fit_tail_to_width(value, budget - char_len(&prompt));
    (prompt, value)
}

/// `read_inline_input` on a line that must not wrap. With `cols`, the
/// terminal's width, what is drawn never reaches the right margin however
/// much is typed, so the rows drawn around the line stay where they are.
///
/// `idle` is called while the input waits for a key, with the cursor on the
/// input's row, where it has to leave it. A dialog uses it to keep the row
/// under its ruler up to date.
fn read_inline_input_within(
    stdout: &mut io::Stdout,
    prompt: &str,
    mask: bool,
    prefill: &str,
    cols: Option<usize>,
    mut idle: Option<&mut dyn FnMut(&mut io::Stdout) -> io::Result<()>>,
) -> io::Result<InlineInput> {
    let mut buf = prefill.to_string();

    let shown = |buf: &str| -> (String, String) {
        let value = if mask && !buf.is_empty() { "•".repeat(char_len(buf)) } else { buf.to_string() };
        inline_input_line(prompt, &value, cols)
    };
    let render_line = |stdout: &mut io::Stdout, buf: &str| -> io::Result<()> {
        execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
        let (prompt, value) = shown(buf);
        execute!(stdout, Print(format!("{}{}\x1b[48;5;247m\x1b[38;5;0m \x1b[0m", prompt, value)))?;
        stdout.flush()?;
        Ok(())
    };

    render_line(stdout, &buf)?;

    // Often enough for a notice's pulse to be seen when there is one to draw.
    let wait = Duration::from_millis(if idle.is_some() { 30 } else { 100 });
    loop {
        if let Some(idle) = idle.as_mut() {
            idle(stdout)?;
        }
        if event::poll(wait)? {
            let event = event::read()?;
            // A paste fills the input: its first line, since the input is one.
            if let Event::Paste(text) = &event {
                buf.push_str(text.lines().next().unwrap_or("").trim());
            }
            if let Event::Key(key) = event {
                if key.kind != event::KeyEventKind::Press { continue; }
                // Like esc, both leave the cursor on the row under the prompt.
                let quit = key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c');
                if quit || key.code == KeyCode::Esc {
                    execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
                    execute!(stdout, Print("\r\n"))?;
                    return Ok(if quit { InlineInput::Quit } else { InlineInput::Cancelled });
                }
                match key.code {
                    KeyCode::Enter => {
                        execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
                        let (prompt, value) = shown(&buf);
                        execute!(stdout, Print(format!("{}{}\r\n", prompt, value)))?;
                        return Ok(InlineInput::Entered(buf));
                    }
                    KeyCode::Char(c) if types_a_character(key.modifiers) => { buf.push(c); }
                    KeyCode::Backspace => { buf.pop(); }
                    _ => {}
                }
            }
        }

        render_line(stdout, &buf)?;
    }
}

// Inline yes/no prompt in raw mode
fn confirm_inline(stdout: &mut io::Stdout, prompt: &str) -> io::Result<bool> {
    execute!(stdout, Print(format!("{} (Y/n) ", prompt)))?;
    stdout.flush()?;
    loop {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != event::KeyEventKind::Press { continue; }
                if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
                    execute!(stdout, cursor::Show)?;
                    terminal::disable_raw_mode()?;
                    exit_process(0);
                }
                if let Some(answer) = yes_no_from_key(&key) {
                    execute!(stdout, Print(if answer { "y\r\n" } else { "n\r\n" }))?;
                    return Ok(answer);
                }
            }
        }
    }
}

/// What the hint line says when the name typed for export mode is refused.
const EXPORT_NAME_REFUSED: &str = "export needs a namespaced key, like com.heads.seedID";

/// ctrl+r: turn export mode on or off for the session, as `--export` does for
/// a run. Turning it on needs the external identifier's name. There is no
/// default: it is asked for the first time, and remembered until the session
/// ends (a session started with `--export <name>` knows it already).
///
/// Returns `true` when ctrl+c in the dialog asked to leave the client.
fn handle_export_toggle(state: &mut AppState, stdout: &mut io::Stdout) -> io::Result<bool> {
    let notice = |state: &mut AppState, stdout: &mut io::Stdout, text: String| -> io::Result<bool> {
        state.status_msg = text;
        state.status_msg_at = Some(Instant::now());
        render(stdout, state)?;
        Ok(false)
    };
    if state.config.export_id.take().is_some() {
        state.config.export_pinned = false;
        return notice(state, stdout, "export off".to_string());
    }
    let name = match state.export_name.clone() {
        Some(name) => name,
        None => match ask_export_name(state, stdout)? {
            InlineInput::Quit => return Ok(true),
            InlineInput::Cancelled => return notice(state, stdout, "cancelled".to_string()),
            InlineInput::Entered(name) => name,
        },
    };
    state.streaming_flash_at = Some(Instant::now());
    state.export_name = Some(name.clone());
    state.config.export_id = Some(name.clone());
    // For the session, as `--export` is for a run: an `export` line in a
    // file run from here does not change it.
    state.config.export_pinned = true;
    notice(state, stdout, format!("export on: {}", name))
}

/// Ask, in the command area, for the name export mode keeps a lone key
/// under, the way ctrl+s asks for a connection's name: a prompt on the input
/// line, and `enter to …, esc to cancel` under the ruler.
///
/// The dialog stays open until it has a name that can be used, or is left:
/// `Entered` holds a namespaced key, esc or an empty answer is `Cancelled`,
/// ctrl+c is `Quit`. A name that is not a namespaced key is refused with the
/// prompt's regular notice, in the hint line, styled and timed as `render`
/// shows one, and what was typed stays on the line to correct.
///
/// The dialog takes the command area's place, row for row: the top ruler
/// stays, the prompt stands on the first input line, and the bottom ruler
/// and the hint line follow. Nothing in it may wrap. A row more than was
/// counted would put the prompt a row too low, over the bottom ruler, and
/// every redraw after the dialog would start a row too low as well and leave
/// a ruler behind. So the input line keeps to the width, and the rows below
/// it are drawn with auto-wrap off, as `render` draws its own. However it
/// ends, the cursor is left on the command area's hint line, where `render`
/// and the session's closing clear both start from.
fn ask_export_name(state: &mut AppState, stdout: &mut io::Stdout) -> io::Result<InlineInput> {
    let width = state.width as usize;
    let ruler_line = format!("\x1b[38;5;239m{}\x1b[0m", "─".repeat(width));
    let input_lines = state.prev_input_lines;
    let prompt = "› Export with external identifier: ";
    let hint = "enter to turn export on, esc to cancel";

    // From the hint line, where `render` leaves the cursor, up to the first
    // input line. Clear the command area from there; the top ruler is kept.
    // Leave the prompt's row empty for now, draw the bottom ruler and the
    // hint under it, and come back up for the input.
    execute!(
        stdout,
        cursor::MoveUp(1 + input_lines),
        cursor::MoveToColumn(0),
        Clear(ClearType::FromCursorDown),
        Print("\x1b[?7l"),
        Print("\r\n"),
        Print(format!("{}\r\n", ruler_line)),
        Print(format!("  {}", hint.chars().take(width.saturating_sub(2)).collect::<String>().dimmed())),
        Print("\x1b[?7h"),
        cursor::MoveUp(2),
        cursor::MoveToColumn(0)
    )?;

    // When the name was last refused. The notice stands in the hint line for
    // as long as a status message does, then the hint is back.
    let refused_at: std::cell::Cell<Option<Instant>> = std::cell::Cell::new(None);
    let mut notice_shown = false;
    let mut draw_hint_line = |stdout: &mut io::Stdout| -> io::Result<()> {
        let active = refused_at.get().filter(|at| at.elapsed() < STATUS_MSG_TTL);
        // Cut at the margin: with auto-wrap off a terminal would otherwise
        // pile the rest of the text onto its last column.
        let fits = |text: &str| -> String { text.chars().take(width.saturating_sub(2)).collect() };
        let line = match active {
            Some(at) => status_msg_styled(&fits(EXPORT_NAME_REFUSED), Some(at)),
            None if notice_shown => fits(hint).dimmed().to_string(),
            None => return Ok(()),
        };
        notice_shown = active.is_some();
        // The hint line is two rows under the prompt's.
        execute!(
            stdout,
            cursor::MoveDown(2),
            cursor::MoveToColumn(0),
            Clear(ClearType::CurrentLine),
            Print("\x1b[?7l"),
            Print(format!("  {}", line)),
            Print("\x1b[?7h"),
            cursor::MoveUp(2),
            cursor::MoveToColumn(0)
        )
    };

    let mut typed = String::new();
    let answer = loop {
        match read_inline_input_within(stdout, prompt, false, &typed, Some(width), Some(&mut draw_hint_line))? {
            InlineInput::Entered(name) => {
                let name = name.trim().to_string();
                if name.is_empty() {
                    break InlineInput::Cancelled;
                }
                if is_namespaced_key(&name) {
                    break InlineInput::Entered(name);
                }
                // Refused: say so, and ask again with the name left to
                // correct. Enter left the cursor a row down, on the ruler.
                refused_at.set(Some(Instant::now()));
                typed = name;
                execute!(stdout, cursor::MoveUp(1), cursor::MoveToColumn(0))?;
            }
            ended => break ended,
        }
    };

    // Enter, esc and ctrl+c all leave the cursor on the row under the prompt.
    // Clear from there, and go down to where the hint line of the command
    // area is.
    execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;
    for _ in 0..input_lines {
        execute!(stdout, Print("\r\n"))?;
    }
    Ok(answer)
}

/// Whether saving as `name` asks first: it would write over a saved
/// connection that is not the one the session runs.
fn save_asks_to_overwrite(saved: &[String], name: &str, current: &str) -> bool {
    saved.iter().any(|s| s == name) && name != current
}

/// The saved connection that a save as `name` takes the place of. A session
/// that runs the connection `current` renames it when it saves under a new
/// name. With a flag in the place of what `current` has stored, the session
/// does not hold that connection: a new name is then a new connection and
/// `current` stays as it is, with its secret.
fn save_replaces(current: &str, name: &str, overridden: bool) -> Option<String> {
    (!current.is_empty() && (!overridden || current == name)).then(|| current.to_string())
}

/// Returns `true` when ctrl+c at the name prompt asked to leave the client.
fn handle_save_connection(state: &mut AppState, stdout: &mut io::Stdout) -> io::Result<bool> {
    let width = state.width as usize;
    let ruler = "─".repeat(width);
    let input_lines = state.prev_input_lines;

    // Clear command area (input lines + bottom ruler + hint) but keep top ruler
    let clear_lines = 1 + input_lines; // input line(s) + bottom ruler + hint
    execute!(stdout, cursor::MoveUp(clear_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;

    // Print save prompt inside command area (between rulers)
    // Cursor is now just below the top ruler
    let prefill = state.connection_alias.clone();
    let prompt = "› Save connection as: ".to_string();

    // Print placeholder lines for bottom ruler + hint so terminal doesn't scroll
    let ruler_line = format!("\x1b[38;5;239m{}\x1b[0m", ruler);
    // Nothing here may wrap: a row more than was counted would put every
    // redraw a row too low. So the hint is cut to the width and drawn with
    // auto-wrap off, and the input keeps to the width, as in `ask_export_name`.
    let hint: String = "enter to save, esc to cancel".chars().take(width.saturating_sub(2)).collect();
    execute!(stdout, Print("\x1b[?7l"))?;
    execute!(stdout, Print("\r\n"))?; // placeholder for prompt line
    execute!(stdout, Print(format!("{}\r\n", ruler_line)))?; // bottom ruler
    execute!(stdout, Print(format!("  {}", hint.dimmed())))?; // hint
    execute!(stdout, Print("\x1b[?7h"))?;
    // Move back up to prompt line
    execute!(stdout, cursor::MoveUp(2), cursor::MoveToColumn(0))?;

    let name = match read_inline_input_within(stdout, &prompt, false, &prefill, Some(width), None)? {
        InlineInput::Entered(n) if !n.is_empty() => n,
        ended => {
            // Restore normal command area
            execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;
            for _ in 0..input_lines { execute!(stdout, Print("\r\n"))?; }
            if ended == InlineInput::Quit {
                // The cursor is on the hint line: the session's own closing
                // clear takes it from here.
                return Ok(true);
            }
            state.status_msg = "cancelled".to_string();
            state.status_msg_at = Some(Instant::now());
            render(stdout, state)?;
            return Ok(false);
        }
    };

    // Check if overwriting a different alias
    let envs = list_connections();
    if save_asks_to_overwrite(&envs, &name, &state.connection_alias) {
        // Move down past bottom ruler, replace hint with confirm prompt
        execute!(stdout, Print("\r\n"), cursor::MoveDown(1), cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
        if !confirm_inline(stdout, &format!("  \"{}\" already exists. Overwrite?", name))? {
            execute!(stdout, cursor::MoveUp(1), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;
            for _ in 0..input_lines { execute!(stdout, Print("\r\n"))?; }
            state.status_msg = "cancelled".to_string();
            state.status_msg_at = Some(Instant::now());
            render(stdout, state)?;
            return Ok(false);
        }
        // Move back up to prompt line area for cleanup
        execute!(stdout, cursor::MoveUp(2), cursor::MoveToColumn(0))?;
    }

    // Determine auth type from current config
    let (auth_type, credential, client_id) = if !state.config.oauth2_client_id.is_empty() && !state.config.oauth2_client_secret.is_empty() {
        // OAuth2 client credentials - save the credentials, not the token
        ("oauth2".to_string(), state.config.oauth2_client_secret.clone(), state.config.oauth2_client_id.clone())
    } else if !state.config.token.is_empty() {
        ("token".to_string(), state.config.token.clone(), String::new())
    } else {
        ("key".to_string(), state.config.api_key.clone(), String::new())
    };

    let env = SavedConnection {
        name: name.clone(),
        url: state.config.base_uri.clone(),
        auth_type,
        credential,
        client_id,
    };

    // Saved under a new name, the connection is renamed: the old entry goes
    // and its default flag moves with it.
    let replaces = save_replaces(&state.connection_alias, &name, state.config.connection_overridden);
    match save_connection(&env, replaces.as_deref()) {
        Ok(()) => {
            state.connection_alias = name.clone();
            // From here on the session holds a stored connection.
            state.config.connection_overridden = false;
            state.status_msg = format!("connection {} saved", name);
            state.status_msg_at = Some(Instant::now());
        }
        Err(e) => {
            state.status_msg = format!("save failed: {}", e);
            state.status_msg_at = Some(Instant::now());
        }
    }

    // Restore normal command area
    execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;
    for _ in 0..input_lines { execute!(stdout, Print("\r\n"))?; }
    render(stdout, state)?;
    Ok(false)
}

fn handle_switch_connection(state: &mut AppState, stdout: &mut io::Stdout) -> io::Result<Option<std::sync::mpsc::Receiver<BackgroundLoadResult>>> {
    let envs = list_connections();
    if envs.is_empty() {
        // A store that could not be read is not the same as none saved.
        state.status_msg = store_problem().unwrap_or_else(|| "no saved connections".to_string());
        state.status_msg_at = Some(Instant::now());
        render(stdout, state)?;
        return Ok(None);
    }

    let input_lines = state.prev_input_lines;

    // Clear command area (top ruler + input + bottom ruler + hint)
    let clear_lines = 2 + input_lines;
    execute!(stdout, cursor::MoveUp(clear_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;

    // Use unified connection flow
    let mut flow = ConnectionFlow::for_runtime(&envs, state.width);

    match flow.run(stdout)? {
        ConnectionFlowResult::Connected(env, preloaded, resolved_config) => {
            // Clear the flow UI (use tracked lines from last render)
            execute!(stdout, cursor::MoveUp(flow.last_rendered_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;

            // Apply connection
            if env.name.is_empty() {
                // From setup - new connection
                state.connection_alias = String::new();
                state.status_msg = "ctrl+s to save this connection".to_string();
            } else {
                // From picker - existing connection
                state.connection_alias = env.name.clone();
                state.loading_connection_name = Some(env.name.clone());
                state.status_msg = format!("connected to: {}", env.name);
            }
            state.status_msg_at = Some(Instant::now());

            // Only the connection changes: the session keeps its flags
            // (`-i`, `--timeout`, `-f`, `--export`, streaming…). What it
            // holds now is the connection as it is stored.
            state.config.connection_overridden = false;
            if let Err(e) = connect(&mut state.config, &env, resolved_config) {
                state.status_msg = e;
                state.status_msg_at = Some(Instant::now());
            }

            // Use preloaded result if available, otherwise load now
            let result = preloaded.unwrap_or_else(|| background_load(&state.config, None));
            apply_background_result(state, result);

            // Full screen clear and fresh start for new connection
            state.output_history.clear();
            terminal::disable_raw_mode()?;
            out!("\x1b[2J\x1b[3J\x1b[H");
            io::stdout().flush().ok();
            print_splash_with_width(&state.config, state.width);
            outln!();
            outln!();
            outln!();
            io::stdout().flush().ok();
            terminal::enable_raw_mode()?;

            state.last_was_splash = true;
            state.prev_input_lines = 1;
            render(stdout, state)?;
            Ok(None)
        }
        ConnectionFlowResult::Cancelled => {
            // Clear flow UI and restore normal view (use tracked lines from last render)
            execute!(stdout, cursor::MoveUp(flow.last_rendered_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;
            state.prev_input_lines = 1;
            execute!(stdout, Print("\r\n\r\n\r\n"))?;
            render(stdout, state)?;
            Ok(None)
        }
        ConnectionFlowResult::Quit => {
            // Full screen clear before exit
            terminal::disable_raw_mode()?;
            out!("\x1b[2J\x1b[3J\x1b[H");
            io::stdout().flush().ok();
            execute!(stdout, cursor::Show)?;
            exit_process(0);
        }
    }
}

/// One word for a POSIX shell, whatever it holds: in single quotes, where
/// nothing is special, with each `'` of its own written as `'\''`.
fn sh_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// The last request sent, as a curl command that sends the same thing: the
/// same method, URL, authorization, headers and body. Every value is one
/// quoted shell word, so a body with a `'`, or a URI with `$` or a backtick,
/// is passed as it is and nothing in it is run. `None` before any request.
///
/// The command holds the credential: that is what a command that can be run
/// as it is takes.
fn build_curl(state: &AppState) -> Option<String> {
    if state.prev_uri.is_empty() {
        return None;
    }
    let config = &state.config;

    let mut content_type = "application/json".to_string();
    let mut accept = "application/json".to_string();
    if config.ndjson {
        content_type = "application/x-ndjson".to_string();
        accept = "application/x-ndjson".to_string();
    }

    // An `@file` body: its extension says what it is, and `~map()` is a header.
    let is_file_body = state.prev_body.starts_with('@');
    let mut file_path = String::new();
    let mut body_headers: Vec<(String, String)> = Vec::new();
    if is_file_body {
        let (clean_body, extra_headers) = parse_body_functions(&state.prev_body);
        file_path = expand_home(clean_body.trim_start_matches("@ ").trim_start_matches('@').trim());
        body_headers = extra_headers;
        match outfile_format(&file_path) {
            OutFormat::Ndjson => {
                content_type = "application/x-ndjson".to_string();
                accept = "application/x-ndjson".to_string();
            }
            OutFormat::Csv => content_type = "text/csv".to_string(),
            _ => {}
        }
    }

    let to_clipboard = is_clipboard_target(&state.prev_display_outfile);
    let to_file = !state.prev_outfile.is_empty() && !to_clipboard;
    if let Some(asked) = to_file.then(|| accept_for_outfile(&state.prev_outfile)).flatten() {
        accept = asked.to_string();
    }
    if config.streaming {
        content_type.push_str(";stream=true");
        accept.push_str(";stream=true");
    }
    if config.include_nulls {
        accept.push_str(";skipNulls=false");
    }

    let url = format!("{}{}", config.base_uri, resolve_request_path(&config.api_path, &state.prev_uri));
    let mut cmd = format!("curl -gfsSL -X {} {}", state.prev_method, sh_quote(&url));
    // The header the request itself carried: Bearer for a token and for a
    // key shaped like a JWT, Basic otherwise.
    if let Some(authorization) = auth_header(config) {
        cmd.push_str(&format!(" -H {}", sh_quote(&format!("Authorization: {}", authorization))));
    }
    cmd.push_str(&format!(" -H {}", sh_quote(&format!("Accept: {}", accept))));
    if ["PUT", "PATCH", "POST"].contains(&state.prev_method.as_str()) {
        cmd.push_str(&format!(" -H {}", sh_quote(&format!("Content-Type: {}", content_type))));
    }
    if is_file_body {
        for (name, value) in &body_headers {
            cmd.push_str(&format!(" -H {}", sh_quote(&format!("{}: {}", name, value))));
        }
        cmd.push_str(&format!(" --data-binary {}", sh_quote(&format!("@{}", file_path))));
    } else if !state.prev_body.is_empty() {
        cmd.push_str(&format!(" --data-binary {}", sh_quote(&state.prev_body)));
    }
    // `> file` is curl's `-o`; `>> file` is the shell's; the clipboard is
    // nothing a command line has.
    if to_file && state.prev_outfile_append {
        cmd.push_str(&format!(" >> {}", sh_quote(&state.prev_outfile)));
    } else if to_file {
        cmd.push_str(&format!(" -o {}", sh_quote(&state.prev_outfile)));
    }
    Some(cmd)
}

fn copy_curl(state: &AppState) -> bool {
    build_curl(state).is_some_and(|cmd| cli_clipboard::set_contents(cmd).is_ok())
}

fn render_input_content(state: &mut AppState, width: usize) -> (String, u16, String) {
    // Ghost text is computed per `&&` segment, FIRST — the view mutates
    // `state.input` in place, so it must run before any slices are taken.
    // Inside the view, "cursor at end" means at the end of the cursor's SEGMENT
    // (e.g. just before ` && …`), so editing an earlier segment gets the same
    // ghosts as a standalone line.
    let chained = chain_segment_bounds_at(&state.input, 0) != (0, state.input.len());
    let ghost = with_chain_segment_view(state, |state| {
        let file_ctx = extract_file_path_context(&state.input, state.cursor_pos);
        // The view shows one segment as a whole line, which would make a
        // chain's bare word look like an include. A chain can't hold one.
        if chained && file_ctx.as_ref().is_some_and(|ctx| ctx.is_include) {
            return String::new();
        }
        let in_file_mode = file_ctx.is_some();
        let at_segment_end = state.cursor_pos == char_len(&state.input);
        if at_segment_end
            && (in_file_mode || (state.config.complete && !state.endpoints.is_empty()))
        {
            get_completion_ghost(state)
        } else if !at_segment_end && state.config.complete && !state.endpoints.is_empty() {
            get_completion_ghost_at_cursor(state)
        } else {
            String::new()
        }
    });

    // Build the rendered input string with cursor and ghost text
    let cursor_byte = char_to_byte_idx(&state.input, state.cursor_pos);
    let input_char_len = char_len(&state.input);
    let before_cursor = &state.input[..cursor_byte];
    let at_cursor = state.input.chars().nth(state.cursor_pos).unwrap_or(' ');
    let after_cursor = if state.cursor_pos < input_char_len {
        let next_byte = char_to_byte_idx(&state.input, state.cursor_pos + 1);
        &state.input[next_byte..]
    } else {
        ""
    };

    // Whether the cursor sits at the end of the WHOLE line — decides how the
    // ghost is drawn below (appended vs. inserted before the rest of the line).
    let cursor_at_end = state.cursor_pos == input_char_len;

    // Apply JSON syntax highlighting to the full body as one unit, then split at cursor
    let body_start = find_body_start(&state.input);
    let (hl_before, hl_at_cursor, hl_after) = if state.config.experimental {
        if let Some(bs) = body_start {
            let body = &state.input[bs..];
            let prefix = &state.input[..bs];
            let body_start_char = char_len(&state.input[..bs]);
            if cursor_byte >= bs && state.cursor_pos < input_char_len {
                // Cursor is inside body
                let cursor_in_body = state.cursor_pos - body_start_char;
                let (hb, hc, ha) = highlight_json_split(body, Some(cursor_in_body));
                (format!("{}{}", prefix, hb), hc.unwrap_or(' '), ha)
            } else if cursor_byte < bs {
                // Cursor is on URL line — highlight full body, split prefix at cursor
                let highlighted_body = highlight_json(body);
                let prefix_before = &state.input[..cursor_byte];
                let prefix_after = if state.cursor_pos < input_char_len {
                    let next_byte = char_to_byte_idx(&state.input, state.cursor_pos + 1);
                    &state.input[next_byte..bs]
                } else {
                    ""
                };
                (prefix_before.to_string(), at_cursor, format!("{}{}", prefix_after, highlighted_body))
            } else {
                // Cursor at end, past body
                (format!("{}{}", prefix, highlight_json(body)), ' ', String::new())
            }
        } else {
            (before_cursor.to_string(), at_cursor, after_cursor.to_string())
        }
    } else {
        (before_cursor.to_string(), at_cursor, after_cursor.to_string())
    };

    let mut rendered = String::new();
    rendered.push_str(&hl_before);

    if !ghost.is_empty() {
        if cursor_at_end {
            let ghost_chars: Vec<char> = ghost.chars().collect();
            if state.completions.len() > 1 {
                rendered.push_str(&format!("\x1b[48;5;240m{}\x1b[0m", ghost_chars[0]));
            } else {
                rendered.push_str(&format!("\x1b[48;5;247m\x1b[38;5;0m{}\x1b[0m", ghost_chars[0]));
            }
            if ghost_chars.len() > 1 {
                rendered.push_str(&format!("\x1b[38;5;240m{}\x1b[0m", ghost_chars[1..].iter().collect::<String>()));
            }
        } else {
            // Cursor char first, then ghost text, then rest of input
            if hl_at_cursor == '\n' {
                rendered.push_str("\x1b[48;5;247m\x1b[38;5;0m \x1b[0m");
                rendered.push_str(&format!("\x1b[38;5;240m{}\x1b[0m", ghost));
                rendered.push('\n');
                // hl_after must be verbatim: the cursor cell + the '\n' above
                // already represent the at-cursor newline. Trimming leading '\n'
                // here would swallow a following blank line, undercounting input
                // rows and making the block shift on redraw.
                rendered.push_str(&hl_after);
            } else {
                rendered.push_str(&format!("\x1b[48;5;247m\x1b[38;5;0m{}\x1b[0m", hl_at_cursor));
                rendered.push_str(&format!("\x1b[38;5;240m{}\x1b[0m", ghost));
                rendered.push_str(&hl_after);
            }
        }
    } else {
        if hl_at_cursor == '\n' {
            rendered.push_str("\x1b[48;5;247m\x1b[38;5;0m \x1b[0m");
            rendered.push('\n');
            // Verbatim — see note above; trimming would collapse a following
            // blank line and desync the rendered row count.
            rendered.push_str(&hl_after);
        } else {
            rendered.push_str(&format!("\x1b[48;5;247m\x1b[38;5;0m{}\x1b[0m", hl_at_cursor));
            rendered.push_str(&hl_after);
        }
    }

    // Cap the input viewport so the printed block never exceeds the screen (which
    // would scroll the terminal and desync render()'s relative cursor math). Window
    // around the cursor's logical line, leaving room for both rulers, the hint, and
    // some output above.
    let cursor_line = state.input[..cursor_byte].matches('\n').count();
    let max_input_lines = state.height.saturating_sub(5).max(3);
    let (rendered, input_line_count) = clamp_input_viewport(&rendered, width, max_input_lines, cursor_line);

    // Build the final output lines with hints appended to the last line
    let lines: Vec<&str> = rendered.split('\n').collect();
    let mut output = String::new();
    for line in &lines[..lines.len() - 1] {
        output.push_str(line);
        output.push_str("\r\n");
    }

    let last_line = lines.last().unwrap_or(&"");
    let mut final_line = last_line.to_string();

    let last_input_line = state.input.split('\n').last().unwrap_or("");
    let last_line_len = char_len(last_input_line) + char_len(&ghost) + 1;

    let parts: Vec<&str> = state.input.split_whitespace().collect();
    let uri = if parts.len() >= 2 { parts[1] } else if parts.len() == 1 && parts[0].starts_with('/') { parts[0] } else { "/" };
    let param_hint = if state.config.complete { get_param_hint(state, uri) } else { String::new() };

    if !param_hint.is_empty() {
        let padding = width.saturating_sub(last_line_len).saturating_sub(param_hint.len());
        if padding > 0 {
            final_line.push_str(&" ".repeat(padding));
            final_line.push_str(&format!("\x1b[38;5;240m{}\x1b[0m", param_hint));
        }
    } else if state.completions.len() > 1 {
        let counter = format!("({}/{})", state.completion_idx + 1, state.completions.len());
        let padding = width.saturating_sub(last_line_len).saturating_sub(counter.len());
        if padding > 0 {
            final_line.push_str(&" ".repeat(padding));
            final_line.push_str(&format!("\x1b[38;5;240m{}\x1b[0m", counter));
        }
    }

    output.push_str(&final_line);

    (output, input_line_count, ghost)
}

/// Right margin kept clear to the marker's right, mirroring the 2-space indent
/// the hint line carries on the left.
const STREAMING_INDICATOR_MARGIN: usize = 2;

/// The right-aligned `streaming` marker for the hint line, sitting
/// `STREAMING_INDICATOR_MARGIN` columns in from the right edge. `left_width` is
/// the visible width already used by the hint or status message (excluding its
/// 2-space indent). Returns an empty string when streaming is off or the line is
/// too narrow to hold both.
///
/// Auto-wrap is disabled around this block, so even writing to the final column
/// is safe — no phantom line appears.
fn streaming_indicator(state: &AppState, left_width: usize) -> String {
    let (Some(pad), Some(label)) = (streaming_indicator_pad(state, left_width), footer_indicator(state)) else {
        return String::new();
    };

    // Pulse white on activation, using the same two-beat envelope as status
    // messages but reaching full white so it reads as a state change.
    let styled = match state.streaming_flash_at {
        Some(at) => {
            let ms = at.elapsed().as_millis() as u16;
            let base: u16 = 240;
            let peak: u16 = 255;
            let range = peak - base;
            let shade = if ms < 150 {
                let t = ms as f32 / 150.0;
                Some(base + ((t * std::f32::consts::PI).sin() * range as f32) as u16)
            } else if (200..350).contains(&ms) {
                let t = (ms - 200) as f32 / 150.0;
                Some(base + ((t * std::f32::consts::PI).sin() * range as f32) as u16)
            } else {
                None
            };
            match shade {
                Some(s) => format!("\x1b[38;5;{}m{}\x1b[0m", s, label),
                None => label.dimmed().to_string(),
            }
        }
        None => label.dimmed().to_string(),
    };

    // No trailing spaces needed — render clears the area first, so the margin is
    // simply columns we decline to write into.
    format!("{}{}", " ".repeat(pad), styled)
}

/// The marker at the right of the hint line: `export` while export mode is
/// on, `streaming` while streaming is, nothing otherwise. Export wins, since
/// a response is read whole while it is on.
fn footer_indicator(state: &AppState) -> Option<&'static str> {
    if state.config.export_id.is_some() {
        Some(EXPORT_INDICATOR)
    } else if state.config.streaming {
        Some(STREAMING_INDICATOR)
    } else {
        None
    }
}

/// Spaces between the left-hand text and the marker, or `None` when there is
/// no marker to show or the line can't hold both.
fn streaming_indicator_pad(state: &AppState, left_width: usize) -> Option<usize> {
    let label = footer_indicator(state)?;
    let width = state.width as usize;
    let used = 2 + left_width + label.len() + STREAMING_INDICATOR_MARGIN;
    // Not enough room — the left-hand text is the more useful of the two.
    (width >= used + 1).then(|| width - used)
}

/// One full dim-white-dim swing of the marker while data is arriving.
const STREAM_PULSE_PERIOD: Duration = Duration::from_millis(1000);

/// How long after the last byte the marker keeps pulsing. Longer than a
/// redraw tick, so a steady transfer doesn't flicker between the two states.
const STREAM_PULSE_LINGER: Duration = Duration::from_millis(300);

/// 256-colour grey for the marker `since` into a pulse: dim (240) at the
/// start of each period, white (255) halfway through.
fn stream_pulse_shade(since: Duration) -> u16 {
    let phase = (since.as_millis() % STREAM_PULSE_PERIOD.as_millis()) as f32
        / STREAM_PULSE_PERIOD.as_millis() as f32;
    240 + ((phase * std::f32::consts::PI).sin() * 15.0).round() as u16
}

/// Decides, from successive byte counts, whether data is arriving right now.
struct StreamPulse {
    last_received: u64,
    last_growth: Option<Instant>,
    /// When the current run of arriving data began.
    pulse_start: Option<Instant>,
}

impl StreamPulse {
    fn new() -> Self {
        StreamPulse { last_received: 0, last_growth: None, pulse_start: None }
    }

    /// Feed the latest byte count. Returns how far into a pulse the marker
    /// is, or `None` when nothing has arrived lately.
    fn observe(&mut self, received: u64, now: Instant) -> Option<Duration> {
        if received > self.last_received {
            self.last_received = received;
            self.last_growth = Some(now);
            self.pulse_start.get_or_insert(now);
        }
        match self.last_growth {
            Some(at) if now.duration_since(at) <= STREAM_PULSE_LINGER => {
                self.pulse_start.map(|start| now.duration_since(start))
            }
            _ => {
                self.pulse_start = None;
                None
            }
        }
    }
}

/// A transient hint line (spinner, progress, abort notice) with the
/// `streaming` marker kept in its usual place. `pulse` is how far into a
/// pulse the marker is; `None` leaves it steady.
fn transient_hint_line(state: &AppState, text: &str, pulse: Option<Duration>) -> String {
    let mut line = format!("  {}", text.dimmed());
    if let (Some(pad), Some(label)) = (streaming_indicator_pad(state, text.chars().count()), footer_indicator(state)) {
        line.push_str(&" ".repeat(pad));
        match pulse {
            Some(since) => line.push_str(&format!(
                "\x1b[38;5;{}m{}\x1b[0m",
                stream_pulse_shade(since),
                label
            )),
            None => line.push_str(&label.dimmed().to_string()),
        }
    }
    line
}

/// Put the streaming caveat on the footer. Shown on every activation, not once
/// a session: at three seconds it reads as confirmation of the state change
/// standing beside it, and the lasting reminder is the `streaming` marker.
fn show_streaming_info(state: &mut AppState) {
    state.status_msg = STREAMING_INFO_MSG.to_string();
    state.status_msg_at = Some(Instant::now());
}

/// Drop the streaming caveat if it's the message currently up — used when
/// streaming is switched off before the notice has finished.
fn clear_streaming_info(state: &mut AppState) {
    if state.status_msg == STREAMING_INFO_MSG {
        state.status_msg.clear();
        state.status_msg_at = None;
    }
}

fn flash_rulers(stdout: &mut io::Stdout, state: &mut AppState, color: &str, ms: u64) -> io::Result<()> {
    let w = state.width as usize;
    let up = 2 + state.prev_input_lines;
    let r = "\x1b[0m";

    // Move to top ruler, redraw only rulers — skip over input content entirely
    queue!(
        stdout,
        cursor::Hide,
        cursor::MoveUp(up.min(state.height.saturating_sub(1))),
        cursor::MoveToColumn(0),
        Clear(ClearType::CurrentLine),
    )?;

    // Top ruler in color
    if !state.config.base_uri.is_empty() && state.config.base_uri.len() + 11 <= w {
        let host_len = state.config.base_uri.len() + 2;
        let right = 7;
        let left = w.saturating_sub(host_len).saturating_sub(right);
        queue!(stdout, Print(format!(
            "{color}{}{r} \x1b[38;5;247m{}{r} {color}{}{r}",
            "─".repeat(left),
            state.config.base_uri,
            "─".repeat(right),
        )))?;
    } else {
        queue!(stdout, Print(format!("{color}{}{r}", "─".repeat(w))))?;
    }

    // Skip over input lines, redraw bottom ruler in color
    queue!(
        stdout,
        cursor::MoveDown(state.prev_input_lines + 1),
        cursor::MoveToColumn(0),
        Clear(ClearType::CurrentLine),
        Print(format!("{color}{}{r}", "─".repeat(w))),
    )?;

    // Move back down past hint line to restore cursor position
    queue!(stdout, cursor::MoveDown(1), cursor::MoveToColumn(0))?;
    stdout.flush()?;

    thread::sleep(Duration::from_millis(ms));

    // Restore rulers to dimmed
    let d = "\x1b[38;5;239m";
    queue!(
        stdout,
        cursor::MoveUp(2 + state.prev_input_lines),
        cursor::MoveToColumn(0),
        Clear(ClearType::CurrentLine),
    )?;
    if !state.config.base_uri.is_empty() && state.config.base_uri.len() + 11 <= w {
        let host_len = state.config.base_uri.len() + 2;
        let right = 7;
        let left = w.saturating_sub(host_len).saturating_sub(right);
        queue!(stdout, Print(format!(
            "{d}{}{r} {}{d} {}{r}",
            "─".repeat(left),
            state.config.base_uri.dimmed(),
            "─".repeat(right)
        )))?;
    } else {
        queue!(stdout, Print(format!("{d}{}{r}", "─".repeat(w))))?;
    }
    queue!(
        stdout,
        cursor::MoveDown(state.prev_input_lines + 1),
        cursor::MoveToColumn(0),
        Clear(ClearType::CurrentLine),
        Print(format!("{d}{}{r}", "─".repeat(w))),
        cursor::MoveDown(1),
        cursor::MoveToColumn(0),
    )?;
    stdout.flush()?;

    Ok(())
}

/// A status message as the hint line shows it: dimmed, pulsing twice in its
/// first 350ms when `at` says when it was put up. Used by `render`, and by a
/// dialog that has something to say while it is open, so a notice looks the
/// same wherever it appears.
fn status_msg_styled(msg: &str, at: Option<Instant>) -> String {
    if msg.contains("ctrl+c again") {
        // Stay white for the full duration
        return format!("\x1b[97m{}\x1b[0m", msg);
    }
    if msg.starts_with("connected to:") {
        // No flash, just dimmed gray for 3 seconds
        return msg.dimmed().to_string();
    }
    let Some(at) = at else {
        return msg.dimmed().to_string();
    };
    // Two smooth pulses: 0-150ms and 200-350ms
    // Each pulse fades from 240 (dim) up to 250 (light) and back
    let ms = at.elapsed().as_millis() as u16;
    let (base, peak): (u16, u16) = (240, 250);
    let into_pulse = if ms < 150 {
        Some(ms)
    } else if (200..350).contains(&ms) {
        Some(ms - 200)
    } else {
        None
    };
    match into_pulse {
        Some(t) => {
            let v = (t as f32 / 150.0 * std::f32::consts::PI).sin();
            format!("\x1b[38;5;{}m{}\x1b[0m", base + (v * (peak - base) as f32) as u16, msg)
        }
        None => msg.dimmed().to_string(),
    }
}

fn render<W: Write>(stdout: &mut W, state: &mut AppState) -> io::Result<()> {
    let width = state.width as usize;
    state.prev_width = state.width;

    // Determine how many lines to clear:
    // - Normal input area: 2 + input_lines (ruler + input line(s) + hint)
    // - Help menu: its fixed rows, plus the streaming section when it applies
    let help_lines: u16 = help_line_count(state);
    let normal_lines: u16 = 2 + state.prev_input_lines; // ruler + input line(s) + hint
    let lines_to_clear: u16 = if state.prev_show_help && !state.show_help {
        help_lines  // Closing help - clear all help lines
    } else if state.show_help && state.prev_show_help {
        help_lines  // Help already showing - redraw help area
    } else if state.show_help && !state.prev_show_help {
        normal_lines  // Opening help - clear normal input, expand down
    } else {
        normal_lines  // Normal input area
    };

    // Update prev_show_help for next render
    state.prev_show_help = state.show_help;

    // Queue all render operations without flushing — single flush at end of render.
    //
    // Auto-wrap (DECAWM) is disabled for the whole block draw below. The block's
    // lines are pre-wrapped to the terminal width by `hard_wrap_ansi`, so the rows
    // we print exactly equal the rows we count in `prev_input_lines`. With auto-wrap
    // left on, a line that reaches the right margin leaves some terminals in a
    // "pending wrap" state that materializes as a phantom extra row — making the
    // printed height disagree with our count, so the relative clear below moves up
    // the wrong amount and the block creeps into the splash after a wrapped paste.
    queue!(
        stdout,
        cursor::Hide,
        Print("\x1b[?7l"), // disable auto-wrap for deterministic block height
        cursor::MoveUp(lines_to_clear.min(state.height.saturating_sub(1))),
        cursor::MoveToColumn(0),
        Clear(ClearType::FromCursorDown)
    )?;

    // Top ruler
    let ruler_line = format!("\x1b[38;5;239m{}\x1b[0m", "─".repeat(width));
    if !state.config.base_uri.is_empty() && char_len(&state.config.base_uri) + 11 <= width {
        let host_text = &state.config.base_uri;
        let host = format!(" {} ", host_text);
        let host_len = char_len(&host);
        let right = 7;
        let left = width.saturating_sub(host_len).saturating_sub(right);
        let d = "\x1b[38;5;239m";
        let r = "\x1b[0m";
        queue!(
            stdout,
            Print(format!(
                "{d}{}{r} {}{d} {}{r}\r\n",
                "─".repeat(left),
                host_text.dimmed(),
                "─".repeat(right)
            ))
        )?;
    } else {
        queue!(stdout, Print(format!("{}\r\n", ruler_line)))?;
    }

    // Input line or help
    if state.loading {
        let frame = SPINNER_FRAMES[state.loading_frame % SPINNER_FRAMES.len()];
        // Which step is running is reported by the background thread — the main
        // thread's `config.base_uri` isn't set until the whole load finishes, so
        // it can't distinguish a 1P wait from a slow server.
        let msg = match (&state.loading_connection_name, load_phase::get()) {
            (Some(env_name), load_phase::RESOLVING_1P) => {
                format!(" {} Loading connection {} from 1P...", frame, env_name)
            }
            (Some(env_name), load_phase::LOADING_SPEC) => {
                format!(" {} Loading API spec from {}...", frame, env_name)
            }
            (Some(env_name), _) => format!(" {} Connecting to {}...", frame, env_name),
            (None, load_phase::RESOLVING_1P) => format!(" {} Loading environment from 1P...", frame),
            (None, load_phase::LOADING_SPEC) => format!(" {} Loading API spec...", frame),
            (None, _) => format!(" {} Connecting...", frame),
        };
        queue!(stdout, Print(format!("{}\r\n", msg.dimmed())))?;
        state.prev_input_lines = 1; // single spinner line — keep the span exact
    } else if state.show_help {
        // Drawn from the rows the closing clear counts — see `help_rows`.
        for row in help_rows(state) {
            queue!(stdout, Print(format!("{}\r\n", row.dimmed())))?;
        }
    } else if state.body_input_mode {
        // Show method + URI on first line, prompt on second, buffer with cursor below
        let header = format!("{} {}", state.body_input_method, state.body_input_uri);
        let header_lines = visual_line_count(&header, width);
        queue!(stdout, Print(format!("{}\r\n", hard_wrap_ansi(&header, width))))?;
        let prompt = "Enter body, ctrl+d when done (esc to cancel)";
        let prompt_lines = visual_line_count(prompt, width);
        queue!(stdout, Print(format!("{}\r\n", hard_wrap_ansi(&prompt.dimmed().to_string(), width))))?;
        let buf_lines: Vec<&str> = if state.body_input_buffer.is_empty() {
            vec![""]
        } else {
            state.body_input_buffer.split('\n').collect()
        };
        let last_idx = buf_lines.len() - 1;
        let mut total_buf_visual_lines: u16 = 0;
        for (i, line) in buf_lines.iter().enumerate() {
            if i == last_idx {
                // Account for the cursor character (1 column)
                let line_with_cursor_width = visible_len(line) + 1;
                let lines_for_this = if width == 0 { 1 } else {
                    ((line_with_cursor_width + width - 1) / width).max(1) as u16
                };
                total_buf_visual_lines += lines_for_this;
                let line_with_cursor = format!("{}\x1b[48;5;247m\x1b[38;5;0m \x1b[0m", line);
                queue!(stdout, Print(format!("{}\r\n", hard_wrap_ansi(&line_with_cursor, width))))?;
            } else {
                total_buf_visual_lines += visual_line_count(line, width);
                queue!(stdout, Print(format!("{}\r\n", hard_wrap_ansi(line, width))))?;
            }
        }
        state.prev_input_lines = header_lines + prompt_lines + total_buf_visual_lines;
    } else {
        let (input_output, input_line_count, _ghost) = render_input_content(state, width);
        // Pre-wrap to the terminal width and print with auto-wrap disabled (set at
        // the top of render) so the rows printed exactly match `input_line_count`.
        let wrapped = hard_wrap_ansi(&input_output, width);
        queue!(stdout, Print(&wrapped), Print("\r\n"))?;
        state.prev_input_lines = input_line_count;
    }

    // Bottom ruler and hint (only when not showing help - help has its own)
    if !state.show_help {
        queue!(stdout, Print(format!("{}\r\n", ruler_line)))?;

        // Hint line. A status message is always said, cut to the width if
        // it has to be: "ctrl+c again to exit" and a program's error are not
        // to go missing on a narrow terminal. The standing hint is only
        // drawn where it fits ("ctrl+h for shortcuts" is 21 chars + 2 indent).
        if !state.status_msg.is_empty() {
            let shown = if width >= 22 {
                state.status_msg.clone()
            } else {
                fit_to_width(&visible_text(&state.status_msg), width.saturating_sub(2))
            };
            let msg_style = status_msg_styled(&shown, state.status_msg_at);
            queue!(stdout, Print(format!("  {}", msg_style)))?;
            if width >= 22 {
                queue!(stdout, Print(streaming_indicator(state, visible_len(&state.status_msg))))?;
            }
        } else if width >= 22 {
            let hint = "ctrl+h for shortcuts";
            queue!(stdout, Print(format!("  {}", hint.dimmed())))?;
            queue!(stdout, Print(streaming_indicator(state, hint.len())))?;
        }
    }

    // Re-enable auto-wrap now that the fixed-height block has been drawn.
    queue!(stdout, Print("\x1b[?7h"))?;
    stdout.flush()?;

    Ok(())
}

fn print_splash_with_width(config: &Config, term_width: u16) {
    let full_width = 60usize;
    let min_width = SPLASH_MIN_WIDTH; // Minimum to show title properly
    let hint_section_width = 20usize; // " │ ctrl+b for docs │" length

    let term_w = term_width as usize;

    // Don't print splash if terminal is too narrow
    if term_w < min_width {
        outln!();
        return;
    }

    let host = config.base_uri.as_str();

    let title = "CommerceOS API Client";
    let version = format!("v{}", VERSION);
    let hint = "ctrl+b for docs";

    // Determine actual width to use
    let show_hint = term_w >= full_width;
    let actual_width = if show_hint {
        full_width
    } else {
        // Clamp between min and full_width - hint section
        term_w.max(min_width).min(full_width - hint_section_width + 2)
    };

    let title_len = title.len() + version.len() + 3;
    let top_padding = actual_width.saturating_sub(4 + title_len + 1);

    outln!();
    outln!(
        "{}{}{}{}",
        "╭───".dimmed(),
        format!(" {} {} ", title.bold(), version.dimmed()),
        "─".repeat(top_padding.max(1)).dimmed(),
        "╮".dimmed()
    );

    if show_hint {
        // Full width with hint
        let host_space = actual_width - 7 - hint.len();
        let host_display = head_chars(host, host_space);
        let host_padded = format!("{:width$}", host_display, width = host_space);
        // Use \x1b[K to clear to end of line (prevents artifacts from previous content)
        outln!(
            "{}{}{}{}{}\x1b[K",
            "│ ".dimmed(),
            host_padded.dimmed(),
            " │ ".dimmed(),
            hint.dimmed(),
            " │".dimmed()
        );
    } else {
        // Truncated - no hint section
        let host_space = actual_width.saturating_sub(4);
        let host_display = head_chars(host, host_space);
        let host_padded = format!("{:width$}", host_display, width = host_space);
        outln!(
            "{}{}{}",
            "│ ".dimmed(),
            host_padded.dimmed(),
            " │".dimmed()
        );
    }

    outln!("{}", format!("╰{}╯", "─".repeat(actual_width - 2)).dimmed());
    outln!();
}

/// How many lines `print_splash_with_width` prints at this width: the box
/// with a blank line above and below, or just the blank line when the
/// terminal is too narrow for the box.
fn splash_line_count(term_width: u16) -> u16 {
    if (term_width as usize) < SPLASH_MIN_WIDTH { 1 } else { 5 }
}

/// Narrower than this, the splash box is not drawn at all.
const SPLASH_MIN_WIDTH: usize = 36;

fn print_splash(config: &Config) {
    // Default to 80 width when called without terminal size
    print_splash_with_width(config, 80);
}

fn print_splash_loading(config: &Config, term_width: u16) {
    let mut loading_config = config.clone();
    loading_config.base_uri = "".to_string();
    print_splash_with_width(&loading_config, term_width);
}

fn background_load(config: &Config, op_selector: Option<String>) -> BackgroundLoadResult {
    // Resolve 1Password credentials first if needed
    let mut config = config.clone();
    let mut base_uri: Option<String> = None;
    let mut api_key: Option<String> = None;

    // Publish the starting phase so the spinner doesn't report a 1P wait that
    // isn't happening (or keep reporting one that's already finished).
    load_phase::set(if op_selector.is_some() {
        load_phase::RESOLVING_1P
    } else {
        load_phase::CONNECTING
    });

    if let Some(selector) = op_selector {
        match get_1password_credentials(&selector) {
            Ok((uri, key)) => {
                config.base_uri = uri.clone();
                config.api_key = key.clone();
                base_uri = Some(uri);
                api_key = Some(key);
                load_phase::set(load_phase::CONNECTING);
            }
            Err(e) => {
                return BackgroundLoadResult {
                    spec_unreadable: false,
                    streaming: false,
                    complete: false,
                    connected: false,
                    base_uri: None,
                    api_key: None,
                    error: Some(e),
                    endpoints: Vec::new(),
                    schema_props: HashMap::new(),
                    endpoint_types: HashMap::new(),
                    param_types: HashMap::new(),
                    endpoint_schemas: HashMap::new(),
                    indexer_info: HashMap::new(),
                    prop_types: HashMap::new(),
                    array_members: HashMap::new(),
                    primitive_members: HashMap::new(),
                    additional_props_key: HashMap::new(),
                    array_schemas: std::collections::HashSet::new(),
                    array_endpoints: std::collections::HashSet::new(),
                    enum_values: HashMap::new(),
                    subtypes: HashMap::new(),
            parent_types: HashMap::new(),
                    mapped_types: Vec::new(),
                    spec: None,
                };
            }
        }
    }

    let (connected, complete, streaming) = match check_connection(&config) {
        Ok(v) => v,
        Err(status) => {
            return BackgroundLoadResult {
                spec_unreadable: false,
                streaming: false,
                complete: false,
                connected: true,  // got a response, just auth error
                base_uri,
                api_key,
                error: Some(format!(
                    "HTTP/1.1 {}",
                    format!("{} {}", status, if status == 401 { "Unauthorized" } else { "Forbidden" }).red()
                )),
                endpoints: Vec::new(),
                schema_props: HashMap::new(),
                endpoint_types: HashMap::new(),
                param_types: HashMap::new(),
                endpoint_schemas: HashMap::new(),
                indexer_info: HashMap::new(),
                prop_types: HashMap::new(),
                array_members: HashMap::new(),
                primitive_members: HashMap::new(),
                additional_props_key: HashMap::new(),
                array_schemas: std::collections::HashSet::new(),
                array_endpoints: std::collections::HashSet::new(),
                enum_values: HashMap::new(),
                subtypes: HashMap::new(),
            parent_types: HashMap::new(),
                spec: None,
                mapped_types: Vec::new(),
            };
        }
    };

    let mut result = BackgroundLoadResult {
        spec_unreadable: false,
        streaming,
        complete,
        connected,
        base_uri,
        api_key,
        error: None,
        endpoints: Vec::new(),
        schema_props: HashMap::new(),
        endpoint_types: HashMap::new(),
        param_types: HashMap::new(),
        endpoint_schemas: HashMap::new(),
        indexer_info: HashMap::new(),
        prop_types: HashMap::new(),
        array_members: HashMap::new(),
        primitive_members: HashMap::new(),
        additional_props_key: HashMap::new(),
        array_schemas: std::collections::HashSet::new(),
        array_endpoints: std::collections::HashSet::new(),
        enum_values: HashMap::new(),
        subtypes: HashMap::new(),
        parent_types: HashMap::new(),
        mapped_types: Vec::new(),
        spec: None,
    };

    if complete {
        load_phase::set(load_phase::LOADING_SPEC);

        // Parallelize OpenAPI spec and mapped types fetches
        let config_clone = config.clone();
        let mapped_types_handle = std::thread::spawn(move || {
            fetch_mapped_type_names(&config_clone)
        });

        load_openapi_spec_into(&config, &mut result);

        if let Ok(names) = mapped_types_handle.join() {
            result.mapped_types = names;
        }
    }

    result
}

fn fetch_mapped_type_names(config: &Config) -> Vec<String> {
    let client = client_builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("could not set up the HTTP client");

    let url = format!("{}{}/mapped-types", config.base_uri, config.api_path);
    let mut request = client.get(&url);

    if let Some(authorization) = auth_header(config) {
        request = request.header("Authorization", authorization);
    }

    match request.send() {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(items) = resp.json::<Vec<serde_json::Value>>() {
                let mut names: Vec<String> = items
                    .iter()
                    .filter_map(|item| {
                        item.get("identifiers")
                            .and_then(|ids| ids.get("mappedTypeName"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect();
                names.sort();
                names
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

fn apply_background_result(state: &mut AppState, result: BackgroundLoadResult) {
    if let Some(uri) = result.base_uri {
        state.config.base_uri = uri;
    }
    if let Some(key) = result.api_key {
        state.config.api_key = key;
    }
    // The TUI learns the server's capability from /about, so it can AND it with
    // the user's opt-in rather than sending a header an old server can't parse.
    state.config.server_streaming = result.streaming;
    state.config.streaming = result.streaming && state.config.stream_requested;
    if state.config.streaming {
        state.streaming_flash_at = Some(Instant::now());
        show_streaming_info(state);
    }
    state.config.complete = result.complete && !result.spec_unreadable;
    if result.spec_unreadable && state.status_msg.is_empty() {
        // Said once, where everything is said: the regular notification.
        state.status_msg = "completion unavailable: the API spec could not be read".to_string();
        state.status_msg_at = Some(Instant::now());
    }
    state.endpoints = result.endpoints;
    state.schema_props = result.schema_props;
    state.endpoint_types = result.endpoint_types;
    state.param_types = result.param_types;
    state.endpoint_schemas = result.endpoint_schemas;
    state.indexer_info = result.indexer_info;
    state.prop_types = result.prop_types;
    state.array_members = result.array_members;
    state.primitive_members = result.primitive_members;
    state.additional_props_key = result.additional_props_key;
    state.array_schemas = result.array_schemas;
    state.array_endpoints = result.array_endpoints;
    state.enum_values = result.enum_values;
    state.subtypes = result.subtypes;
    state.parent_types = result.parent_types;
    state.spec = result.spec;
    state.mapped_types = result.mapped_types;
}

fn load_openapi_spec_into(config: &Config, result: &mut BackgroundLoadResult) {
    let client = client_builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("could not set up the HTTP client");

    let url = format!("{}/openapi/spec.json", config.base_uri);

    let mut request = client.get(&url);

    if let Some(authorization) = auth_header(config) {
        request = request.header("Authorization", authorization);
    }

    if let Ok(resp) = request.send() {
        // A server without a spec (a 404) simply has none. One that answers
        // with something that is not a spec is worth a word: see
        // `apply_background_result`.
        let answered = resp.status().is_success();
        let spec = resp.json::<ApiSpec>();
        result.spec_unreadable = answered && spec.is_err();
        if let Ok(spec) = spec {
            let mut endpoints: Vec<String> = spec.paths.keys().cloned().collect();
            endpoints.sort();
            result.endpoints = endpoints;

            if let Some(components) = &spec.components {
                for (name, schema) in &components.schemas {
                    if let Some(props) = &schema.properties {
                        let mut prop_names: Vec<String> = props.keys().cloned().collect();
                        prop_names.sort();
                        result.schema_props.insert(name.clone(), prop_names);

                        let mut prop_type_map: HashMap<String, String> = HashMap::new();
                        for (prop_name, prop_ref) in props {
                            if let Some(ref_path) = &prop_ref.ref_path {
                                if let Some(type_name) = ref_path.strip_prefix("#/components/schemas/") {
                                    prop_type_map.insert(prop_name.clone(), type_name.to_string());
                                }
                            } else if prop_ref.examples.as_ref()
                                .and_then(|ex| ex.first())
                                .map_or(false, |v| v.is_object())
                            {
                                // Property has object examples — mark as object-typed
                                prop_type_map.insert(prop_name.clone(), String::new());
                            }
                        }
                        if !prop_type_map.is_empty() {
                            result.prop_types.insert(name.clone(), prop_type_map);
                        }
                    }
                    if let Some(indexer) = &schema.x_indexer {
                        result.indexer_info.insert(name.clone(), indexer.clone());
                    }
                    if schema.schema_type.as_deref() == Some("array") {
                        result.array_schemas.insert(name.clone());
                    }
                    if let Some(members) = &schema.x_array_members {
                        let mut member_map: HashMap<String, String> = HashMap::new();
                        for (member_name, member_info) in members {
                            if let Some(ref_path) = &member_info.ref_path {
                                if let Some(type_name) = ref_path.strip_prefix("#/components/schemas/") {
                                    member_map.insert(member_name.clone(), type_name.to_string());
                                }
                            } else if let Some(items) = &member_info.items {
                                if let Some(ref_path) = &items.ref_path {
                                    if let Some(type_name) = ref_path.strip_prefix("#/components/schemas/") {
                                        member_map.insert(member_name.clone(), type_name.to_string());
                                    }
                                }
                            }
                        }
                        if !member_map.is_empty() {
                            result.array_members.insert(name.clone(), member_map);
                        }
                    }
                    if let Some(members) = &schema.x_primitive_members {
                        let mut member_map: HashMap<String, String> = HashMap::new();
                        for (member_name, member_info) in members {
                            if let Some(ref_path) = &member_info.ref_path {
                                if let Some(type_name) = ref_path.strip_prefix("#/components/schemas/") {
                                    member_map.insert(member_name.clone(), type_name.to_string());
                                }
                            } else if let Some(items) = &member_info.items {
                                if let Some(ref_path) = &items.ref_path {
                                    if let Some(type_name) = ref_path.strip_prefix("#/components/schemas/") {
                                        member_map.insert(member_name.clone(), type_name.to_string());
                                    }
                                }
                            }
                        }
                        if !member_map.is_empty() {
                            result.primitive_members.insert(name.clone(), member_map);
                        }
                    }
                    if let Some(add_props) = &schema.additional_properties {
                        if let Some(key_name) = &add_props.additional_properties_name {
                            let key_type = key_name.trim_start_matches('[').trim_end_matches(']').to_string();
                            if !key_type.is_empty() {
                                result.additional_props_key.insert(name.clone(), key_type);
                            }
                        }
                    }

                    // Extract enum values from properties
                    if let Some(props) = &schema.properties {
                        let mut enum_map: HashMap<String, Vec<String>> = HashMap::new();
                        for (prop_name, prop_ref) in props {
                            if let Some(ev) = &prop_ref.enum_values {
                                let values: Vec<String> = ev.iter().filter_map(|v| {
                                    match v {
                                        serde_json::Value::String(s) => Some(s.clone()),
                                        _ => Some(v.to_string()),
                                    }
                                }).collect();
                                if !values.is_empty() {
                                    enum_map.insert(prop_name.clone(), values);
                                }
                            }
                            // Boolean properties get true/false as enum values
                            if prop_ref.schema_type.as_deref() == Some("boolean") {
                                enum_map.insert(prop_name.clone(), vec!["true".to_string(), "false".to_string()]);
                            }
                        }
                        if !enum_map.is_empty() {
                            result.enum_values.insert(name.clone(), enum_map);
                        }
                    }

                    // Extract subtypes from x-child-types (metadata v1.2+) or allOf fallback
                    if let Some(children) = &schema.x_child_types {
                        result.subtypes.entry(name.clone())
                            .or_insert_with(Vec::new)
                            .extend(children.iter().cloned());
                    } else if let Some(all_of) = &schema.all_of {
                        for ref_item in all_of {
                            if let Some(ref_path) = &ref_item.ref_path {
                                if let Some(base_name) = ref_path.strip_prefix("#/components/schemas/") {
                                    result.subtypes
                                        .entry(base_name.to_string())
                                        .or_insert_with(Vec::new)
                                        .push(name.clone());
                                }
                            }
                        }
                    }
                    if let Some(parent) = &schema.x_parent_type {
                        result.parent_types.insert(name.clone(), parent.clone());
                    }
                }
            }

            let mut tag_types: HashMap<String, String> = HashMap::new();
            if let Some(tags) = &spec.tags {
                for tag in tags {
                    if let Some(x_type) = &tag.x_type {
                        tag_types.insert(tag.name.clone(), x_type.clone());
                    }
                }
            }

            for (path, item) in &spec.paths {
                if path.contains('{') {
                    let params = item.parameters.as_ref().or_else(|| {
                        item.get.as_ref().and_then(|op| op.parameters.as_ref())
                    });
                    if let Some(params) = params {
                        for param in params {
                            if let Some(schema) = &param.schema {
                                if let Some(ref_path) = &schema.ref_path {
                                    if let Some(type_name) = extract_schema_name(ref_path) {
                                        result.param_types.insert(path.clone(), type_name);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                if let Some(get_op) = &item.get {
                    if let Some(op_tags) = &get_op.tags {
                        for tag_name in op_tags {
                            if let Some(schema_name) = tag_types.get(tag_name) {
                                result.endpoint_schemas.insert(path.clone(), schema_name.clone());
                                break;
                            }
                        }
                    }

                    if let Some(resp200) = get_op.responses.get("200") {
                        if let Some(content) = &resp200.content {
                            if let Some(json_content) = content.get("application/json") {
                                if let Some(schema) = &json_content.schema {
                                    if let Some(ref_path) = &schema.ref_path {
                                        if let Some(schema_name) = extract_schema_name(ref_path) {
                                            result.endpoint_types.insert(path.clone(), schema_name);
                                        }
                                    }
                                    if let Some(items) = &schema.items {
                                        result.array_endpoints.insert(path.clone());
                                        if let Some(ref_path) = &items.ref_path {
                                            if let Some(schema_name) = extract_schema_name(ref_path) {
                                                result.endpoint_types.insert(path.clone(), schema_name);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            result.spec = Some(spec);
        }
    }
}

/// Check if a schema is or inherits from a given ancestor (via x-parent-type chain).
fn schema_inherits_from(parent_types: &HashMap<String, String>, schema: &str, ancestor: &str) -> bool {
    if schema == ancestor { return true; }
    let mut current = schema;
    for _ in 0..10 { // guard against cycles
        match parent_types.get(current) {
            Some(parent) if parent == ancestor => return true,
            Some(parent) => current = parent,
            None => return false,
        }
    }
    false
}

fn extract_schema_name(ref_path: &str) -> Option<String> {
    const PREFIX: &str = "#/components/schemas/";
    if ref_path.starts_with(PREFIX) {
        Some(ref_path[PREFIX.len()..].to_string())
    } else {
        None
    }
}

/// Determine JSON context at cursor: which schema we're in, existing keys, key/value position.
/// Returns (schema_name, partial_text, is_value_position, current_key, existing_keys_in_current_obj)
fn json_context_at_cursor(state: &AppState) -> Option<(String, String, bool, String, Vec<String>)> {
    // Extract URI from input
    let trimmed = state.input.trim_start();
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    let first_end = trimmed.find(|c: char| c.is_whitespace()).unwrap_or(trimmed.len());
    let first_word = &trimmed[..first_end];
    let uri = if methods.contains(&first_word.to_uppercase().as_str()) {
        let after = trimmed[first_end..].trim_start();
        let uri_end = after.find(|c: char| c.is_whitespace()).unwrap_or(after.len());
        &after[..uri_end]
    } else if first_word.starts_with('/') {
        first_word
    } else {
        return None;
    };

    // Resolve schema from URI
    let resolve_uri = format!("{}/", uri.trim_end_matches('/'));
    let (base_schema, _, _) = resolve_type_at_path(state, &resolve_uri);
    let mut base_schema = base_schema?;

    // If the resolved schema has an indexer with a return type, the body likely
    // describes the item type (e.g., PUT /people body is a Person, not a collection)
    if let Some(indexer) = state.indexer_info.get(&base_schema) {
        if let Some(return_type) = &indexer.return_type {
            base_schema = return_type.trim_end_matches('?').to_string();
        }
    }

    // Parse JSON body up to cursor to understand context
    let body_start = find_body_start(&state.input)?;
    let cursor_byte = char_to_byte_idx(&state.input, state.cursor_pos);
    if cursor_byte < body_start {
        return None;
    }
    let json_before = &state.input[body_start..cursor_byte];

    // Walk through JSON tracking schema stack, key/value state, existing keys
    let mut schema_stack: Vec<String> = vec![base_schema.clone()];
    let mut key_stack: Vec<String> = Vec::new(); // property names leading to current nesting
    let mut existing_keys: Vec<Vec<String>> = vec![Vec::new()]; // per nesting level
    let mut in_string = false;
    let mut escape = false;
    let mut current_string = String::new();
    let mut is_key = true;
    let mut last_key = String::new();
    let mut partial = String::new();
    let mut in_array = Vec::new(); // track whether each nesting level is array or object

    for ch in json_before.chars() {
        if escape {
            escape = false;
            if in_string { current_string.push(ch); }
            continue;
        }
        if ch == '\\' && in_string {
            escape = true;
            current_string.push(ch);
            continue;
        }

        if in_string {
            if ch == '"' {
                in_string = false;
                if is_key {
                    last_key = current_string.clone();
                    partial = current_string.clone();
                }
                current_string.clear();
            } else {
                current_string.push(ch);
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                current_string.clear();
                partial.clear();
            }
            '{' => {
                in_array.push(false);
                // Entering a new object — resolve the schema for the current key
                let new_schema = if let Some(current_schema) = schema_stack.last() {
                    if let Some(ptypes) = state.prop_types.get(current_schema) {
                        ptypes.get(&last_key).cloned()
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(s) = new_schema {
                    schema_stack.push(s);
                } else if last_key.is_empty() {
                    // Top-level or array element object — keep the parent schema
                    schema_stack.push(schema_stack.last().cloned().unwrap_or_default());
                } else {
                    // Nested object without a $ref schema — push empty to avoid
                    // parent properties/subtypes leaking into child context
                    schema_stack.push(String::new());
                }
                key_stack.push(last_key.clone());
                existing_keys.push(Vec::new());
                is_key = true;
                partial.clear();
            }
            '}' => {
                in_array.pop();
                schema_stack.pop();
                key_stack.pop();
                existing_keys.pop();
                is_key = false;
                partial.clear();
            }
            '[' => {
                in_array.push(true);
                existing_keys.push(Vec::new());
                // Arrays don't push a new schema level by themselves
                // The schema stays the same until we enter an object inside the array
                is_key = false;
                partial.clear();
            }
            ']' => {
                in_array.pop();
                existing_keys.pop();
                is_key = false;
                partial.clear();
            }
            ':' => {
                // After key, now expecting value
                is_key = false;
                // Record this key as existing in current object
                if let Some(keys) = existing_keys.last_mut() {
                    keys.push(last_key.clone());
                }
                partial.clear();
            }
            ',' => {
                // After value, expecting next key (in object) or next value (in array)
                is_key = !in_array.last().copied().unwrap_or(false);
                partial.clear();
            }
            ' ' | '\n' | '\r' | '\t' => {
                // whitespace — don't clear partial if we're building one
            }
            _ => {
                // Part of an unquoted value (number, true, false, null)
                partial.push(ch);
            }
        }
    }

    // If currently inside a string, partial is what's been typed so far
    if in_string {
        partial = current_string.clone();
    }

    let current_schema = schema_stack.last().cloned().unwrap_or_default();
    let current_existing = existing_keys.last().cloned().unwrap_or_default();

    Some((current_schema, partial, !is_key, last_key.clone(), current_existing))
}

fn handle_json_tab_completion(state: &mut AppState, reverse: bool, apply: bool) {
    let ctx = match json_context_at_cursor(state) {
        Some(c) => c,
        None => return,
    };
    let (schema_name, partial, is_value, current_key, existing_keys) = ctx;

    // Don't offer completions when cursor is on a line that already has content after cursor
    // (e.g. cursor on the " of "identifiers": { — don't insert a new key before it)
    if partial.is_empty() {
        let cursor_byte = char_to_byte_idx(&state.input, state.cursor_pos);
        let line_end = state.input[cursor_byte..].find('\n').map_or(state.input.len(), |p| cursor_byte + p);
        let rest_of_line = state.input[cursor_byte..line_end].trim();
        if !rest_of_line.is_empty() {
            return;
        }
    }

    // Detect @type combo cycling: after applying "@type": "value", context says value position
    // with current_key == "@type". Treat this as key-mode combo cycling.
    let is_combo_cycling = is_value && current_key == "@type" && partial.is_empty()
        && !state.completions.is_empty()
        && state.completions.first().map_or(false, |c| c.starts_with("@type\x00"));

    // Build completions
    let mut completions: Vec<String> = Vec::new();

    if !is_value {
        let is_common_identifiers = schema_inherits_from(&state.parent_types, &schema_name, "common identifiers");
        let has_subtypes = !is_common_identifiers && state.subtypes.get(&schema_name).map_or(false, |s| !s.is_empty());
        // Key position — offer property names from schema
        if let Some(props) = state.schema_props.get(&schema_name) {
            for prop in props {
                if prop.starts_with('@') {
                    // Only offer @type when schema has subtypes (ambiguous type)
                    if prop != "@type" || !has_subtypes {
                        continue;
                    }
                }
                if is_common_identifiers && prop == "key" {
                    continue;
                }
                if existing_keys.contains(prop) {
                    continue; // Skip already-present keys
                }
                if partial.is_empty() || prop.starts_with(&partial) {
                    completions.push(prop.clone());
                }
            }
        }
        // Priority ordering: @type first (if ambiguous), identifiers second (if object-typed)
        // For @type, expand into full "@type\x00subtype" entries so cycling changes the value
        if has_subtypes && !existing_keys.contains(&"@type".to_string()) && ("@type".starts_with(&partial) || partial.is_empty()) {
            completions.retain(|c| c != "@type");
            if let Some(subs) = state.subtypes.get(&schema_name) {
                for sub in subs.iter().rev() {
                    completions.insert(0, format!("@type\x00{}", sub));
                }
            }
        }
        // Prioritize identifiers first, then other object-typed properties, after @type combos
        {
            let type_count = completions.iter().take_while(|c| c.starts_with("@type\x00")).count();
            // Move identifiers right after @type combos
            if let Some(pos) = completions.iter().position(|c| c == "identifiers") {
                if pos != type_count {
                    completions.remove(pos);
                    completions.insert(type_count, "identifiers".to_string());
                }
            }
            // Then move other object-typed properties after identifiers
            if let Some(pt) = state.prop_types.get(&schema_name) {
                let skip = completions.iter().take_while(|c| c.starts_with("@type\x00") || c == &"identifiers").count();
                let mut insert_at = skip;
                let mut i = skip;
                while i < completions.len() {
                    let c = &completions[i];
                    if pt.contains_key(c.as_str()) && i != insert_at {
                        let moved = completions.remove(i);
                        completions.insert(insert_at, moved);
                        insert_at += 1;
                    } else {
                        if pt.contains_key(c.as_str()) { insert_at += 1; }
                        i += 1;
                    }
                }
            }
        }
    } else {
        // Value position — offer enum values, booleans, and @type subtypes
        if current_key == "@type" {
            // Offer subtype names for the current schema
            if let Some(subs) = state.subtypes.get(&schema_name) {
                for sub in subs {
                    if partial.is_empty() || sub.starts_with(&partial) {
                        completions.push(sub.clone());
                    }
                }
            }
        }

        // Check enum values for this property
        if let Some(schema_enums) = state.enum_values.get(&schema_name) {
            if let Some(values) = schema_enums.get(&current_key) {
                for v in values {
                    if partial.is_empty() || v.starts_with(&partial) {
                        completions.push(v.clone());
                    }
                }
            }
        }

        // Check if property type is boolean or object (from prop_types)
        if completions.is_empty() {
            if let Some(ptypes) = state.prop_types.get(&schema_name) {
                if let Some(prop_type) = ptypes.get(&current_key) {
                    if prop_type == "boolean" {
                        completions.push("true".to_string());
                        completions.push("false".to_string());
                    }
                }
                // Object-typed property — offer { as value
                if ptypes.contains_key(&current_key) && partial.is_empty() && completions.is_empty() {
                    completions.push("{".to_string());
                }
            }
        }
    }

    // Check if cycling
    let cursor_byte = char_to_byte_idx(&state.input, state.cursor_pos);
    // For combo cycling, keep tab_key as "key" mode to match stored state
    let tab_key = if is_combo_cycling {
        format!("json:{}:key", schema_name)
    } else {
        format!("json:{}:{}", schema_name, if is_value { "val" } else { "key" })
    };

    if is_combo_cycling && apply {
        // Cycle through existing combo completions
        if reverse {
            state.completion_idx = if state.completion_idx == 0 {
                state.completions.len() - 1
            } else {
                state.completion_idx - 1
            };
        } else {
            state.completion_idx = (state.completion_idx + 1) % state.completions.len();
        }
    } else if completions.is_empty() {
        return;
    } else if apply && state.last_tab_input == tab_key && !state.completions.is_empty() {
        // Already applied once — cycle to next completion
        if reverse {
            state.completion_idx = if state.completion_idx == 0 {
                state.completions.len() - 1
            } else {
                state.completion_idx - 1
            };
        } else {
            state.completion_idx = (state.completion_idx + 1) % state.completions.len();
        }
    } else {
        state.completions = completions;
        state.completion_idx = if reverse && !state.completions.is_empty() {
            state.completions.len() - 1
        } else {
            0
        };
        // Use tab_key for applied completions so cycling works on subsequent Tab presses
        // Use "json_ghost:" prefix for preview-only so first Tab doesn't cycle
        state.last_tab_input = if apply { tab_key.clone() } else { format!("json_ghost:{}:{}", schema_name, if is_value { "val" } else { "key" }) };
    }

    if state.completions.is_empty() {
        return;
    }

    if !apply {
        return; // Preview only — completions populated for ghost text
    }

    let completion = &state.completions[state.completion_idx].clone();

    // Find what to replace: go back from cursor to find the start of current token
    let body_start = match find_body_start(&state.input) {
        Some(bs) => bs,
        None => return,
    };

    // Check for @type combo completions (key\x00value format)
    let is_type_combo = completion.contains('\x00');

    // Find token start by scanning backwards from cursor
    let before = &state.input[body_start..cursor_byte];
    let token_start_in_body;
    let skip_after: usize; // bytes after cursor to skip (closing quotes etc.)

    if is_type_combo {
        // For combo cycling, find the start of the entire "key": "value" block
        // Scan back to find the opening " of the key (or insert point if first application)
        // Check if there's already a "@type": "..." to replace
        let prev_was_combo = state.last_tab_input == tab_key;
        if prev_was_combo {
            // Cycling — find @type in the CURRENT object (not a parent)
            // Restrict search to after the last unmatched '{' (current object start)
            let current_obj_start = {
                let mut depth = 0i32;
                let mut pos = before.len();
                for (i, ch) in before.char_indices().rev() {
                    match ch {
                        '}' => depth += 1,
                        '{' if depth > 0 => depth -= 1,
                        '{' => { pos = i; break; }
                        _ => {}
                    }
                }
                pos
            };
            let search_region = &before[current_obj_start..];
            if let Some(rel_pos) = search_region.rfind("\"@type\": \"") {
                token_start_in_body = current_obj_start + rel_pos;
                skip_after = 0;
            } else {
                token_start_in_body = before.len();
                skip_after = 0;
            }
        } else {
            // First application — insert at cursor
            token_start_in_body = before.len();
            skip_after = 0;
        }
    } else if !is_value {
        if partial.is_empty() {
            // No key string opened yet — insert at cursor
            token_start_in_body = before.len();
        } else if let Some(q) = before.rfind('"') {
            token_start_in_body = q + 1; // after the opening quote of the key being typed
        } else {
            token_start_in_body = before.len();
        }
        let after = &state.input[cursor_byte..];
        skip_after = if !partial.is_empty() && after.starts_with('"') { 1 } else { 0 };
    } else {
        // For values: find position after `: ` or `:` or after last `"`
        if let Some(q) = before.rfind('"') {
            token_start_in_body = q + 1;
        } else if let Some(c) = before.rfind(':') {
            let after_colon = &before[c + 1..];
            token_start_in_body = c + 1 + after_colon.len() - after_colon.trim_start().len();
        } else {
            token_start_in_body = before.len();
        }
        skip_after = 0;
    };
    let replace_start = body_start + token_start_in_body;

    // Build the replacement text
    // Check if the completed key is an object-typed property (has $ref in prop_types)
    let is_object_prop = !is_value && !is_type_combo && state.prop_types.get(&schema_name)
        .and_then(|pt| pt.get(completion.as_str()))
        .is_some();
    let replacement = if is_type_combo {
        let parts: Vec<&str> = completion.splitn(2, '\x00').collect();
        let key = parts[0];
        let value = parts[1];
        let prev_was_combo = state.last_tab_input == tab_key;
        if prev_was_combo {
            // Cycling — replace entire "key": "value"
            format!("\"{}\": \"{}\"", key, value)
        } else {
            let needs_space = !before.is_empty() && !before.ends_with(' ') && !before.ends_with('\n');
            let prefix = if partial.is_empty() && needs_space { " " } else { "" };
            if partial.is_empty() {
                format!("{}\"{}\": \"{}\"", prefix, key, value)
            } else {
                format!("{}\": \"{}\"", &key[partial.len()..], value)
            }
        }
    } else if !is_value {
        let suffix = if is_object_prop { "\": {" } else { "\":" };
        if partial.is_empty() {
            // No key started — insert full "key": with leading space if needed
            let needs_space = !before.is_empty() && !before.ends_with(' ') && !before.ends_with('\n');
            let prefix = if needs_space { " " } else { "" };
            format!("{}\"{}{}",  prefix, completion, suffix)
        } else {
            // Replace partial with completion, add closing quote and colon
            format!("{}{}", completion, suffix)
        }
    } else {
        completion.clone()
    };

    // Replace
    let new_input = format!(
        "{}{}{}",
        &state.input[..replace_start],
        replacement,
        &state.input[cursor_byte + skip_after..]
    );
    let cursor_after_replacement = char_len(&new_input[..replace_start]) + char_len(&replacement);
    state.input = new_input;

    // For object-typed properties (key or value position), expand to multiline block
    let is_object_value = is_value && completion == "{";
    if is_object_prop || is_object_value {
        let is_multiline = state.input.contains('\n');
        if is_multiline {
            // Base indent on current line's leading whitespace (not bracket depth)
            let cursor_byte_after = char_to_byte_idx(&state.input, cursor_after_replacement);
            let line_start = state.input[..cursor_byte_after].rfind('\n').map_or(0, |p| p + 1);
            let line_content = &state.input[line_start..cursor_byte_after];
            let current_indent: String = line_content.chars().take_while(|c| *c == ' ').collect();
            let inner_indent = format!("{}  ", current_indent);
            let expansion = format!("\n{}\n{}}}", inner_indent, current_indent);
            let inner_len = inner_indent.len();
            state.input.insert_str(cursor_byte_after, &expansion);
            // Cursor on the blank inner line
            state.cursor_pos = cursor_after_replacement + 1 + inner_len; // \n + indent
        } else {
            // Single-line: just add space after {
            let cursor_byte_after = char_to_byte_idx(&state.input, cursor_after_replacement);
            state.input.insert_str(cursor_byte_after, " ");
            state.cursor_pos = cursor_after_replacement + 1;
        }
        state.completions.clear();
        state.last_tab_input.clear();
    } else {
        state.cursor_pos = cursor_after_replacement;
    }
}

fn handle_tab_completion(state: &mut AppState) {
    // Parse input preserving body and outfile suffix
    // Format: METHOD URI [BODY] [> outfile]
    let input = &state.input;
    let cursor_pos = state.cursor_pos;

    // Find the URI boundaries (in char offsets)
    let parts: Vec<&str> = input.split_whitespace().collect();
    let (method_part, uri_full, uri_char_start, suffix) = if parts.is_empty() {
        ("", "/".to_string(), 0usize, String::new())
    } else if parts.len() == 1 {
        if parts[0].starts_with('/') {
            let start = input.chars().take_while(|c| c.is_whitespace()).count();
            ("", parts[0].to_string(), start, String::new())
        } else {
            let start = input.chars().take_while(|c| c.is_whitespace()).count() + char_len(parts[0]);
            (parts[0], "/".to_string(), start, String::new())
        }
    } else {
        let method = parts[0];
        // Everything after method and URI is the suffix (body, > outfile, etc.)
        let method_end = input.find(method).unwrap_or(0) + method.len();
        let uri_byte_start = input[method_end..].find(parts[1]).map(|i| method_end + i).unwrap_or(method_end);
        let uri_byte_end = uri_byte_start + parts[1].len();
        let uri_char_start = input[..uri_byte_start].chars().count();
        let suffix = input[uri_byte_end..].to_string();
        (method, parts[1].to_string(), uri_char_start, suffix)
    };

    // Split URI at cursor position to support completion with characters after cursor
    let cursor_in_uri = if cursor_pos > uri_char_start {
        cursor_pos - uri_char_start
    } else {
        0
    };
    let uri_chars: Vec<char> = uri_full.chars().collect();
    let cursor_in_uri = cursor_in_uri.min(uri_chars.len());
    let uri_before: String = uri_chars[..cursor_in_uri].iter().collect();
    let uri_after: String = uri_chars[cursor_in_uri..].iter().collect();

    // Use only the text before cursor for completion
    let uri = if uri_before.is_empty() { "/".to_string() } else { uri_before };

    // Check if cycling through completions (only compare method + uri-before-cursor part)
    let current_base = if method_part.is_empty() {
        uri.clone()
    } else {
        format!("{} {}", method_part, uri)
    };

    let is_cycling = if !state.completions.is_empty() && !state.last_tab_input.is_empty() {
        state.completions.iter().enumerate().any(|(i, comp)| {
            let expected = if method_part.is_empty() {
                comp.clone()
            } else {
                format!("{} {}", method_part, comp)
            };
            if current_base == expected {
                state.completion_idx = (i + 1) % state.completions.len();
                true
            } else {
                false
            }
        })
    } else {
        false
    };

    if !is_cycling {
        state.completions = get_completions(state, &uri);
        state.completion_idx = 0;
        state.last_tab_input = current_base;
        state.completion_uri_suffix = uri_after.clone();
    }

    let uri_after = &state.completion_uri_suffix;

    if !state.completions.is_empty() {
        let completion = &state.completions[state.completion_idx];
        let new_base = if method_part.is_empty() {
            completion.clone()
        } else {
            format!("{} {}", method_part, completion)
        };
        // Preserve the uri text after cursor + original suffix (body and outfile)
        state.input = format!("{}{}{}", new_base, uri_after, suffix);
        state.cursor_pos = char_len(&new_base);
    }
}

fn handle_tab_completion_reverse(state: &mut AppState) {
    // Cycle backward through existing completions
    if state.completions.is_empty() {
        return;
    }

    // Parse input to get method and suffix (body/outfile, not including uri_after)
    let input = &state.input;
    let parts: Vec<&str> = input.split_whitespace().collect();
    let (method_part, suffix) = if parts.is_empty() {
        ("", String::new())
    } else if parts.len() == 1 {
        if parts[0].starts_with('/') {
            ("", String::new())
        } else {
            (parts[0], String::new())
        }
    } else {
        let method = parts[0];
        let method_end = input.find(method).unwrap_or(0) + method.len();
        let uri_start = input[method_end..].find(parts[1]).map(|i| method_end + i).unwrap_or(method_end);
        let uri_end = uri_start + parts[1].len();
        let suffix = input[uri_end..].to_string();
        (method, suffix)
    };

    // Cycle backward
    if state.completion_idx == 0 {
        state.completion_idx = state.completions.len() - 1;
    } else {
        state.completion_idx -= 1;
    }

    let uri_after = &state.completion_uri_suffix;
    let completion = &state.completions[state.completion_idx];
    let new_base = if method_part.is_empty() {
        completion.clone()
    } else {
        format!("{} {}", method_part, completion)
    };
    state.input = format!("{}{}{}", new_base, uri_after, suffix);
    state.cursor_pos = char_len(&new_base);
}

/// Replace the file-path span `[path_start, path_end)` with `new_path`, keeping
/// everything after it (` && …` chain tail) intact, and leave the cursor at the
/// end of the replacement — mid-line when a tail follows, end-of-line otherwise.
fn replace_file_path_span(state: &mut AppState, path_start: usize, path_end: usize, new_path: &str) {
    let prefix = &state.input[..path_start];
    let tail = &state.input[path_end..];
    let cursor = char_len(prefix) + char_len(new_path);
    state.input = format!("{}{}{}", prefix, new_path, tail);
    state.cursor_pos = cursor;
}

fn handle_file_tab_completion(state: &mut AppState) {
    let ctx = match extract_file_path_context(&state.input, state.cursor_pos) {
        Some(ctx) => ctx,
        None => return,
    };
    let (path_start, path_end) = (ctx.path_start, ctx.path_end);
    let partial = &ctx.partial;

    // Check for ~ operator on body file argument
    if let Some(tilde_idx) = partial.rfind('~').filter(|_| !ctx.is_include) {
        let file_part = partial[..tilde_idx].to_string();
        let after_tilde = partial[tilde_idx + 1..].to_string();
        if after_tilde.starts_with("map(") {
            let inside_raw = &after_tilde[4..];
            // Strip trailing ) so cycling works after a completed type name
            let inside = inside_raw.trim_end_matches(')');
            let has_closing_paren = inside_raw.ends_with(')');
            // If we have a closing paren and the name matches a mapped type, always cycle
            let is_cycling = if !state.completions.is_empty() && has_closing_paren {
                // Find current type in completions and advance
                if let Some(idx) = state.completions.iter().position(|c| c.trim_end_matches(')') == inside) {
                    state.completion_idx = (idx + 1) % state.completions.len();
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if !is_cycling {
                state.completions = state.mapped_types.iter()
                    .filter(|name| inside.is_empty() || name.to_lowercase().starts_with(&inside.to_lowercase()))
                    .map(|name| format!("{})", name))
                    .collect();
                state.completion_idx = 0;
            }
            if !state.completions.is_empty() {
                let completion = state.completions[state.completion_idx].clone();
                let new_path = format!("{}~map({}", file_part, completion);
                replace_file_path_span(state, path_start, path_end, &new_path);
            }
            return;
        }
        // Only complete map( on body file args
        if !after_tilde.contains('(') && "map(".starts_with(after_tilde.as_str()) && after_tilde != "map(" {
            let new_path = format!("{}~map(", file_part);
            replace_file_path_span(state, path_start, path_end, &new_path);
            return;
        }
    }

    // Check if cycling through completions: the current path span matching one
    // of the completions means the last Tab produced it — advance to the next.
    let current_span = state.input[path_start..path_end].to_string();
    let is_cycling = if !state.completions.is_empty() && !state.last_tab_input.is_empty() {
        state.completions.iter().enumerate().any(|(i, comp)| {
            if current_span == *comp {
                state.completion_idx = (i + 1) % state.completions.len();
                true
            } else {
                false
            }
        })
    } else {
        false
    };

    if !is_cycling {
        state.completions = file_completions_for(&ctx);
        state.completion_idx = 0;
        state.last_tab_input = state.input.clone();
    }

    if !state.completions.is_empty() {
        let completion = state.completions[state.completion_idx].clone();
        replace_file_path_span(state, path_start, path_end, &completion);
    }
}

fn handle_file_tab_completion_reverse(state: &mut AppState) {
    if state.completions.is_empty() {
        return;
    }

    let ctx = match extract_file_path_context(&state.input, state.cursor_pos) {
        Some(ctx) => ctx,
        None => return,
    };
    let FilePathContext { path_start, path_end, partial, is_include, .. } = ctx;

    if state.completion_idx == 0 {
        state.completion_idx = state.completions.len() - 1;
    } else {
        state.completion_idx -= 1;
    }

    let completion = state.completions[state.completion_idx].clone();

    // Handle ~map() completions: reconstruct with file path prefix
    if let Some(tilde_idx) = partial.rfind('~').filter(|_| !is_include) {
        let file_part = partial[..tilde_idx].to_string();
        let after_tilde = &partial[tilde_idx + 1..];
        if after_tilde.starts_with("map(") {
            let new_path = format!("{}~map({}", file_part, completion);
            replace_file_path_span(state, path_start, path_end, &new_path);
            return;
        }
    }

    replace_file_path_span(state, path_start, path_end, &completion);
}

fn get_json_completion_ghost(state: &AppState) -> Option<String> {
    let ctx = json_context_at_cursor(state)?;
    let (schema, partial, is_value, current_key, existing_keys) = ctx;
    let current_is_key = !is_value;

    // If completions are populated from a json trigger, use them
    if !state.completions.is_empty() && (state.last_tab_input.starts_with("json:") || state.last_tab_input.starts_with("json_ghost:")) {
        let completion = &state.completions[state.completion_idx];
        let stored_is_key = state.last_tab_input.ends_with(":key");
        // Only show ghost when context matches (don't show key ghost in value position)
        if stored_is_key == current_is_key {
            if current_is_key {
                // Handle @type combo completions (key\x00value)
                if let Some(sep) = completion.find('\x00') {
                    let key = &completion[..sep];
                    let value = &completion[sep + 1..];
                    let remaining: String = key.chars().skip(partial.chars().count()).collect();
                    return Some(format!("{}\": \"{}\"", remaining, value));
                }
                let remaining: String = completion.chars().skip(partial.chars().count()).collect();
                if !remaining.is_empty() {
                    let is_obj = state.prop_types.get(&schema)
                        .and_then(|pt| pt.get(completion.as_str()))
                        .is_some();
                    let suffix = if is_obj { "\": {" } else { "\":" };
                    return Some(format!("{}{}", remaining, suffix));
                }
            } else {
                let remaining: String = completion.chars().skip(partial.chars().count()).collect();
                return Some(remaining);
            }
        }
    }

    // No pre-populated completions — compute ghost proactively in key position
    // Only suggest on an empty line (no existing content before or after cursor)
    let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
    let line_start = state.input[..byte_idx].rfind('\n').map_or(0, |p| p + 1);
    let line_before = &state.input[line_start..byte_idx];
    let line_end = state.input[byte_idx..].find('\n').map_or(state.input.len(), |p| byte_idx + p);
    let line_after = &state.input[byte_idx..line_end];
    let on_clean_line = line_before.chars().all(|c| c.is_whitespace())
        && line_after.chars().all(|c| c.is_whitespace());
    if current_is_key && partial.is_empty() && on_clean_line {
        let is_common_identifiers = schema_inherits_from(&state.parent_types, &schema, "common identifiers");
        let has_subtypes = !is_common_identifiers && state.subtypes.get(&schema).map_or(false, |s| !s.is_empty());
        // Determine the best first key suggestion
        if has_subtypes && !existing_keys.contains(&"@type".to_string()) {
            // Show @type with first subtype value
            if let Some(subs) = state.subtypes.get(&schema) {
                if let Some(first_sub) = subs.first() {
                    return Some(format!("\"@type\": \"{}\"", first_sub));
                }
            }
        }
        let first_key = state.schema_props.get(&schema).and_then(|props| {
            let skip = |p: &&String| -> bool {
                p.starts_with('@') || existing_keys.contains(p)
                    || (is_common_identifiers && p.as_str() == "key")
            };
            // Priority: identifiers first, then other object-typed properties
            if props.contains(&"identifiers".to_string()) && !existing_keys.contains(&"identifiers".to_string()) {
                return Some("identifiers".to_string());
            }
            let obj_key = props.iter().find(|p| {
                !skip(p) && state.prop_types.get(&schema)
                    .and_then(|pt| pt.get(p.as_str()))
                    .is_some()
            });
            if let Some(k) = obj_key {
                return Some(k.clone());
            }
            props.iter().find(|p| !skip(p)).cloned()
        });
        if let Some(key) = first_key {
            let is_obj = state.prop_types.get(&schema)
                .and_then(|pt| pt.get(key.as_str()))
                .is_some();
            let suffix = if is_obj { "\": {" } else { "\":" };
            return Some(format!("\"{}{}", key, suffix));
        }
    }

    // Value position: suggest { for object-typed properties
    if is_value && partial.is_empty() {
        if let Some(ptypes) = state.prop_types.get(&schema) {
            if ptypes.contains_key(&current_key) {
                return Some("{".to_string());
            }
        }
    }

    None
}

/// Returns closing brackets ghost text (e.g. "}" or "}]") when cursor is after a complete value.
fn get_closing_brackets_ghost(input: &str, cursor_pos: usize) -> String {
    let byte_idx = char_to_byte_idx(input, cursor_pos);
    let last_nws = input[..byte_idx].chars().rev()
        .find(|c| !c.is_whitespace());
    // After a closing quote, closing bracket — suggest all pending closers
    if !matches!(last_nws, Some('"') | Some('}') | Some(']')) {
        return String::new();
    }
    // Walk bracket stack and key/value state to determine if we're after a complete value
    let mut stack = Vec::new();
    let mut in_str = false;
    let mut esc = false;
    let mut is_key = true;
    let mut in_array = Vec::new();
    for ch in input[..byte_idx].chars() {
        if esc { esc = false; continue; }
        if ch == '\\' && in_str { esc = true; continue; }
        if ch == '"' { in_str = !in_str; continue; }
        if !in_str {
            match ch {
                '{' => { stack.push(ch); in_array.push(false); is_key = true; },
                '[' => { stack.push(ch); in_array.push(true); is_key = false; },
                '}' => { stack.pop(); in_array.pop(); is_key = false; },
                ']' => { stack.pop(); in_array.pop(); is_key = false; },
                ':' => { is_key = false; },
                ',' => { is_key = !in_array.last().copied().unwrap_or(false); },
                _ => {}
            }
        }
    }
    // Don't suggest closing if inside an unclosed string, after a key, or after structural chars
    if in_str || is_key || matches!(last_nws, Some(':') | Some(',') | Some('{') | Some('[')) {
        return String::new();
    }
    // Return only the innermost closing bracket, formatted to match what Tab inserts
    if let Some(&open) = stack.last() {
        let bracket = if open == '{' { "}" } else { "]" };
        let is_multiline = input[..byte_idx].contains('\n');
        if is_multiline {
            let depth = stack.len();
            let dedent = depth.saturating_sub(1);
            let indent = "  ".repeat(dedent);
            // Check if cursor is on a blank/whitespace-only line
            let line_start = input[..byte_idx].rfind('\n').map_or(0, |p| p + 1);
            let line_before = &input[line_start..byte_idx];
            if line_before.chars().all(|c| c == ' ') {
                // Will reuse this line — ghost shows just the bracket at correct indent
                // But we need to show what the line will look like after replacement
                let current_indent_len = line_before.len();
                let target = format!("{}{}", indent, bracket);
                if target.len() > current_indent_len {
                    // Need more chars than current position — show remaining
                    target[current_indent_len..].to_string()
                } else {
                    bracket.to_string()
                }
            } else {
                format!("\n{}{}", indent, bracket)
            }
        } else {
            bracket.to_string()
        }
    } else {
        String::new()
    }
}

fn get_completion_ghost(state: &AppState) -> String {
    // JSON body completion ghost text (experimental only)
    if state.config.experimental && cursor_inside_brackets(&state.input, state.cursor_pos) {
        if let Some(ghost) = get_json_completion_ghost(state) {
            return ghost;
        }
        // Suggest closing brackets after a value
        let closing = get_closing_brackets_ghost(&state.input, state.cursor_pos);
        if !closing.is_empty() {
            return closing;
        }
        return String::new();
    }

    // File completion ghost text (works even without API completion)
    if let Some(ctx) = extract_file_path_context(&state.input, state.cursor_pos) {
        let partial = &ctx.partial;
        if ctx.is_include && could_become_a_keyword(partial) {
            return String::new();
        }
        // Check for ~ operator on body file argument
        if let Some(tilde_idx) = partial.rfind('~').filter(|_| !ctx.is_include) {
            let after_tilde = &partial[tilde_idx + 1..];
            if after_tilde.starts_with("map(") {
                let inside_raw = &after_tilde[4..]; // after "map("
                let inside = inside_raw.trim_end_matches(')');
                for name in &state.mapped_types {
                    if name.to_lowercase().starts_with(&inside.to_lowercase()) && name.len() > inside.len() {
                        let ghost: String = name.chars().skip(inside.chars().count()).collect();
                        return format!("{})", ghost);
                    }
                }
                return String::new();
            }
            // Only complete map( on body file args
            if !after_tilde.contains('(') && "map(".starts_with(after_tilde) {
                let ghost: String = "map(".chars().skip(after_tilde.chars().count()).collect();
                if !ghost.is_empty() {
                    return ghost;
                }
                return String::new();
            }
        }
        // Reuse state.completions if populated from file Tab, else compute fresh
        let fresh;
        let completions = if !state.completions.is_empty() && state.last_tab_input == state.input {
            &state.completions
        } else {
            fresh = file_completions_for(&ctx);
            &fresh
        };
        if let Some(first) = completions.first() {
            if first.starts_with(partial.as_str()) {
                let partial_chars = partial.chars().count();
                let ghost: String = first.chars().skip(partial_chars).collect();
                if !ghost.is_empty() {
                    return ghost;
                }
            }
        }
        return String::new();
    }

    if state.endpoints.is_empty() {
        return String::new();
    }

    let parts: Vec<&str> = state.input.split_whitespace().collect();

    let uri = if parts.is_empty() {
        return String::new();
    } else if parts.len() == 1 {
        if parts[0].starts_with('/') {
            parts[0].to_string()
        } else {
            return String::new();
        }
    } else {
        parts[1].to_string()
    };

    // Don't suggest URI completions when there's already content after the URI
    // (body, outfile, etc.) — the cursor is past the URI in that case.
    if parts.len() > 2 {
        return String::new();
    }

    // Only show ghost text if URI contains a delimiter (we're typing after /, (, or ~)
    if uri.rfind(|c| c == '/' || c == '(' || c == '~').is_none() {
        return if state.config.experimental { get_body_bracket_ghost(state, &parts, &uri) } else { String::new() };
    }

    // Get completions for current input
    let completions = get_completions(state, &uri);
    if completions.is_empty() {
        return if state.config.experimental { get_body_bracket_ghost(state, &parts, &uri) } else { String::new() };
    }

    // Get first completion
    let completion = &completions[0];

    // Calculate what would be added (the ghost part)
    if completion.starts_with(&uri) {
        // Use character-safe slicing
        let uri_chars = uri.chars().count();
        let ghost: String = completion.chars().skip(uri_chars).collect();
        if !ghost.is_empty() {
            return ghost;
        }
    }

    if state.config.experimental { get_body_bracket_ghost(state, &parts, &uri) } else { String::new() }
}

/// Get ghost text for body brackets (e.g., `[{ }]` for PUT on array endpoints)
fn get_body_bracket_ghost(state: &AppState, parts: &[&str], uri: &str) -> String {
    // Only when input ends with trailing space after method+URI and no body yet
    if parts.len() != 2 || !state.input.ends_with(' ') {
        return String::new();
    }
    let method = parts[0].to_uppercase();
    let is_put_patch = method == "PUT" || method == "PATCH";
    let is_post = method == "POST";
    if !is_put_patch && !is_post {
        return String::new();
    }

    let shape = expected_body_shape(state, uri);
    let (is_array, is_object) = (shape.is_array(), shape.is_object());

    if is_put_patch && is_array && is_object {
        "[{ ".to_string()
    } else if is_put_patch && is_array {
        "[ ".to_string()
    } else if is_post && is_object {
        "{ ".to_string()
    } else {
        String::new()
    }
}

fn get_completion_ghost_at_cursor(state: &AppState) -> String {
    if state.config.experimental && cursor_inside_brackets(&state.input, state.cursor_pos) {
        // Only show JSON ghost if cursor is on a line with no content after it
        // (prevents ghost text from overlapping with existing content and causing visual artifacts)
        let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
        let line_end = state.input[byte_idx..].find('\n').map_or(state.input.len(), |p| byte_idx + p);
        let after_on_line = &state.input[byte_idx..line_end];
        if after_on_line.chars().any(|c| !c.is_whitespace()) {
            return String::new();
        }
        return get_json_completion_ghost(state).unwrap_or_default();
    }

    if state.endpoints.is_empty() {
        return String::new();
    }

    let parts: Vec<&str> = state.input.split_whitespace().collect();
    let (uri_full, uri_char_start) = if parts.is_empty() {
        return String::new();
    } else if parts.len() == 1 {
        if parts[0].starts_with('/') {
            let start = state.input.chars().take_while(|c| c.is_whitespace()).count();
            (parts[0].to_string(), start)
        } else {
            return String::new();
        }
    } else {
        let method_end = state.input.find(parts[0]).unwrap_or(0) + parts[0].len();
        let uri_byte_start = state.input[method_end..].find(parts[1]).map(|i| method_end + i).unwrap_or(method_end);
        let uri_char_start = state.input[..uri_byte_start].chars().count();
        (parts[1].to_string(), uri_char_start)
    };

    // Split URI at cursor position
    let cursor_in_uri = if state.cursor_pos > uri_char_start {
        state.cursor_pos - uri_char_start
    } else {
        return String::new();
    };
    let uri_chars: Vec<char> = uri_full.chars().collect();
    // Cursor past end of URI — no ghost (cursor is in body/elsewhere)
    if cursor_in_uri > uri_chars.len() {
        return String::new();
    }
    let uri_before: String = uri_chars[..cursor_in_uri.min(uri_chars.len())].iter().collect();
    if uri_before.is_empty() {
        return String::new();
    }
    // Don't show ghost text when cursor is in the middle of the URI — it would splice into existing text
    if cursor_in_uri < uri_chars.len() {
        return String::new();
    }

    // Only show ghost text if URI before cursor contains a delimiter
    if uri_before.rfind(|c: char| c == '/' || c == '(' || c == '~').is_none() {
        return String::new();
    }

    let completions = get_completions(state, &uri_before);
    if completions.is_empty() {
        return String::new();
    }

    let completion = &completions[0];
    if completion.starts_with(&uri_before) {
        let uri_before_chars = uri_before.chars().count();
        let ghost: String = completion.chars().skip(uri_before_chars).collect();
        if !ghost.is_empty() {
            return ghost;
        }
    }

    String::new()
}

/// Extract the file path portion being typed after ">" or "@" in the input.
/// Returns Some((prefix_before_path, partial_path)) if in file completion mode.
/// Triggers directly after " >" or " @" (space not required after the symbol).
/// True when the active file-path context is the `>` outfile redirect (as opposed
/// to a `@` body-file). Mirrors `extract_file_path_context`, which checks `" >"`
/// first and uses it whenever present.
/// A file-path region (outfile `> path` or body `@path`) in the `&&` segment
/// the cursor is in. Byte offsets are absolute; the partial excludes trailing
/// whitespace, so `path_end` marks exactly where a completion's replacement
/// stops — everything from there on (` && …`) is a tail to preserve.
struct FilePathContext {
    path_start: usize,
    path_end: usize,
    partial: String,
    /// `> outfile` (true) vs `@file` body (false) — decides the completion set.
    is_outfile: bool,
    /// `>> outfile` — append mode; `clipboard` is not a valid target there.
    is_append: bool,
    /// The line itself is a path to a `.api` file to run.
    is_include: bool,
}

const DIRECTIVES: [&str; 5] = ["sleep", "assert", "confirm", "url", "import"];

/// The include path being typed, when the line can only be one: a single line
/// that is no chain and whose first word is no method, directive or `/path`.
/// The whole line is the path, as the bulk parser reads it. A glob is left as
/// typed, and an absolute path is not offered because until its `.api` suffix
/// is there it reads as a URI.
fn include_path_context(input: &str, seg_start: usize, seg_end: usize) -> Option<FilePathContext> {
    if seg_start != 0 || seg_end != input.len() || input.contains('\n') {
        return None;
    }
    let partial = input.trim();
    let first_word = partial.split_whitespace().next()?;
    if starts_a_request(first_word)
        || first_word.starts_with('/')
        || DIRECTIVES.iter().any(|d| first_word.eq_ignore_ascii_case(d))
        || partial.contains(['*', '?', '['])
    {
        return None;
    }
    let path_start = input.len() - input.trim_start().len();
    Some(FilePathContext {
        path_start,
        path_end: path_start + partial.len(),
        partial: partial.to_string(),
        is_outfile: false,
        is_append: false,
        is_include: true,
    })
}

/// Whether `partial` may still be the start of a method or a directive, in
/// which case no include is suggested until the user asks with Tab.
fn could_become_a_keyword(partial: &str) -> bool {
    let typed = partial.to_ascii_lowercase();
    ["get", "post", "put", "patch", "delete", "head", "options"]
        .iter()
        .chain(DIRECTIVES.iter())
        .any(|keyword| keyword.starts_with(&typed))
}

/// Find the file-path region at the cursor, scoped to the cursor's `&&`
/// segment: a ` >` or ` @` in some OTHER segment never produces a context here,
/// and the partial never runs past the segment into the rest of the chain.
/// `cursor_pos` is in chars, like `state.cursor_pos`.
fn extract_file_path_context(input: &str, cursor_pos: usize) -> Option<FilePathContext> {
    let cursor_byte = char_to_byte_idx(input, cursor_pos.min(char_len(input)));
    let (seg_start, seg_end) = chain_segment_bounds_at(input, cursor_byte);
    let segment = &input[seg_start..seg_end];

    // ` >` (outfile, including ` >>` append) takes precedence over ` @`, as
    // before. Space before the marker required, optional space after.
    for (marker, is_outfile) in [(" >", true), (" @", false)] {
        // The outfile marker is found the way the parser finds it, so a `>`
        // inside a body being typed is not taken for one.
        let at = if is_outfile { outfile_marker_at(segment) } else { segment.rfind(marker) };
        if let Some(idx) = at {
            let mut after = idx + 2;
            // ` >>` — the second `>` is part of the marker, not the path.
            let is_append = is_outfile && segment[after..].starts_with('>');
            if is_append {
                after += 1;
            }
            let path_rel = if segment[after..].starts_with(' ') { after + 1 } else { after };
            let partial = segment[path_rel..].trim_end();
            let path_start = seg_start + path_rel;
            return Some(FilePathContext {
                path_start,
                path_end: path_start + partial.len(),
                partial: partial.to_string(),
                is_outfile,
                is_append,
                is_include: false,
            });
        }
    }
    include_path_context(input, seg_start, seg_end)
}

/// Get file/directory completions for a partial path.
/// Returns full paths (from the partial's perspective) suitable for replacing the partial.
fn get_file_completions(partial: &str) -> Vec<String> {
    let expanded = if partial.starts_with("~/") || (cfg!(windows) && partial.starts_with("~\\")) {
        expand_home(partial)
    } else if partial.starts_with('~') && !partial.contains('/') {
        // Just "~" with no slash yet
        if let Some(home) = dirs::home_dir() {
            format!("{}", home.display())
        } else {
            partial.to_string()
        }
    } else {
        partial.to_string()
    };

    // Split into directory and file prefix
    let path = std::path::Path::new(&expanded);
    let (dir, file_prefix) = if expanded.ends_with('/') {
        (std::path::PathBuf::from(&expanded), String::new())
    } else if let Some(parent) = path.parent() {
        let file_part = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
        let parent_path = if parent.as_os_str().is_empty() {
            std::path::PathBuf::from(".")
        } else {
            parent.to_path_buf()
        };
        (parent_path, file_part)
    } else {
        (std::path::PathBuf::from("."), expanded.clone())
    };

    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut results: Vec<String> = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // Skip hidden files unless the prefix starts with .
        if name.starts_with('.') && !file_prefix.starts_with('.') {
            continue;
        }
        if !name.starts_with(&file_prefix) {
            continue;
        }
        let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
        // Build the completion using the original partial's directory prefix (preserving ~)
        let dir_prefix = if partial.ends_with('/') {
            partial.to_string()
        } else if let Some(last_slash) = partial.rfind('/') {
            partial[..=last_slash].to_string()
        } else {
            String::new()
        };
        let suffix = if is_dir { "/" } else { "" };
        results.push(format!("{}{}{}", dir_prefix, name, suffix));
    }

    results.sort();
    // Put directories first
    results.sort_by(|a, b| {
        let a_dir = a.ends_with('/');
        let b_dir = b.ends_with('/');
        b_dir.cmp(&a_dir).then(a.cmp(b))
    });

    results
}

/// Completions for an outfile context (`> …`). Returns the normal file/dir
/// completions plus a virtual `clipboard` target when the partial is a prefix of
/// "clipboard". The virtual entry is purely additive: real files/folders (even
/// ones beginning with "clip"/"clipboard") are always kept, and `clipboard` is
/// not added if a real entry by that name already exists (no duplication). Used
/// only for the `>` redirect, never for `@` body-file completion.
fn get_outfile_completions(partial: &str) -> Vec<String> {
    let mut results = get_file_completions(partial);
    let want_clipboard = !partial.is_empty()
        && "clipboard".starts_with(partial)
        && partial != "clipboard"
        && !results.iter().any(|c| c.trim_end_matches('/') == "clipboard");
    if want_clipboard {
        results.insert(0, "clipboard".to_string());
    }
    results
}

/// Completions for an include: what `get_file_completions` finds, narrowed to
/// directories and `.api` files.
fn get_include_completions(partial: &str) -> Vec<String> {
    if partial == "~" {
        return vec!["~/".to_string()];
    }
    let runnable = |c: &String| c.ends_with('/') || names_api_file(c);
    let imports = session_imports().lock().unwrap();
    // `cl/…` completes inside whatever was imported as `cl`.
    if let Some((repo, rest)) = alias_include(partial, &imports) {
        let root = format!("{}/", repo.root.display());
        return get_file_completions(&format!("{}{}", root, rest))
            .into_iter()
            .filter(runnable)
            .filter_map(|c| c.strip_prefix(&root).map(|inside| format!("{}/{}", repo.alias, inside)))
            .collect();
    }
    let mut results: Vec<String> = get_file_completions(partial).into_iter().filter(runnable).collect();
    if !partial.is_empty() && !partial.contains('/') {
        let mut aliases: Vec<String> = imports
            .keys()
            .filter(|alias| alias.starts_with(partial))
            .map(|alias| format!("{}/", alias))
            .collect();
        aliases.sort();
        results.splice(0..0, aliases);
    }
    results
}

fn file_completions_for(ctx: &FilePathContext) -> Vec<String> {
    if ctx.is_include {
        get_include_completions(&ctx.partial)
    } else if ctx.is_outfile && !ctx.is_append {
        // Append targets get plain file completions — the virtual `clipboard`
        // entry only makes sense for `>`, where it can be overwritten.
        get_outfile_completions(&ctx.partial)
    } else {
        get_file_completions(&ctx.partial)
    }
}

fn get_completions(state: &AppState, uri: &str) -> Vec<String> {
    // Check for operator completion
    if let Some(tilde_idx) = uri.rfind('~') {
        let after_tilde = &uri[tilde_idx + 1..];
        let base_path = &uri[..tilde_idx];

        // Inside operator parentheses?
        if let Some(paren_idx) = after_tilde.rfind('(') {
            let op_name = &after_tilde[..paren_idx + 1];

            // take() and skip() take numbers, not properties
            if op_name == "take(" || op_name == "skip(" {
                return Vec::new();
            }

            return complete_inside_operator(state, base_path, after_tilde, paren_idx);
        }

        // Completing operator name
        return complete_operator(base_path, after_tilde);
    }

    // Try endpoint completion
    let endpoint_completions = complete_endpoint(state, uri);

    // Use path resolver to get current schema type
    // Strip trailing partial for resolution (get parent path)
    let (parent_uri, partial) = if uri.ends_with('/') {
        (uri.to_string(), "")
    } else if let Some(last_slash) = uri.rfind('/') {
        (format!("{}/", &uri[..last_slash]), &uri[last_slash + 1..])
    } else {
        return endpoint_completions;
    };

    let (schema_opt, expects_index, _) = resolve_type_at_path(state, &parent_uri);

    let schema_name = match schema_opt {
        Some(s) => s,
        None => return endpoint_completions,
    };

    let mut completions = Vec::new();
    let base_path = parent_uri.trim_end_matches('/');

    // Detect *member projection mode (e.g., /pos-profiles/*name)
    let (star_mode, clean_partial) = if partial.starts_with('*') {
        (true, &partial[1..])
    } else {
        (false, partial)
    };

    if star_mode {
        // *member completion: offer schema properties prefixed with *
        // When at a collection (expects_index), resolve the return type to get item properties
        let props_schema = if expects_index {
            if let Some(indexer) = state.indexer_info.get(&schema_name) {
                indexer.return_type.as_ref().map(|rt| rt.trim_end_matches('?').to_string())
            } else {
                None
            }
        } else {
            Some(schema_name.clone())
        };

        if let Some(ref props_schema_name) = props_schema {
            if let Some(props) = state.schema_props.get(props_schema_name) {
                for prop in props {
                    if prop.starts_with('@') {
                        continue;
                    }
                    if prop.starts_with(clean_partial) {
                        completions.push(format!("{}/*{}", base_path, prop));
                    }
                }
            }
        }
    } else if expects_index {
        // If current type expects an index, offer array members and identifier completions
        // Add array members (like count, add, after)
        if let Some(members) = state.array_members.get(&schema_name) {
            for member_name in members.keys() {
                if member_name.starts_with(clean_partial) {
                    completions.push(format!("{}/{}", base_path, member_name));
                }
            }
        }

        // Add identifier property completions (e.g., currencyCode=)
        let identifier_completions = get_identifier_completions_for_schema(state, &schema_name, base_path, clean_partial);
        completions.extend(identifier_completions);
    } else {
        // Complete with properties of current schema
        if let Some(props) = state.schema_props.get(&schema_name) {
            for prop in props {
                if prop.starts_with('@') {
                    continue;
                }
                if prop.starts_with(clean_partial) {
                    completions.push(format!("{}/{}", base_path, prop));
                }
            }
        }

        // Also offer primitive members (e.g., string.length, string.upper)
        if let Some(members) = state.primitive_members.get(&schema_name) {
            for member_name in members.keys() {
                if member_name.starts_with(clean_partial) {
                    completions.push(format!("{}/{}", base_path, member_name));
                }
            }
        }
    }

    // Filter out completions where the property name repeats a segment already in the parent path
    // (avoids circular suggestions like /about/api-versions/api-versions)
    let parent_segments: Vec<&str> = parent_uri.split('/').filter(|s| !s.is_empty()).collect();
    completions.retain(|c| {
        if let Some(last_seg) = c.rsplit('/').next() {
            !parent_segments.contains(&last_seg)
        } else {
            true
        }
    });

    // Merge endpoint completions with schema completions, avoiding duplicates
    // Skip endpoint completions when schema expects an index (e.g., string array)
    // to avoid suggesting sibling endpoints as if they were array entries
    if !expects_index {
        for ec in &endpoint_completions {
            if !completions.contains(ec) {
                completions.push(ec.clone());
            }
        }
    }

    if !completions.is_empty() {
        // Sort completions, but put add/remove/replace at the end
        completions.sort_by(|a, b| {
            let a_name = a.rsplit('/').next().unwrap_or("");
            let b_name = b.rsplit('/').next().unwrap_or("");
            let a_is_rare = matches!(a_name, "add" | "remove" | "replace");
            let b_is_rare = matches!(b_name, "add" | "remove" | "replace");
            match (a_is_rare, b_is_rare) {
                (true, false) => std::cmp::Ordering::Greater,
                (false, true) => std::cmp::Ordering::Less,
                _ => a.cmp(b),
            }
        });
        return completions;
    }

    // Don't fall back to endpoint completions when schema expects an index
    if expects_index {
        return Vec::new();
    }

    endpoint_completions
}

/// Parse ~func(arg) suffixes from a body string.
/// Returns (cleaned body, extra headers).
/// Currently supports: ~map(name) → X-Request-Map header.
fn parse_body_functions(body: &str) -> (String, Vec<(String, String)>) {
    let mut remaining = body.to_string();
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let Some(tilde_pos) = remaining.rfind('~') else { break };
        let after_tilde = &remaining[tilde_pos + 1..];
        let Some(paren_open) = after_tilde.find('(') else { break };
        if !after_tilde.ends_with(')') { break; }
        let func = &after_tilde[..paren_open];
        let arg = &after_tilde[paren_open + 1..after_tilde.len() - 1];
        if func.is_empty() || arg.is_empty() { break; }
        if !func.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') { break; }
        if !arg.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') { break; }
        match func {
            "map" => headers.push(("X-Request-Map".to_string(), arg.to_string())),
            _ => {} // ignore unknown functions
        }
        remaining = remaining[..tilde_pos].to_string();
    }
    (remaining, headers)
}

/// Result of resolving an `@file` (possibly glob) body argument.
struct AtFileResult {
    contents: Vec<u8>,
    content_type: Option<String>,
    accept_type: Option<String>,
}

/// Resolve an `@<path>` body argument into request bytes.
/// Supports single files and glob patterns (`*`, `?`, `[`). Multiple matched files
/// are combined: `.ndjson`/`.njson` files concatenate as a single NDJSON stream;
/// everything else parses as JSON and combines into a flat JSON array.
fn resolve_at_file_body(path_raw: &str) -> Result<AtFileResult, String> {
    let expanded = expand_home(path_raw);

    let is_glob = expanded.chars().any(|c| c == '*' || c == '?' || c == '[');

    if !is_glob {
        // Single file — preserve existing behavior
        match fs::read(&expanded) {
            Ok(contents) => {
                let (content_type, accept_type) =
                    if expanded.ends_with(".ndjson") || expanded.ends_with(".njson") {
                        (
                            Some("application/x-ndjson".to_string()),
                            Some("application/x-ndjson".to_string()),
                        )
                    } else if expanded.ends_with(".csv") {
                        (Some("text/csv".to_string()), None)
                    } else {
                        (None, None)
                    };
                Ok(AtFileResult {
                    contents,
                    content_type,
                    accept_type,
                })
            }
            Err(_) => Err(format!("File not found: {}", path_raw)),
        }
    } else {
        // Glob — expand and combine
        let mut paths: Vec<std::path::PathBuf> = glob::glob_with(&expanded, glob_match_options())
            .map_err(|e| format!("invalid glob pattern '{}': {}", path_raw, e))?
            .filter_map(|r| r.ok())
            .filter(|p| p.is_file() && !is_os_junk(p))
            .collect();
        if paths.is_empty() {
            return Err(format!("no files match: {}", path_raw));
        }
        paths.sort();

        let all_ndjson = paths.iter().all(|p| {
            let s = p.to_string_lossy();
            s.ends_with(".ndjson") || s.ends_with(".njson")
        });

        if all_ndjson {
            // NDJSON: concatenate file contents (ensure trailing newline between files)
            let mut combined: Vec<u8> = Vec::new();
            for path in &paths {
                let bytes = fs::read(path)
                    .map_err(|e| format!("could not read {}: {}", path.display(), e))?;
                combined.extend_from_slice(&bytes);
                if !combined.ends_with(b"\n") {
                    combined.push(b'\n');
                }
            }
            Ok(AtFileResult {
                contents: combined,
                content_type: Some("application/x-ndjson".to_string()),
                accept_type: Some("application/x-ndjson".to_string()),
            })
        } else {
            // JSON: parse each file, flatten arrays, push objects/values; emit single array
            let mut combined: Vec<Value> = Vec::new();
            for path in &paths {
                let bytes = fs::read(path)
                    .map_err(|e| format!("could not read {}: {}", path.display(), e))?;
                let v: Value = serde_json::from_slice(&bytes).map_err(|e| {
                    format!("invalid JSON in {}: {}", path.display(), e)
                })?;
                match v {
                    Value::Array(items) => combined.extend(items),
                    other => combined.push(other),
                }
            }
            let body_bytes = serde_json::to_vec(&combined)
                .map_err(|e| format!("could not serialize combined JSON: {}", e))?;
            Ok(AtFileResult {
                contents: body_bytes,
                content_type: Some("application/json".to_string()),
                accept_type: Some("application/json".to_string()),
            })
        }
    }
}

fn looks_like_id(s: &str) -> bool {
    // Check if string looks like a database key or UUID
    // Accepts: 24+ hex chars (MongoDB ObjectID), UUIDs with dashes, or alphanumeric IDs 8+ chars with digits
    if s.len() < 8 {
        return false;
    }
    // Pure hex 24+ chars (MongoDB ObjectID)
    if s.len() >= 24 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // UUID format: 8-4-4-4-12 hex with dashes (36 chars)
    if s.len() == 36 && s.chars().filter(|&c| c == '-').count() == 4 {
        return s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    }
    // Alphanumeric ID with at least one digit (8+ chars)
    if s.len() >= 8 && s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return s.chars().any(|c| c.is_ascii_digit());
    }
    false
}

fn complete_property_path(
    state: &AppState,
    base_resource: &str,
    path_parts: &[&str],
    uri: &str,
) -> Vec<String> {
    // Find schema for this resource's single item
    // Use deterministic matching: prefer exact pattern match, then shortest matching endpoint
    let pattern = format!("{}/{{index}}", base_resource);
    let mut schema_name = if let Some(schema) = state.endpoint_types.get(&pattern) {
        schema.clone()
    } else {
        // Fall back to shortest matching endpoint with {}
        let mut matching: Vec<_> = state.endpoint_types.iter()
            .filter(|(endpoint, _)| endpoint.starts_with(base_resource) && endpoint.contains('{'))
            .collect();
        matching.sort_by_key(|(endpoint, _)| endpoint.len());
        matching.first().map(|(_, schema)| (*schema).clone()).unwrap_or_default()
    };

    if schema_name.is_empty() {
        return Vec::new();
    }

    // Check if path[2] is an array member (like /receipts/after/)
    // In this case, we navigate using the array member's type, not an indexer
    if path_parts.len() >= 3 {
        let segment = path_parts[2];
        if !segment.is_empty() && !segment.contains('=') {
            // Check if this is an array member
            if let Some(members) = state.array_members.get(&schema_name) {
                if let Some(member_type) = members.get(segment) {
                    // Navigate using array member's type
                    schema_name = member_type.clone();
                    // Continue navigating from index 3 if more parts exist
                    if path_parts.len() > 4 {
                        for i in 3..path_parts.len() - 1 {
                            let prop_name = path_parts[i];
                            if prop_name.is_empty() || prop_name.contains('=') {
                                continue;
                            }
                            if let Some(prop_type_map) = state.prop_types.get(&schema_name) {
                                if let Some(prop_type) = prop_type_map.get(prop_name) {
                                    schema_name = prop_type.clone();
                                } else {
                                    return Vec::new();
                                }
                            } else {
                                return Vec::new();
                            }
                        }
                    }
                    // Return completions for current schema
                    let props = match state.schema_props.get(&schema_name) {
                        Some(p) => p,
                        None => return Vec::new(),
                    };
                    let last_part = path_parts.last().unwrap_or(&"");
                    let base_path_str = path_parts[..path_parts.len() - 1].join("/");
                    let mut completions = Vec::new();
                    for prop in props {
                        if prop.starts_with('@') {
                            continue;
                        }
                        if prop.starts_with(last_part) {
                            completions.push(format!("{}/{}", base_path_str, prop));
                        }
                    }
                    if completions.is_empty() && uri.ends_with('/') {
                        for prop in props {
                            if prop.starts_with('@') {
                                continue;
                            }
                            completions.push(format!("{}{}", uri, prop));
                        }
                    }
                    return completions;
                }
            }
        }
    }

    // Traverse nested properties to find the correct schema
    // path_parts: ["", "currencies", "currencyCode=NOK", "identifiers", ""]
    // We need to navigate from index 3 onwards (after the ID)
    if path_parts.len() > 4 {
        for i in 3..path_parts.len() - 1 {
            let prop_name = path_parts[i];
            // Skip empty parts and ID-like parts
            if prop_name.is_empty() || prop_name.contains('=') {
                continue;
            }
            // Look up the property type in current schema
            if let Some(prop_type_map) = state.prop_types.get(&schema_name) {
                if let Some(prop_type) = prop_type_map.get(prop_name) {
                    schema_name = prop_type.clone();
                } else {
                    // Property not found, can't navigate further
                    return Vec::new();
                }
            } else {
                return Vec::new();
            }
        }
    }

    let props = match state.schema_props.get(&schema_name) {
        Some(p) => p,
        None => return Vec::new(),
    };

    // Get the partial property name being typed
    let last_part = path_parts.last().unwrap_or(&"");
    let base_path = path_parts[..path_parts.len() - 1].join("/");

    let mut completions = Vec::new();
    for prop in props {
        // Skip @ properties
        if prop.starts_with('@') {
            continue;
        }
        if prop.starts_with(last_part) {
            completions.push(format!("{}/{}", base_path, prop));
        }
    }

    // If no prefix match but at trailing slash, show all properties
    if completions.is_empty() && uri.ends_with('/') {
        for prop in props {
            if prop.starts_with('@') {
                continue;
            }
            completions.push(format!("{}{}", uri, prop));
        }
    }

    completions
}

fn complete_endpoint(state: &AppState, prefix: &str) -> Vec<String> {
    // If typing inside a path that is itself an endpoint (after its trailing slash),
    // don't suggest sub-endpoints — unless there ARE sub-endpoints matching the prefix
    if let Some(last_slash) = prefix.rfind('/') {
        let parent = &prefix[..last_slash];
        if !parent.is_empty() && state.endpoints.contains(&parent.to_string()) {
            // Only suppress if no sub-endpoints match
            let has_sub = state.endpoints.iter().any(|e| {
                !e.contains("{key}=") && !e.contains('{') && e.starts_with(prefix) && e != parent
            });
            if !has_sub {
                return Vec::new();
            }
        }
    }

    let mut completions: Vec<String> = state
        .endpoints
        .iter()
        .filter(|e| !e.contains("{key}=") && !e.contains('{') && e.starts_with(prefix))
        .cloned()
        .collect();

    if completions.is_empty() {
        let search_term = prefix.trim_start_matches('/');
        completions = state
            .endpoints
            .iter()
            .filter(|e| !e.contains("{key}=") && !e.contains('{') && e.contains(search_term))
            .cloned()
            .collect();
    }

    completions
}

/// Resolve the schema type at a given URI path.
/// Returns (schema_name, expects_index, index_hint) where:
/// - schema_name: the resolved type at this path
/// - expects_index: true if current position expects an indexer value
/// - index_hint: the hint to show for the expected index (from x-indexer or additionalProperties)
fn resolve_type_at_path(state: &AppState, uri: &str) -> (Option<String>, bool, Option<String>) {
    // Strip operator suffix for type resolution
    let base_uri = if let Some(tilde_idx) = uri.find('~') {
        &uri[..tilde_idx]
    } else {
        uri
    };

    let path_parts: Vec<&str> = base_uri.split('/').filter(|s| !s.is_empty()).collect();
    if path_parts.is_empty() {
        return (None, false, None);
    }

    // Find the base endpoint and its schema
    // Try progressively shorter prefixes to find the endpoint
    let mut schema_name: Option<String> = None;
    let mut start_idx = 0;

    // First, find the collection endpoint (e.g., /receipts, /v2/receipts)
    // Check endpoint_schemas (from tag x-type) first, then endpoint_types (from response schema)
    for i in 1..=path_parts.len() {
        let prefix = format!("/{}", path_parts[..i].join("/"));
        if let Some(name) = state.endpoint_schemas.get(&prefix) {
            schema_name = Some(name.clone());
            start_idx = i;
        } else if let Some(name) = state.endpoint_types.get(&prefix) {
            schema_name = Some(name.clone());
            start_idx = i;
        }
    }

    let mut current_schema = match schema_name {
        Some(ref s) => {
            s.clone()
        },
        None => return (None, false, None),
    };

    // Walk remaining path segments to resolve final type
    let mut expects_index = false;
    let mut index_hint: Option<String> = None;

    for i in start_idx..path_parts.len() {
        let segment = path_parts[i];

        // Skip empty segments
        if segment.is_empty() {
            continue;
        }

        // Check if this segment is an array member
        if let Some(members) = state.array_members.get(&current_schema) {
            if let Some(member_type) = members.get(segment) {
                current_schema = member_type.clone();
                expects_index = false;
                index_hint = None;

                // Check if this type has additionalProperties (expects index)
                if let Some(key_type) = state.additional_props_key.get(&current_schema) {
                    expects_index = true;
                    index_hint = Some(key_type.clone());
                }
                continue;
            }
        }

        // Check if this segment is a property
        if let Some(prop_types) = state.prop_types.get(&current_schema) {
            if let Some(prop_type) = prop_types.get(segment) {
                current_schema = prop_type.clone();
                expects_index = false;
                index_hint = None;
                continue;
            }
        }

        // Check if this segment is a primitive member (e.g., string.length, string.upper)
        if let Some(members) = state.primitive_members.get(&current_schema) {
            if let Some(member_type) = members.get(segment) {
                current_schema = member_type.clone();
                expects_index = false;
                index_hint = None;
                continue;
            }
        }

        // Check if segment contains '=' (identifier lookup like currencyCode=NOK)
        if segment.contains('=') {
            // After identifier lookup, we get the indexed type
            if let Some(indexer) = state.indexer_info.get(&current_schema) {
                if let Some(return_type) = &indexer.return_type {
                    current_schema = return_type.trim_end_matches('?').to_string();
                    expects_index = false;
                    index_hint = None;
                    continue;
                }
            }
        }

        // If the segment matches a property name but has no typed $ref, it's a leaf
        // (primitive or array-of-primitives) — no further sub-properties exist
        if let Some(props) = state.schema_props.get(&current_schema) {
            if props.iter().any(|p| p == segment) {
                return (None, false, None);
            }
        }

        // Otherwise, this segment is likely an index value
        // After indexing, we get the returnType from x-indexer or stay at same type
        if let Some(indexer) = state.indexer_info.get(&current_schema) {
            if let Some(return_type) = &indexer.return_type {
                current_schema = return_type.trim_end_matches('?').to_string();
            }
        } else if let Some(_key_type) = state.additional_props_key.get(&current_schema) {
            // For additionalProperties, the value type comes from items or stays same
            // For now, assume we can't navigate further
        } else {
            // Segment doesn't match anything — can't resolve further
            return (None, false, None);
        }

        expects_index = false;
        index_hint = None;
    }

    // If URI ends with '/', check if current type expects an index
    if base_uri.ends_with('/') {
        // Check for x-indexer
        if let Some(indexer) = state.indexer_info.get(&current_schema) {
            if let Some(index_type) = &indexer.index_type {
                expects_index = true;
                index_hint = Some(index_type.clone());
            }
        }
        // Check for additionalProperties
        else if let Some(key_type) = state.additional_props_key.get(&current_schema) {
            expects_index = true;
            index_hint = Some(key_type.clone());
        }
        // Fallback: if schema is an array type, it expects an index (for older specs without x-indexer)
        else if state.array_schemas.contains(&current_schema) {
            expects_index = true;
            // No hint available without x-indexer
        }
        // Fallback: if this endpoint returns an array (response had items)
        else {
            let base_path = base_uri.trim_end_matches('/');
            if state.array_endpoints.contains(base_path) {
                expects_index = true;
            }
        }
    }

    (Some(current_schema), expects_index, index_hint)
}

fn get_param_hint(state: &AppState, uri: &str) -> String {
    // Show hint while typing an index value - before and during writing
    // But don't show hint if the current segment matches a static property/member

    // Find the last delimiter position
    let last_delim = uri.rfind(|c| c == '/' || c == '~' || c == '(').unwrap_or(0);

    // Get the parent path (with trailing slash) and current segment
    let (parent_uri, current_segment) = if last_delim > 0 {
        let parent = format!("{}/", &uri[..last_delim]);
        let segment = &uri[last_delim + 1..];
        (parent, segment)
    } else {
        return String::new();
    };

    // Use path resolver to get current type and index hint
    let (schema_opt, expects_index, index_hint) = resolve_type_at_path(state, &parent_uri);

    if !expects_index {
        return String::new();
    }

    // Check if current segment matches a static property/member - if so, no hint
    if !current_segment.is_empty() {
        // *member projection is never an index
        if current_segment.starts_with('*') {
            return String::new();
        }
        if let Some(schema_name) = &schema_opt {
            // Check array members
            if let Some(members) = state.array_members.get(schema_name) {
                if members.contains_key(current_segment) {
                    return String::new();
                }
            }
            // Check properties
            if let Some(props) = state.schema_props.get(schema_name) {
                if props.contains(&current_segment.to_string()) {
                    return String::new();
                }
            }
        }
    }

    if let Some(hint) = index_hint {
        return format!("index: {}", hint);
    }

    String::new()
}

fn get_identifier_completions_for_schema(state: &AppState, schema_name: &str, base_path: &str, partial: &str) -> Vec<String> {
    // Get x-indexer info
    let indexer = match state.indexer_info.get(schema_name) {
        Some(info) => info,
        None => return Vec::new(),
    };

    let index_type = match &indexer.index_type {
        Some(t) => t,
        None => return Vec::new(),
    };

    // Parse index_type to find identifier types (look for "X identifiers" patterns)
    let mut completions = Vec::new();

    for type_name in index_type.split(" or ") {
        let type_name = type_name.trim();
        if type_name.ends_with(" identifiers") || type_name == "common identifiers" {
            if let Some(props) = state.schema_props.get(type_name) {
                for prop in props {
                    if prop.starts_with('@') || prop == "key" {
                        continue;
                    }
                    let completion = format!("{}=", prop);
                    if completion.starts_with(partial) {
                        completions.push(format!("{}/{}", base_path, completion));
                    }
                }
            }
        }
    }

    completions
}

fn complete_operator(base_path: &str, after_tilde: &str) -> Vec<String> {
    let mut completions = Vec::new();

    for op in API_OPERATORS {
        if op.starts_with(after_tilde) {
            completions.push(format!("{}~{}", base_path, op));
        }
    }

    if completions.is_empty() {
        for op in API_OPERATORS {
            completions.push(format!("{}~{}", base_path, op));
        }
    }

    completions
}

/// Resolve the schema type at the end of a selector path.
/// Walks `/`-separated segments through prop_types, array_members, primitive_members.
/// Returns None if any segment can't be resolved.
fn resolve_selector_schema(state: &AppState, start_schema: &str, path_segments: &[&str]) -> Option<String> {
    let mut current = start_schema.to_string();
    for &segment in path_segments {
        if segment.is_empty() {
            continue;
        }
        // Strip any trailing operator on the segment (e.g., "customerRelations~count" -> just walk "customerRelations")
        let seg = if let Some(t) = segment.find('~') { &segment[..t] } else { segment };
        // Check array_members
        if let Some(members) = state.array_members.get(&current) {
            if let Some(member_type) = members.get(seg) {
                current = member_type.clone();
                continue;
            }
        }
        // Check prop_types (properties with $ref to another schema)
        if let Some(prop_types) = state.prop_types.get(&current) {
            if let Some(prop_type) = prop_types.get(seg) {
                current = prop_type.clone();
                continue;
            }
        }
        // Check primitive_members
        if let Some(members) = state.primitive_members.get(&current) {
            if let Some(member_type) = members.get(seg) {
                current = member_type.clone();
                continue;
            }
        }
        // Check if it's a known property (primitive, no sub-schema)
        if let Some(props) = state.schema_props.get(&current) {
            if props.iter().any(|p| p == seg) {
                // Known property but no $ref — it's a primitive type.
                // Check if the schema itself has primitive_members (e.g., string type)
                // We don't know the primitive type name here, so we can't resolve further.
                return None;
            }
        }
        return None;
    }
    Some(current)
}

/// Get all completable names for a schema: properties + array_members + primitive_members
fn get_schema_completions(state: &AppState, schema: &str) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(props) = state.schema_props.get(schema) {
        for p in props {
            if !p.starts_with('@') {
                names.push(p.clone());
            }
        }
    }
    if let Some(members) = state.array_members.get(schema) {
        for name in members.keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
    }
    if let Some(members) = state.primitive_members.get(schema) {
        for name in members.keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
    }
    names.sort();
    names
}

fn complete_inside_operator(
    state: &AppState,
    base_path: &str,
    after_tilde: &str,
    paren_idx: usize,
) -> Vec<String> {
    // ~map() completes with mapped type names, not schema properties
    let op_name = &after_tilde[..paren_idx];
    if op_name == "map" {
        let inside_paren = &after_tilde[paren_idx + 1..];
        let partial = inside_paren.trim();
        let prefix = format!("{}~map(", base_path);
        return state.mapped_types.iter()
            .filter(|name| partial.is_empty() || name.to_lowercase().starts_with(&partial.to_lowercase()))
            .map(|name| format!("{}{})", prefix, name))
            .collect();
    }

    // Get schema for the endpoint path
    // For nested operators like /people~with(addresses, resolve through the outer operator:
    // 1. Get the root endpoint schema (/people → Person)
    // 2. Resolve the selector within the outer operator (addresses → Address type)
    let root_schema = if let Some(outer_tilde) = base_path.find('~') {
        let endpoint = &base_path[..outer_tilde];
        let outer_after = &base_path[outer_tilde + 1..];
        let ep_schema = get_schema_for_path(state, endpoint);
        if ep_schema.is_empty() {
            return Vec::new();
        }
        // Extract the selector inside the outer operator's parens
        if let Some(outer_paren) = outer_after.find('(') {
            let selector = &outer_after[outer_paren + 1..];
            if selector.is_empty() {
                ep_schema
            } else {
                // Resolve the selector path to get the nested schema
                let segments: Vec<&str> = selector.split('/').collect();
                match resolve_selector_schema(state, &ep_schema, &segments) {
                    Some(s) => s,
                    None => return Vec::new(),
                }
            }
        } else {
            ep_schema
        }
    } else {
        let s = get_schema_for_path(state, base_path);
        if s.is_empty() { return Vec::new(); }
        s
    };

    let inside_paren = &after_tilde[paren_idx + 1..];

    // Split by comma to find current selector being typed
    let last_comma = inside_paren.rfind(',');
    let current_selector = if let Some(comma_idx) = last_comma {
        inside_paren[comma_idx + 1..].trim()
    } else {
        inside_paren.trim()
    };

    // The prefix that stays fixed (everything before what we're completing)
    let prefix_part = if let Some(comma_idx) = last_comma {
        format!("{}~{}{}",
            base_path,
            &after_tilde[..paren_idx + 1],
            &inside_paren[..comma_idx + 1])
    } else {
        format!("{}~{}", base_path, &after_tilde[..paren_idx + 1])
    };

    // Collect already-used top-level selectors for dedup
    // Extract the base property name from each selector (before / : or ~)
    let used: std::collections::HashSet<&str> = if let Some(comma_idx) = last_comma {
        inside_paren[..comma_idx].split(',').map(|s| {
            let s = s.trim();
            // Strip alias prefix
            let s = if let Some(colon) = s.find(':') { &s[colon + 1..] } else { s };
            // Take only the first path segment
            if let Some(slash) = s.find('/') { &s[..slash] }
            else if let Some(tilde) = s.find('~') { &s[..tilde] }
            else { s }
        }).collect()
    } else {
        std::collections::HashSet::new()
    };

    // Strip alias prefix from current selector: "foo:bar/baz" -> "bar/baz"
    let selector_path = if let Some(colon) = current_selector.find(':') {
        &current_selector[colon + 1..]
    } else {
        current_selector
    };

    // Strip negation prefix for property matching (e.g., "!com.heads.synced" -> "com.heads.synced")
    let (negation_prefix, selector_path) = if let Some(stripped) = selector_path.strip_prefix('!') {
        ("!", stripped)
    } else {
        ("", selector_path)
    };

    // Check if we're inside a nested operator: "customerRelations~just(na"
    // Find the last unmatched `~op(` in the selector
    if let Some(nested_tilde) = find_last_unmatched_operator(selector_path) {
        let before_op = &selector_path[..nested_tilde];
        let op_part = &selector_path[nested_tilde + 1..];
        if let Some(op_paren) = op_part.find('(') {
            // We're inside a nested operator's parens
            // Resolve the schema at the path before the operator
            let path_segments: Vec<&str> = before_op.split('/').collect();
            if let Some(nested_schema) = resolve_selector_schema(state, &root_schema, &path_segments) {
                // Recurse: complete inside this nested operator
                return complete_inside_operator_with_schema(
                    state, &nested_schema, op_part, op_paren, &prefix_part, current_selector,
                );
            }
        }
        // Completing the operator name itself after ~
        return Vec::new();
    }

    // Split selector path by / to handle nested property navigation
    let path_parts: Vec<&str> = selector_path.split('/').collect();

    if path_parts.len() <= 1 {
        // Simple case: completing a top-level property
        let current_prefix = path_parts.first().copied().unwrap_or("");
        let completions_from = get_schema_completions(state, &root_schema);
        let mut completions = Vec::new();
        for name in &completions_from {
            if used.contains(name.as_str()) {
                continue;
            }
            if name.starts_with(current_prefix) {
                completions.push(format!("{}{}{}", prefix_part, negation_prefix, current_selector.strip_prefix('!').unwrap_or(current_selector).replace(current_prefix, name)));
            }
        }
        if completions.is_empty() && current_prefix.is_empty() {
            for name in &completions_from {
                if used.contains(name.as_str()) {
                    continue;
                }
                completions.push(format!("{}{}{}", prefix_part, negation_prefix, name));
            }
        }
        return completions;
    }

    // Multi-segment: resolve all but last, complete the last
    let resolved_segments = &path_parts[..path_parts.len() - 1];
    let completing_prefix = path_parts[path_parts.len() - 1];

    let resolved_schema = match resolve_selector_schema(state, &root_schema, resolved_segments) {
        Some(s) => s,
        None => return Vec::new(),
    };

    let completions_from = get_schema_completions(state, &resolved_schema);
    let mut completions = Vec::new();
    // The fixed part is everything up to and including the last /
    let selector_base = &current_selector[..current_selector.rfind('/').unwrap() + 1];
    for name in &completions_from {
        if name.starts_with(completing_prefix) {
            completions.push(format!("{}{}{}", prefix_part, selector_base, name));
        }
    }
    if completions.is_empty() && completing_prefix.is_empty() {
        for name in &completions_from {
            completions.push(format!("{}{}{}", prefix_part, selector_base, name));
        }
    }
    completions
}

/// Helper to complete inside a nested operator, given a resolved schema context.
fn complete_inside_operator_with_schema(
    state: &AppState,
    schema: &str,
    op_after_tilde: &str,
    op_paren_idx: usize,
    outer_prefix: &str,
    full_current_selector: &str,
) -> Vec<String> {
    let inside_nested = &op_after_tilde[op_paren_idx + 1..];

    // Find the last comma in the nested parens
    let last_comma = inside_nested.rfind(',');
    let nested_current = if let Some(comma_idx) = last_comma {
        inside_nested[comma_idx + 1..].trim()
    } else {
        inside_nested.trim()
    };

    // Strip alias
    let nested_path = if let Some(colon) = nested_current.find(':') {
        &nested_current[colon + 1..]
    } else {
        nested_current
    };

    // Strip negation prefix for property matching
    let (_nested_negation, nested_path) = if let Some(stripped) = nested_path.strip_prefix('!') {
        ("!", stripped)
    } else {
        ("", nested_path)
    };

    // Check for further nesting
    if let Some(nested_tilde) = find_last_unmatched_operator(nested_path) {
        let before = &nested_path[..nested_tilde];
        let after = &nested_path[nested_tilde + 1..];
        if let Some(paren) = after.find('(') {
            let segs: Vec<&str> = before.split('/').collect();
            if let Some(deeper_schema) = resolve_selector_schema(state, schema, &segs) {
                return complete_inside_operator_with_schema(
                    state, &deeper_schema, after, paren, outer_prefix, full_current_selector,
                );
            }
        }
        return Vec::new();
    }

    // Split by / and resolve
    let path_parts: Vec<&str> = nested_path.split('/').collect();
    let (resolve_parts, completing_prefix) = if path_parts.len() <= 1 {
        (&[][..], path_parts.first().copied().unwrap_or(""))
    } else {
        (&path_parts[..path_parts.len() - 1], path_parts[path_parts.len() - 1])
    };

    let target_schema = if resolve_parts.is_empty() {
        schema.to_string()
    } else {
        match resolve_selector_schema(state, schema, resolve_parts) {
            Some(s) => s,
            None => return Vec::new(),
        }
    };

    let completions_from = get_schema_completions(state, &target_schema);

    // Build the prefix: outer_prefix + full_current_selector up to what we're completing
    let replace_from = full_current_selector.len() - completing_prefix.len();
    let fixed = &full_current_selector[..replace_from];

    let mut completions = Vec::new();
    for name in &completions_from {
        if name.starts_with(completing_prefix) {
            completions.push(format!("{}{}{}", outer_prefix, fixed, name));
        }
    }
    if completions.is_empty() && completing_prefix.is_empty() {
        for name in &completions_from {
            completions.push(format!("{}{}{}", outer_prefix, fixed, name));
        }
    }
    completions
}

/// Find the position of the last `~` that starts an unmatched operator
/// (i.e., where `(` count > `)` count after it).
fn find_last_unmatched_operator(s: &str) -> Option<usize> {
    // Walk backwards to find ~ that has an unmatched (
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut i = s.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth < 0 {
                    // Unmatched ( — find the ~ before it
                    if let Some(tilde_pos) = s[..i].rfind('~') {
                        return Some(tilde_pos);
                    }
                    return None;
                }
            }
            _ => {}
        }
    }
    None
}

fn get_schema_for_path(state: &AppState, path: &str) -> String {
    // Remove operators
    let base_path = if let Some(idx) = path.find('~') {
        &path[..idx]
    } else {
        path
    };

    // Try exact match
    if let Some(schema) = state.endpoint_types.get(base_path) {
        return schema.clone();
    }

    // Try pattern match
    let parts: Vec<&str> = base_path.split('/').collect();
    if parts.len() >= 3 {
        let mut pattern_parts = parts.clone();
        for i in (2..pattern_parts.len()).step_by(2) {
            if i < pattern_parts.len() && !pattern_parts[i].is_empty() {
                pattern_parts[i] = "{index}";
            }
        }
        let pattern = pattern_parts.join("/");
        if let Some(schema) = state.endpoint_types.get(&pattern) {
            return schema.clone();
        }
    }

    // Try base resource
    if parts.len() >= 2 {
        let base_pattern = format!("/{}/{{index}}", parts[1]);
        if let Some(schema) = state.endpoint_types.get(&base_pattern) {
            return schema.clone();
        }
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_wrap_row_count_matches_visual_line_count() {
        // The whole point: with auto-wrap off, printed rows must equal what the
        // clear math counts. hard_wrap inserts a break per wrap boundary, so the
        // number of resulting lines must equal visual_line_count of the original.
        for len in [0usize, 1, 79, 80, 81, 159, 160, 161, 214, 240, 320] {
            let s = "X".repeat(len);
            let wrapped = hard_wrap_ansi(&s, 80);
            let rows = wrapped.split('\n').count() as u16;
            assert_eq!(rows, visual_line_count(&s, 80), "len {} mismatch", len);
        }
    }

    #[test]
    fn hard_wrap_preserves_ansi_and_zero_width() {
        // ANSI escapes don't count toward width; a styled 80-char run stays one row.
        let s = format!("\x1b[38;5;240m{}\x1b[0m", "Y".repeat(80));
        let wrapped = hard_wrap_ansi(&s, 80);
        assert!(!wrapped.contains("\r\n"), "80 visible cols must not wrap");
        assert!(wrapped.contains("\x1b[38;5;240m") && wrapped.contains("\x1b[0m"), "escapes preserved");
        // 81 visible cols → exactly one wrap.
        let s2 = format!("\x1b[1m{}\x1b[0m", "Z".repeat(81));
        assert_eq!(hard_wrap_ansi(&s2, 80).matches("\r\n").count(), 1);
    }

    #[test]
    fn render_input_line_count_stable_across_cursor_on_blank_lines() {
        // Regression: moving the cursor onto a blank line (consecutive newlines)
        // must not change the rendered input's line count, or the block shifts on
        // redraw. Build a minimal AppState with a multi-line input and check the
        // line count is identical with the cursor at the end vs. on each blank line.
        let mut state = AppState::new(Config::default());
        state.width = 80;
        state.input = "PUT /\n\n\nasd".to_string(); // 4 logical lines, 2 blank
        let counts: Vec<u16> = (0..=char_len(&state.input))
            .map(|pos| {
                state.cursor_pos = pos;
                let (_o, n, _g) = render_input_content(&mut state, 80);
                n
            })
            .collect();
        // Every cursor position must yield the same 4-line count.
        assert!(counts.iter().all(|&c| c == 4), "line counts varied by cursor pos: {:?}", counts);
    }

    #[test]
    fn extract_identifier_pairs_skips_at_type() {
        // Case 1: identifiers child with @type metadata mixed in — @type excluded.
        let json = r#"{"identifiers":{"@type":"common identifiers","com.foo.example":"123"}}"#;
        assert_eq!(
            extract_identifier_pairs(json),
            vec![("com.foo.example".to_string(), "123".to_string())]
        );

        // Full person-shaped object (has identifiers child) — only the real id.
        let person = r#"{"@type":"person","identifiers":{"@type":"common identifiers","key":"eea"},"fullName":"Joe"}"#;
        assert_eq!(
            extract_identifier_pairs(person),
            vec![("key".to_string(), "eea".to_string())]
        );

        // Case 2: flat object with @type plus a real string key — @type excluded.
        let flat = r#"{"@type":"thing","com.bar":"9"}"#;
        assert_eq!(
            extract_identifier_pairs(flat),
            vec![("com.bar".to_string(), "9".to_string())]
        );
    }

    #[test]
    fn auto_promote_fires_on_at_infile_prefix() {
        // `@` at the body position is a file-reference request body
        // (`@data.json`), which implies a write — it must promote GET → PUT
        // exactly like a literal body character.
        let mut state = AppState::new(Config::default());
        state.input = "GET /elements/properties @".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '@');
        assert_eq!(state.input, "PUT /elements/properties @");
        assert_eq!(state.method, "PUT");

        // Sanity: a `{` body char still promotes GET → PUT.
        let mut state = AppState::new(Config::default());
        state.input = "GET /elements/properties {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "PUT /elements/properties {");
        assert_eq!(state.method, "PUT");

        // The `>` outfile redirect must still NOT promote.
        let mut state = AppState::new(Config::default());
        state.input = "GET /elements/properties >".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '>');
        assert_eq!(state.input, "GET /elements/properties >");
        assert_eq!(state.method, "GET");
    }

    #[test]
    fn auto_promote_uri_only_prepends_put() {
        // A URI-only line (implicit GET) gets an explicit `PUT ` prepended when a
        // body is started.
        let mut state = AppState::new(Config::default());
        state.input = "/people {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "PUT /people {");
        assert_eq!(state.method, "PUT");
        assert_eq!(state.cursor_pos, char_len("PUT /people {"));
        assert!(state.method_auto_promoted);
    }

    #[test]
    fn auto_promote_arms_cycle_window() {
        // Immediately cycling after an auto-promotion must go PUT → PATCH (the
        // promotion arms the ctrl+space window), not reset to GET and stash the
        // just-typed body.
        let mut state = AppState::new(Config::default());
        state.input = "GET /people {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "PUT /people {");
        assert!(state.last_method_cycle.is_some());
        cycle_method(&mut state);
        assert_eq!(state.input, "PATCH /people {");
        assert_eq!(state.method, "PATCH");
    }

    #[test]
    fn auto_revert_on_body_clear() {
        // Auto-promoted PUT reverts to GET when the body is deleted again.
        let mut state = AppState::new(Config::default());
        state.input = "GET /people {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "PUT /people {");
        // Simulate backspace deleting the `{`.
        state.input = "PUT /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_revert_method_on_body_clear(&mut state);
        assert_eq!(state.input, "GET /people ");
        assert_eq!(state.method, "GET");
        assert!(!state.method_auto_promoted);

        // A manually chosen PUT (flag not set) is never reverted.
        let mut state = AppState::new(Config::default());
        state.input = "PUT /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "PUT".to_string();
        auto_revert_method_on_body_clear(&mut state);
        assert_eq!(state.input, "PUT /people ");
        assert_eq!(state.method, "PUT");

        // Body still present → no revert yet.
        let mut state = AppState::new(Config::default());
        state.input = "GET /people {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        state.input = "PUT /people {\"a\"".to_string();
        auto_revert_method_on_body_clear(&mut state);
        assert_eq!(state.method, "PUT");
        assert!(state.method_auto_promoted);
    }

    #[test]
    fn promote_method_prefix_for_paste_positions() {
        // Paste of a body at the first-body position promotes (same rule as
        // typing): before-text is `GET <uri> `.
        let mut state = AppState::new(Config::default());
        state.input = "GET /people {\"name\":\"Joe\"}".to_string();
        let body_start = "GET /people ".len();
        let delta = promote_method_prefix(&mut state, body_start);
        assert_eq!(state.input, "PUT /people {\"name\":\"Joe\"}");
        assert_eq!(delta, 0); // GET→PUT, same length

        // URI-only + pasted body → prepend PUT (delta +4 chars).
        let mut state = AppState::new(Config::default());
        state.input = "/people {\"a\":1}".to_string();
        let delta = promote_method_prefix(&mut state, "/people ".len());
        assert_eq!(state.input, "PUT /people {\"a\":1}");
        assert_eq!(delta, 4);

        // Mid-URI position (no separating whitespace) must NOT promote.
        let mut state = AppState::new(Config::default());
        state.input = "GET /people".to_string();
        assert_eq!(promote_method_prefix(&mut state, "GET /peo".len()), 0);
        assert_eq!(state.input, "GET /people");

        // Non-GET methods are never touched.
        let mut state = AppState::new(Config::default());
        state.input = "POST /people {".to_string();
        assert_eq!(promote_method_prefix(&mut state, "POST /people ".len()), 0);
        assert_eq!(state.input, "POST /people {");
    }

    #[test]
    fn cycle_method_preserves_multiline_body() {
        // Cycling methods must not flatten a multi-line body into one line.
        let mut state = AppState::new(Config::default());
        let body = "{\n  \"name\": \"Joe\"\n}";
        state.input = format!("PUT /people {}", body);
        state.method = "PUT".to_string();
        state.last_method_cycle = Some(std::time::Instant::now()); // within window
        cycle_method(&mut state);
        assert_eq!(state.input, format!("PATCH /people {}", body));

        // Stash on switch to GET keeps the body verbatim, and restore brings the
        // newlines back.
        state.last_method_cycle = Some(std::time::Instant::now());
        cycle_method(&mut state); // PATCH → POST
        state.last_method_cycle = Some(std::time::Instant::now());
        cycle_method(&mut state); // POST → GET (stash)
        assert_eq!(state.input, "GET /people");
        assert_eq!(state.stashed_body, body);
        state.last_method_cycle = Some(std::time::Instant::now());
        cycle_method(&mut state); // GET → PUT (restore)
        assert_eq!(state.input, format!("PUT /people {}", body));
    }

    #[test]
    fn cycle_method_uri_only_keeps_uri() {
        // A URI-only line cycles as implicit GET and must not lose the URI.
        let mut state = AppState::new(Config::default());
        state.input = "/people".to_string();
        cycle_method(&mut state);
        assert_eq!(state.input, "PUT /people");
    }

    #[test]
    fn uppercase_method_token_normalizes() {
        assert_eq!(uppercase_method_token("get /x"), "GET /x");
        assert_eq!(uppercase_method_token("Put /people {\"a\":1}"), "PUT /people {\"a\":1}");
        assert_eq!(uppercase_method_token("  delete /y"), "  DELETE /y");
        assert_eq!(uppercase_method_token("GET /x"), "GET /x");
    }

    /// Test state with a fixed width so render (used by handle_paste) is happy.
    fn test_state() -> AppState {
        let mut state = AppState::new(Config::default());
        state.width = 80;
        state
    }

    /// A write sink for handle_paste tests — keeps ANSI render output out of the
    /// test terminal.
    fn sink() -> Vec<u8> {
        Vec::new()
    }

    #[test]
    fn expected_body_shape_reads_the_spec() {
        // Array endpoint whose element type has properties → array of objects.
        let mut state = test_state();
        state.array_endpoints.insert("/suppliers".to_string());
        state.endpoint_types.insert("/suppliers".to_string(), "supplier".to_string());
        state.schema_props.insert("supplier".to_string(), vec!["name".to_string()]);
        assert_eq!(expected_body_shape(&state, "/suppliers"), BodyShape::ArrayOfObjects);

        // Array endpoint with no object element type → array of scalars.
        let mut state = test_state();
        state.array_endpoints.insert("/tags".to_string());
        assert_eq!(expected_body_shape(&state, "/tags"), BodyShape::ArrayOfScalars);

        // Non-array endpoint with a known object schema → single object.
        let mut state = test_state();
        state.endpoint_types.insert("/settings".to_string(), "settings".to_string());
        state.schema_props.insert("settings".to_string(), vec!["locale".to_string()]);
        assert_eq!(expected_body_shape(&state, "/settings"), BodyShape::Object);

        // No spec loaded at all → Unknown, so nothing may be reshaped.
        let state = test_state();
        assert_eq!(expected_body_shape(&state, "/suppliers"), BodyShape::Unknown);
    }

    #[test]
    fn auto_wrap_array_body_follows_the_endpoint_shape() {
        // An array OF OBJECTS takes only `{`. A `"` or a digit could never be a
        // valid element, so neither expands any more — previously both did.
        for c in ['"', '7', '-', 't', 'f', 'n', '<', '>', 'x'] {
            let mut state = test_state();
            state.array_endpoints.insert("/suppliers".to_string());
            state.endpoint_types.insert("/suppliers".to_string(), "supplier".to_string());
            state.schema_props.insert("supplier".to_string(), vec!["name".to_string()]);
            state.input = format!("PUT /suppliers {c}");
            state.cursor_pos = char_len(&state.input);
            auto_wrap_array_body(&mut state, c);
            assert_eq!(state.input, format!("PUT /suppliers {c}"), "should not wrap: {c:?}");
        }

        // `{` still wraps there, which is the whole point.
        let mut state = test_state();
        state.array_endpoints.insert("/suppliers".to_string());
        state.endpoint_types.insert("/suppliers".to_string(), "supplier".to_string());
        state.schema_props.insert("supplier".to_string(), vec!["name".to_string()]);
        state.input = "PUT /suppliers {".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '{');
        assert_eq!(state.input, "PUT /suppliers [{");

        // With no spec loaded nothing expands, however plausible the character.
        let mut state = test_state();
        state.input = "PUT /suppliers {".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '{');
        assert_eq!(state.input, "PUT /suppliers {");
    }

    #[test]
    fn wrap_pasted_array_body_requires_an_object_on_an_object_array() {
        // Pasting a scalar onto an array-of-objects endpoint is a mistake;
        // wrapping it to `["x"]` would only cement it.
        let mut state = test_state();
        state.array_endpoints.insert("/suppliers".to_string());
        state.endpoint_types.insert("/suppliers".to_string(), "supplier".to_string());
        state.schema_props.insert("supplier".to_string(), vec!["name".to_string()]);
        state.input = "PUT /suppliers \"x\"".to_string();
        let body_start = "PUT /suppliers ".len();
        let body_end = state.input.len();
        wrap_pasted_array_body(&mut state, body_start, body_end);
        assert_eq!(state.input, "PUT /suppliers \"x\"");

        // An object still wraps.
        let mut state = test_state();
        state.array_endpoints.insert("/suppliers".to_string());
        state.endpoint_types.insert("/suppliers".to_string(), "supplier".to_string());
        state.schema_props.insert("supplier".to_string(), vec!["name".to_string()]);
        state.input = "PUT /suppliers {\"name\":\"A\"}".to_string();
        let body_start = "PUT /suppliers ".len();
        let body_end = state.input.len();
        wrap_pasted_array_body(&mut state, body_start, body_end);
        assert_eq!(state.input, "PUT /suppliers [{\"name\":\"A\"}]");
    }

    #[test]
    fn auto_wrap_array_body_only_expands_on_a_json_value_start() {
        // The reported bug: `<` is a mistyped `>`, and wrapping it to `PUT
        // /suppliers [<` cost two backspaces to undo.
        let mut state = test_state();
        state.array_endpoints.insert("/suppliers".to_string());
        state.input = "PUT /suppliers <".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '<');
        assert_eq!(state.input, "PUT /suppliers <");
        assert_eq!(state.cursor_pos, char_len("PUT /suppliers <"));

        // `>` opens an outfile, not a body — it had the same defect.
        let mut state = test_state();
        state.array_endpoints.insert("/suppliers".to_string());
        state.input = "PUT /suppliers >".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '>');
        assert_eq!(state.input, "PUT /suppliers >");

        // Every JSON value start still expands, `[` excepted (already an array).
        for c in ['{', '"', '-', '0', '7', 't', 'f', 'n'] {
            let mut state = test_state();
            state.array_endpoints.insert("/suppliers".to_string());
            state.input = format!("PUT /suppliers {c}");
            state.cursor_pos = char_len(&state.input);
            auto_wrap_array_body(&mut state, c);
            assert_eq!(state.input, format!("PUT /suppliers [{c}"), "should wrap: {c:?}");
        }

        // A letter that starts no JSON literal is a typo, not a body.
        for c in ['x', 'q', '<', '>', '%', ')'] {
            let mut state = test_state();
            state.array_endpoints.insert("/suppliers".to_string());
            state.input = format!("PUT /suppliers {c}");
            state.cursor_pos = char_len(&state.input);
            auto_wrap_array_body(&mut state, c);
            assert_eq!(state.input, format!("PUT /suppliers {c}"), "should not wrap: {c:?}");
        }
    }

    #[test]
    fn auto_promote_only_fires_on_a_body_start() {
        // Same defect on the promotion path: `/suppliers <` used to become
        // `PUT /suppliers <`.
        let mut state = test_state();
        state.input = "/suppliers <".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_promote_method_on_body_start(&mut state, '<');
        assert_eq!(state.input, "/suppliers <");
        assert!(!state.method_auto_promoted);

        // `@` is a file reference — a body, so it still promotes.
        let mut state = test_state();
        state.input = "/suppliers @data.json".to_string();
        state.cursor_pos = char_len("/suppliers @");
        auto_promote_method_on_body_start(&mut state, '@');
        assert_eq!(state.input, "PUT /suppliers @data.json");
    }

    #[test]
    fn auto_wrap_array_body_guards() {
        // Self-typed `[` → no extra bracket.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "PUT /people [".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '[');
        assert_eq!(state.input, "PUT /people [");

        // Non-array endpoint → no wrap.
        let mut state = test_state();
        state.input = "PUT /thing {".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '{');
        assert_eq!(state.input, "PUT /thing {");

        // POST → no wrap (matches the `{ ` object ghost semantics, not array).
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "POST /people {".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '{');
        assert_eq!(state.input, "POST /people {");

        // Second body character → no wrap (only the first body char triggers).
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "PUT /people {a".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, 'a');
        assert_eq!(state.input, "PUT /people {a");

        // PATCH on an array endpoint wraps like PUT.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "PATCH /people {".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '{');
        assert_eq!(state.input, "PATCH /people [{");
    }

    #[test]
    fn auto_promote_then_wrap_chain_on_uri_only() {
        // The key handler calls promote then wrap on the same keystroke: a
        // URI-only line typed `{` on an array endpoint gets both.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "/people {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        auto_wrap_array_body(&mut state, '{');
        assert_eq!(state.input, "PUT /people [{");
        assert_eq!(state.method, "PUT");
        assert_eq!(state.cursor_pos, char_len("PUT /people [{"));
    }

    #[test]
    fn promote_method_prefix_edge_cases() {
        // Lowercase `get` is recognized and replaced with uppercase PUT.
        let mut state = test_state();
        state.input = "get /x {".to_string();
        let delta = promote_method_prefix(&mut state, "get /x ".len());
        assert_eq!(state.input, "PUT /x {");
        assert_eq!(delta, 0);

        // Bare method with no URI → nothing to promote.
        let mut state = test_state();
        state.input = "GET {".to_string();
        assert_eq!(promote_method_prefix(&mut state, "GET ".len()), 0);
        assert_eq!(state.input, "GET {");

        // Body already present (three tokens before the position) → no promote.
        let mut state = test_state();
        state.input = "GET /x { a".to_string();
        assert_eq!(promote_method_prefix(&mut state, "GET /x { ".len()), 0);
        assert_eq!(state.input, "GET /x { a");
    }

    #[test]
    fn auto_revert_flag_hygiene() {
        // Fully cleared input drops the flag without touching anything.
        let mut state = test_state();
        state.method_auto_promoted = true;
        state.input = String::new();
        auto_revert_method_on_body_clear(&mut state);
        assert!(!state.method_auto_promoted);
        assert_eq!(state.input, "");

        // Method no longer PUT (e.g. user cycled onward) → flag drops, method
        // and input stay as the user chose.
        let mut state = test_state();
        state.method_auto_promoted = true;
        state.method = "PATCH".to_string();
        state.input = "PATCH /people ".to_string();
        auto_revert_method_on_body_clear(&mut state);
        assert!(!state.method_auto_promoted);
        assert_eq!(state.input, "PATCH /people ");
        assert_eq!(state.method, "PATCH");
    }

    #[test]
    fn cycle_method_stale_resets_to_get() {
        // >5s since the last cycle on a non-GET → reset to GET, stashing the body.
        let mut state = test_state();
        state.input = "PUT /people {\"a\":1}".to_string();
        state.method = "PUT".to_string();
        state.last_method_cycle = std::time::Instant::now().checked_sub(Duration::from_secs(6));
        cycle_method(&mut state);
        assert_eq!(state.input, "GET /people");
        assert_eq!(state.method, "GET");
        assert_eq!(state.stashed_body, "{\"a\":1}");

        // No prior cycle timestamp at all behaves the same (stale).
        let mut state = test_state();
        state.input = "PUT /people {\"a\":1}".to_string();
        state.method = "PUT".to_string();
        state.last_method_cycle = None;
        cycle_method(&mut state);
        assert_eq!(state.input, "GET /people");
        assert_eq!(state.stashed_body, "{\"a\":1}");
    }

    #[test]
    fn cycle_method_clears_flag_and_handles_other_methods() {
        // Cycling is an explicit choice — it must clear the auto-promotion flag.
        let mut state = test_state();
        state.input = "PUT /people {".to_string();
        state.method = "PUT".to_string();
        state.method_auto_promoted = true;
        state.last_method_cycle = Some(std::time::Instant::now());
        cycle_method(&mut state);
        assert_eq!(state.method, "PATCH");
        assert!(!state.method_auto_promoted);

        // DELETE (not in the cycle set) falls back to GET, stashing the body.
        let mut state = test_state();
        state.input = "DELETE /x {\"a\":1}".to_string();
        state.method = "DELETE".to_string();
        state.last_method_cycle = Some(std::time::Instant::now());
        cycle_method(&mut state);
        assert_eq!(state.input, "GET /x");
        assert_eq!(state.stashed_body, "{\"a\":1}");

        // Garbage input (no method, no URI) is a no-op.
        let mut state = test_state();
        state.input = "hello world".to_string();
        cycle_method(&mut state);
        assert_eq!(state.input, "hello world");
    }

    #[test]
    fn handle_paste_method_line_replaces_uppercase_and_clears_flag() {
        let mut state = test_state();
        state.input = "GET /".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method_auto_promoted = true;
        let mut out = sink();
        handle_paste(&mut state, "get /people/com.test=1", &mut out).unwrap();
        assert_eq!(state.input, "GET /people/com.test=1");
        assert_eq!(state.cursor_pos, char_len(&state.input));
        assert!(!state.method_auto_promoted);
    }

    #[test]
    fn handle_paste_directive_replaces_the_line() {
        // The user's case: `assert …` pasted over the prompt's `GET /` must not
        // become `GET /assert …`.
        let mut state = test_state();
        state.input = "GET /".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        let line = "assert GET /receipts/receiptID=HLH00000003733~where(no.omnium.returnSynced)";
        handle_paste(&mut state, line, &mut out).unwrap();
        assert_eq!(state.input, line);
        assert_eq!(state.cursor_pos, char_len(&state.input));

        for text in ["confirm", "sleep 2", "url has localhost", "# a note", "seed.api", "~/x/seed.api"] {
            let mut state = test_state();
            state.input = "GET /people".to_string();
            state.cursor_pos = char_len(&state.input);
            handle_paste(&mut state, text, &mut sink()).unwrap();
            assert_eq!(state.input, text, "pasting {text:?}");
        }
    }

    #[test]
    fn handle_paste_reads_carriage_returns_as_line_breaks() {
        // Terminals send a pasted newline as `\r`. Three lines joined that way
        // are three lines, and a copied line's trailing newline is dropped so
        // the cursor stays on the line it belongs to.
        let mut state = test_state();
        state.input = "GET /".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "assert /a\rassert /b\r\nassert /c\r", &mut out).unwrap();
        assert_eq!(state.input, "assert /a\nassert /b\nassert /c");
        assert_eq!(state.cursor_pos, char_len(&state.input));
        assert!(matches!(classify_prompt_line(&state.input, None), PromptLine::Program));

        // A single copied line, newline and all, over the default prompt.
        let mut state = test_state();
        state.input = "GET /".to_string();
        state.cursor_pos = char_len(&state.input);
        handle_paste(&mut state, "GET /people~take(5)\r", &mut out).unwrap();
        assert_eq!(state.input, "GET /people~take(5)");
        assert_eq!(state.cursor_pos, char_len(&state.input));

        // A path pasted after `GET /` is still inserted, minus its newline.
        let mut state = test_state();
        state.input = "GET /".to_string();
        state.cursor_pos = char_len(&state.input);
        handle_paste(&mut state, "/people\r", &mut out).unwrap();
        assert_eq!(state.input, "GET /people");

        // Several `/path` lines are a block and replace the line.
        let mut state = test_state();
        state.input = "GET /".to_string();
        state.cursor_pos = char_len(&state.input);
        handle_paste(&mut state, "/a\r/b\r", &mut out).unwrap();
        assert_eq!(state.input, "/a\n/b");
    }

    #[test]
    fn handle_paste_multiline_body_is_still_inserted() {
        // A JSON body spanning lines is a body, not a block of requests: it
        // lands at the cursor and promotes the method as a typed body would.
        let mut state = test_state();
        state.input = "GET /people/com.test=1 ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "{\r  \"name\": \"Joe\"\r}\r", &mut out).unwrap();
        assert_eq!(state.input, "PUT /people/com.test=1 {\n  \"name\": \"Joe\"\n}");
        assert_eq!(state.method, "PUT");

        // Inside a body a `\r` is a line break too, and a trailing one is kept.
        let mut state = test_state();
        state.input = "PUT /x {\n  \"a\": 1".to_string();
        state.cursor_pos = char_len(&state.input);
        handle_paste(&mut state, ",\r  \"b\": 2\r", &mut out).unwrap();
        assert_eq!(state.input, "PUT /x {\n  \"a\": 1,\n  \"b\": 2\n");
    }

    #[test]
    fn handle_paste_body_paste_promotes_get() {
        // Pasting a JSON body at the body position promotes GET → PUT.
        let mut state = test_state();
        state.input = "GET /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "{\"a\":1}", &mut out).unwrap();
        assert_eq!(state.input, "PUT /people {\"a\":1}");
        assert_eq!(state.method, "PUT");
        assert!(state.method_auto_promoted);
        assert_eq!(state.cursor_pos, char_len(&state.input));

        // Pasting an @file reference promotes the same way.
        let mut state = test_state();
        state.input = "GET /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "@data.json", &mut out).unwrap();
        assert_eq!(state.input, "PUT /people @data.json");
        assert_eq!(state.method, "PUT");

        // A pasted `>` redirect is not a body — no promotion.
        let mut state = test_state();
        state.input = "GET /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "> out.json", &mut out).unwrap();
        assert_eq!(state.input, "GET /people > out.json");
        assert_eq!(state.method, "GET");
    }

    #[test]
    fn handle_paste_wraps_array_body_on_array_endpoint() {
        // GET + pasted object on an array endpoint → promote AND full wrap.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "GET /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "{ \"name\": \"Joe\" }", &mut out).unwrap();
        assert_eq!(state.input, "PUT /people [{ \"name\": \"Joe\" }]");
        assert_eq!(state.method, "PUT");
        assert_eq!(state.cursor_pos, char_len(&state.input)); // after `]`

        // Manual PUT paste wraps the same way.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "PUT /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "{\"a\":1}", &mut out).unwrap();
        assert_eq!(state.input, "PUT /people [{\"a\":1}]");

        // PATCH wraps too.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "PATCH /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "{\"a\":1}", &mut out).unwrap();
        assert_eq!(state.input, "PATCH /people [{\"a\":1}]");
    }

    #[test]
    fn handle_paste_array_wrap_guards() {
        // Already an array → promote only, no double wrap.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "GET /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "[{\"a\":1}]", &mut out).unwrap();
        assert_eq!(state.input, "PUT /people [{\"a\":1}]");

        // @file reference → promote only, never wrapped.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "GET /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "@data.json", &mut out).unwrap();
        assert_eq!(state.input, "PUT /people @data.json");

        // Non-array endpoint → promote only.
        let mut state = test_state();
        state.input = "GET /thing ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "{\"a\":1}", &mut out).unwrap();
        assert_eq!(state.input, "PUT /thing {\"a\":1}");

        // Partial JSON (still composing) → promote only, no wrap.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "GET /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "{\"a\":", &mut out).unwrap();
        assert_eq!(state.input, "PUT /people {\"a\":");

        // POST is never array-wrapped (object endpoints take a single object).
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "POST /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "{\"a\":1}", &mut out).unwrap();
        assert_eq!(state.input, "POST /people {\"a\":1}");
    }

    #[test]
    fn handle_paste_array_wrap_multiline_and_trailing_ws() {
        // Multi-line pasted JSON wraps around the whole block; the trailing
        // newline a copied block brings along is dropped, so the cursor ends
        // right after the `]`. Non-ASCII content keeps the cursor math correct
        // (char vs byte).
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "GET /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "{\n  \"name\": \"Zoë\"\n}\n", &mut out).unwrap();
        assert_eq!(state.input, "PUT /people [{\n  \"name\": \"Zoë\"\n}]");
        assert_eq!(state.cursor_pos, char_len(&state.input));
    }

    #[test]
    fn handle_paste_double_slash_guard() {
        let mut state = test_state();
        state.input = "GET /".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "/products/x", &mut out).unwrap();
        assert_eq!(state.input, "GET /products/x");
        assert_eq!(state.method, "GET"); // path paste is not a body — no promote
    }

    #[test]
    fn handle_paste_identifier_cycle_window() {
        let multi = r#"{"identifiers":{"com.a":"1","com.b":"2"}}"#;

        // First paste expands to the first identifier; re-pasting the same JSON
        // cycles the slot in place — never accumulates segments.
        let mut state = test_state();
        state.input = "GET /people".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, multi, &mut out).unwrap();
        assert_eq!(state.input, "GET /people/com.a=1");
        handle_paste(&mut state, multi, &mut out).unwrap();
        assert_eq!(state.input, "GET /people/com.b=2");
        handle_paste(&mut state, multi, &mut out).unwrap();
        assert_eq!(state.input, "GET /people/com.a=1"); // wraps around

        // Inside an open JSON body the same paste inserts verbatim (no expansion).
        let mut state = test_state();
        state.input = "PUT /x {\"a\":".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, multi, &mut out).unwrap();
        assert!(state.input.contains("identifiers"), "got {:?}", state.input);
        assert!(!state.input.contains("com.a=1"));
    }

    #[test]
    fn find_body_start_basics() {
        // Method + URI + body → offset of the body.
        assert_eq!(find_body_start("GET /people {\"a\":1}"), Some(12));
        // Lowercase method is recognized too.
        assert_eq!(find_body_start("get /x {\"a\":1}"), Some(7));
        // URI-only line with a body.
        assert_eq!(find_body_start("/people {"), Some(8));
        // No body → None.
        assert_eq!(find_body_start("GET /people"), None);
    }

    #[test]
    fn apply_identifier_index_without_slash_adds_separator() {
        // Fallback branch: no `/` anywhere before the cursor.
        assert_eq!(apply_identifier_index("GET", "com.a=1"), "GET/com.a=1");
    }

    #[test]
    fn evaluate_url_gate_reports_empty_base_url() {
        let conds = vec![UrlCondition::Has("localhost".to_string())];
        let err = evaluate_url_gate(&conds, "").unwrap_err();
        assert!(err.contains("(no base URL)"), "got: {err}");
        assert!(err.contains("url has localhost"), "got: {err}");
    }

    #[test]
    fn auto_wrap_array_body_skips_at_infile_prefix() {
        // A `@` file reference already provides the full body shape — no `[`
        // must be prepended, even on an array endpoint with explicit PUT.
        let mut state = AppState::new(Config::default());
        state.array_endpoints.insert("/elements/properties".to_string());
        state.input = "PUT /elements/properties @".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '@');
        assert_eq!(state.input, "PUT /elements/properties @");

        // Sanity: a `{` body char on an array endpoint still gets `[` prepended.
        let mut state = AppState::new(Config::default());
        state.array_endpoints.insert("/elements/properties".to_string());
        state.input = "PUT /elements/properties {".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '{');
        assert_eq!(state.input, "PUT /elements/properties [{");
    }

    #[test]
    fn paste_in_index_mode_requires_cursor_on_uri_token() {
        // Cursor attached to the URI token → index mode (identifier expansion).
        let s = "GET /people";
        assert!(paste_in_index_mode(s, char_len(s)));
        let s = "GET /people/";
        assert!(paste_in_index_mode(s, char_len(s)));
        let s = "GET /people/com.bar=9";
        assert!(paste_in_index_mode(s, char_len(s)));

        // Cursor past the URI's separating space (body position) → NOT index
        // mode; the paste is a request body and must insert verbatim.
        let s = "PUT /people ";
        assert!(!paste_in_index_mode(s, char_len(s)));

        // Cursor inside an open JSON body → never index mode.
        let s = "PUT /people {\"a\":";
        assert!(!paste_in_index_mode(s, char_len(s)));

        // No URI yet (bare method) → not index mode.
        let s = "GET ";
        assert!(!paste_in_index_mode(s, char_len(s)));

        // Cursor MID-token (inside the URI) → not index mode; expanding there
        // would splice text into the URI (`/peo|ple` → `/peo/key=valple`).
        let s = "GET /people";
        assert!(!paste_in_index_mode(s, char_len("GET /peo")));
        // Cursor at end of URI token but followed by more input (body) is fine —
        // the char right after the cursor is whitespace.
        let s = "GET /people {\"a\":1}";
        assert!(paste_in_index_mode(s, char_len("GET /people")));
    }

    #[test]
    fn parse_sleep_directive_forms() {
        assert_eq!(parse_sleep_directive("5").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_sleep_directive("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_sleep_directive("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_sleep_directive("0.5").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_sleep_directive(" 1.5s ").unwrap(), Duration::from_millis(1500));
        assert!(parse_sleep_directive("").is_err());
        assert!(parse_sleep_directive("abc").is_err());
        assert!(parse_sleep_directive("-3").is_err());
        // More seconds than a Duration holds is an error, not a panic.
        for too_long in ["1e20", "1e300", "1e23ms", "inf", "nan"] {
            assert_eq!(
                parse_sleep_directive(too_long).unwrap_err(),
                format!("invalid sleep duration: `{too_long}`"),
            );
        }
    }

    #[test]
    fn parse_sleep_step_plain_sleep_is_unchanged() {
        assert_eq!(parse_sleep_step("5").unwrap(), BulkStep::Sleep(Duration::from_secs(5)));
        assert_eq!(parse_sleep_step("500ms").unwrap(), BulkStep::Sleep(Duration::from_millis(500)));
        assert!(parse_sleep_step("").is_err());
        assert!(parse_sleep_step("abc").is_err());
    }

    #[test]
    fn parse_sleep_step_while_forms() {
        let step = |interval, negate, request: &str| BulkStep::SleepWhile {
            interval,
            negate,
            request: request.to_string(),
        };
        let five = DEFAULT_SLEEP_WHILE_INTERVAL;
        assert_eq!(
            parse_sleep_step("while GET /people~count/==0").unwrap(),
            step(five, false, "GET /people~count/==0")
        );
        assert_eq!(
            parse_sleep_step("while not GET /people~count/==0").unwrap(),
            step(five, true, "GET /people~count/==0")
        );
        assert_eq!(
            parse_sleep_step("20 while GET /people~count/==0").unwrap(),
            step(Duration::from_secs(20), false, "GET /people~count/==0")
        );
        assert_eq!(
            parse_sleep_step("20 while not GET /people~count/==0").unwrap(),
            step(Duration::from_secs(20), true, "GET /people~count/==0")
        );
        // Same interval grammar as plain sleep; keywords are case-insensitive;
        // extra spaces don't matter; GET is implied by a leading slash.
        assert_eq!(
            parse_sleep_step("500ms   WHILE   NOT   /jobs/1/done").unwrap(),
            step(Duration::from_millis(500), true, "/jobs/1/done")
        );
        // A body is fine when it fits on the line.
        assert_eq!(
            parse_sleep_step("while POST /search {\"q\":1}").unwrap(),
            step(five, false, "POST /search {\"q\":1}")
        );
    }

    #[test]
    fn parse_sleep_step_while_rejects_bad_conditions() {
        let err = |s: &str| parse_sleep_step(s).unwrap_err();
        assert!(err("while").contains("sleep while requires a request"));
        assert!(err("while not").contains("sleep while requires a request"));
        assert!(err("abc while GET /x").contains("invalid sleep duration"));
        assert!(err("while GET /a && GET /b").contains("chain"));
        assert!(err("while GET /a || GET /b").contains("chain"));
        assert!(err("while GET /a > out.json").contains("write to a file"));
        assert!(err("while POST /a {\"open\": 1").contains("one line"));
        assert!(err("while nonsense").contains("not a request"));
    }

    #[test]
    fn parse_assert_step_forms() {
        let step = |negate, request: &str| BulkStep::Assert { negate, request: request.to_string() };
        assert_eq!(
            parse_assert_step("GET /companies/com.heads.seedID=ourcompany").unwrap(),
            step(false, "GET /companies/com.heads.seedID=ourcompany")
        );
        assert_eq!(parse_assert_step("/companies/x").unwrap(), step(false, "/companies/x"));
        assert_eq!(
            parse_assert_step("not GET /people~where(givenName=Test)~count").unwrap(),
            step(true, "GET /people~where(givenName=Test)~count")
        );
        assert_eq!(
            parse_assert_step("  NOT   post /search {\"q\":1}").unwrap(),
            step(true, "post /search {\"q\":1}")
        );
    }

    #[test]
    fn parse_assert_step_rejects_bad_conditions() {
        let err = |s: &str| parse_assert_step(s).unwrap_err();
        assert!(err("").contains("assert requires a request"));
        assert!(err("not").contains("assert requires a request"));
        assert!(err("GET /a && GET /b").contains("chain"));
        assert!(err("GET /a > out.json").contains("write to a file"));
        assert!(err("POST /a {\"open\": 1").contains("one line"));
        assert!(err("nonsense").contains("not a request"));
    }

    #[test]
    fn split_bulk_requests_recognises_assert() {
        let src = "assert /companies/x\nGET /a\nASSERT not GET /b~count\n";
        let prog = split_bulk_requests(src, None).unwrap();
        assert_eq!(prog.steps.len(), 3);
        assert_eq!(prog.steps[0], BulkStep::Assert { negate: false, request: "/companies/x".to_string() });
        assert_eq!(prog.steps[2], BulkStep::Assert { negate: true, request: "GET /b~count".to_string() });
    }

    #[test]
    fn format_assert_and_describe_check_response() {
        assert_eq!(format_assert(true, "/companies/x"), "assert not GET /companies/x");
        assert_eq!(describe_check_response(404, ""), "404 Not Found");
        assert_eq!(describe_check_response(200, "0"), "0");
        assert_eq!(describe_check_response(200, "{\n  \"a\": null\n}"), "{\"a\":null}");
        assert_eq!(describe_check_response(200, "  "), "empty response");
        let long = format!("\"{}\"", "x".repeat(200));
        let shown = describe_check_response(200, &long);
        assert!(shown.ends_with('…') && shown.chars().count() == 81, "{shown}");
    }

    #[test]
    fn parse_confirm_step_forms() {
        // Empty message uses default.
        assert_eq!(parse_confirm_step("").unwrap(), BulkStep::Confirm(None));
        // Custom message is preserved.
        assert_eq!(
            parse_confirm_step("Move on to the next step").unwrap(),
            BulkStep::Confirm(Some("Move on to the next step".to_string()))
        );
        // Extra whitespace is trimmed.
        assert_eq!(
            parse_confirm_step("  Ready?  ").unwrap(),
            BulkStep::Confirm(Some("Ready?".to_string()))
        );
    }

    #[test]
    fn a_previewed_request_reads_as_it_is_written() {
        let shown = |line: &str| {
            let (method, uri, body) = parse_request_line(line).unwrap();
            format_request_preview(&method, &uri, &body)
        };
        assert_eq!(shown("GET /a"), "GET /a");
        assert_eq!(shown("GET /a > out.json"), "GET /a > out.json");
        // The body is compacted and the outfile stays behind it.
        assert_eq!(shown("PUT /f { \"y\": 2 } > out.json"), "PUT /f {\"y\":2} > out.json");
        assert_eq!(shown("PUT /f {\"y\":2} >> out.json"), "PUT /f {\"y\":2} >> out.json");
        assert_eq!(shown("PUT /f @body.json > out.json"), "PUT /f @body.json > out.json");
        assert_eq!(format_assert(true, "PUT /c {\"z\": 3}"), "assert not PUT /c {\"z\":3}");
    }

    #[test]
    fn a_tls_failure_is_found_wherever_the_error_carries_it() {
        let cert = || rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        // On its own, inside an `io::Error`, and behind another error.
        assert!(tls_failure(&cert()).is_some());
        let wrapped = io::Error::new(io::ErrorKind::InvalidData, cert());
        assert!(tls_failure(&wrapped).is_some());
        assert!(tls_failure(&io::Error::new(io::ErrorKind::ConnectionRefused, "refused")).is_none());

        let says = |why| describe_tls_failure(&rustls::Error::InvalidCertificate(why), "example.com");
        assert_eq!(
            says(rustls::CertificateError::UnknownIssuer),
            "The certificate of example.com is not trusted: it is not signed by a public certificate authority."
        );
        assert_eq!(says(rustls::CertificateError::Expired), "The certificate of example.com is not trusted: it has expired.");
        assert_eq!(
            says(rustls::CertificateError::NotValidForName),
            "The certificate of example.com is not trusted: it is for another host name."
        );
        assert!(describe_tls_failure(&rustls::Error::HandshakeNotComplete, "h:1").starts_with("No secure connection to h:1: "));
        assert_eq!(host_of("https://cos.example.com"), "cos.example.com");
        assert_eq!(host_of("http://localhost:5000"), "localhost:5000");
    }

    #[test]
    fn parse_export_step_takes_a_namespaced_key_or_off() {
        let on = |name: &str| BulkStep::Export { name: Some(name.to_string()), written: true };
        assert_eq!(parse_export_step("com.heads.seedID").unwrap(), on("com.heads.seedID"));
        assert_eq!(parse_export_step("  my_co.my-org.seed-id$  ").unwrap(), on("my_co.my-org.seed-id$"));
        for off in ["off", "OFF", "Off"] {
            assert_eq!(parse_export_step(off).unwrap(), BulkStep::Export { name: None, written: true });
        }
        assert!(parse_export_step("").unwrap_err().contains("export needs a name"));
        for bad in ["seedID", "com.heads", "a.b.c d", "off now", "on"] {
            assert!(parse_export_step(bad).unwrap_err().contains("invalid export identifier"), "{bad}");
        }
        assert_eq!(format_export(&Some("a.b.c".to_string())), "export a.b.c");
        assert_eq!(format_export(&None), "export off");
    }

    #[test]
    fn an_export_line_is_scoped_to_its_file_by_steps_around_each_include() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("plain.api"), "GET /plain\n").unwrap();
        fs::write(dir.path().join("own.api"), "export in.ner.id\nGET /own\n").unwrap();
        let steps = |text: &str, export: Option<&str>| {
            split_bulk_requests_with(text, Some(dir.path()), &mut ImportAliases::new(), export.map(String::from))
                .unwrap()
                .steps
        };
        let written = |name: Option<&str>| BulkStep::Export { name: name.map(String::from), written: true };
        let scope = |name: Option<&str>| BulkStep::Export { name: name.map(String::from), written: false };
        let get = |uri: &str| BulkStep::Request(format!("GET {}", uri));

        // Without a line there is nothing to keep an include out of.
        assert_eq!(steps("GET /a\nplain.api\n", None), [get("/a"), get("/plain")]);
        // Under a line: off on the way in, back on the way out.
        assert_eq!(
            steps("export a.b.c\nplain.api\nGET /a\n", None),
            [written(Some("a.b.c")), scope(None), get("/plain"), scope(Some("a.b.c")), get("/a")]
        );
        // What an included file sets ends with it, whatever the includer has.
        assert_eq!(
            steps("own.api\nGET /a\n", None),
            [written(Some("in.ner.id")), get("/own"), scope(None), get("/a")]
        );
        assert_eq!(
            steps("export a.b.c\nown.api\n", None),
            [written(Some("a.b.c")), scope(None), written(Some("in.ner.id")), get("/own"), scope(Some("a.b.c"))]
        );
        // After `export off` an include needs nothing around it again.
        assert_eq!(
            steps("export a.b.c\nexport off\nplain.api\n", None),
            [written(Some("a.b.c")), written(None), get("/plain")]
        );
        // A line typed at the prompt starts in the mode an earlier one left.
        assert_eq!(steps("plain.api", Some("a.b.c")), [scope(None), get("/plain"), scope(Some("a.b.c"))]);
        assert_eq!(steps("GET /a", Some("a.b.c")), [get("/a")]);

        // So a one-request file is a program there, not a request of the prompt's.
        let line = dir.path().join("plain.api").display().to_string();
        assert!(matches!(classify_prompt_line(&line, None), PromptLine::Request(_)));
        assert!(matches!(classify_prompt_line(&line, Some("a.b.c".to_string())), PromptLine::Program));
        assert!(matches!(classify_prompt_line("export a.b.c", None), PromptLine::Program));

        // `--export` and ctrl+r pin the mode: a step leaves it alone.
        let mut config = Config::default();
        assert!(apply_export_step(&mut config, &Some("a.b.c".to_string())));
        assert_eq!(config.export_id.as_deref(), Some("a.b.c"));
        assert_eq!(typed_export(&config).as_deref(), Some("a.b.c"));
        config.export_pinned = true;
        assert!(!apply_export_step(&mut config, &None));
        assert_eq!(config.export_id.as_deref(), Some("a.b.c"));
        assert_eq!(typed_export(&config), None);
    }

    #[test]
    fn format_confirm_lines() {
        assert_eq!(format_confirm(&None), "confirm");
        assert_eq!(
            format_confirm(&Some("Ready?".to_string())),
            "confirm Ready?"
        );
        assert_eq!(
            format_confirm(&Some("Move forward".to_string())),
            "confirm Move forward"
        );
    }

    #[test]
    fn status_tone_is_orange_only_for_an_expected_no() {
        use StatusTone::*;
        // 2xx is green whatever was expected.
        assert_eq!(status_tone(200, false), Ok);
        assert_eq!(status_tone(204, true), Ok);
        // A plain "no": red by default, orange when the line was asking for it.
        assert_eq!(status_tone(404, false), Bad);
        assert_eq!(status_tone(404, true), Expected);
        assert_eq!(status_tone(400, true), Expected);
        assert_eq!(status_tone(409, true), Expected);
        // An unanswered question is never expected.
        for status in [401, 403, 408, 429, 500, 502, 503] {
            assert_eq!(status_tone(status, true), Bad, "{status}");
            assert_eq!(status_tone(status, false), Bad, "{status}");
        }
    }

    #[test]
    fn format_status_keeps_the_text_whatever_the_tone() {
        let not_found = reqwest::StatusCode::NOT_FOUND;
        assert!(format_status(not_found, true).contains("404 Not Found"));
        assert!(format_status(not_found, false).contains("404 Not Found"));
        assert!(format_status(reqwest::StatusCode::OK, false).contains("200 OK"));
    }

    #[test]
    fn is_program_line_only_for_non_request_first_words() {
        // Requests, implied GETs, and chains starting with one are not programs.
        assert!(!is_program_line("GET /people"));
        assert!(!is_program_line("get /people"));
        assert!(!is_program_line("/people~count"));
        assert!(!is_program_line("PUT /people {\"a\":1} && GET /people"));
        assert!(!is_program_line(""));
        // Directives and includes are.
        assert!(is_program_line("confirm"));
        assert!(is_program_line("confirm Move on?"));
        assert!(is_program_line("sleep 2"));
        assert!(is_program_line("assert /companies/x"));
        assert!(is_program_line("url has localhost"));
        assert!(is_program_line("seed.api"));
        // A typo'd request is a program too — it must reach the parser and be
        // reported, not silently re-send the previous request.
        assert!(is_program_line("peple"));
        // An absolute path to a .api file is an include, not a URI.
        assert!(is_program_line("/tmp/seed.api"));
        assert!(is_program_line("/Users/me/seeds/*.api"));
        assert!(!is_program_line("/tmp/seed.apiary"));
    }

    #[test]
    fn starts_a_request_tells_a_uri_from_an_absolute_include() {
        assert!(starts_a_request("GET"));
        assert!(starts_a_request("options"));
        assert!(starts_a_request("/people"));
        assert!(starts_a_request("/people~where(name=x.api)"));
        assert!(!starts_a_request("/tmp/seed.api"));
        assert!(!starts_a_request("/tmp/SEED.API"));
        assert!(!starts_a_request("seed.api"));
        assert!(!starts_a_request("sleep"));
        assert!(!starts_a_request("~/seed.api"));
    }

    #[test]
    fn normalize_request_text_matches_the_file_parser() {
        // Comments go, raw newlines in strings become escapes, structure stays.
        let text = "PUT /a {\n  \"x\": \"l1\nl2\", // note\n  \"y\": 2 /* two */\n}";
        let normalized = normalize_request_text(text).unwrap();
        let program = split_bulk_requests(text, None).unwrap();
        assert_eq!(program.steps, vec![BulkStep::Request(normalized.clone())]);
        assert!(!normalized.contains("note") && !normalized.contains("two"), "{normalized}");
        assert!(normalized.contains("l1\\nl2"), "{normalized}");
        // Outside a body nothing is touched — a URI may contain `#` or `//`.
        assert_eq!(
            normalize_request_text("GET /a~where(url=http://x/y#z)").unwrap(),
            "GET /a~where(url=http://x/y#z)"
        );
        assert!(normalize_request_text("PUT /a {\"x\": 1").is_err());
    }

    #[test]
    fn a_chain_segment_must_be_a_request() {
        for line in ["GET /a && sleep 1", "GET /a || peple", "assert /a && GET /b"] {
            let err = match split_bulk_requests(line, None) {
                Err(e) => e,
                Ok(p) => panic!("{line} parsed as {:?}", p.steps),
            };
            assert!(
                err.contains("chain segment is not a request") || err.contains("can't be a"),
                "{line}: {err}"
            );
        }
        // The real thing still parses.
        assert!(matches!(
            split_bulk_requests("GET /a && PUT /b {\"x\":1}", None).unwrap().steps[..],
            [BulkStep::Chain(_)]
        ));
    }

    #[test]
    fn classify_prompt_line_keeps_one_request_or_chain_apart_from_programs() {
        assert!(matches!(classify_prompt_line("GET /a", None), PromptLine::Request(r) if r == "GET /a"));
        assert!(matches!(
            classify_prompt_line("PUT /a {\"x\":1 // c\n}", None),
            PromptLine::Request(r) if !r.contains("// c")
        ));
        assert!(matches!(classify_prompt_line("GET /a && GET /b", None), PromptLine::Chain(s) if s.len() == 2));
        for program in ["sleep 1", "GET /a\nGET /b", "peple", "url has x\nGET /a", "# note", "/tmp/x.api"] {
            assert!(matches!(classify_prompt_line(program, None), PromptLine::Program), "{program}");
        }
    }

    #[test]
    fn parse_request_line_reads_an_absolute_api_path_as_no_request() {
        assert_eq!(parse_request_line("/tmp/seed.api"), None);
        assert_eq!(
            parse_request_line("/tmp/seed"),
            Some(("GET".to_string(), "/tmp/seed".to_string(), String::new()))
        );
    }

    #[test]
    fn one_shot_program_line_routes_only_what_the_one_shot_path_cannot_send() {
        let s = |v: &str| Some(v.to_string());
        let words = |v: &[&str]| v.iter().map(|w| w.to_string()).collect::<Vec<_>>();

        // Plain requests keep the one-shot path.
        assert_eq!(one_shot_program_line(&s("GET"), &s("/about"), &[]), None);
        assert_eq!(one_shot_program_line(&s("/about"), &None, &[]), None);
        assert_eq!(one_shot_program_line(&s("PUT"), &s("/p"), &words(&["{\"a\":1}"])), None);
        assert_eq!(one_shot_program_line(&s("GET"), &s("/about > /tmp/x.json"), &[]), None);
        // No positionals at all → interactive, not a program.
        assert_eq!(one_shot_program_line(&None, &None, &[]), None);
        assert_eq!(one_shot_program_line(&s(""), &None, &[]), None);

        // Directives, includes, and typos.
        assert_eq!(one_shot_program_line(&s("assert"), &s("/x"), &[]), s("assert /x"));
        assert_eq!(one_shot_program_line(&s("confirm"), &None, &[]), s("confirm"));
        assert_eq!(
            one_shot_program_line(&s("confirm"), &s("Move"), &words(&["on"])),
            s("confirm Move on")
        );
        assert_eq!(one_shot_program_line(&s("seed.api"), &None, &[]), s("seed.api"));
        assert_eq!(one_shot_program_line(&s("/abs/seed.api"), &None, &[]), s("/abs/seed.api"));
        assert_eq!(one_shot_program_line(&s("peple"), &None, &[]), s("peple"));

        // Chains, split by the shell or quoted whole.
        assert_eq!(
            one_shot_program_line(&s("GET"), &s("/a"), &words(&["&&", "GET", "/b"])),
            s("GET /a && GET /b")
        );
        assert_eq!(one_shot_program_line(&s("GET"), &s("/a && GET /b"), &[]), s("GET /a && GET /b"));
        assert_eq!(one_shot_program_line(&s("GET /a && GET /b"), &None, &[]), s("GET /a && GET /b"));

        // A whole request in one argument used to fall into interactive mode.
        assert_eq!(one_shot_program_line(&s("GET /about"), &None, &[]), s("GET /about"));
        // A `&&` inside a body is not a chain.
        assert_eq!(
            one_shot_program_line(&s("PUT"), &s("/p"), &words(&["{\"q\":\"a && b\"}"])),
            None
        );
    }

    #[test]
    fn describe_program_error_names_the_typo() {
        assert_eq!(
            describe_program_error("include not found: peple"),
            "not a request or .api file: peple"
        );
        // Something that was clearly meant as a file keeps the file message.
        for path in ["seed.api", "shared/seeds", "~/x", "./x", "/abs/seed.api"] {
            assert_eq!(
                describe_program_error(&format!("include not found: {path}")),
                format!("include not found: {path}")
            );
        }
        assert_eq!(
            describe_program_error("include not found: peple /a"),
            "not a request or .api file: peple"
        );
        assert_eq!(
            describe_program_error("invalid sleep duration: `abc`"),
            "invalid sleep duration: `abc`"
        );
        // The bulk parser really does route an unknown word to include handling.
        let err = split_bulk_requests("peple", None).unwrap_err();
        assert!(err.starts_with("include not found:"), "{err}");
    }

    #[test]
    fn confirm_prompt_text_adds_a_question_mark_once() {
        assert_eq!(confirm_prompt_text(&None), "Continue?");
        assert_eq!(confirm_prompt_text(&Some("Ready?".to_string())), "Ready?");
        assert_eq!(confirm_prompt_text(&Some("Move on".to_string())), "Move on?");
    }

    #[test]
    fn directive_output_block_renders_verbatim_with_a_blank_line() {
        let block = OutputBlock::directive("sleep 2s".to_string());
        assert_eq!(block.render(80), "sleep 2s\n\n");
        assert!(!block.has_body());
        // Width is irrelevant to a directive line.
        assert_eq!(block.render(10), "sleep 2s\n\n");
    }

    #[test]
    fn split_bulk_requests_recognises_confirm() {
        let src = "confirm\nGET /a\nconfirm Ready?\n";
        let prog = split_bulk_requests(src, None).unwrap();
        assert_eq!(prog.steps.len(), 3);
        assert_eq!(prog.steps[0], BulkStep::Confirm(None));
        assert_eq!(prog.steps[2], BulkStep::Confirm(Some("Ready?".to_string())));
    }

    #[test]
    fn split_bulk_requests_keeps_sleep_while_in_order() {
        let src = "PUT /import {\"x\":1}\nsleep 2 while not GET /import~count\nGET /done\n";
        let prog = split_bulk_requests(src, None).unwrap();
        assert_eq!(prog.steps.len(), 3);
        assert_eq!(
            prog.steps[1],
            BulkStep::SleepWhile {
                interval: Duration::from_secs(2),
                negate: true,
                request: "GET /import~count".to_string(),
            }
        );
    }

    #[test]
    fn format_sleep_while_and_elapsed() {
        assert_eq!(
            format_sleep_while(Duration::from_secs(20), true, "/people~count/==0"),
            "sleep 20s while not GET /people~count/==0"
        );
        assert_eq!(format_elapsed(Duration::from_millis(800)), "800ms");
        assert_eq!(format_elapsed(Duration::from_millis(12_400)), "12s");
        assert_eq!(format_elapsed(Duration::from_secs(60)), "1m0s");
        assert_eq!(format_elapsed(Duration::from_secs(100)), "1m40s");
        assert_eq!(format_elapsed(Duration::from_secs(3600)), "1h0m0s");
        assert_eq!(format_elapsed(Duration::from_secs(3723)), "1h2m3s");
    }

    /// A finished request keeps hundredths under a minute and switches to the
    /// progress line's `XmYs` shape above it, so the two never disagree.
    #[test]
    fn format_latency_matches_progress_line_past_a_minute() {
        assert_eq!(format_latency(Duration::from_millis(20)), "0.02s");
        assert_eq!(format_latency(Duration::from_millis(45_380)), "45.38s");
        assert_eq!(format_latency(Duration::from_millis(59_999)), "1m0s");
        assert_eq!(format_latency(Duration::from_millis(59_994)), "59.99s");
        assert_eq!(format_latency(Duration::from_secs(60)), "1m0s");
        assert_eq!(format_latency(Duration::from_millis(153_380)), "2m33s");
        assert_eq!(format_latency(Duration::from_secs(3723)), "1h2m3s");
        assert_eq!(
            format_latency(Duration::from_millis(153_380)),
            format_elapsed(Duration::from_millis(153_380))
        );
    }

    /// `sleep` is echoed the way the file wrote it, fractions included.
    #[test]
    fn format_duration_keeps_fractional_seconds() {
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::from_secs(2)), "2s");
        assert_eq!(format_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(format_duration(Duration::from_millis(2250)), "2.25s");
        assert_eq!(format_duration(Duration::from_millis(1001)), "1.001s");
    }

    #[test]
    fn parse_url_condition_forms() {
        assert_eq!(parse_url_condition("url has localhost:5000").unwrap(),
            Some(UrlCondition::Has("localhost:5000".to_string())));
        assert_eq!(parse_url_condition("url is http://localhost:5000").unwrap(),
            Some(UrlCondition::Is("http://localhost:5000".to_string())));
        // Not a url directive → None (falls through to include handling).
        assert_eq!(parse_url_condition("other.api").unwrap(), None);
        // Malformed url directives → error.
        assert!(parse_url_condition("url has").is_err());
        assert!(parse_url_condition("url foo bar").is_err());
        // Any case, and any run of blanks between the words.
        let has = Some(UrlCondition::Has("localhost:5000".to_string()));
        for line in ["URL has localhost:5000", "Url HAS localhost:5000", "url  has   localhost:5000", "url\thas\tlocalhost:5000"] {
            assert_eq!(parse_url_condition(line).unwrap(), has, "{line:?}");
        }
        assert_eq!(
            parse_url_condition("URL IS  http://Localhost:5000").unwrap(),
            Some(UrlCondition::Is("http://Localhost:5000".to_string())),
        );
        assert!(parse_url_condition("URL has").is_err());
        assert_eq!(parse_url_condition("urls.api").unwrap(), None);
    }

    #[test]
    fn a_byte_order_mark_is_not_part_of_the_first_line() {
        assert_eq!(strip_bom("\u{feff}GET /a\n".to_string()), "GET /a\n");
        assert_eq!(strip_bom("GET /a\n".to_string()), "GET /a\n");
        assert_eq!(strip_bom(String::new()), "");
        // Only at the very start.
        assert_eq!(strip_bom("GET /a\u{feff}".to_string()), "GET /a\u{feff}");
    }

    #[test]
    fn form_encode_escapes_what_a_form_body_reserves() {
        assert_eq!(form_encode("abc-XYZ_0.9*"), "abc-XYZ_0.9*");
        assert_eq!(form_encode("s&x=1+2%"), "s%26x%3D1%2B2%25");
        assert_eq!(form_encode("a b"), "a+b");
        assert_eq!(form_encode("å/~"), "%C3%A5%2F%7E");
    }

    #[test]
    fn up_and_down_keep_the_column_in_characters() {
        // The crash this guards: `ååå`, a new line, `a`, Up.
        let input = "ååå\na";
        assert_eq!(cursor_line_up(input, 5), 1);
        assert_eq!(cursor_line_down(input, 1), 5);
        // A shorter target line takes the cursor to its end.
        assert_eq!(cursor_line_down(input, 3), 5);
        assert_eq!(cursor_line_up("a\nååå", 5), 1);
        // Three lines, column kept through the middle one.
        let three = "åäö\nxy\nåäö";
        assert_eq!(cursor_line_up(three, 9), 6); // col 2 of line 3 → end of `xy`
        assert_eq!(cursor_line_up(three, 6), 2);
        assert_eq!(cursor_line_down(three, 3), 6);
        assert_eq!(cursor_line_down(three, 5), 8);
        // Nowhere to go: stays put.
        assert_eq!(cursor_line_up(three, 2), 2);
        assert_eq!(cursor_line_down(three, 8), 8);
        assert_eq!(cursor_line_up("", 0), 0);
        assert_eq!(cursor_line_down("", 0), 0);
        // Every position of a multi-byte text is a valid place to move from.
        for pos in 0..=three.chars().count() {
            assert!(cursor_line_up(three, pos) <= three.chars().count());
            assert!(cursor_line_down(three, pos) <= three.chars().count());
        }
    }

    #[test]
    fn only_a_plain_or_shifted_key_types_a_character() {
        assert!(types_a_character(KeyModifiers::NONE));
        assert!(types_a_character(KeyModifiers::SHIFT));
        assert!(!types_a_character(KeyModifiers::CONTROL));
        assert!(!types_a_character(KeyModifiers::ALT));
        assert!(!types_a_character(KeyModifiers::CONTROL | KeyModifiers::SHIFT));
    }

    #[test]
    fn the_outfile_marker_is_found_outside_strings_and_brackets() {
        // (line, where the redirect starts)
        let cases: [(&str, Option<&str>); 12] = [
            ("GET /people > out.json", Some(" > out.json")),
            ("GET /people >> out.json", Some(" >> out.json")),
            ("GET /people >out.json", Some(" >out.json")),
            ("GET /people", None),
            (r#"PUT /x {"a":"b > c"}"#, None),
            (r#"PUT /x {"a":"b > c"} > out.json"#, Some(" > out.json")),
            (r#"PUT /x {"a":"he said \"x > y\""} >> o.json"#, Some(" >> o.json")),
            (r#"PUT /x [1 > 2]"#, None),
            (r#"GET /x~where(name="a > b")"#, None),
            (r#"GET /x~where(a >1) > o.csv"#, Some(" > o.csv")),
            // The last one outside wins, as it always did.
            ("GET /x > a > b", Some(" > b")),
            // Unbalanced: nothing to go by, so the last ` >` is taken.
            (r#"PUT /x {"a":"b > c"#, Some(r#" > c"#)),
        ];
        for (line, redirect) in cases {
            assert_eq!(outfile_marker_at(line).map(|at| &line[at..]), redirect, "{line}");
        }
        assert_eq!(split_uri_outfile(r#"/x~where(n="a > b") > o.json"#), (r#"/x~where(n="a > b")"#, " > o.json"));
        assert_eq!(split_uri_outfile("/x"), ("/x", ""));
    }

    #[test]
    fn a_request_line_keeps_a_gt_that_is_its_own() {
        let parsed = |line: &str| parse_request_line(line).unwrap();
        let s = |v: &str| v.to_string();
        assert_eq!(parsed(r#"PUT /x {"a":"b > c"}"#), (s("PUT"), s("/x"), s(r#"{"a":"b > c"}"#)));
        assert_eq!(
            parsed(r#"PUT /x {"a":"b > c"} > out.json"#),
            (s("PUT"), s("/x > out.json"), s(r#"{"a":"b > c"}"#))
        );
        // A URI operator with blanks and a `>` in its parentheses is one URI.
        assert_eq!(parsed(r#"GET /x~where(name="a > b")"#), (s("GET"), s(r#"/x~where(name="a > b")"#), s("")));
        assert_eq!(parsed(r#"/x~where(name="a b") > o.json"#), (s("GET"), s(r#"/x~where(name="a b") > o.json"#), s("")));
        assert_eq!(
            parsed(r#"PUT /x~where(a=1 || b=2) {"y":1}"#),
            (s("PUT"), s("/x~where(a=1 || b=2)"), s(r#"{"y":1}"#))
        );
        // Unbalanced: the URI ends at the first blank, as before.
        assert_eq!(parsed(r#"PUT /x(y {"a":1}"#), (s("PUT"), s("/x(y"), s(r#"{"a":1}"#)));

        // The prompt reads the same line the same way.
        let mut state = AppState::new(Config::default());
        parse_input(&mut state, r#"PUT /x {"a":"b > c"}"#);
        assert_eq!((state.uri.as_str(), state.body.as_str()), ("/x", r#"{"a":"b > c"}"#));
        assert!(state.config.outfile.is_empty());
        parse_input(&mut state, r#"GET /x~where(name="a > b") >> o.json"#);
        assert_eq!((state.uri.as_str(), state.body.as_str()), (r#"/x~where(name="a > b")"#, ""));
        assert_eq!((state.config.outfile.as_str(), state.config.outfile_append), ("o.json", true));
    }

    #[test]
    fn appending_to_the_clipboard_is_refused_when_the_line_is_read() {
        for line in ["GET /a >> clipboard", "PUT /a {\"x\":1} >> CLIPBOARD", "GET /a && GET /b >> clipboard"] {
            let err = split_bulk_requests(line, None).unwrap_err();
            assert_eq!(err, "cannot append to clipboard — use > clipboard", "{line}");
        }
        for line in ["GET /a > clipboard", "GET /a >> clipboard.json", r#"PUT /a {"x":" >> clipboard"}"#] {
            assert!(split_bulk_requests(line, None).is_ok(), "{line}");
        }
        // An assert may not write anywhere, and says that first.
        assert!(split_bulk_requests(r#"assert PUT /x {"a":"b > c"}"#, None).is_ok());
        assert!(split_bulk_requests("assert GET /x > o.json", None).unwrap_err().contains("can't write to a file"));
    }

    #[test]
    fn a_base_url_gets_its_scheme_and_loses_the_api_prefix() {
        // (typed, base URL, whether a path was cut)
        let cases = [
            ("http://localhost:5000", "http://localhost:5000", false),
            ("https://cos.example.com", "https://cos.example.com", false),
            // The scheme in any case, kept in lower case.
            ("HTTP://host", "http://host", false),
            ("Https://Host.Example.com", "https://Host.Example.com", false),
            // No scheme: http for localhost, an IP, or an explicit port.
            ("localhost", "http://localhost", false),
            ("LOCALHOST:5000", "http://LOCALHOST:5000", false),
            ("127.0.0.1", "http://127.0.0.1", false),
            ("10.0.0.5", "http://10.0.0.5", false),
            ("[::1]:5000", "http://[::1]:5000", false),
            ("example.com:8080", "http://example.com:8080", false),
            ("cos.example.com", "https://cos.example.com", false),
            ("localhost.example.com", "https://localhost.example.com", false),
            // The API prefix and what follows it are not part of the base.
            ("host/api/v1", "https://host", true),
            ("http://host:5000/api/v1/people", "http://host:5000", true),
            ("https://host/api", "https://host", true),
            ("https://host/", "https://host", true),
            ("https://host/tenant/api/v1", "https://host/tenant", true),
            ("https://host/tenant", "https://host/tenant", false),
            // Only a path component: the host's own `api` stays.
            ("api.example.com", "https://api.example.com", false),
            ("https://api.example.com/api/v1", "https://api.example.com", true),
            ("https://host/apiary", "https://host/apiary", false),
            ("https://host/apiary/api/v1", "https://host/apiary", true),
        ];
        for (typed, base, trimmed) in cases {
            assert_eq!(base_url_of(typed), (base.to_string(), trimmed), "{typed}");
            assert_eq!(normalize_base_uri(typed), base, "{typed}");
            // What it gives is a base URL already.
            assert_eq!(base_url_of(base), (base.to_string(), false), "{base}");
        }
    }

    #[test]
    fn command_line_flags_win_over_a_saved_connection() {
        let saved = |auth_type: &str, client_id: &str| SavedConnection {
            name: "local".to_string(),
            url: "http://localhost:5000".to_string(),
            auth_type: auth_type.to_string(),
            credential: "STORED".to_string(),
            client_id: client_id.to_string(),
        };
        let shape = |env: SavedConnection| (env.url, env.auth_type, env.credential, env.client_id);
        let s = |v: &str| v.to_string();
        let stored = (s("http://localhost:5000"), s("key"), s("STORED"), s(""));
        assert_eq!(shape(override_connection(&saved("key", ""), None, None, None)), stored);
        assert_eq!(
            shape(override_connection(&saved("key", ""), None, Some("CLI"), None)),
            (s("http://localhost:5000"), s("key"), s("CLI"), s(""))
        );
        assert_eq!(
            shape(override_connection(&saved("key", ""), None, None, Some("T"))),
            (s("http://localhost:5000"), s("token"), s("T"), s(""))
        );
        // A key over an OAuth2 connection: no client credentials are left
        // to exchange, so the key is what is sent.
        assert_eq!(
            shape(override_connection(&saved("oauth2", "id"), None, Some("CLI"), None)),
            (s("http://localhost:5000"), s("key"), s("CLI"), s(""))
        );
        // Another host with the stored credential, whatever its kind.
        assert_eq!(
            shape(override_connection(&saved("oauth2", "id"), Some("http://other"), None, None)),
            (s("http://other"), s("oauth2"), s("STORED"), s("id"))
        );
        // Applied, a key connection leaves no token and no client credentials.
        let mut config = Config { token: "old".to_string(), oauth2_client_id: "x".to_string(), ..Config::default() };
        apply_connection_to_config(&mut config, &override_connection(&saved("oauth2", "id"), None, Some("CLI"), None)).unwrap();
        assert_eq!((config.api_key.as_str(), config.token.as_str(), config.oauth2_client_id.as_str()), ("CLI", "", ""));
        assert_eq!(auth_header(&config), Some(format!("Basic {}", BASE64.encode(":CLI"))));
    }

    #[test]
    fn switching_connection_keeps_the_sessions_flags() {
        let mut config = Config {
            include_nulls: true,
            fail_fast: true,
            timeout_secs: 7,
            export_id: Some("com.heads.seedID".to_string()),
            api_key: "old".to_string(),
            ..Config::default()
        };
        let picked = Config { base_uri: "http://other".to_string(), token: "tok".to_string(), ..Config::default() };
        adopt_connection(&mut config, &picked);
        assert_eq!((config.base_uri.as_str(), config.token.as_str(), config.api_key.as_str()), ("http://other", "tok", ""));
        assert!(config.include_nulls && config.fail_fast);
        assert_eq!((config.timeout_secs, config.export_id.as_deref()), (7, Some("com.heads.seedID")));
    }

    #[test]
    fn a_store_that_cannot_be_read_is_not_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");

        // Not there yet: empty, and fine to write.
        assert!(read_store_file(&path).unwrap().connections.is_empty());
        // Created but never written to: the same.
        fs::write(&path, " \n").unwrap();
        assert!(read_store_file(&path).unwrap().connections.is_empty());

        // `client_id` and `default` may be left out.
        fs::write(&path, r#"{"connections":[{"name":"a","url":"http://x","auth_type":"key","credential":"k"}]}"#).unwrap();
        let data = read_store_file(&path).unwrap();
        assert_eq!((data.connections.len(), data.connections[0].client_id.as_str(), data.default.as_str()), (1, "", ""));

        // One trailing comma: an error that names the file, not an empty store.
        let broken = r#"{"connections":[{"name":"keep","url":"http://x","auth_type":"key","credential":"SECRET","client_id":""},],"default":"keep"}"#;
        fs::write(&path, broken).unwrap();
        let err = read_store_file(&path).unwrap_err();
        assert!(err.starts_with(&format!("could not read {}: ", path.display())), "{err}");
        // A directory where the file should be: an error too.
        assert!(read_store_file(dir.path()).is_err());
    }

    #[test]
    fn the_store_is_written_whole_and_keeps_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let connection = |name: &str| SavedConnection {
            name: name.to_string(),
            url: "http://x".to_string(),
            auth_type: "key".to_string(),
            credential: "k".to_string(),
            client_id: String::new(),
        };
        let mut data = KeychainData::default();
        put_connection(&mut data, &connection("a"), None);
        write_store_file(&path, &data).unwrap();
        assert_eq!(read_store_file(&path).unwrap().connections.len(), 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            put_connection(&mut data, &connection("b"), None);
            write_store_file(&path, &data).unwrap();
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Nothing is left beside it.
        let names: Vec<String> =
            fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
        assert_eq!(names, ["credentials.json"]);
    }

    #[test]
    fn saving_under_a_new_name_renames_and_keeps_the_default() {
        let connection = |name: &str, credential: &str| SavedConnection {
            name: name.to_string(),
            url: "http://x".to_string(),
            auth_type: "key".to_string(),
            credential: credential.to_string(),
            client_id: String::new(),
        };
        let names = |data: &KeychainData| data.connections.iter().map(|e| e.name.clone()).collect::<Vec<_>>();
        let mut data = KeychainData::default();
        put_connection(&mut data, &connection("a", "1"), None);
        put_connection(&mut data, &connection("b", "1"), None);
        data.default = "a".to_string();

        // The same name: replaced in place.
        put_connection(&mut data, &connection("a", "2"), Some("a"));
        assert_eq!((names(&data), data.connections[0].credential.as_str(), data.default.as_str()), (vec!["a".to_string(), "b".to_string()], "2", "a"));

        // A new name: the old entry goes and the default follows.
        put_connection(&mut data, &connection("c", "3"), Some("a"));
        assert_eq!((names(&data), data.default.as_str()), (vec!["b".to_string(), "c".to_string()], "c"));

        // Renaming one that was not the default leaves the default alone.
        put_connection(&mut data, &connection("d", "4"), Some("b"));
        assert_eq!((names(&data), data.default.as_str()), (vec!["c".to_string(), "d".to_string()], "c"));

        // Onto a name that exists: that entry is replaced, not doubled.
        put_connection(&mut data, &connection("c", "5"), Some("d"));
        assert_eq!((names(&data), data.connections[0].credential.as_str()), (vec!["c".to_string()], "5"));
    }

    #[test]
    fn history_keeps_an_entry_of_several_lines_as_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".api_history");
        assert!(load_history_from(&path).is_empty());

        let body = "PUT /x {\n  \"a\": \"C:\\\\dir\\n\",\n  \"b\": 1\n}";
        append_history_to(&path, "GET /a");
        append_history_to(&path, body);
        append_history_to(&path, "GET /b");
        // One line per entry in the file…
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 3);
        // …and the entries come back as they were typed, backslashes and all.
        assert_eq!(load_history_from(&path), ["GET /a", body, "GET /b"]);

        // A file from before: every line is an entry, read as it is.
        let old = "GET /a\nPUT /x {\"s\":\"a\\nb \\\\ c\"}\n\nGET /c\n";
        fs::write(&path, old).unwrap();
        assert_eq!(load_history_from(&path), ["GET /a", "PUT /x {\"s\":\"a\\nb \\\\ c\"}", "GET /c"]);
    }

    #[test]
    fn history_is_capped_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".api_history");
        let lines: String = (0..HISTORY_LIMIT + 250).map(|i| format!("GET /{i}\n")).collect();
        fs::write(&path, lines).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }

        // Loading keeps the last 1000 and rewrites the file to match.
        let loaded = load_history_from(&path);
        assert_eq!(loaded.len(), HISTORY_LIMIT);
        assert_eq!((loaded[0].as_str(), loaded.last().unwrap().as_str()), ("GET /250", "GET /1249"));
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), HISTORY_LIMIT);
        // A file within the limit is left as it is.
        let before = fs::read_to_string(&path).unwrap();
        load_history_from(&path);
        assert_eq!(fs::read_to_string(&path).unwrap(), before);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600, "an existing file is made private");
            let fresh = dir.path().join("fresh");
            append_history_to(&fresh, "GET /a");
            assert_eq!(mode(&fresh), 0o600, "a new file is created private");
            // A world-readable file within the limit is made private too.
            fs::set_permissions(&fresh, fs::Permissions::from_mode(0o644)).unwrap();
            load_history_from(&fresh);
            assert_eq!(mode(&fresh), 0o600);
        }
        // Nothing is left beside it.
        assert!(fs::read_dir(dir.path()).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().contains(".tmp-")));
    }

    #[test]
    fn a_curl_command_quotes_every_value_for_the_shell() {
        assert_eq!(sh_quote("plain"), "'plain'");
        assert_eq!(sh_quote("O'Brien"), r#"'O'\''Brien'"#);
        assert_eq!(sh_quote("$HOME `id` \"x\""), "'$HOME `id` \"x\"'");

        let mut state = AppState::new(Config {
            base_uri: "http://localhost:5000".to_string(),
            api_key: "k".to_string(),
            ..Config::default()
        });
        assert_eq!(build_curl(&state), None, "nothing was sent yet");

        // A body with an apostrophe, a URI with `$` and a backtick.
        state.prev_method = "PUT".to_string();
        state.prev_uri = "/people~where(name=$USER`id`)".to_string();
        state.prev_body = r#"{"name":"O'Brien"}"#.to_string();
        assert_eq!(
            build_curl(&state).unwrap(),
            concat!(
                "curl -gfsSL -X PUT 'http://localhost:5000/api/v1/people~where(name=$USER`id`)'",
                " -H 'Authorization: Basic Oms='",
                " -H 'Accept: application/json'",
                " -H 'Content-Type: application/json'",
                r#" --data-binary '{"name":"O'\''Brien"}'"#,
            )
        );

        // A key shaped like a JWT went out as Bearer, and so does the command.
        let jwt = format!("ey{}", "a".repeat(200));
        state.config.api_key = jwt.clone();
        state.prev_method = "GET".to_string();
        state.prev_uri = "/people".to_string();
        state.prev_body.clear();
        assert_eq!(
            build_curl(&state).unwrap(),
            format!("curl -gfsSL -X GET 'http://localhost:5000/api/v1/people' -H 'Authorization: Bearer {jwt}' -H 'Accept: application/json'")
        );
        state.config.api_key.clear();
        state.config.token = "tok".to_string();
        assert!(build_curl(&state).unwrap().contains(" -H 'Authorization: Bearer tok' "));

        // Outfiles: `>` is -o, `>>` is the shell's, the clipboard is neither.
        let tail = |state: &AppState| build_curl(state).unwrap().split(" -H 'Accept: ").nth(1).unwrap().to_string();
        state.prev_outfile = "it's.CSV".to_string();
        state.prev_display_outfile = "it's.CSV".to_string();
        assert_eq!(tail(&state), r#"text/csv' -o 'it'\''s.CSV'"#);
        state.prev_outfile_append = true;
        assert_eq!(tail(&state), r#"text/csv' >> 'it'\''s.CSV'"#);
        state.prev_outfile = "clipboard".to_string();
        state.prev_display_outfile = "Clipboard".to_string();
        state.prev_outfile_append = false;
        assert_eq!(tail(&state), "application/json'");

        // A file body with `~map()`.
        state.prev_outfile.clear();
        state.prev_display_outfile.clear();
        state.prev_method = "PUT".to_string();
        state.prev_body = "@data's.csv~map(com.heads.t)".to_string();
        assert_eq!(
            tail(&state),
            r#"application/json' -H 'Content-Type: text/csv' -H 'X-Request-Map: com.heads.t' --data-binary '@data'\''s.csv'"#
        );
    }

    #[test]
    fn a_spec_that_leaves_things_out_is_still_a_spec() {
        // An operation without `responses`, a tag without a name, components
        // without schemas: none of them makes the spec unreadable.
        let spec: ApiSpec = serde_json::from_str(
            r#"{
                "paths": {
                    "/people": { "get": { "tags": ["people"] }, "put": { "responses": {} } },
                    "/things": {}
                },
                "components": {},
                "tags": [{ "x-type": "person" }, { "name": "people" }]
            }"#,
        )
        .unwrap();
        let mut paths: Vec<&String> = spec.paths.keys().collect();
        paths.sort();
        assert_eq!(paths, ["/people", "/things"]);
        assert!(spec.components.unwrap().schemas.is_empty());
        // No paths at all is an empty spec, not an error.
        assert!(serde_json::from_str::<ApiSpec>("{}").unwrap().paths.is_empty());
        // What is not a spec still is not one.
        assert!(serde_json::from_str::<ApiSpec>("[1]").is_err());
    }

    #[test]
    fn paths_are_read_with_either_separator_where_both_separate() {
        // `~/` everywhere; `~\` only where `\` is a separator.
        assert_eq!(home_relative("~/seeds/a.api", false), Some("seeds/a.api"));
        assert_eq!(home_relative("~/seeds/a.api", true), Some("seeds/a.api"));
        assert_eq!(home_relative(r"~\seeds\a.api", true), Some(r"seeds\a.api"));
        assert_eq!(home_relative(r"~\seeds\a.api", false), None);
        for other in ["seeds/a.api", "/tmp/~/a", "~user/a", "~"] {
            assert_eq!(home_relative(other, true), None, "{other}");
        }
        // On this platform `~/x` is in the home directory, and nothing else is.
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand_home("~/x.json"), home.join("x.json").to_string_lossy());
        assert_eq!(expand_home("x.json"), "x.json");
        assert_eq!(expand_home("/tmp/x.json"), "/tmp/x.json");

        // An alias include.
        assert_eq!(split_alias("cl/sv.api", false), Some(("cl", "sv.api")));
        assert_eq!(split_alias("cl/seeds/sv.api", true), Some(("cl", "seeds/sv.api")));
        assert_eq!(split_alias(r"cl\sv.api", true), Some(("cl", "sv.api")));
        assert_eq!(split_alias(r"cl\sv.api", false), None);
        assert_eq!(split_alias("sv.api", true), None);
    }

    #[test]
    fn a_command_that_is_not_installed_is_known_by_trying_it() {
        assert!(!command_exists("no-such-command-for-the-api-client-tests"));
        // The test runner itself is certainly there.
        assert!(command_exists("cargo"));
    }

    #[test]
    fn display_strings_are_cut_on_characters() {
        assert_eq!(head_chars("blåbär.example.com", 4), "blåb");
        assert_eq!(head_chars("abc", 10), "abc");
        assert_eq!(head_chars("åäö", 0), "");
        assert_eq!(tail_chars("https://blåbär.se", 6), "bär.se");
        assert_eq!(tail_chars("abc", 10), "abc");
        assert_eq!(tail_chars("åäö", 0), "");
        assert_eq!(tail_chars("åäö", 2), "äö");
    }

    #[test]
    fn evaluate_url_gate_or_allowlist() {
        let conds = vec![
            UrlCondition::Has("test.app.heads.com".to_string()),
            UrlCondition::Has("localhost:5000".to_string()),
        ];
        // Matches at least one → ok.
        assert!(evaluate_url_gate(&conds, "http://localhost:5000").is_ok());
        assert!(evaluate_url_gate(&conds, "https://test.app.heads.com").is_ok());
        // Matches none → blocked.
        assert!(evaluate_url_gate(&conds, "https://api.heads.com").is_err());
        // No conditions → always ok.
        assert!(evaluate_url_gate(&[], "https://api.heads.com").is_ok());
        // `is` is literal, not substring.
        let lit = vec![UrlCondition::Is("http://localhost:5000".to_string())];
        assert!(evaluate_url_gate(&lit, "http://localhost:5000").is_ok());
        assert!(evaluate_url_gate(&lit, "http://localhost:5000/api").is_err());
    }

    #[test]
    fn split_bulk_requests_collects_steps_and_conditions() {
        let src = "url has localhost:5000\nGET /a\nsleep 2\nPUT /b {\"x\":1}\n";
        let prog = split_bulk_requests(src, None).unwrap();
        assert_eq!(prog.url_conditions, vec![UrlCondition::Has("localhost:5000".to_string())]);
        assert_eq!(prog.steps.len(), 3);
        assert_eq!(prog.steps[1], BulkStep::Sleep(Duration::from_secs(2)));
        assert!(matches!(&prog.steps[0], BulkStep::Request(r) if r.starts_with("GET /a")));
        assert!(matches!(&prog.steps[2], BulkStep::Request(r) if r.starts_with("PUT /b")));
    }

    #[test]
    fn with_chain_segment_view_presents_one_segment_and_splices_back() {
        // Identity on an unchained line: the closure sees the input untouched.
        let mut state = test_state();
        state.input = "GET /people".to_string();
        state.cursor_pos = 5;
        with_chain_segment_view(&mut state, |s| {
            assert_eq!(s.input, "GET /people");
            assert_eq!(s.cursor_pos, 5);
        });
        assert_eq!(state.input, "GET /people");
        assert_eq!(state.cursor_pos, 5);

        // Cursor in the LAST segment: the view is that segment, cursor relative.
        let mut state = test_state();
        state.input = "GET /a && GET /pro".to_string();
        state.cursor_pos = char_len(&state.input);
        with_chain_segment_view(&mut state, |s| {
            assert_eq!(s.input, "GET /pro");
            assert_eq!(s.cursor_pos, char_len("GET /pro"));
            // Edit as a completion would: replace the URI.
            s.input = "GET /products".to_string();
            s.cursor_pos = char_len(&s.input);
        });
        assert_eq!(state.input, "GET /a && GET /products");
        assert_eq!(state.cursor_pos, char_len(&state.input));

        // Cursor in the FIRST segment: edits there leave the tail alone.
        let mut state = test_state();
        state.input = "GET /peo && GET /b".to_string();
        state.cursor_pos = char_len("GET /peo");
        with_chain_segment_view(&mut state, |s| {
            assert_eq!(s.input, "GET /peo");
            s.input = "GET /people".to_string();
            s.cursor_pos = char_len(&s.input);
        });
        assert_eq!(state.input, "GET /people && GET /b");
        assert_eq!(state.cursor_pos, char_len("GET /people"));

        // A `&&` inside a JSON string doesn't split the view.
        let mut state = test_state();
        state.input = r#"PUT /r {"e": "a && b"}"#.to_string();
        state.cursor_pos = char_len(&state.input);
        with_chain_segment_view(&mut state, |s| {
            assert_eq!(s.input, r#"PUT /r {"e": "a && b"}"#);
        });
    }

    #[test]
    fn uri_tab_completion_targets_the_cursor_segment() {
        // The reported bug: Tab in the LAST segment completed against segment 1's
        // URI. Through the view, handle_tab_completion sees only its segment.
        let mut state = test_state();
        state.config.complete = true;
        state.endpoints = vec!["/people".to_string(), "/products".to_string()];
        state.input = "GET /people~take(1) && GET /pro".to_string();
        state.cursor_pos = char_len(&state.input);
        with_chain_segment_view(&mut state, handle_tab_completion);
        assert_eq!(state.input, "GET /people~take(1) && GET /products");
        assert_eq!(state.cursor_pos, char_len(&state.input));

        // First segment: completing its URI must preserve the tail.
        let mut state = test_state();
        state.config.complete = true;
        state.endpoints = vec!["/people".to_string(), "/products".to_string()];
        state.input = "GET /peo && GET /b".to_string();
        state.cursor_pos = char_len("GET /peo");
        with_chain_segment_view(&mut state, handle_tab_completion);
        assert_eq!(state.input, "GET /people && GET /b");
        assert_eq!(state.cursor_pos, char_len("GET /people"));
    }

    #[test]
    fn ghost_text_is_computed_per_segment() {
        // URI ghost in the LAST segment (cursor at line end) — previously empty
        // because the ghost parsed segment 1's URI.
        let mut state = test_state();
        state.config.complete = true;
        state.endpoints = vec!["/people".to_string(), "/products".to_string()];
        state.input = "GET /people~take(1) && GET /pro".to_string();
        state.cursor_pos = char_len(&state.input);
        let ghost = with_chain_segment_view(&mut state, |s| get_completion_ghost(s));
        assert_eq!(ghost, "ducts");
        // The view must leave the line and cursor untouched.
        assert_eq!(state.input, "GET /people~take(1) && GET /pro");
        assert_eq!(state.cursor_pos, char_len(&state.input));

        // File ghost in the FIRST segment with the cursor at the segment's end
        // (mid-line absolutely) — previously the mid-line branch had no file
        // mode at all, so editing the first segment's outfile showed nothing.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("report.json"), "{}").unwrap();
        let base = dir.path().display().to_string();
        let mut state = test_state();
        state.input = format!("GET /a > {}/rep && GET /b > keep.json", base);
        state.cursor_pos = char_len(&format!("GET /a > {}/rep", base));
        let ghost = with_chain_segment_view(&mut state, |s| {
            let in_file_mode = extract_file_path_context(&s.input, s.cursor_pos).is_some();
            assert!(in_file_mode, "view must expose the first segment's outfile");
            assert_eq!(s.cursor_pos, char_len(&s.input), "cursor is at the SEGMENT's end");
            get_completion_ghost(s)
        });
        assert_eq!(ghost, "ort.json");
    }

    #[test]
    fn append_to_outfile_merges_json_arrays() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        let p = path.to_str().unwrap();

        // Missing target → identical to `>`.
        append_to_outfile(p, r#"[{"id":1}]"#).unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), r#"[{"id":1}]"#);

        // Array + array → one concatenated array, pretty-printed.
        append_to_outfile(p, r#"[{"id":2}]"#).unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap();
        assert_eq!(v, serde_json::json!([{"id":1},{"id":2}]));

        // Array + single value → pushed.
        append_to_outfile(p, r#"{"id":3}"#).unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap();
        assert_eq!(v, serde_json::json!([{"id":1},{"id":2},{"id":3}]));

        // Empty (whitespace-only) target → plain write.
        let path2 = dir.path().join("empty.json");
        fs::write(&path2, "  \n").unwrap();
        append_to_outfile(path2.to_str().unwrap(), "[1]").unwrap();
        assert_eq!(fs::read_to_string(&path2).unwrap(), "[1]");
    }

    #[test]
    fn append_to_outfile_text_appends_without_touching_existing_bytes() {
        // Text append applies only when at least one side is NOT JSON — two JSON
        // values merge into an array instead (see the wrap test below).
        let dir = tempfile::tempdir().unwrap();

        // Unparseable existing + JSON payload → text append, never an error.
        let path = dir.path().join("notjson.txt");
        let p = path.to_str().unwrap();
        fs::write(p, "hello\n").unwrap();
        append_to_outfile(p, r#"[1,2]"#).unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), "hello\n[1,2]");

        // JSON existing + non-JSON payload → text append, existing bytes untouched.
        let path = dir.path().join("obj.json");
        let p = path.to_str().unwrap();
        fs::write(p, r#"{"a":1}"#).unwrap();
        append_to_outfile(p, "not json at all").unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), "{\"a\":1}\nnot json at all");
    }

    #[test]
    fn append_to_outfile_wraps_two_json_values_into_an_array() {
        // The reported bug: GET /about >> f twice left two newline-separated
        // objects — an invalid JSON file. The second append must produce an array.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.json");
        let p = path.to_str().unwrap();

        let about = r#"{"@type":"api version info","schema-version":"1.1"}"#;
        append_to_outfile(p, about).unwrap();
        // First write: bare object, verbatim.
        assert_eq!(fs::read_to_string(p).unwrap(), about);

        append_to_outfile(p, about).unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(p).unwrap())
            .expect("file must be valid JSON after the second append");
        assert_eq!(
            v,
            serde_json::json!([
                {"@type":"api version info","schema-version":"1.1"},
                {"@type":"api version info","schema-version":"1.1"},
            ]),
        );

        // Third append flows through the array+push path: one three-element array.
        append_to_outfile(p, r#"{"id":3}"#).unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap();
        assert_eq!(v.as_array().map(|a| a.len()), Some(3), "got: {v}");

        // value + array → the existing value is wrapped, then the rest appended.
        let path = dir.path().join("scalar.json");
        let p = path.to_str().unwrap();
        append_to_outfile(p, "5").unwrap();
        append_to_outfile(p, "[6, 7]").unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap();
        assert_eq!(v, serde_json::json!([5, 6, 7]));
    }

    #[test]
    fn append_to_outfile_splices_without_reserializing() {
        let dir = tempfile::tempdir().unwrap();

        // The user's example, byte-for-byte: no pretty-printing, no reflow.
        let path = dir.path().join("ex.json");
        let p = path.to_str().unwrap();
        append_to_outfile(p, "\"example1\"").unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), "\"example1\"");
        append_to_outfile(p, "\"example2\"").unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), "[\"example1\",\"example2\"]");
        append_to_outfile(p, "\"example3\"").unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), "[\"example1\",\"example2\",\"example3\"]");

        // The property that distinguishes a splice from compact re-serialization:
        // existing bytes are NEVER normalized. Serde would turn `1e2` into `100.0`.
        let path = dir.path().join("sci.json");
        let p = path.to_str().unwrap();
        fs::write(p, "[1e2]").unwrap();
        append_to_outfile(p, "3").unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), "[1e2,3]");

        // Array + array splices interiors.
        let path = dir.path().join("arr.json");
        let p = path.to_str().unwrap();
        fs::write(p, r#"[{"id":1}]"#).unwrap();
        append_to_outfile(p, r#"[{"id":2},{"id":3}]"#).unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), r#"[{"id":1},{"id":2},{"id":3}]"#);

        // Appending an empty array is a no-op — the file is left byte-identical.
        append_to_outfile(p, "[]").unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), r#"[{"id":1},{"id":2},{"id":3}]"#);

        // Appending ONTO an empty array wraps just the payload.
        let path = dir.path().join("onto-empty.json");
        let p = path.to_str().unwrap();
        fs::write(p, "[]").unwrap();
        append_to_outfile(p, r#"{"id":9}"#).unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), r#"[{"id":9}]"#);

        // A legacy pretty-printed file (from the previous merge style) splices
        // into a still-valid array, existing formatting preserved inside.
        let path = dir.path().join("legacy.json");
        let p = path.to_str().unwrap();
        fs::write(p, "[\n  {\n    \"id\": 1\n  }\n]").unwrap();
        append_to_outfile(p, r#"{"id":2}"#).unwrap();
        let merged = fs::read_to_string(p).unwrap();
        assert_eq!(merged, "[{\n    \"id\": 1\n  },{\"id\":2}]");
        let v: Value = serde_json::from_str(&merged).expect("mixed-format file stays valid JSON");
        assert_eq!(v.as_array().map(|a| a.len()), Some(2));
    }

    #[test]
    fn append_to_outfile_is_format_aware_for_ndjson_and_csv() {
        let dir = tempfile::tempdir().unwrap();

        // NDJSON: a JSON-array payload explodes to one compact object per line.
        let path = dir.path().join("out.ndjson");
        let p = path.to_str().unwrap();
        fs::write(p, "{\"id\":1}\n").unwrap();
        append_to_outfile(p, r#"[{"id":2}, {"id":3}]"#).unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), "{\"id\":1}\n{\"id\":2}\n{\"id\":3}\n");

        // A single (even pretty-printed) JSON value becomes one compact line.
        append_to_outfile(p, "{\n  \"id\": 4\n}").unwrap();
        assert_eq!(
            fs::read_to_string(p).unwrap(),
            "{\"id\":1}\n{\"id\":2}\n{\"id\":3}\n{\"id\":4}\n",
        );

        // Already-NDJSON payload → plain text append.
        append_to_outfile(p, "{\"id\":5}\n{\"id\":6}\n").unwrap();
        assert!(fs::read_to_string(p).unwrap().ends_with("{\"id\":5}\n{\"id\":6}\n"));

        // CSV: the payload's header row is dropped when the target has content.
        let path = dir.path().join("out.csv");
        let p = path.to_str().unwrap();
        fs::write(p, "id,name\n1,Alice\n").unwrap();
        append_to_outfile(p, "id,name\n2,Bob\n").unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), "id,name\n1,Alice\n2,Bob\n");

        // Header-only payload (empty result set) → nothing added.
        append_to_outfile(p, "id,name\n").unwrap();
        assert_eq!(fs::read_to_string(p).unwrap(), "id,name\n1,Alice\n2,Bob\n");

        // First write to a missing CSV keeps its header.
        let fresh = dir.path().join("fresh.csv");
        append_to_outfile(fresh.to_str().unwrap(), "id,name\n9,Zoe\n").unwrap();
        assert_eq!(fs::read_to_string(&fresh).unwrap(), "id,name\n9,Zoe\n");
    }

    #[test]
    fn an_ndjson_outfile_is_ndjson_from_the_first_write() {
        let dir = tempfile::tempdir().unwrap();
        let read = |p: &std::path::Path| fs::read_to_string(p).unwrap();
        let about_pretty = "{\n  \"@type\": \"api version info\",\n  \"schema-version\": \"1.1\"\n}";
        let about_line = "{\"@type\":\"api version info\",\"schema-version\":\"1.1\"}\n";

        // The reported bug: one record, indented on its way to the file. `>`
        // wrote it indented, and so did the first `>>`, ahead of a compact line.
        for name in ["about.ndjson", "about.njson", "ABOUT.NDJSON"] {
            let path = dir.path().join(name);
            let p = path.to_str().unwrap();
            assert_eq!(write_outfile(p, about_pretty).unwrap(), about_line.len() as u64, "{name}");
            assert_eq!(read(&path), about_line, "{name}");
            fs::remove_file(&path).unwrap();
            append_to_outfile(p, about_pretty).unwrap();
            append_to_outfile(p, about_pretty).unwrap();
            assert_eq!(read(&path), about_line.repeat(2), "{name}");
        }

        // A list is its elements, a scalar is a line, an empty list is nothing.
        let path = dir.path().join("list.ndjson");
        let p = path.to_str().unwrap();
        write_outfile(p, "[\n  {\"id\": 1},\n  {\"id\": 2}\n]").unwrap();
        assert_eq!(read(&path), "{\"id\":1}\n{\"id\":2}\n");
        append_to_outfile(p, "[]").unwrap();
        append_to_outfile(p, "3").unwrap();
        assert_eq!(read(&path), "{\"id\":1}\n{\"id\":2}\n3\n");
        write_outfile(p, "[]").unwrap();
        assert_eq!(read(&path), "");

        // NDJSON of several lines, and what is not JSON, is written as it came.
        let lines = "{\"id\":1}\n{\"id\":2}\n";
        assert_eq!(write_outfile(p, lines).unwrap(), lines.len() as u64);
        assert_eq!(read(&path), lines);
        write_outfile(p, "not json").unwrap();
        assert_eq!(read(&path), "not json");

        // Any other target is written as it is given.
        let json = dir.path().join("about.json");
        write_outfile(json.to_str().unwrap(), about_pretty).unwrap();
        assert_eq!(read(&json), about_pretty);

        assert_eq!(ndjson_lines("{\"a\": 1}").as_deref(), Some("{\"a\":1}\n"));
        assert_eq!(ndjson_lines("[]").as_deref(), Some(""));
        assert_eq!(ndjson_lines(lines), None);
        assert!(is_ndjson_path("a/b.NJSON") && !is_ndjson_path("b.json") && !is_ndjson_path("ndjson"));
    }

    #[test]
    fn parse_input_detects_append_redirect() {
        // `>>` sets the append flag; the path parses identically to `>`.
        let mut state = test_state();
        parse_input(&mut state, "GET /people >> out.json");
        assert_eq!(state.config.outfile, "out.json");
        assert_eq!(state.display_outfile, "out.json");
        assert!(state.config.outfile_append);
        assert_eq!(state.method, "GET");
        assert_eq!(state.uri, "/people");

        // Plain `>` leaves it unset.
        let mut state = test_state();
        parse_input(&mut state, "GET /people > out.json");
        assert_eq!(state.config.outfile, "out.json");
        assert!(!state.config.outfile_append);

        // The flag resets between parses — a previous `>>` must not leak into
        // a later request without one (chains re-parse per segment).
        parse_input(&mut state, "GET /people >> a.json");
        assert!(state.config.outfile_append);
        parse_input(&mut state, "GET /people > b.json");
        assert!(!state.config.outfile_append);
        parse_input(&mut state, "GET /people");
        assert!(!state.config.outfile_append);

        // No space after `>>` works, matching `>`.
        let mut state = test_state();
        parse_input(&mut state, "GET /people >>out.json");
        assert_eq!(state.config.outfile, "out.json");
        assert!(state.config.outfile_append);
    }

    #[test]
    fn parse_request_line_preserves_the_append_marker() {
        // Bulk lines carry the outfile in the URI suffix; `>>` must survive the
        // round-trip so run_non_interactive sees it.
        let (method, uri, body) = parse_request_line("GET /people >> out.json").unwrap();
        assert_eq!(method, "GET");
        assert_eq!(uri, "/people >> out.json");
        assert_eq!(body, "");

        let (_, uri, _) = parse_request_line("GET /people > out.json").unwrap();
        assert_eq!(uri, "/people > out.json");
    }

    #[test]
    fn file_context_and_log_line_understand_append() {
        // Completion context: the second `>` is part of the marker, not the path.
        let input = "GET /people >> ou";
        let ctx = extract_file_path_context(input, char_len(input)).expect("context");
        assert_eq!(ctx.partial, "ou");
        assert!(ctx.is_outfile);
        assert!(ctx.is_append);

        // `>` alone is not append.
        let input = "GET /people > ou";
        let ctx = extract_file_path_context(input, char_len(input)).expect("context");
        assert!(!ctx.is_append);

        // The request log line shows the marker the user typed.
        assert_eq!(
            format_request_log_line("GET", "/people", "", "out.json", true, 80),
            "GET /people >> out.json",
        );
    }

    #[test]
    fn restore_input_after_send_is_chain_aware() {
        // Single request: rebuilt from method/URI/body plus the outfile marker
        // as typed — `>>` must survive (restoring it as `>` would turn an
        // append into an overwrite on re-send). This also covers the @file-error
        // path, which used to drop the outfile entirely.
        let mut state = test_state();
        state.method = "PUT".to_string();
        state.uri = "/people".to_string();
        state.body = "@missing.json".to_string();
        state.display_outfile = "out.json".to_string();
        state.config.outfile_append = true;
        restore_input_after_send(&mut state);
        assert_eq!(state.input, "PUT /people @missing.json >> out.json");
        assert_eq!(state.cursor_pos, char_len(&state.input));

        // Plain `>` restores as `>`.
        state.config.outfile_append = false;
        restore_input_after_send(&mut state);
        assert_eq!(state.input, "PUT /people @missing.json > out.json");

        // Mid-chain: the full chain wins over the just-sent segment, and stale
        // completion state is cleared.
        let mut state = test_state();
        state.method = "GET".to_string();
        state.uri = "/about".to_string();
        state.chain_input = Some("GET /about && GET /about/api-versions".to_string());
        state.completions = vec!["stale".to_string()];
        state.last_tab_input = "stale".to_string();
        restore_input_after_send(&mut state);
        assert_eq!(state.input, "GET /about && GET /about/api-versions");
        assert_eq!(state.cursor_pos, char_len(&state.input));
        assert!(state.completions.is_empty());
        assert!(state.last_tab_input.is_empty());
    }

    #[test]
    fn file_path_context_is_scoped_to_the_cursor_segment() {
        // Cursor in the FIRST segment's outfile: the context is that segment's,
        // not the rightmost `>` on the line — the reported bug.
        let input = "GET /people~take(1) > ~/Do && GET /products~take(1) > ~/Downloads/1.json";
        let cursor = char_len("GET /people~take(1) > ~/Do"); // right after "Do"
        let ctx = extract_file_path_context(input, cursor).expect("context in segment 1");
        assert_eq!(ctx.partial, "~/Do");
        assert!(ctx.is_outfile);
        assert_eq!(&input[ctx.path_start..ctx.path_end], "~/Do");
        // The partial must never run past the segment into the chain tail.
        assert!(!ctx.partial.contains("&&"));

        // Cursor at end of line: the LAST segment's outfile, as before.
        let ctx = extract_file_path_context(input, char_len(input)).expect("context in segment 2");
        assert_eq!(ctx.partial, "~/Downloads/1.json");

        // Cursor in a segment with no `>`/`@` of its own: no file context, even
        // though other segments have one — URI completion applies there instead.
        let input = "GET /people && GET /products > out.json";
        let cursor = char_len("GET /peop");
        assert!(extract_file_path_context(input, cursor).is_none());

        // `@` body in the first segment, cursor inside it.
        let input = "PUT /people @da && GET /check > out.json";
        let cursor = char_len("PUT /people @da");
        let ctx = extract_file_path_context(input, cursor).expect("body-file context");
        assert_eq!(ctx.partial, "da");
        assert!(!ctx.is_outfile);

        // A `&&` inside a JSON string doesn't split the segment.
        let input = r#"PUT /r {"e": "a && b"} > out"#;
        let ctx = extract_file_path_context(input, char_len(input)).expect("single segment");
        assert_eq!(ctx.partial, "out");

        // Single request behaves exactly as before, wherever the cursor is.
        let input = "GET /people > ~/Do";
        for cursor in [0, 4, char_len(input)] {
            let ctx = extract_file_path_context(input, cursor).expect("context");
            assert_eq!(ctx.partial, "~/Do");
        }
    }

    #[test]
    fn file_completion_in_first_segment_preserves_the_chain_tail() {
        // End-to-end against a real directory: completing the FIRST segment's
        // outfile must replace only that path — wiping the ` && …` tail was the
        // second half of the reported bug.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("report.json"), "{}").unwrap();
        let base = dir.path().display().to_string();

        let mut state = test_state();
        state.input = format!("GET /a~take(1) > {}/rep && GET /b > keep.json", base);
        state.cursor_pos = char_len(&format!("GET /a~take(1) > {}/rep", base));
        handle_file_tab_completion(&mut state);

        assert_eq!(
            state.input,
            format!("GET /a~take(1) > {}/report.json && GET /b > keep.json", base),
            "tail must survive completion",
        );
        // Cursor sits at the end of the completed path, mid-line.
        assert_eq!(state.cursor_pos, char_len(&format!("GET /a~take(1) > {}/report.json", base)));

        // A second Tab cycles (single match → same value), still preserving the tail.
        handle_file_tab_completion(&mut state);
        assert!(state.input.ends_with(" && GET /b > keep.json"), "got: {}", state.input);

        // Reverse cycling preserves the tail too.
        handle_file_tab_completion_reverse(&mut state);
        assert!(state.input.ends_with(" && GET /b > keep.json"), "got: {}", state.input);
    }

    #[test]
    fn is_outfile_context_distinguishes_redirect_from_body() {
        let is_outfile = |s: &str| {
            extract_file_path_context(s, char_len(s)).map(|c| c.is_outfile)
        };
        assert_eq!(is_outfile("GET /foo > cl"), Some(true));
        assert_eq!(is_outfile("GET /foo >"), Some(true));
        assert_eq!(is_outfile("PUT /foo @cl"), Some(false));
        assert_eq!(is_outfile("GET /foo"), None);
    }

    #[test]
    fn include_context_is_a_line_that_can_only_be_a_path() {
        let include = |s: &str| {
            extract_file_path_context(s, char_len(s)).filter(|c| c.is_include).map(|c| c.partial)
        };
        assert_eq!(include("se"), Some("se".to_string()));
        assert_eq!(include("shared/se"), Some("shared/se".to_string()));
        assert_eq!(include("~/seeds/"), Some("~/seeds/".to_string()));
        assert_eq!(include("../se"), Some("../se".to_string()));
        // The whole line is the path, as the bulk parser reads it.
        assert_eq!(include("my seeds/se"), Some("my seeds/se".to_string()));
        // A file named after a keyword is still a file.
        assert_eq!(include("sleep.api"), Some("sleep.api".to_string()));
        assert_eq!(include("get.api"), Some("get.api".to_string()));

        // Leading whitespace is not part of the path.
        let ctx = extract_file_path_context("  se ", 4).unwrap();
        assert_eq!((ctx.path_start, ctx.path_end), (2, 4));

        for line in [
            "", "   ", "GET", "get /x", "PUT /x {}", "/people", "/tmp/seed.api",
            "sleep 2", "assert /x", "confirm", "URL has localhost",
            "shared/*.api", "se?d.api", "se && GET /x", "GET /x || se", "se\nGET /x",
        ] {
            assert_eq!(include(line), None, "{:?}", line);
        }

        // A request's own file regions are untouched.
        let ctx = extract_file_path_context("PUT /x @da", 10).unwrap();
        assert!(!ctx.is_include && !ctx.is_outfile);
    }

    #[test]
    fn no_include_is_suggested_while_a_keyword_is_still_possible() {
        for typed in ["g", "PU", "pat", "sl", "asser", "u", "options"] {
            assert!(could_become_a_keyword(typed), "{}", typed);
        }
        for typed in ["pub", "se", "shared/", "get.api", "~/"] {
            assert!(!could_become_a_keyword(typed), "{}", typed);
        }
    }

    /// `dir` as the path from the working directory, since an include is not
    /// completed from an absolute path.
    #[cfg(unix)]
    fn relative_to_cwd(dir: &std::path::Path) -> String {
        let cwd = std::env::current_dir().unwrap();
        let ups = "../".repeat(cwd.components().count() - 1);
        format!("{}{}", ups, dir.display().to_string().trim_start_matches('/'))
    }

    #[test]
    fn include_completions_are_directories_and_api_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("seed.api"), "GET /about").unwrap();
        fs::write(dir.path().join("SEED2.API"), "GET /about").unwrap();
        fs::write(dir.path().join("seed.json"), "{}").unwrap();
        fs::write(dir.path().join(".hidden.api"), "GET /about").unwrap();
        fs::create_dir(dir.path().join("seeds")).unwrap();
        let base = dir.path().display().to_string();

        assert_eq!(
            get_include_completions(&format!("{}/", base)),
            vec![format!("{}/seeds/", base), format!("{}/SEED2.API", base), format!("{}/seed.api", base)],
        );
        assert_eq!(get_include_completions(&format!("{}/seed.", base)), vec![format!("{}/seed.api", base)]);
        assert_eq!(get_include_completions(&format!("{}/.h", base)), vec![format!("{}/.hidden.api", base)]);
        assert!(get_include_completions(&format!("{}/nothing", base)).is_empty());
        assert_eq!(get_include_completions("~"), vec!["~/".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn tab_completes_and_cycles_an_include() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("seed.api"), "GET /about").unwrap();
        fs::write(dir.path().join("seed.json"), "{}").unwrap();
        fs::create_dir(dir.path().join("seeds")).unwrap();
        let base = relative_to_cwd(dir.path());

        let mut state = test_state();
        state.input = format!("{}/se", base);
        state.cursor_pos = char_len(&state.input);
        assert_eq!(get_completion_ghost(&state), "eds/");
        assert!(render_input_content(&mut state, 200).0.contains("ds/"));

        // A chain can't hold an include, so its first word gets no suggestion.
        let mut chained = test_state();
        chained.input = format!("{}/se && GET /x", base);
        chained.cursor_pos = char_len(&state.input);
        assert!(!render_input_content(&mut chained, 200).0.contains("ds/"));
        handle_file_tab_completion(&mut chained);
        assert_eq!(chained.input, format!("{}/se && GET /x", base));

        handle_file_tab_completion(&mut state);
        assert_eq!(state.input, format!("{}/seeds/", base));
        assert_eq!(state.cursor_pos, char_len(&state.input));
        handle_file_tab_completion(&mut state);
        assert_eq!(state.input, format!("{}/seed.api", base));
        handle_file_tab_completion(&mut state);
        assert_eq!(state.input, format!("{}/seeds/", base));
        handle_file_tab_completion_reverse(&mut state);
        assert_eq!(state.input, format!("{}/seed.api", base));

        // The completed line is one the parser reads as that file.
        assert_eq!(split_bulk_requests(&state.input, None).unwrap().steps.len(), 1);
    }

    #[test]
    fn a_tilde_in_an_include_is_the_home_directory_not_a_map_operator() {
        let mut state = test_state();
        state.input = "~".to_string();
        state.cursor_pos = 1;
        assert_eq!(get_completion_ghost(&state), "/");
        handle_file_tab_completion(&mut state);
        assert_eq!(state.input, "~/");
    }

    #[test]
    fn get_outfile_completions_adds_virtual_clipboard() {
        // Prefix of "clipboard" → virtual entry present and first.
        let r = get_outfile_completions("cl");
        assert!(r.first().map(|s| s == "clipboard").unwrap_or(false), "got {:?}", r);
        let r2 = get_outfile_completions("clip");
        assert!(r2.contains(&"clipboard".to_string()));
        // Non-prefix → no virtual entry.
        assert!(!get_outfile_completions("xyz").contains(&"clipboard".to_string()));
        // Full word already typed → no duplicate virtual entry.
        assert!(!get_outfile_completions("clipboard").contains(&"clipboard".to_string()));
        // Empty partial → no virtual entry (don't mask local files at the bare `>`).
        assert!(!get_outfile_completions("").contains(&"clipboard".to_string()));
    }

    #[test]
    fn get_outfile_completions_keeps_real_files_named_clip() {
        // Real files/folders beginning with "clip" must survive unchanged. With a
        // directory-qualified partial, the bare "clipboard" sentinel never applies
        // (it's a bare token, not a path), so only real entries are returned.
        let dir = std::env::temp_dir().join(format!("api_clip_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("clipboard-backup.json"), b"{}").unwrap();
        std::fs::create_dir(dir.join("clipboard")).unwrap();
        let partial = format!("{}/clip", dir.display());
        let r = get_outfile_completions(&partial);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(r.iter().any(|c| c.ends_with("clipboard-backup.json")), "missing real file: {:?}", r);
        assert!(r.iter().any(|c| c.ends_with("clipboard/")), "missing real dir: {:?}", r);
        // No bare virtual entry injected mid-path.
        assert!(!r.iter().any(|c| c == "clipboard"), "virtual clipboard wrongly added mid-path: {:?}", r);
    }

    #[test]
    fn apply_identifier_index_replace_or_append() {
        // Collection segment → append a new index slot.
        assert_eq!(apply_identifier_index("GET /people", "com.foo=1"), "GET /people/com.foo=1");
        // Trailing slash → append, no double slash.
        assert_eq!(apply_identifier_index("GET /people/", "com.foo=1"), "GET /people/com.foo=1");
        assert_eq!(apply_identifier_index("GET /", "com.foo=1"), "GET /com.foo=1");
        // Existing identifier slot → replace it (idempotent / cycling in place).
        assert_eq!(apply_identifier_index("GET /people/com.bar=9", "com.foo=1"), "GET /people/com.foo=1");
        assert_eq!(apply_identifier_index("GET /people/com.foo=1", "com.foo=1"), "GET /people/com.foo=1");
        // Only the last segment is the index slot; earlier ones are preserved.
        assert_eq!(
            apply_identifier_index("GET /people/com.a=1/things/com.b=2", "com.c=3"),
            "GET /people/com.a=1/things/com.c=3"
        );
    }

    #[test]
    fn apply_identifier_index_preserves_operator_segments() {
        // An `=` inside an operator expression is NOT an identifier slot — the
        // segment must be preserved and the identifier appended after it.
        assert_eq!(
            apply_identifier_index("GET /people~where(name=Joe)", "com.foo=1"),
            "GET /people~where(name=Joe)/com.foo=1"
        );
        // Operator chained onto an identifier segment: also append, never replace.
        assert_eq!(
            apply_identifier_index("GET /people/com.a=1~take(5)", "com.foo=1"),
            "GET /people/com.a=1~take(5)/com.foo=1"
        );
    }

    #[test]
    fn paste_starts_with_method_detection() {
        assert!(paste_starts_with_method("GET /people/com.test.example=123"));
        assert!(paste_starts_with_method("put /foo"));        // case-insensitive
        assert!(paste_starts_with_method("  POST /bar"));     // leading whitespace
        assert!(paste_starts_with_method("DELETE /x\n"));     // trailing newline
        // Not a method-prefixed line:
        assert!(!paste_starts_with_method("/people/com.test=1")); // bare path
        assert!(!paste_starts_with_method("GETTER /x"));          // not a real method
        assert!(!paste_starts_with_method("GET"));               // no following space/URI
        assert!(!paste_starts_with_method("{\"a\":1}"));         // JSON body
        assert!(!paste_starts_with_method(""));
    }

    #[test]
    fn paste_is_api_text_detection() {
        assert!(paste_is_api_text("GET /people"));
        assert!(paste_is_api_text("assert /x"));
        assert!(paste_is_api_text("ASSERT not /x~count"));
        assert!(paste_is_api_text("confirm"));
        assert!(paste_is_api_text("sleep 5 while /imports~count"));
        assert!(paste_is_api_text("url is http://localhost:5000"));
        assert!(paste_is_api_text("# comment"));
        assert!(paste_is_api_text("shared/seed.api"));
        assert!(paste_is_api_text("/tmp/seed.API"));
        assert!(paste_is_api_text("/a\n/b"));          // a block of requests
        assert!(paste_is_api_text("  /a\n/b\n"));
        // Inserted at the cursor instead:
        assert!(!paste_is_api_text("/people/com.test=1"));   // one bare path
        assert!(!paste_is_api_text("/people\n"));            // one path, newline and all
        assert!(!paste_is_api_text("{\"a\":1}"));            // JSON body
        assert!(!paste_is_api_text("{\n  \"a\": 1\n}"));     // multi-line body
        assert!(!paste_is_api_text("@people/*.json"));
        assert!(!paste_is_api_text("> out.json"));
        assert!(!paste_is_api_text("urls"));                  // not a directive
        assert!(!paste_is_api_text("GET"));
        assert!(!paste_is_api_text(""));
    }

    #[test]
    fn hard_wrap_respects_existing_newlines() {
        // Existing \n resets the column counter (hard break).
        let s = "ab\ncd";
        assert_eq!(hard_wrap_ansi(s, 80), "ab\ncd");
    }

    #[test]
    fn clamp_input_viewport_short_input_unchanged() {
        let input = "GET /people\n[\n  {}\n]";
        let (out, count) = clamp_input_viewport(input, 80, 20, 0);
        assert_eq!(out, input);
        assert_eq!(count, 4);
    }

    #[test]
    fn clamp_input_viewport_never_exceeds_cap() {
        // 50 short logical lines, cap at 10 visual lines.
        let input: String = (0..50).map(|i| format!("line{}", i)).collect::<Vec<_>>().join("\n");
        for cursor_line in [0usize, 7, 25, 49] {
            let (out, count) = clamp_input_viewport(&input, 80, 10, cursor_line);
            assert!(count <= 10, "count {} exceeded cap for cursor_line {}", count, cursor_line);
            // The cursor's logical line must be present in the window.
            assert!(
                out.contains(&format!("line{}", cursor_line)),
                "cursor line{} not visible (cursor_line {})", cursor_line, cursor_line
            );
        }
    }

    #[test]
    fn clamp_input_viewport_marks_clipped_regions() {
        let input: String = (0..50).map(|i| format!("line{}", i)).collect::<Vec<_>>().join("\n");
        // Cursor in the middle → both top and bottom should be clipped/marked.
        let (out, _) = clamp_input_viewport(&input, 80, 10, 25);
        assert!(out.contains('⋯'), "expected an ellipsis marker when content is clipped");
        // Cursor at the very end → no bottom marker, last real line stays last.
        let (out_end, _) = clamp_input_viewport(&input, 80, 10, 49);
        assert!(out_end.trim_end().ends_with("line49"), "cursor-at-end window must end at the last line");
    }

    #[test]
    fn resolve_request_path_default_prefix() {
        assert_eq!(resolve_request_path("/api/v1", "/people"), "/api/v1/people");
        assert_eq!(resolve_request_path("/api/me/v1", "/people"), "/api/me/v1/people");
    }

    #[test]
    fn resolve_request_path_version_prefix() {
        assert_eq!(resolve_request_path("/api/v1", "/v1/people"), "/api/v1/people");
        assert_eq!(resolve_request_path("/api/v1", "/v2/people"), "/api/v2/people");
        assert_eq!(resolve_request_path("/api/v1", "/v42/foo"), "/api/v42/foo");
        // Bare /v2 (no trailing path) also works
        assert_eq!(resolve_request_path("/api/v1", "/v2"), "/api/v2");
    }

    #[test]
    fn resolve_request_path_explicit_api_prefix() {
        assert_eq!(resolve_request_path("/api/v1", "/api/v1/people"), "/api/v1/people");
        assert_eq!(resolve_request_path("/api/v1", "/api/v2/people"), "/api/v2/people");
        assert_eq!(resolve_request_path("/api/v1", "/api/me/v1/people"), "/api/me/v1/people");
        assert_eq!(resolve_request_path("/api/v1", "/api"), "/api");
    }

    #[test]
    fn resolve_request_path_versionlike_is_not_a_version() {
        // /version is NOT a version prefix
        assert_eq!(resolve_request_path("/api/v1", "/version/foo"), "/api/v1/version/foo");
        // /v alone (no digits)
        assert_eq!(resolve_request_path("/api/v1", "/v/foo"), "/api/v1/v/foo");
        // /v2foo — digits not followed by /
        assert_eq!(resolve_request_path("/api/v1", "/v2foo"), "/api/v1/v2foo");
    }

    #[test]
    fn resolve_request_path_without_leading_slash() {
        // A path pasted from a URL or a log resolves like the slashed form —
        // the `/api` prefix must not be duplicated.
        assert_eq!(
            resolve_request_path("/api/v1", "api/v1/stock-transfers/key=8298~map(no.omnium.x)"),
            "/api/v1/stock-transfers/key=8298~map(no.omnium.x)"
        );
        assert_eq!(resolve_request_path("/api/v1", "api/v2/people"), "/api/v2/people");
        assert_eq!(resolve_request_path("/api/v1", "api/me/v1/people"), "/api/me/v1/people");
        assert_eq!(resolve_request_path("/api/v1", "api"), "/api");
        // The version and default rules apply to bare paths too.
        assert_eq!(resolve_request_path("/api/v1", "v2/people"), "/api/v2/people");
        assert_eq!(resolve_request_path("/api/v1", "people"), "/api/v1/people");
        assert_eq!(resolve_request_path("/api/me/v1", "people"), "/api/me/v1/people");
        assert_eq!(resolve_request_path("/api/v1", "version/foo"), "/api/v1/version/foo");
        // Empty stays empty-prefixed, exactly as before.
        assert_eq!(resolve_request_path("/api/v1", ""), "/api/v1");
    }

    #[test]
    fn resolve_request_path_me_skipped_with_explicit_version() {
        // --me sets api_path to /api/me/v1. An explicit /v2/ should bypass it.
        assert_eq!(resolve_request_path("/api/me/v1", "/v2/people"), "/api/v2/people");
        assert_eq!(resolve_request_path("/api/me/v1", "/api/v2/people"), "/api/v2/people");
    }

    #[test]
    fn extract_identifier_pairs_nested_identifiers() {
        let s = r#"{ "identifiers": { "com.heads.seedID": "someid" }, "name": "Bob" }"#;
        assert_eq!(
            extract_identifier_pairs(s),
            vec![("com.heads.seedID".to_string(), "someid".to_string())]
        );
    }

    #[test]
    fn extract_identifier_pairs_nested_identifiers_multiple() {
        let s = r#"{ "identifiers": { "com.heads.seedID": "a", "com.foo.other": "b" } }"#;
        let pairs = extract_identifier_pairs(s);
        assert_eq!(pairs.len(), 2);
        // Insertion order is preserved thanks to serde_json's preserve_order feature.
        assert_eq!(pairs[0], ("com.heads.seedID".to_string(), "a".to_string()));
        assert_eq!(pairs[1], ("com.foo.other".to_string(), "b".to_string()));
    }

    #[test]
    fn extract_identifier_pairs_flat_object() {
        let s = r#"{ "com.heads.seedID": "someid" }"#;
        assert_eq!(
            extract_identifier_pairs(s),
            vec![("com.heads.seedID".to_string(), "someid".to_string())]
        );
    }

    #[test]
    fn extract_identifier_pairs_flat_object_multiple() {
        let s = r#"{ "com.heads.seedID": "someid", "com.foo.other": "otherid" }"#;
        let pairs = extract_identifier_pairs(s);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("com.heads.seedID".to_string(), "someid".to_string()));
        assert_eq!(pairs[1], ("com.foo.other".to_string(), "otherid".to_string()));
    }

    #[test]
    fn extract_identifier_pairs_skips_non_string_values_in_flat() {
        // Mixed types in a flat object → not identifier-shaped, no expansion.
        let s = r#"{ "name": "Bob", "age": 30 }"#;
        assert_eq!(extract_identifier_pairs(s), Vec::<(String, String)>::new());
    }

    #[test]
    fn extract_identifier_pairs_nested_takes_precedence() {
        // Both shapes present — the explicit "identifiers" wrapper wins.
        let s = r#"{ "identifiers": { "com.heads.id": "x" }, "com.other.id": "y" }"#;
        let pairs = extract_identifier_pairs(s);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("com.heads.id".to_string(), "x".to_string()));
    }

    #[test]
    fn extract_identifier_pairs_non_json_returns_empty() {
        assert_eq!(
            extract_identifier_pairs("not json at all"),
            Vec::<(String, String)>::new()
        );
    }

    #[test]
    fn extract_identifier_pairs_unwraps_single_element_array() {
        // A one-item list body (as pasted for a list endpoint) addresses the
        // same index slot as the bare object would — flat shape …
        assert_eq!(
            extract_identifier_pairs(r#"[{"com.heads.id": "x"}]"#),
            vec![("com.heads.id".to_string(), "x".to_string())]
        );
        // … and the explicit `identifiers` child shape, keeping key order.
        let json = r#"[{ "identifiers": { "com.heads.seedID": "martintörnwall", "com.heads.test2": "123"} }]"#;
        assert_eq!(
            extract_identifier_pairs(json),
            vec![
                ("com.heads.seedID".to_string(), "martintörnwall".to_string()),
                ("com.heads.test2".to_string(), "123".to_string()),
            ]
        );
    }

    #[test]
    fn format_byte_size_picks_short_units() {
        assert_eq!(format_byte_size(0), "0 B");
        assert_eq!(format_byte_size(1), "1 B");
        assert_eq!(format_byte_size(1023), "1023 B");
        assert_eq!(format_byte_size(1024), "1.0 KB");
        assert_eq!(format_byte_size(1204), "1.2 KB");
        assert_eq!(format_byte_size(48_213), "47.1 KB");
        // One decimal below 100, none from 100 up.
        assert_eq!(format_byte_size(150 * 1024), "150 KB");
        assert_eq!(format_byte_size(5 * 1024 * 1024 + 512 * 1024), "5.5 MB");
        assert_eq!(format_byte_size(3 * 1024 * 1024 * 1024), "3.0 GB");
        // A value that would round to "1024 KB" carries into the next unit.
        assert_eq!(format_byte_size(1024 * 1024 - 1), "1.0 MB");
    }

    #[test]
    fn outfile_marker_shows_size_and_append_delta() {
        assert_eq!(outfile_marker("out.json", 48_213, false), "> out.json (47.1 KB)");
        assert_eq!(outfile_marker("clipboard", 300, false), "> clipboard (300 B)");
        assert_eq!(outfile_marker("out.json", 1204, true), ">> out.json (+1.2 KB)");
    }

    #[test]
    fn stream_to_sink_counts_every_byte_past_the_prefix() {
        let body = vec![b'x'; CLASSIFY_PREFIX_BYTES * 3 + 7];
        let got = stream_to_sink(&body[..], &mut Vec::new()).unwrap();
        assert_eq!(got.bytes, body.len() as u64);
        assert_eq!(stream_to_sink(&b""[..], &mut Vec::new()).unwrap().bytes, 0);
    }

    #[test]
    fn file_len_is_zero_for_a_missing_file() {
        let dir = std::env::temp_dir().join(format!("api-file-len-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.txt");
        let path = path.to_str().unwrap();
        assert_eq!(file_len(path), 0);
        std::fs::write(path, b"12345").unwrap();
        assert_eq!(file_len(path), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_identifier_pairs_rejects_other_arrays() {
        let none = Vec::<(String, String)>::new();
        // Several items can't name a single index slot.
        assert_eq!(
            extract_identifier_pairs(r#"[{"com.heads.id": "x"}, {"com.heads.id": "y"}]"#),
            none
        );
        // Empty array and non-object element stay verbatim.
        assert_eq!(extract_identifier_pairs("[]"), none);
        assert_eq!(extract_identifier_pairs(r#"["com.heads.id=x"]"#), none);
    }

    #[test]
    fn handle_paste_single_element_array_indexes_uri_and_keeps_body() {
        // Cursor right after the URI, body already present after the cursor:
        // pasting the body's one-item array inserts the identifier index and
        // leaves the body untouched.
        let body = r#"[{ "identifiers": { "com.heads.seedID": "martintörnwall", "com.heads.test2": "123"} }]"#;
        let mut state = AppState::new(Config::default());
        state.input = format!("PUT /people {}", body);
        state.cursor_pos = char_len("PUT /people");
        state.method = "PUT".to_string();
        let mut sink: Vec<u8> = Vec::new();
        handle_paste(&mut state, body, &mut sink).unwrap();
        assert_eq!(
            state.input,
            format!("PUT /people/com.heads.seedID=martintörnwall {}", body)
        );
        assert_eq!(state.cursor_pos, char_len("PUT /people/com.heads.seedID=martintörnwall"));

        // Re-pasting within the window cycles to the second identifier.
        handle_paste(&mut state, body, &mut sink).unwrap();
        assert_eq!(
            state.input,
            format!("PUT /people/com.heads.test2=123 {}", body)
        );
    }

    #[test]
    fn extract_identifier_pairs_handles_surrounding_whitespace() {
        let s = "  \n  { \"com.heads.id\": \"abc\" }  \n  ";
        assert_eq!(
            extract_identifier_pairs(s),
            vec![("com.heads.id".to_string(), "abc".to_string())]
        );
    }

    #[test]
    fn resolve_at_file_body_glob_skips_os_junk() {
        // End-to-end: a temp dir with two real JSON files plus typical OS junk —
        // resolve_at_file_body should return only the real files, combined into
        // a JSON array of length 2.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.json"), r#"{"id":1,"name":"Alice"}"#).unwrap();
        fs::write(dir.path().join("b.json"), r#"{"id":2,"name":"Bob"}"#).unwrap();
        // .DS_Store would crash JSON parsing if it got through (binary header).
        fs::write(dir.path().join(".DS_Store"), b"\x00\x00\x00\x01junk").unwrap();
        fs::write(dir.path().join("._a.json"), b"\x00binary").unwrap();
        fs::write(dir.path().join("Thumbs.db"), b"not json").unwrap();
        fs::write(dir.path().join("desktop.ini"), b"[.ShellClassInfo]").unwrap();

        let pattern = format!("{}/*", dir.path().display());
        let result = resolve_at_file_body(&pattern).expect("glob should succeed");
        let parsed: Value = serde_json::from_slice(&result.contents)
            .expect("combined body should be valid JSON");
        let arr = parsed.as_array().expect("body should be an array");
        assert_eq!(arr.len(), 2, "only real JSON files should be included, got: {parsed}");
        let names: Vec<&str> = arr
            .iter()
            .map(|v| v.get("name").and_then(|n| n.as_str()).unwrap_or(""))
            .collect();
        assert!(names.contains(&"Alice"), "Alice missing in {names:?}");
        assert!(names.contains(&"Bob"), "Bob missing in {names:?}");
    }

    #[test]
    fn is_clipboard_target_matches_case_insensitive_bare_token() {
        assert!(is_clipboard_target("clipboard"));
        assert!(is_clipboard_target("Clipboard"));
        assert!(is_clipboard_target("CLIPBOARD"));
        assert!(is_clipboard_target("  clipboard  "));
        assert!(is_clipboard_target("\tclipboard\n"));
    }

    #[test]
    fn is_clipboard_target_rejects_anything_path_like() {
        // Real filenames must not be treated as the special target.
        assert!(!is_clipboard_target("clipboard.json"));
        assert!(!is_clipboard_target("./clipboard"));
        assert!(!is_clipboard_target("/tmp/clipboard"));
        assert!(!is_clipboard_target("~/clipboard"));
        assert!(!is_clipboard_target("my-clipboard"));
        // Empty / unrelated.
        assert!(!is_clipboard_target(""));
        assert!(!is_clipboard_target("clipper"));
    }

    #[test]
    fn is_os_junk_recognizes_windows_junk_case_insensitively() {
        use std::path::Path;
        assert!(is_os_junk(Path::new("Thumbs.db")));
        assert!(is_os_junk(Path::new("/some/where/Thumbs.db")));
        assert!(is_os_junk(Path::new("THUMBS.DB")));
        assert!(is_os_junk(Path::new("desktop.ini")));
        assert!(is_os_junk(Path::new("Desktop.INI")));
        assert!(is_os_junk(Path::new("$RECYCLE.BIN")));
        // Real files are not junk.
        assert!(!is_os_junk(Path::new("people.json")));
        assert!(!is_os_junk(Path::new("/data/main.ndjson")));
        // .DS_Store is handled by the leading-dot glob rule, not this filter —
        // but if a glob ever did surface it, this filter wouldn't claim it.
        assert!(!is_os_junk(Path::new(".DS_Store")));
    }

    #[test]
    fn collapse_newlines_for_log_only_touches_newline_runs() {
        // A body typed on one line is echoed byte-for-byte — odd spacing included.
        let single = "{ \"a\":  1,\t\"b\": 2 }";
        assert_eq!(collapse_newlines_for_log(single), single);

        // Each newline-containing run becomes exactly one space, however long.
        assert_eq!(
            collapse_newlines_for_log("{\n  \"a\": 1,\n  \"b\": 2\n}"),
            "{ \"a\": 1, \"b\": 2 }",
        );
        assert_eq!(
            collapse_newlines_for_log("line one\n\n  line two"),
            "line one line two",
        );
        // Trailing and leading newline runs collapse too, not dropped.
        assert_eq!(collapse_newlines_for_log("\n{}\n"), " {} ");
        assert_eq!(collapse_newlines_for_log("a\r\nb"), "a b");
        assert_eq!(collapse_newlines_for_log(""), "");
    }

    #[test]
    fn fit_body_to_width_fits_within_budget() {
        // Under budget — returned as-is.
        assert_eq!(fit_body_to_width("\"A new name\"", 40), "\"A new name\"");
        // Exactly at budget — still untouched, no ellipsis.
        let exact = "z".repeat(20);
        assert_eq!(fit_body_to_width(&exact, 20), exact);

        // One past budget — cut, and the result is never wider than the budget.
        let over = "z".repeat(21);
        let out = fit_body_to_width(&over, 20);
        assert_eq!(char_len(&out), 20, "got: {out}");
        assert_eq!(out, format!("{}…", "z".repeat(19)));

        // The ellipsis counts inside the budget at every size.
        for budget in MIN_INLINE_BODY_CHARS..40 {
            let out = fit_body_to_width(&"x".repeat(200), budget);
            assert!(char_len(&out) <= budget, "budget {budget} overflowed: {out}");
        }

        // Multibyte input is counted and cut by chars, never mid-codepoint.
        let out = fit_body_to_width(&"ö".repeat(50), 10);
        assert_eq!(out, format!("{}…", "ö".repeat(9)));

        // A multi-line body is collapsed before it's measured.
        let out = fit_body_to_width("{\n  \"a\": 1\n}", 40);
        assert_eq!(out, "{ \"a\": 1 }");
    }

    /// Composition and styling of the echoed request line.
    ///
    /// Kept as one test on purpose: forcing color on flips a global in `colored`,
    /// so a second test toggling it would race this one under the parallel test
    /// runner. No other test asserts on color, so owning the global here is safe.
    #[test]
    fn format_request_log_line_composition_and_styling() {
        // Under `cargo test` stdout isn't a tty, so `colored` emits no escapes by
        // default — forcing the override on is what makes "no styling" provable.
        colored::control::set_override(true);

        // Bare request — no body, no outfile.
        assert_eq!(format_request_log_line("GET", "/people", "", "", false, 80), "GET /people");

        // Body follows the URI, unstyled and unreformatted.
        assert_eq!(
            format_request_log_line("PUT", "/people/*givenName", "\"A new name\"", "", false, 80),
            "PUT /people/*givenName \"A new name\"",
        );

        // Outfile is appended last, after the body.
        assert_eq!(
            format_request_log_line("GET", "/people", "", "out.json", false, 80),
            "GET /people > out.json",
        );
        assert_eq!(
            format_request_log_line("PUT", "/people", "@data.json", "~/out.json", false, 80),
            "PUT /people @data.json > ~/out.json",
        );

        // Nothing on the line is styled, so the renderer's `visible_len` sizing
        // sees exactly the characters printed.
        let line = format_request_log_line("PUT", "/people", "{ \"a\": 1 }", "out.json", false, 80);
        assert!(!line.contains('\x1b'), "expected no escapes, got: {line:?}");
        assert_eq!(visible_len(&line), char_len(&line));

        colored::control::unset_override();
    }

    #[test]
    fn format_request_log_line_fits_one_row_at_any_width() {
        let long_body = format!("{{ \"name\": \"{}\" }}", "x".repeat(200));
        let long_glob = format!("@/very/long/path/{}/*.json", "segment".repeat(10));
        let multiline = "{\n  \"givenName\": \"Möör\",\n  \"familyName\": \"Test\"\n}";

        for width in [20usize, 40, 60, 80, 120, 200] {
            for body in [long_body.as_str(), long_glob.as_str(), multiline] {
                for outfile in ["", "out.json", "~/some/longer/path/output.json"] {
                    let line = format_request_log_line("PUT", "/people", body, outfile, false, width);
                    // Never wraps...
                    assert!(
                        char_len(&line) <= width.max(char_len("PUT /people") + char_len(outfile) + 3),
                        "width {width} overflowed with outfile {outfile:?}: {line:?}",
                    );
                    // ...and never spans rows.
                    assert!(!line.contains('\n'), "line broke at width {width}: {line:?}");
                    // The request identity always survives, body or not.
                    assert!(line.starts_with("PUT /people"), "got: {line:?}");
                    if !outfile.is_empty() {
                        assert!(line.ends_with(outfile), "outfile lost at width {width}: {line:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn format_request_log_line_body_absorbs_the_shortfall() {
        // Wide terminal: a long body is cut to the columns left over, exactly
        // filling the row rather than wrapping.
        let long = "x".repeat(500);
        let line = format_request_log_line("PUT", "/people", &long, "", false, 80);
        assert_eq!(char_len(&line), 80, "got: {line:?}");
        assert!(line.ends_with('…'), "got: {line:?}");

        // The outfile is reserved first, so it always survives intact.
        let line = format_request_log_line("PUT", "/people", &long, "out.json", false, 80);
        assert_eq!(char_len(&line), 80, "got: {line:?}");
        assert!(line.ends_with(" > out.json"), "got: {line:?}");

        // Exactly `MIN_INLINE_BODY_CHARS` left is still shown, filling the row.
        // ("PUT /people" is 11 columns, plus the separating space.)
        let at_min = 11 + 1 + MIN_INLINE_BODY_CHARS;
        let line = format_request_log_line("PUT", "/people", &long, "", false, at_min);
        assert_eq!(char_len(&line), at_min, "got: {line:?}");
        assert!(line.ends_with('…'), "got: {line:?}");

        // One column narrower and the body is dropped, not stubbed.
        let line = format_request_log_line("PUT", "/people", &long, "", false, at_min - 1);
        assert_eq!(line, "PUT /people");

        // A URI wider than the terminal keeps the URI and drops the body; the
        // saturating arithmetic must not panic here.
        let long_uri = format!("/{}", "segment/".repeat(30));
        let line = format_request_log_line("GET", &long_uri, &long, "", false, 40);
        assert_eq!(line, format!("GET {}", long_uri));
    }

    fn sample_block() -> OutputBlock {
        OutputBlock {
            method: "PUT".to_string(),
            uri: "/people".to_string(),
            body: format!("{{ \"name\": \"{}\" }}", "x".repeat(200)),
            display_outfile: String::new(),
            outfile_append: false,
            head: "HTTP/1.1 200 OK 0.08s\n".to_string(),
            tail: "\n{\n  \"ok\": true\n}\n\n".to_string(),
            raw_line: None,
            prefix: String::new(),
        }
    }

    #[test]
    fn output_block_refits_request_line_per_width() {
        let block = sample_block();
        let narrow = block.render(60);
        let wide = block.render(200);

        // The request line is fitted to each width...
        let narrow_req = narrow.lines().next().unwrap();
        let wide_req = wide.lines().next().unwrap();
        assert_eq!(char_len(narrow_req), 60, "got: {narrow_req:?}");
        assert_eq!(char_len(wide_req), 200, "got: {wide_req:?}");
        assert!(narrow_req.ends_with('…') && wide_req.ends_with('…'));

        // ...and the wide rendering recovers body text the narrow one cut.
        assert!(char_len(wide_req) > char_len(narrow_req));
        assert!(wide_req.starts_with(narrow_req.trim_end_matches('…')));

        // Everything below the request line is replayed verbatim at any width.
        let below = |s: &str| s.split_once('\n').unwrap().1.to_string();
        assert_eq!(below(&narrow), below(&wide));
        assert_eq!(below(&narrow), format!("{}{}", block.head, block.tail));
    }

    #[test]
    fn body_block_spacing_ignores_the_payloads_trailing_newline() {
        // Same body, with and without the newline the server may or may not
        // send: both must render identically. `-r` used to show an extra blank
        // line because the raw payload kept a newline pretty-printing dropped.
        let with = format_body_block("{\"a\":1}\n");
        let without = format_body_block("{\"a\":1}");
        assert_eq!(with, without);
        assert_eq!(without, "{\"a\":1}\n\n");

        // Streamed JSON and error bodies arrive with no trailing newline;
        // NDJSON always has one. All land on the same spacing.
        assert_eq!(format_body_block("{\"error\":\"nope\"}"), "{\"error\":\"nope\"}\n\n");

        // A multi-line body keeps its internal breaks — only the final run goes.
        assert_eq!(
            format_body_block("{\"a\":1}\n{\"b\":2}\n"),
            "{\"a\":1}\n{\"b\":2}\n\n"
        );

        // A blank line the server actually sent inside the payload is still
        // trailing whitespace here; collapsing it keeps the block height fixed.
        assert_eq!(format_body_block("x\n\n\n"), "x\n\n");

        // Non-empty is what makes has_body() true, so ctrl+j still finds it.
        assert!(!format_body_block("{}").is_empty());
    }

    #[test]
    fn output_block_strip_body_keeps_the_status_line() {
        let mut block = sample_block();
        assert!(block.has_body());

        block.strip_body();
        assert!(!block.has_body());
        // The status line survives; only the response body is gone.
        assert!(block.render(200).ends_with("HTTP/1.1 200 OK 0.08s\n"));
        // Stripping twice is a no-op, so a repeated ctrl+j can't corrupt the block.
        block.strip_body();
        assert!(!block.has_body());
    }

    #[test]
    fn output_block_outfile_response_keeps_its_status_line() {
        // Regression: the outfile and clipboard branches used to write only to the
        // printed buffer, never to the stored one, so a resize redraw dropped the
        // status line and left a bare request line behind.
        let block = OutputBlock {
            method: "PUT".to_string(),
            uri: "/people".to_string(),
            body: "@data.json".to_string(),
            display_outfile: "out.json".to_string(),
            outfile_append: false,
            head: "HTTP/1.1 200 OK 0.08s\n> out.json\n\n".to_string(),
            tail: String::new(),
            raw_line: None,
            prefix: String::new(),
        };

        let rendered = block.render(80);
        assert!(rendered.starts_with("PUT /people @data.json > out.json\n"), "got: {rendered:?}");
        assert!(rendered.contains("HTTP/1.1 200 OK"), "status line lost: {rendered:?}");
        assert!(rendered.contains("> out.json"), "outfile note lost: {rendered:?}");
        // No response body was printed, so ctrl+j has nothing to erase.
        assert!(!block.has_body());
    }

    #[test]
    fn output_block_prefix_leads_the_request_line_within_the_width() {
        let block = OutputBlock {
            method: "GET".to_string(),
            uri: "/zero".to_string(),
            prefix: "assert not ".to_string(),
            head: "HTTP/1.1 200 OK\n\n".to_string(),
            ..Default::default()
        };
        assert_eq!(block.render(80), "assert not GET /zero\nHTTP/1.1 200 OK\n\n");

        // The prefix counts against the row: a long body is cut so the whole
        // line, prefix included, still fits.
        let block = OutputBlock {
            method: "PUT".to_string(),
            uri: "/people".to_string(),
            body: "x".repeat(200),
            prefix: "assert ".to_string(),
            ..Default::default()
        };
        let line = block.render(60).lines().next().unwrap().to_string();
        assert!(line.starts_with("assert PUT /people "), "{line:?}");
        assert_eq!(char_len(&line), 60, "{line:?}");
    }

    #[test]
    fn output_block_note_sits_under_the_status_line() {
        // A bodyless block: the note goes before the closing blank line.
        let mut block = OutputBlock {
            head: "HTTP/1.1 200 OK\n\n".to_string(),
            ..Default::default()
        };
        block.push_note("↳ assertion failed (null)");
        assert_eq!(block.head, "HTTP/1.1 200 OK\n↳ assertion failed (null)\n\n");
        assert!(!block.has_body());

        // A head without a closing blank line just gets the note appended.
        let mut block = OutputBlock {
            head: "Request failed\n".to_string(),
            ..Default::default()
        };
        block.push_note("↳ could not be evaluated");
        assert_eq!(block.head, "Request failed\n↳ could not be evaluated\n");
    }

    #[test]
    fn push_output_block_evicts_oldest_past_the_limit() {
        let mut state = AppState::new(Config::default());
        for i in 0..(OUTPUT_HISTORY_LIMIT + 5) {
            let mut block = sample_block();
            block.uri = format!("/people/{i}");
            push_output_block(&mut state, block);
        }

        assert_eq!(state.output_history.len(), OUTPUT_HISTORY_LIMIT);
        // The survivors are the most recent ones, oldest-first.
        assert_eq!(state.output_history.first().unwrap().uri, "/people/5");
        assert_eq!(
            state.output_history.last().unwrap().uri,
            format!("/people/{}", OUTPUT_HISTORY_LIMIT + 4),
        );
    }

    #[test]
    fn output_with_timeout_returns_fast_command_output() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf hello; printf oops >&2"]);
        let out = output_with_timeout(&mut cmd, Duration::from_secs(10))
            .expect("spawn")
            .expect("should finish well inside the deadline");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hello");
        assert_eq!(String::from_utf8_lossy(&out.stderr), "oops");
    }

    #[test]
    fn output_with_timeout_kills_an_overrunning_command() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 30"]);
        let start = Instant::now();
        let out = output_with_timeout(&mut cmd, Duration::from_millis(300)).expect("spawn");
        assert!(out.is_none(), "expected the deadline to be reported");
        // Returns promptly rather than waiting out the child — this is the hang
        // the 1Password calls used to be able to produce.
        assert!(start.elapsed() < Duration::from_secs(5), "took {:?}", start.elapsed());
    }

    #[test]
    fn output_with_timeout_survives_output_larger_than_the_pipe_buffer() {
        // A child writing more than the pipe buffer blocks until it's drained. If
        // the wait didn't drain concurrently, this would deadlock until the
        // deadline instead of returning the full output.
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "yes abcdefghijklmnopqrstuvwxyz | head -c 400000"]);
        let out = output_with_timeout(&mut cmd, Duration::from_secs(20))
            .expect("spawn")
            .expect("should finish, not deadlock against the pipe buffer");
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 400_000);
    }

    #[test]
    fn output_with_timeout_reports_spawn_failure() {
        let mut cmd = Command::new("definitely-not-a-real-binary-xyz");
        assert!(output_with_timeout(&mut cmd, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn op_stderr_detail_appends_only_real_output() {
        use std::os::unix::process::ExitStatusExt;
        let mk = |stderr: &str| std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        };
        assert_eq!(op_stderr_detail(&mk("")), "");
        assert_eq!(op_stderr_detail(&mk("   \n  ")), "");
        assert_eq!(op_stderr_detail(&mk("not signed in")), "\nnot signed in");
        // Trailing newlines from the CLI don't produce a blank line.
        assert_eq!(op_stderr_detail(&mk("session expired\n")), "\nsession expired");
    }

    #[test]
    fn last_chain_segment_start_finds_the_final_separator() {
        // Returns the offset just past the final `&&` — the leading space (if
        // any) belongs to the segment and is trimmed by the callers.
        assert_eq!(last_chain_segment_start("GET /a"), 0);
        assert_eq!(last_chain_segment_start("GET /a && GET /b"), 9);
        assert_eq!(last_chain_segment_start("GET /a && GET /b && GET /c"), 19);
        // Inside a string or body, `&&` doesn't start a segment.
        assert_eq!(last_chain_segment_start(r#"PUT /r {"e": "a && b"}"#), 0);
        assert_eq!(last_chain_segment_start(r#"PUT /r {"a": 1 && 2}"#), 0);
        // After a body closes, it does.
        let s = r#"PUT /a {"x":1} && GET /b"#;
        assert_eq!(last_chain_segment_start(s), s.find(" GET").unwrap());
        // `&&&`: the separator is the first two chars, the third starts the segment.
        assert_eq!(last_chain_segment_start("GET /a &&& GET /b"), 9);
        // Trailing separator — the (empty) last segment starts at the end.
        assert_eq!(last_chain_segment_start("GET /a &&"), 9);
    }

    #[test]
    fn promotion_fires_only_in_the_last_segment() {
        // Typing `{` at the end of the last segment promotes THAT segment's GET.
        let mut state = test_state();
        state.input = "GET /a && GET /b {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "GET /a && PUT /b {");
        // The line's leading method is untouched, as is the TUI's method state.
        assert_eq!(state.method, "GET");
        assert!(state.method_auto_promoted);
        assert_eq!(state.method_auto_promoted_uri, "/b");

        // URI-only last segment gets an explicit PUT prepended.
        let mut state = test_state();
        state.input = "GET /a && /b {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "GET /a && PUT /b {");
        assert_eq!(state.method, "GET");

        // Typing a body char in an EARLIER segment never promotes anything —
        // the `&&` after the cursor stays top-level, so the edit is not in the
        // last segment.
        let mut state = test_state();
        state.input = "GET /a x && GET /b".to_string();
        // Cursor just after the `x` (char 8).
        state.cursor_pos = 8;
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, 'x');
        assert_eq!(state.input, "GET /a x && GET /b");
        assert_eq!(state.method, "GET");
        assert!(!state.method_auto_promoted);

        // Typing `{` mid-line is different BY THE GRAMMAR: the unclosed bracket
        // swallows the rest of the line into a body (the `&&` is no longer
        // top-level), the line is one request again, and prefix-based promotion
        // applies exactly as it did before chains existed.
        let mut state = test_state();
        state.input = "GET /a { && GET /b".to_string();
        state.cursor_pos = 8; // just after the `{`
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "PUT /a { && GET /b");
        assert_eq!(state.method, "PUT");

        // A `&&` inside a JSON string is body text — the whole line is one
        // segment, and its promotion works as for any single request.
        let mut state = test_state();
        state.input = "GET /r {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "PUT /r {");
        assert_eq!(state.method, "PUT");
    }

    #[test]
    fn revert_fires_only_on_the_promoted_segment_uri() {
        // Promote in the last segment, clear its body → that segment reverts.
        let mut state = test_state();
        state.input = "GET /a && GET /b {".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "GET /a && PUT /b {");
        state.input = "GET /a && PUT /b ".to_string(); // body deleted
        auto_revert_method_on_body_clear(&mut state);
        assert_eq!(state.input, "GET /a && GET /b ");
        assert!(!state.method_auto_promoted);

        // THE protection case: segment-1 PUT was typed by hand; a promotion in
        // segment 2 then a deletion of segment 2 must never revert segment 1.
        let mut state = test_state();
        state.input = "PUT /a && /b {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "PUT".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "PUT /a && PUT /b {");
        // Segment 2 deleted wholesale (e.g. kill-to-end from before the `&&`).
        state.input = "PUT /a ".to_string();
        auto_revert_method_on_body_clear(&mut state);
        assert_eq!(state.input, "PUT /a ", "an explicitly typed PUT must survive");
        assert_eq!(state.method, "PUT");
        // The stale promotion flag is cleared, so no later edit can revert either.
        assert!(!state.method_auto_promoted);
        auto_revert_method_on_body_clear(&mut state);
        assert_eq!(state.input, "PUT /a ");

        // Narrowing (pinned as intended): editing the promoted URI while the
        // body exists, then clearing the body, no longer reverts — the URI on
        // the line isn't the one that was promoted.
        let mut state = test_state();
        state.input = "GET /x {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "PUT /x {");
        state.input = "PUT /xy ".to_string(); // URI edited, body cleared
        auto_revert_method_on_body_clear(&mut state);
        assert_eq!(state.input, "PUT /xy ");
        assert!(!state.method_auto_promoted);
    }

    #[test]
    fn array_wrap_is_scoped_to_the_last_segment() {
        // Wrap fires for the last segment of a chain on an array endpoint.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "GET /a && PUT /people {".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '{');
        assert_eq!(state.input, "GET /a && PUT /people [{");

        // But never for an earlier segment: typing a body char inside segment 1
        // while the `&&` stays top-level does not wrap.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "PUT /people x && GET /b".to_string();
        state.cursor_pos = 13; // just after the `x`
        auto_wrap_array_body(&mut state, 'x');
        assert_eq!(state.input, "PUT /people x && GET /b");

        // Promotion + wrap in one keystroke, chained: GET → PUT then `[`.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "GET /a && GET /people {".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_promote_method_on_body_start(&mut state, '{');
        auto_wrap_array_body(&mut state, '{');
        assert_eq!(state.input, "GET /a && PUT /people [{");
    }

    #[test]
    fn paste_promotion_is_scoped_to_the_last_segment() {
        // Pasting a body at the end of a chain promotes the LAST segment only.
        let mut state = test_state();
        state.input = "GET /a && GET /b ".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        let mut out = sink();
        handle_paste(&mut state, "{\"x\":1}", &mut out).unwrap();
        assert_eq!(state.input, "GET /a && PUT /b {\"x\":1}");
        assert_eq!(state.method, "GET");

        // Pasted array wrap in the last segment of a chain.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "GET /a && GET /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        let mut out = sink();
        handle_paste(&mut state, "{\"n\":\"Joe\"}", &mut out).unwrap();
        assert_eq!(state.input, "GET /a && PUT /people [{\"n\":\"Joe\"}]");
    }

    #[test]
    fn typing_a_chain_separator_never_promotes_get() {
        // Typing `&` after `GET /uri ` starts a `&&` chain, not a body — the GET
        // must survive, or the chain the user is composing silently becomes a PUT.
        let mut state = test_state();
        state.input = "GET /people &".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '&');
        assert_eq!(state.input, "GET /people &");
        assert_eq!(state.method, "GET");
        assert!(!state.method_auto_promoted);

        // Same for a URI-only line (implicit GET) — no `PUT ` prepended.
        let mut state = test_state();
        state.input = "/people &".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '&');
        assert_eq!(state.input, "/people &");
        assert_eq!(state.method, "GET");

        // And the array auto-wrap must not produce `PUT /people [&`.
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "PUT /people &".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '&');
        assert_eq!(state.input, "PUT /people &");

        // Sanity: a real body char right after still promotes as before.
        let mut state = test_state();
        state.input = "GET /people {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "PUT /people {");
        assert_eq!(state.method, "PUT");
    }

    #[test]
    fn pasting_a_chain_tail_never_promotes_get() {
        // Pasting `&& GET /b` at the body position of `GET /a ` extends the
        // chain; it must not read as a body and promote.
        let mut state = test_state();
        state.input = "GET /a ".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        let mut out = sink();
        handle_paste(&mut state, "&& GET /b", &mut out).unwrap();
        assert_eq!(state.input, "GET /a && GET /b");
        assert_eq!(state.method, "GET");
        assert!(!state.method_auto_promoted);

        // Even with a body inside the pasted tail — the `&` prefix decides.
        let mut state = test_state();
        state.input = "GET /a ".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        let mut out = sink();
        handle_paste(&mut state, "&& PUT /b {\"x\":1}", &mut out).unwrap();
        assert_eq!(state.input, "GET /a && PUT /b {\"x\":1}");
        assert_eq!(state.method, "GET");
    }

    fn chain_texts(input: &str) -> Vec<String> {
        split_request_chain(input).into_iter().map(|(_, s)| s).collect()
    }

    #[test]
    fn split_request_chain_records_operators() {
        assert_eq!(
            split_request_chain("GET /a || GET /b && GET /c"),
            vec![
                (ChainOp::And, "GET /a".to_string()),
                (ChainOp::Or, "GET /b".to_string()),
                (ChainOp::And, "GET /c".to_string()),
            ],
        );
        // `||` inside a JSON string or body is literal.
        let in_string = r#"PUT /r { "expr": "a || b" }"#;
        assert_eq!(chain_texts(in_string), vec![in_string.to_string()]);
        // A single `|` is not a separator.
        assert_eq!(chain_texts("GET /a|b"), vec!["GET /a|b".to_string()]);
        // An empty middle segment is dropped; the follower keeps ITS operator.
        assert_eq!(
            split_request_chain("GET /a && || GET /b"),
            vec![(ChainOp::And, "GET /a".to_string()), (ChainOp::Or, "GET /b".to_string())],
        );
    }

    #[test]
    fn chain_segment_should_run_implements_shell_rules() {
        use ChainOp::*;
        use RequestOutcome::*;
        // First segment always runs.
        assert!(chain_segment_should_run(None, And));
        assert!(chain_segment_should_run(None, Or));
        // Truthy: && runs, || skips.
        assert!(chain_segment_should_run(Some(Truthy), And));
        assert!(!chain_segment_should_run(Some(Truthy), Or));
        // Falsy: && skips, || runs.
        assert!(!chain_segment_should_run(Some(Falsy), And));
        assert!(chain_segment_should_run(Some(Falsy), Or));

        // If-then-else, simulated with the skipped-doesn't-update rule:
        // a && b || c — truthy a runs b; b truthy skips c.
        let mut prev = Some(Truthy);
        assert!(chain_segment_should_run(prev, And)); // b runs
        prev = Some(Truthy); // b's own outcome
        assert!(!chain_segment_should_run(prev, Or)); // c skipped
        // Falsy a skips b (prev unchanged), a's falsiness then runs c.
        prev = Some(Falsy);
        assert!(!chain_segment_should_run(prev, And)); // b skipped, prev stays
        assert!(chain_segment_should_run(prev, Or)); // c runs
    }

    #[test]
    fn or_separator_composes_with_segment_features() {
        // Typing the first `|` of a separator never promotes or wraps — the
        // same guard class as `&`.
        let mut state = test_state();
        state.input = "GET /people |".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '|');
        assert_eq!(state.input, "GET /people |");
        assert_eq!(state.method, "GET");

        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "PUT /people |".to_string();
        state.cursor_pos = char_len(&state.input);
        auto_wrap_array_body(&mut state, '|');
        assert_eq!(state.input, "PUT /people |");

        // Pasting a `||` tail never promotes.
        let mut state = test_state();
        state.input = "GET /a ".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        let mut out = sink();
        handle_paste(&mut state, "|| PUT /a {\"x\":1}", &mut out).unwrap();
        assert_eq!(state.input, "GET /a || PUT /a {\"x\":1}");
        assert_eq!(state.method, "GET");

        // `||` bounds the "last segment" for promotion, like `&&`.
        let mut state = test_state();
        state.input = "GET /a || GET /b {".to_string();
        state.cursor_pos = char_len(&state.input);
        state.method = "GET".to_string();
        auto_promote_method_on_body_start(&mut state, '{');
        assert_eq!(state.input, "GET /a || PUT /b {");
        assert_eq!(state.method, "GET");

        // The segment view splits on `||` too — completion in the last segment.
        let mut state = test_state();
        state.config.complete = true;
        state.endpoints = vec!["/people".to_string(), "/products".to_string()];
        state.input = "GET /people || GET /pro".to_string();
        state.cursor_pos = char_len(&state.input);
        with_chain_segment_view(&mut state, handle_tab_completion);
        assert_eq!(state.input, "GET /people || GET /products");
    }

    #[test]
    fn split_request_chain_splits_on_top_level_separators() {
        assert_eq!(
            chain_texts("GET /people/123 && PUT /people/123 { \"name\": \"Joe\" }"),
            vec![
                "GET /people/123".to_string(),
                "PUT /people/123 { \"name\": \"Joe\" }".to_string(),
            ],
        );

        // Three segments, and whitespace around separators is trimmed.
        assert_eq!(
            chain_texts("GET /a&&GET /b   &&   GET /c"),
            vec!["GET /a".to_string(), "GET /b".to_string(), "GET /c".to_string()],
        );

        // An unchained line is a one-segment chain, so callers need no special case.
        assert_eq!(chain_texts("GET /people"), vec!["GET /people".to_string()]);
    }

    #[test]
    fn split_request_chain_ignores_separators_inside_bodies_and_strings() {
        // Inside a JSON string — one request, not two.
        let in_string = r#"PUT /rules { "expr": "a && b" }"#;
        assert_eq!(chain_texts(in_string), vec![in_string.to_string()]);

        // Inside brackets but outside a string — still one request.
        let in_body = r#"PUT /rules { "a": 1 && 2 }"#;
        assert_eq!(chain_texts(in_body), vec![in_body.to_string()]);

        // An escaped quote must not end the string early and expose the `&&`.
        let escaped = r#"PUT /x { "s": "he said \"hi\" && bye" }"#;
        assert_eq!(chain_texts(escaped), vec![escaped.to_string()]);

        // Inside the parentheses of a URI operator — one request.
        for in_parens in ["GET /x~where(a=1||b=2)", "GET /x~where(a=1&&b=2)~take(5)"] {
            assert_eq!(chain_texts(in_parens), vec![in_parens.to_string()]);
        }
        assert_eq!(
            chain_texts("GET /x~where(a=1||b=2) || GET /y"),
            vec!["GET /x~where(a=1||b=2)".to_string(), "GET /y".to_string()],
        );

        // A separator after a body closes is a real split.
        assert_eq!(
            chain_texts(r#"PUT /a { "x": 1 } && GET /b"#),
            vec![r#"PUT /a { "x": 1 }"#.to_string(), "GET /b".to_string()],
        );
    }

    #[test]
    fn split_request_chain_drops_empty_segments() {
        // Trailing/leading/doubled separators leave nothing to run.
        assert_eq!(chain_texts("GET /a &&"), vec!["GET /a".to_string()]);
        assert_eq!(chain_texts("&& GET /a"), vec!["GET /a".to_string()]);
        assert_eq!(
            chain_texts("GET /a && && GET /b"),
            vec!["GET /a".to_string(), "GET /b".to_string()],
        );
        assert!(chain_texts("   ").is_empty());
        // A single `&` is not a separator.
        assert_eq!(chain_texts("GET /a&b"), vec!["GET /a&b".to_string()]);
    }

    #[test]
    fn split_request_chain_handles_multiline_bodies() {
        let input = "GET /people/123 && PUT /people/123 {\n  \"name\": \"Joe\"\n}";
        assert_eq!(
            chain_texts(input),
            vec![
                "GET /people/123".to_string(),
                "PUT /people/123 {\n  \"name\": \"Joe\"\n}".to_string(),
            ],
        );
    }

    #[test]
    fn classify_response_follows_js_truthiness_on_2xx() {
        use RequestOutcome::*;
        // Falsy exactly where JavaScript is falsy.
        assert_eq!(classify_response(200, "false"), Falsy);
        assert_eq!(classify_response(200, "null"), Falsy);
        assert_eq!(classify_response(200, "0"), Falsy);
        assert_eq!(classify_response(200, "0.0"), Falsy);
        assert_eq!(classify_response(200, "-0"), Falsy);
        assert_eq!(classify_response(200, "\"\""), Falsy);
        // Surrounding whitespace doesn't change the verdict.
        assert_eq!(classify_response(200, "  0\n"), Falsy);

        // Truthy everywhere else — including empty collections, which are
        // truthy in JS.
        assert_eq!(classify_response(200, "[]"), Truthy);
        assert_eq!(classify_response(200, "{}"), Truthy);
        assert_eq!(classify_response(200, "true"), Truthy);
        assert_eq!(classify_response(200, "1"), Truthy);
        assert_eq!(classify_response(200, "-1"), Truthy);
        assert_eq!(classify_response(200, "\"Möör\""), Truthy);
        assert_eq!(classify_response(200, r#"[{"id":1}]"#), Truthy);
        // Non-JSON payloads (CSV, NDJSON) that reached a 2xx.
        assert_eq!(classify_response(200, "id,name\n1,Joe"), Truthy);
        // No body to test — the 2xx is the answer (204 from a DELETE).
        assert_eq!(classify_response(204, ""), Truthy);
        assert_eq!(classify_response(200, "   "), Truthy);
    }

    #[test]
    fn streaming_indicator_is_right_aligned_and_drops_when_cramped() {
        let hint = "ctrl+h for shortcuts";
        let mut state = AppState::new(Config::default());

        // Off by default — nothing is added to the hint line.
        state.width = 80;
        assert_eq!(streaming_indicator(&state, hint.len()), "");

        // On: the label stops `STREAMING_INDICATOR_MARGIN` columns short of the
        // edge. Overshooting would wrap and break the fixed-height input block.
        state.config.streaming = true;
        let indicator = streaming_indicator(&state, hint.len());
        let rendered = format!("  {}{}", hint, indicator);
        assert_eq!(visible_len(&rendered), 80 - STREAMING_INDICATOR_MARGIN);
        // Padding first, label last — the label ends at the margin.
        assert!(indicator.starts_with(' '));
        assert!(indicator.contains(STREAMING_INDICATOR));

        // Exactly enough room for indent + hint + a space + label + margin.
        state.width =
            (2 + hint.len() + 1 + STREAMING_INDICATOR.len() + STREAMING_INDICATOR_MARGIN) as u16;
        let rendered = format!("  {}{}", hint, streaming_indicator(&state, hint.len()));
        assert_eq!(
            visible_len(&rendered),
            state.width as usize - STREAMING_INDICATOR_MARGIN
        );

        // One column short: the hint is the more useful of the two, so the
        // indicator gives way rather than wrapping.
        state.width -= 1;
        assert_eq!(streaming_indicator(&state, hint.len()), "");
    }

    #[test]
    fn help_block_height_tracks_the_streaming_section() {
        // The help panel is cleared by a line count, so a mismatch between what
        // is drawn and what is counted corrupts the screen on close.
        let mut state = AppState::new(Config::default());
        state.width = 80;
        state.height = 60;
        let plain = help_line_count(&state);
        assert_eq!(plain, 27, "the ruler, a blank row, 24 lines and the closing line");

        // On a terminal too short for it the panel is cut to what can be
        // cleared again: the ruler, its rows and the cursor's row all fit.
        for height in [24u16, 12, 6] {
            state.height = height;
            let rows = help_rows(&state);
            assert_eq!(help_line_count(&state), height - 1, "height {height}");
            assert!(rows.last().unwrap().contains("more rows"), "height {height}: {:?}", rows.last());
            assert!(rows.last().unwrap().contains("ctrl+h or esc to close"));
        }
        state.height = 28;
        assert_eq!(help_line_count(&state), 27);
        assert!(!help_rows(&state).last().unwrap().contains("more rows"));
        state.height = 60;

        state.config.base_uri = "http://localhost:5000".to_string();
        state.config.streaming = true;
        let lines = streaming_help_lines(&state.config.base_uri);
        assert_eq!(
            help_line_count(&state),
            plain + 1 + lines.len() as u16,
            "at 80 columns nothing wraps, so it's one row per line"
        );

        // The link carries the connection's host. A host long enough to wrap it
        // must be counted as the rows it actually occupies, or closing help
        // leaves the tail of the link on screen.
        state.config.base_uri = format!("https://{}.example.com", "x".repeat(60));
        let wrapped = streaming_help_lines(&state.config.base_uri);
        let link_rows = visual_line_count(wrapped.last().unwrap(), 80);
        assert!(link_rows > 1, "test needs a base URI long enough to wrap");
        assert_eq!(
            help_line_count(&state),
            plain + 1 + (wrapped.len() as u16 - 1) + link_rows
        );
    }

    #[test]
    fn streaming_help_links_to_the_connections_own_docs() {
        // Deep-links into the same docs ctrl+b opens, not a fixed host.
        let lines = streaming_help_lines("http://localhost:5000");
        let link = lines.last().expect("link line");
        assert_eq!(
            link.trim(),
            "http://localhost:5000/api-docs#description/streaming"
        );

        // Before a connection exists, fall back to the public docs.
        let lines = streaming_help_lines("");
        assert_eq!(
            lines.last().unwrap().trim(),
            "https://dev.heads.com/api-docs#description/streaming"
        );

        // A blank line separates the prose from the link.
        assert_eq!(lines[lines.len() - 2], "");
    }

    #[test]
    fn streaming_help_lines_fit_without_wrapping() {
        // A wrapped line would print more rows than `help_line_count` claims.
        for line in STREAMING_HELP_PROSE {
            assert!(
                line.chars().count() <= STREAMING_HELP_MAX_COLS,
                "help line too long ({}): {line}",
                line.chars().count()
            );
        }
        // The footer notice has to fit beside the indicator at 80 columns.
        assert!(
            2 + STREAMING_INFO_MSG.chars().count()
                + 1
                + STREAMING_INDICATOR.len()
                + STREAMING_INDICATOR_MARGIN
                <= 80,
            "notice + indicator must fit on one 80-column line"
        );
    }

    #[test]
    fn stream_pulse_shade_swings_dim_white_dim_each_period() {
        assert_eq!(stream_pulse_shade(Duration::ZERO), 240);
        assert_eq!(stream_pulse_shade(STREAM_PULSE_PERIOD / 2), 255);
        assert_eq!(stream_pulse_shade(STREAM_PULSE_PERIOD), 240);
        assert_eq!(stream_pulse_shade(STREAM_PULSE_PERIOD * 3 / 2), 255);
        for ms in (0..3000).step_by(40) {
            let shade = stream_pulse_shade(Duration::from_millis(ms));
            assert!((240..=255).contains(&shade), "{ms}ms gave {shade}");
        }
    }

    #[test]
    fn stream_pulse_runs_only_while_bytes_keep_arriving() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut pulse = StreamPulse::new();

        // Waiting for headers: nothing has arrived, so no pulse.
        assert_eq!(pulse.observe(0, at(0)), None);
        assert_eq!(pulse.observe(0, at(80)), None);

        // Data arrives: the pulse starts from zero and runs on.
        assert_eq!(pulse.observe(100, at(160)), Some(Duration::ZERO));
        assert_eq!(pulse.observe(200, at(240)), Some(Duration::from_millis(80)));
        // A tick with no new bytes is inside the linger, so no flicker.
        assert_eq!(pulse.observe(200, at(320)), Some(Duration::from_millis(160)));

        // A stall past the linger settles the marker.
        assert_eq!(pulse.observe(200, at(240) + STREAM_PULSE_LINGER + Duration::from_millis(1)), None);

        // Resuming starts a fresh pulse rather than jumping mid-swing.
        assert_eq!(pulse.observe(300, at(2000)), Some(Duration::ZERO));
    }

    #[test]
    fn transient_hint_line_keeps_the_streaming_marker_in_place() {
        let mut state = AppState::new(Config::default());
        state.width = 80;
        let text = "⠙ 200 OK, received 12.4 MB";
        let plain_of = |line: &str| -> String {
            let mut out = String::new();
            let mut in_escape = false;
            for c in line.chars() {
                match (in_escape, c) {
                    (true, 'm') => in_escape = false,
                    (true, _) => {}
                    (false, '\x1b') => in_escape = true,
                    (false, c) => out.push(c),
                }
            }
            out
        };

        // Streaming off: the text alone.
        let off = transient_hint_line(&state, text, None);
        assert!(!off.contains(STREAMING_INDICATOR));

        // On: the marker ends at the same column as on the idle hint line,
        // however wide the spinner glyph is in bytes.
        state.config.streaming = true;
        let steady = transient_hint_line(&state, text, None);
        let plain = plain_of(&steady);
        assert!(plain.ends_with(STREAMING_INDICATOR));
        assert_eq!(plain.chars().count(), 80 - STREAMING_INDICATOR_MARGIN);
        assert!(plain.starts_with("  ⠙ 200 OK, received 12.4 MB "));

        // Pulsing: same place, brighter.
        let bright = transient_hint_line(&state, text, Some(STREAM_PULSE_PERIOD / 2));
        assert!(bright.contains("\x1b[38;5;255mstreaming"), "{bright:?}");
        assert_eq!(
            plain_of(&bright),
            plain,
            "the pulse changes colour only"
        );

        // Too narrow for both: the progress text wins.
        state.width = (2 + text.chars().count() + STREAMING_INDICATOR.len() + STREAMING_INDICATOR_MARGIN) as u16;
        assert!(!transient_hint_line(&state, text, None).contains(STREAMING_INDICATOR));
    }

    #[test]
    fn streaming_indicator_pulses_bright_then_settles() {
        let hint = "ctrl+h for shortcuts";
        let mut state = AppState::new(Config::default());
        state.width = 80;
        state.config.streaming = true;

        let shade_at = |state: &mut AppState, ms: u64| -> Option<u16> {
            state.streaming_flash_at = Instant::now().checked_sub(Duration::from_millis(ms));
            let s = streaming_indicator(state, hint.len());
            // Pull the 256-colour index back out of the escape sequence.
            s.split("38;5;")
                .nth(1)
                .and_then(|rest| rest.split('m').next())
                .and_then(|n| n.parse::<u16>().ok())
        };

        // Peaks of the two peaks, and the trough between them.
        assert_eq!(shade_at(&mut state, 75), Some(255), "first pulse should peak white");
        assert_eq!(shade_at(&mut state, 275), Some(255), "second pulse should peak white");
        let trough = shade_at(&mut state, 175);
        assert!(
            trough.is_none() || trough == Some(240),
            "between pulses the indicator sits dim, got {trough:?}"
        );

        // Past the envelope it settles and the flash is cleared by the loop.
        let settled = shade_at(&mut state, 500);
        assert!(
            settled.is_none() || settled == Some(240),
            "after the flash it should be dimmed, got {settled:?}"
        );
    }

    #[test]
    fn streaming_info_shows_on_every_activation() {
        let mut state = AppState::new(Config::default());

        // Every activation puts the caveat up — it confirms the state change,
        // so it must not fall silent after the first one.
        for _ in 0..3 {
            show_streaming_info(&mut state);
            assert_eq!(state.status_msg, STREAMING_INFO_MSG);

            // Switching off takes it down with the state it describes.
            clear_streaming_info(&mut state);
            assert!(state.status_msg.is_empty());
            assert!(state.status_msg_at.is_none());
        }
    }

    #[test]
    fn clearing_streaming_info_leaves_other_messages_alone() {
        // Toggling streaming off must not wipe an unrelated notice that
        // happens to be up at the time.
        let mut state = AppState::new(Config::default());
        state.status_msg = "curl command copied to clipboard".to_string();
        state.status_msg_at = Some(Instant::now());

        clear_streaming_info(&mut state);
        assert_eq!(state.status_msg, "curl command copied to clipboard");
        assert!(state.status_msg_at.is_some());
    }


    #[test]
    fn classify_streamed_matches_buffered_within_the_prefix() {
        use RequestOutcome::*;
        // A body that fit in the retained prefix decides exactly as a buffered
        // read would — streaming must not change chain semantics.
        for body in ["false", "null", "0", "\"\"", "[]", "{}", "true", "[{\"id\":1}]"] {
            assert_eq!(
                classify_streamed(200, body, false),
                classify_response(200, body),
                "streamed verdict diverged for {body}"
            );
        }
    }

    #[test]
    fn progress_text_counts_the_wait_until_headers_arrive() {
        let waiting = ProgressSnapshot { status: None, received: 0, total: None };
        assert_eq!(
            progress_text(&waiting, Duration::from_millis(600), true),
            "waiting for response..."
        );
        assert_eq!(
            progress_text(&waiting, Duration::from_secs(4), true),
            "waiting for response... 4s"
        );
        assert_eq!(
            progress_text(&waiting, Duration::from_secs(100), false),
            "waiting for response... 1m40s"
        );
    }

    #[test]
    fn progress_text_shows_bytes_and_a_percentage_only_with_a_length() {
        let elapsed = Duration::from_secs(2);
        let chunked = ProgressSnapshot { status: Some(200), received: 13_002_342, total: None };
        assert_eq!(progress_text(&chunked, elapsed, true), "200 OK, received 12.4 MB");

        let sized = ProgressSnapshot {
            status: Some(200),
            received: 13_002_342,
            total: Some(49_388_954),
        };
        assert_eq!(
            progress_text(&sized, elapsed, true),
            "200 OK, received 12.4 MB of 47.1 MB (26%)"
        );
        // The batch sender has the status line on screen already.
        assert_eq!(
            progress_text(&sized, elapsed, false),
            "received 12.4 MB of 47.1 MB (26%)"
        );

        let not_found = ProgressSnapshot { status: Some(404), received: 102, total: Some(102) };
        assert_eq!(
            progress_text(&not_found, elapsed, true),
            "404 Not Found, received 102 B of 102 B (100%)"
        );
    }

    #[test]
    fn progress_text_survives_odd_lengths_and_statuses() {
        let elapsed = Duration::from_secs(2);
        // A declared length of zero leaves nothing to take a percentage of.
        let empty = ProgressSnapshot { status: Some(204), received: 0, total: Some(0) };
        assert_eq!(progress_text(&empty, elapsed, true), "204 No Content, received 0 B");
        // More than promised never reads as more than all of it.
        let over = ProgressSnapshot { status: Some(200), received: 300, total: Some(200) };
        assert_eq!(
            progress_text(&over, elapsed, true),
            "200 OK, received 300 B of 200 B (100%)"
        );
        // A status with no canonical reason leaves no stray space.
        let odd = ProgressSnapshot { status: Some(299), received: 5, total: None };
        assert_eq!(progress_text(&odd, elapsed, true), "299, received 5 B");
    }

    #[test]
    fn transfer_progress_starts_out_waiting_with_no_length() {
        let progress = TransferProgress::new();
        assert_eq!(
            progress.snapshot(),
            ProgressSnapshot { status: None, received: 0, total: None }
        );
    }

    #[test]
    fn counting_reader_counts_what_it_passes_through() {
        let progress = TransferProgress::new();
        let body = vec![b'x'; 100_000];
        let mut sink = Vec::new();
        let streamed =
            stream_to_sink(CountingReader::new(&body[..], &progress), &mut sink).unwrap();
        assert_eq!(sink, body);
        assert_eq!(streamed.bytes, 100_000);
        assert_eq!(progress.snapshot().received, 100_000);
    }

    #[test]
    fn charset_of_reads_the_content_type_parameter() {
        assert_eq!(charset_of("application/json"), None);
        assert_eq!(charset_of("application/json; charset=utf-8"), Some("utf-8"));
        assert_eq!(charset_of("text/html;Charset=\"ISO-8859-1\""), Some("ISO-8859-1"));
        assert_eq!(charset_of("application/json;stream=true; charset=UTF-8"), Some("UTF-8"));
        // Only a parameter counts, not the word in the media type.
        assert_eq!(charset_of("text/charset=x"), None);
    }

    #[test]
    fn decode_body_matches_what_reqwest_text_would_give() {
        assert_eq!(decode_body("{\"name\":\"Åsa\"}".as_bytes(), None), "{\"name\":\"Åsa\"}");
        // A byte-order mark is dropped, as `text()` drops it.
        assert_eq!(decode_body(b"\xEF\xBB\xBF[1]", Some("application/json")), "[1]");
        // A declared charset is honoured.
        assert_eq!(decode_body(b"\xC5sa", Some("text/plain; charset=iso-8859-1")), "Åsa");
        // An unknown one falls back to UTF-8, invalid bytes replaced rather than fatal.
        assert_eq!(decode_body(b"a\xFFb", Some("text/plain; charset=nonsense")), "a\u{FFFD}b");
    }

    #[test]
    fn io_error_is_timeout_recognises_a_timed_out_read() {
        assert!(io_error_is_timeout(&io::Error::new(io::ErrorKind::TimedOut, "slow")));
        assert!(!io_error_is_timeout(&io::Error::new(io::ErrorKind::ConnectionReset, "gone")));
    }

    #[test]
    fn a_disabled_ticker_starts_no_thread() {
        let mut ticker = ProgressTicker::start(TransferProgress::new(), false);
        assert!(ticker.handle.is_none());
        let mut printed = false;
        ticker.interrupt(|| printed = true);
        assert!(printed, "the caller's own output still runs");
        ticker.stop();
    }

    #[test]
    fn classify_streamed_treats_overflow_as_truthy() {
        use RequestOutcome::*;
        // Past the prefix the payload can only be a big collection, and no falsy
        // JSON literal is that long — so the truncated prefix must not be judged
        // on its own (`[{"id":1},...` is not parseable JSON).
        assert_eq!(classify_streamed(200, r#"[{"id":1},{"i"#, true), Truthy);
        // Overflow doesn't rescue a non-2xx: those still fall to the status.
        assert_eq!(classify_streamed(404, "a long error page", true), Falsy);
        assert_eq!(classify_streamed(500, "a long error page", true), Errored);
    }

    #[test]
    fn stream_to_sink_reports_overflow_only_past_the_prefix() {
        // Exactly at the boundary is not an overflow — the whole body is still
        // available for classification.
        let body = vec![b'x'; CLASSIFY_PREFIX_BYTES];
        let mut out = Vec::new();
        let got = stream_to_sink(&body[..], &mut out).unwrap();
        assert_eq!(out.len(), CLASSIFY_PREFIX_BYTES);
        assert_eq!(got.prefix.len(), CLASSIFY_PREFIX_BYTES);
        assert!(!got.overflowed);
        assert_eq!(got.bytes, CLASSIFY_PREFIX_BYTES as u64);

        // One byte more, and the prefix caps while the sink still gets it all.
        let body = vec![b'x'; CLASSIFY_PREFIX_BYTES + 1];
        let mut out = Vec::new();
        let got = stream_to_sink(&body[..], &mut out).unwrap();
        assert_eq!(out.len(), CLASSIFY_PREFIX_BYTES + 1);
        assert_eq!(got.prefix.len(), CLASSIFY_PREFIX_BYTES);
        assert!(got.overflowed);
    }

    #[test]
    fn stream_to_sink_reports_the_last_byte_for_newline_matching() {
        // Drives whether the stdout path adds the trailing newline that the
        // buffered path always appends.
        let got = stream_to_sink(&b"[1,2]"[..], &mut Vec::new()).unwrap();
        assert_eq!(got.last_byte, Some(b']'));

        let got = stream_to_sink(&b"[1,2]\n"[..], &mut Vec::new()).unwrap();
        assert_eq!(got.last_byte, Some(b'\n'));

        // An empty body must not gain a newline out of nowhere.
        let got = stream_to_sink(&b""[..], &mut Vec::new()).unwrap();
        assert_eq!(got.last_byte, None);
        assert!(!got.overflowed);
        assert!(got.prefix.is_empty());
    }

    #[test]
    fn env_streaming_accepts_only_truthy_words() {
        // Guard the parsing rule itself; the env var is read in one place.
        for v in ["1", "true", "TRUE", " yes ", "on"] {
            assert!(
                matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
                "{v} should enable streaming"
            );
        }
        for v in ["0", "false", "off", "no", "", "maybe"] {
            assert!(
                !matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
                "{v} should not enable streaming"
            );
        }
    }

    #[test]
    fn classify_response_separates_no_from_could_not_answer() {
        use RequestOutcome::*;
        // A definite "no" — stops a chain, but nothing went wrong.
        assert_eq!(classify_response(404, ""), Falsy);
        assert_eq!(classify_response(400, "bad request"), Falsy);
        assert_eq!(classify_response(409, ""), Falsy);
        // Even a body that looks truthy can't rescue a non-2xx.
        assert_eq!(classify_response(404, r#"{"error":"nope"}"#), Falsy);

        // Credentials, server faults, and backpressure never read as "no" —
        // treating these as falsy would silently skip a chained write.
        assert_eq!(classify_response(401, ""), Errored);
        assert_eq!(classify_response(403, ""), Errored);
        assert_eq!(classify_response(408, ""), Errored);
        assert_eq!(classify_response(429, ""), Errored);
        assert_eq!(classify_response(500, ""), Errored);
        assert_eq!(classify_response(503, ""), Errored);
    }

    #[test]
    fn bulk_program_splits_chained_lines_into_chain_steps() {
        let src = "GET /people/123 && PUT /people/123 {\n  \"name\": \"Joe\"\n}\nGET /plain\n";
        let prog = split_bulk_requests(src, None).expect("parse");
        assert_eq!(prog.steps.len(), 2, "got: {:?}", prog.steps);
        match &prog.steps[0] {
            BulkStep::Chain(segments) => {
                assert_eq!(segments.len(), 2, "got: {segments:?}");
                assert_eq!(segments[0], (ChainOp::And, "GET /people/123".to_string()));
                assert_eq!(segments[1].0, ChainOp::And);
                assert!(segments[1].1.starts_with("PUT /people/123 {"), "got: {}", segments[1].1);
                assert!(segments[1].1.contains("Joe"));
            }
            other => panic!("expected a chain, got: {other:?}"),
        }
        // An unchained line stays a plain request.
        assert!(matches!(&prog.steps[1], BulkStep::Request(r) if r.starts_with("GET /plain")));
    }

    #[test]
    fn extract_identifier_pairs_tolerates_trailing_comma() {
        // Copying one entry out of a larger array/object leaves a trailing comma.
        let s = "{\n  \"@type\": \"common identifiers\",\n  \"key\": \"97454f6f\",\n  \"com.heads.id\": \"omnium-out\"\n},\n";
        let pairs = extract_identifier_pairs(s);
        assert_eq!(pairs.len(), 2, "got: {pairs:?}");
        assert_eq!(pairs[0], ("key".to_string(), "97454f6f".to_string()));
        assert_eq!(pairs[1], ("com.heads.id".to_string(), "omnium-out".to_string()));
    }

    #[test]
    fn extract_identifier_pairs_accepts_bare_property_wrapper() {
        // The selection included the property label the identifiers sit under.
        let s = "\"identifiers\": {\n  \"@type\": \"common identifiers\",\n  \"key\": \"97454f6f\",\n  \"com.heads.id\": \"omnium-out\"\n},";
        let pairs = extract_identifier_pairs(s);
        assert_eq!(pairs.len(), 2, "got: {pairs:?}");
        assert_eq!(pairs[0], ("key".to_string(), "97454f6f".to_string()));
        assert_eq!(pairs[1], ("com.heads.id".to_string(), "omnium-out".to_string()));

        // Without the trailing comma too.
        let no_comma = r#""identifiers": { "com.heads.id": "x" }"#;
        assert_eq!(
            extract_identifier_pairs(no_comma),
            vec![("com.heads.id".to_string(), "x".to_string())]
        );
    }

    #[test]
    fn extract_identifier_pairs_only_unwraps_the_identifiers_key() {
        // `identifiers` is the only bare property repaired into an object — a
        // fragment labelled with any other key stays unparsed, even when its
        // contents look exactly like identifiers.
        let named = r#""whateverTheyCallIt": { "com.heads.id": "x" }"#;
        assert_eq!(extract_identifier_pairs(named), Vec::<(String, String)>::new());

        // Including a bare string-valued property (would otherwise be case 2).
        let bare_string = r#""com.heads.id": "x""#;
        assert_eq!(extract_identifier_pairs(bare_string), Vec::<(String, String)>::new());

        // Braced-but-nested objects aren't searched either: no unwrapping of a
        // lone object-valued property...
        let wrapped = r#"{ "address": { "street": "Main" } }"#;
        assert_eq!(extract_identifier_pairs(wrapped), Vec::<(String, String)>::new());

        // ...and only a direct `identifiers` child counts, not a deeper one.
        let nested = r#"{ "outer": { "identifiers": { "com.heads.id": "x" } } }"#;
        assert_eq!(extract_identifier_pairs(nested), Vec::<(String, String)>::new());
    }

    #[test]
    fn extract_identifier_pairs_rejects_unrecoverable_fragments() {
        // A stray comma doesn't make broken JSON parse.
        assert_eq!(extract_identifier_pairs("not json,"), Vec::<(String, String)>::new());
        assert_eq!(extract_identifier_pairs(","), Vec::<(String, String)>::new());
        assert_eq!(extract_identifier_pairs("\"unterminated: {"), Vec::<(String, String)>::new());
        // A bare string is valid JSON but not an object.
        assert_eq!(extract_identifier_pairs("\"just a string\""), Vec::<(String, String)>::new());
    }

    #[test]
    fn extract_identifier_pairs_empty_identifiers_falls_through() {
        // Empty "identifiers" object — case 1 yields nothing, case 2 then sees the
        // outer object whose other values aren't all strings, so nothing returned.
        let s = r#"{ "identifiers": {}, "name": "Bob" }"#;
        assert_eq!(extract_identifier_pairs(s), Vec::<(String, String)>::new());
    }

    // ----- import git -----

    /// Point the import cache at a scratch directory, once for the whole test
    /// binary: the variable is process-wide.
    fn use_test_import_cache() {
        static CACHE: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        let dir = CACHE.get_or_init(|| tempfile::tempdir().unwrap());
        std::env::set_var("API_IMPORT_CACHE", dir.path());
    }

    fn test_git(dir: &std::path::Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
            .args(args)
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A repository holding `files`, committed and tagged `1.0`. Returns the
    /// directory guard, its `file://` URL and the commit.
    fn test_repo(files: &[(&str, &str)]) -> (tempfile::TempDir, String, String) {
        use_test_import_cache();
        let dir = tempfile::tempdir().unwrap();
        test_git(dir.path(), &["init", "-q", "-b", "main"]);
        for (name, contents) in files {
            let path = dir.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        test_git(dir.path(), &["add", "-A"]);
        test_git(dir.path(), &["commit", "-q", "-m", "seed"]);
        test_git(dir.path(), &["tag", "-a", "1.0", "-m", "one"]);
        let sha = test_git(dir.path(), &["rev-parse", "HEAD"]);
        let url = format!("file://{}", dir.path().canonicalize().unwrap().display());
        (dir, url, sha)
    }

    fn requests_of(program: &BulkProgram) -> Vec<String> {
        program
            .steps
            .iter()
            .flat_map(|step| match step {
                BulkStep::Request(r) => vec![r.clone()],
                BulkStep::Chain(segments) => segments.iter().map(|(_, s)| s.clone()).collect(),
                _ => Vec::new(),
            })
            .collect()
    }

    #[test]
    fn import_directive_parses_its_json() {
        let spec = parse_import_directive(
            r#"import git cl { "url": "https://github.com/Polyjuice/cloddy", "ref": "2.1.0", "path": "seeds" }"#,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            spec,
            ImportSpec {
                alias: "cl".to_string(),
                source: ImportSource::Git {
                    url: "https://github.com/Polyjuice/cloddy".to_string(),
                    git_ref: "2.1.0".to_string(),
                },
                path: Some("seeds".to_string()),
            }
        );
        assert_eq!(
            parse_import_directive(r#"import dir cl { "path": "~/Source/cloddy" }"#, None, None).unwrap(),
            ImportSpec {
                alias: "cl".to_string(),
                source: ImportSource::Dir { path: "~/Source/cloddy".to_string() },
                path: None,
            }
        );
        let sha = "9F2C".repeat(16);
        assert_eq!(
            parse_import_directive(
                &format!(
                    r#"import ARCHIVE cl {{ "url": "https://example.com/c.tar.gz", "sha256": "{sha}", "token_env": "ARTIFACT_TOKEN", "path": "seeds" }}"#
                ),
                None,
                None
            )
            .unwrap(),
            ImportSpec {
                alias: "cl".to_string(),
                source: ImportSource::Archive {
                    url: "https://example.com/c.tar.gz".to_string(),
                    sha256: Some(sha.to_lowercase()),
                    token_env: Some("ARTIFACT_TOKEN".to_string()),
                },
                path: Some("seeds".to_string()),
            }
        );
        // Plain http is for this machine only.
        for url in ["http://localhost:8080/c.zip", "http://127.0.0.1/c.zip", "file:///tmp/c.zip"] {
            let line = format!(r#"import archive cl {{ "url": "{url}" }}"#);
            assert!(parse_import_directive(&line, None, None).is_ok(), "{url}");
        }
        // The scp-like spelling of ssh is a URL too.
        assert!(parse_import_directive(
            r#"import git cl { "url": "git@github.com:Polyjuice/cloddy.git", "ref": "main" }"#,
            None,
            None
        )
        .is_ok());
    }

    #[test]
    fn import_directive_rejects_what_it_cannot_mean() {
        let ok_body = r#"{ "url": "https://example.com/r", "ref": "1.0" }"#;
        for (line, expected) in [
            ("import".to_string(), "incomplete import"),
            ("import git cl".to_string(), "incomplete import"),
            (format!("import svn cl {ok_body}"), "unknown import kind `svn`"),
            (format!("import git get {ok_body}"), "invalid import alias `get`"),
            (format!("import git sleep {ok_body}"), "invalid import alias `sleep`"),
            (format!("import git a/b {ok_body}"), "invalid import alias `a/b`"),
            ("import git cl https://example.com/r".to_string(), "invalid import"),
            ("import git cl [1]".to_string(), "invalid import"),
            (r#"import git cl { "url": "https://example.com/r" }"#.to_string(), "`ref` is required"),
            (r#"import git cl { "ref": "1.0" }"#.to_string(), "`url` is required"),
            (r#"import git cl { "url": "https://example.com/r", "ref": 2.1 }"#.to_string(), "`ref` must be a non-empty string"),
            (r#"import git cl { "url": "https://example.com/r", "ref": "1.0", "tag": "x" }"#.to_string(), "unknown key `tag`"),
            (r#"import git cl { "url": "http://example.com/r", "ref": "1.0" }"#.to_string(), "unsupported url"),
            (r#"import git cl { "url": "--upload-pack=touch /tmp/x", "ref": "1.0" }"#.to_string(), "unsupported url"),
            (r#"import git cl { "url": "ext::sh -c id", "ref": "1.0" }"#.to_string(), "unsupported url"),
            (r#"import git cl { "url": "/some/local/dir", "ref": "1.0" }"#.to_string(), "unsupported url"),
            (r#"import git cl { "url": "https://example.com/r", "ref": "--orphan" }"#.to_string(), "invalid ref"),
            (r#"import git cl { "url": "https://example.com/r", "ref": "1.0", "path": "../x" }"#.to_string(), "`path` must be a relative path"),
            (r#"import git cl { "url": "https://example.com/r", "ref": "1.0", "path": "/etc" }"#.to_string(), "`path` must be a relative path"),
            ("import git cl @imports/*.json".to_string(), "reads one JSON file"),
            (r#"import dir cl { "url": "https://example.com/r" }"#.to_string(), "unknown key `url` (expected `path`)"),
            (r#"import dir cl {}"#.to_string(), "`path` is required"),
            (r#"import archive cl { "sha256": "ab" }"#.to_string(), "`url` is required"),
            (r#"import archive cl { "url": "https://example.com/c.zip", "ref": "1.0" }"#.to_string(), "unknown key `ref`"),
            (r#"import archive cl { "url": "http://example.com/c.zip" }"#.to_string(), "unsupported url"),
            (r#"import archive cl { "url": "ftp://example.com/c.zip" }"#.to_string(), "unsupported url"),
            (r#"import archive cl { "url": "git@example.com:c.zip" }"#.to_string(), "unsupported url"),
            (r#"import archive cl { "url": "file://relative/c.zip" }"#.to_string(), "unsupported url"),
            (r#"import archive cl { "url": "https://example.com/c.zip", "sha256": "abc123" }"#.to_string(), "`sha256` must be 64 hexadecimal characters"),
            (r#"import archive cl { "url": "https://example.com/c.zip", "token_env": "ghp_secret-value" }"#.to_string(), "names an environment variable"),
            (r#"import archive cl { "url": "https://example.com/c.zip", "path": "../x" }"#.to_string(), "`path` must be a relative path"),
            ("import git cl @cloddy.json~map(x)".to_string(), "takes no `~map(…)` suffix"),
        ] {
            let err = parse_import_directive(&line, None, None).unwrap_err();
            assert!(err.contains(expected), "{line:?} gave {err:?}");
        }
    }

    #[test]
    fn pick_remote_ref_prefers_a_tags_commit_then_the_tag_then_the_branch() {
        let listing = "aaa\trefs/heads/1.0\nbbb\trefs/tags/1.0\nccc\trefs/tags/1.0^{}\nddd\trefs/tags/other/1.0\n";
        assert_eq!(pick_remote_ref(listing, "1.0"), Some(("ccc".to_string(), "refs/tags/1.0".to_string())));
        let lightweight = "aaa\trefs/heads/1.0\nbbb\trefs/tags/1.0\n";
        assert_eq!(pick_remote_ref(lightweight, "1.0"), Some(("bbb".to_string(), "refs/tags/1.0".to_string())));
        assert_eq!(
            pick_remote_ref("aaa\trefs/heads/main\n", "main"),
            Some(("aaa".to_string(), "refs/heads/main".to_string()))
        );
        assert_eq!(
            pick_remote_ref("aaa\trefs/heads/main\n", "refs/heads/main"),
            Some(("aaa".to_string(), "refs/heads/main".to_string()))
        );
        // A tail match on another name is not the ref that was asked for.
        assert_eq!(pick_remote_ref("ddd\trefs/tags/other/1.0\n", "1.0"), None);
        assert_eq!(pick_remote_ref("", "1.0"), None);
    }

    #[test]
    fn import_cache_key_is_readable_and_tells_similar_urls_apart() {
        let key = import_cache_key("https://github.com/Polyjuice/cloddy");
        assert!(key.starts_with("https_github.com_Polyjuice_cloddy-"), "{key}");
        assert_eq!(key, import_cache_key("https://github.com/Polyjuice/cloddy"));
        assert_ne!(key, import_cache_key("https://github.com/Polyjuice_cloddy"));
    }

    #[test]
    fn import_makes_a_repository_includable_under_its_alias() {
        let (_repo, url, sha) = test_repo(&[
            ("sv.api", "url has localhost\nGET /sv\nPUT /sv @data/sv.json~map(x) > out.json\nsub/inner.api\n"),
            ("sub/inner.api", "GET /inner && PUT /inner @../data/sv.json\n"),
            ("data/sv.json", "{\"a\":1}"),
            ("other.api", "GET /other\n"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        // A body spanning lines, with a comment, as a request's may.
        let src = format!(
            "import git cl {{\n  \"url\": \"{url}\", // the seeds\n  \"ref\": \"1.0\"\n}}\n\nGET /before\ncl/sv.api\nGET /after\n"
        );
        let program = split_bulk_requests(&src, Some(dir.path())).unwrap();

        let checkout = import_cache_dir().unwrap().join(import_cache_key(&url)).join(&sha);
        let checkout = checkout.canonicalize().unwrap();
        let data = checkout.join("data/sv.json");
        assert_eq!(
            requests_of(&program),
            vec![
                "GET /before".to_string(),
                "GET /sv".to_string(),
                // A file body is a file in the repository, wherever the batch runs.
                format!("PUT /sv @{}~map(x) > out.json", data.display()),
                "GET /inner".to_string(),
                format!("PUT /inner @{}", data.display()),
                "GET /after".to_string(),
            ]
        );
        // The history is not kept, only the files.
        assert!(!checkout.join(".git").exists());
        assert_eq!(
            program.import_notes,
            vec![ImportNote { text: format!("import cl {url} 1.0 ({})", &sha[..7]), stale: false }]
        );

        // The repository's `url` line is a gate of its own, not the batch's.
        assert!(program.url_conditions.is_empty());
        assert_eq!(program.import_gates.len(), 1);
        assert_eq!(program.import_gates[0].conditions, vec![UrlCondition::Has("localhost".to_string())]);
        assert!(evaluate_program_gates(&program, "http://localhost:5000").is_ok());
        let err = evaluate_program_gates(&program, "https://api.heads.com").unwrap_err();
        assert!(err.starts_with("import cl: URL gate failed"), "{err}");
    }

    #[test]
    fn an_imported_url_line_narrows_the_gate_and_never_widens_it() {
        let (_repo, url, _) = test_repo(&[("prod.api", "url has heads.com\nGET /x\n")]);
        let dir = tempfile::tempdir().unwrap();
        let src = format!(
            "url has localhost\nimport git lib {{ \"url\": \"{url}\", \"ref\": \"1.0\" }}\nlib/prod.api\n"
        );
        let program = split_bulk_requests(&src, Some(dir.path())).unwrap();
        // The batch allows localhost only; the import's `heads.com` adds nothing to that.
        assert!(evaluate_program_gates(&program, "https://api.heads.com").is_err());
        // And where the batch would run, the import still has its say.
        assert!(evaluate_program_gates(&program, "http://localhost:5000").is_err());
        assert!(evaluate_program_gates(&program, "http://localhost.heads.com").is_ok());
    }

    #[test]
    fn import_reads_its_json_from_an_at_file_and_honours_path() {
        let (_repo, url, _) = test_repo(&[("seeds/a.api", "GET /a\n"), ("top.api", "GET /top\n")]);
        let dir = tempfile::tempdir().unwrap();
        let json = dir.path().join("cloddy.json");
        fs::write(&json, format!("{{\n  // pinned\n  \"url\": \"{url}\",\n  \"ref\": \"1.0\",\n  \"path\": \"seeds\"\n}}\n")).unwrap();
        let src = format!("import git cl @{}\ncl/*.api\n", json.display());
        let program = split_bulk_requests(&src, Some(dir.path())).unwrap();
        assert_eq!(requests_of(&program), vec!["GET /a".to_string()]);

        let err = split_bulk_requests(&format!("import git cl @{}.missing\n", json.display()), Some(dir.path()))
            .unwrap_err();
        assert!(err.contains("cloddy.json.missing"), "{err}");

        let src = format!("import git cl {{ \"url\": \"{url}\", \"ref\": \"1.0\", \"path\": \"nope\" }}\n");
        let err = split_bulk_requests(&src, Some(dir.path())).unwrap_err();
        assert!(err.contains("no directory `nope`"), "{err}");
    }

    #[test]
    fn import_resolves_a_branch_and_a_commit_and_reports_a_missing_ref() {
        let (_repo, url, sha) = test_repo(&[("a.api", "GET /a\n")]);
        let dir = tempfile::tempdir().unwrap();
        for git_ref in ["main", sha.as_str()] {
            let src = format!("import git r {{ \"url\": \"{url}\", \"ref\": \"{git_ref}\" }}\nr/a.api\n");
            let program = split_bulk_requests(&src, Some(dir.path())).unwrap();
            assert_eq!(requests_of(&program), vec!["GET /a".to_string()], "{git_ref}");
            assert!(program.import_notes[0].text.ends_with(&format!("({})", &sha[..7])), "{git_ref}");
        }
        let src = format!("import git r {{ \"url\": \"{url}\", \"ref\": \"9.9\" }}\n");
        let err = split_bulk_requests(&src, Some(dir.path())).unwrap_err();
        assert_eq!(err, format!("import ref not found: 9.9 in {url}"));

        let src = "import git r { \"url\": \"file:///no/such/repo\", \"ref\": \"1.0\" }\n";
        let err = split_bulk_requests(src, Some(dir.path())).unwrap_err();
        assert!(err.starts_with("could not reach import file:///no/such/repo:"), "{err}");
    }

    #[test]
    fn an_alias_belongs_to_the_file_that_declares_it() {
        let (_repo, url, _) = test_repo(&[("a.api", "GET /a\n")]);
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("child.api"), "cl/a.api\n").unwrap();
        let import = format!("import git cl {{ \"url\": \"{url}\", \"ref\": \"1.0\" }}\n");

        // An included file does not see its parent's alias.
        let err = split_bulk_requests(&format!("{import}child.api\n"), Some(dir.path())).unwrap_err();
        assert_eq!(err, "include not found: cl/a.api");

        // Declared twice in one file.
        let err = split_bulk_requests(&format!("{import}{import}"), Some(dir.path())).unwrap_err();
        assert_eq!(err, "import alias `cl` is declared twice");

        // Used before it is declared.
        let err = split_bulk_requests(&format!("cl/a.api\n{import}"), Some(dir.path())).unwrap_err();
        assert_eq!(err, "include not found: cl/a.api");

        // A directory of the same name next to the file makes `cl/…` ambiguous.
        fs::create_dir(dir.path().join("cl")).unwrap();
        let err = split_bulk_requests(&import, Some(dir.path())).unwrap_err();
        assert!(err.starts_with("import alias `cl` clashes with "), "{err}");
    }

    #[test]
    fn an_imported_file_cannot_reach_outside_its_repository() {
        let (_repo, url, _) = test_repo(&[
            ("abs.api", "PUT /x @/etc/hosts\n"),
            ("home.api", "PUT /x @~/.ssh/id_rsa\n"),
            ("up.api", "PUT /x @../../../../etc/hosts\n"),
            ("glob.api", "PUT /x @../*.json\n"),
            ("include.api", "../../../outside.api\n"),
            ("ok.api", "GET /ok\n"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let import = format!("import git cl {{ \"url\": \"{url}\", \"ref\": \"1.0\" }}\n");
        for file in ["abs.api", "home.api", "up.api", "glob.api"] {
            let err = split_bulk_requests(&format!("{import}cl/{file}\n"), Some(dir.path())).unwrap_err();
            assert!(err.contains("must be a relative path inside the import"), "{file}: {err}");
        }
        let err = split_bulk_requests(&format!("{import}cl/include.api\n"), Some(dir.path())).unwrap_err();
        assert!(err.contains("include not found") || err.contains("leaves the import"), "{err}");

        // Nor can the alias be used to climb out of it.
        fs::write(dir.path().join("outside.api"), "GET /outside\n").unwrap();
        let checkout = match split_bulk_requests(&format!("{import}cl/ok.api\n"), Some(dir.path())) {
            Ok(_) => session_free_checkout(&url),
            Err(e) => panic!("{e}"),
        };
        let climb = pathdiff_up(&checkout, &dir.path().canonicalize().unwrap().join("outside.api"));
        let err = split_bulk_requests(&format!("{import}cl/{climb}\n"), Some(dir.path())).unwrap_err();
        assert!(err.contains("leaves the import"), "{err}");
    }

    /// The single checkout of `url` in the test cache.
    fn session_free_checkout(url: &str) -> PathBuf {
        let repo_cache = import_cache_dir().unwrap().join(import_cache_key(url));
        fs::read_dir(repo_cache)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.is_dir() && p.file_name().is_some_and(|n| n != "refs"))
            .unwrap()
            .canonicalize()
            .unwrap()
    }

    /// `target` written as a path relative to the directory `from`, climbing
    /// all the way to the root first.
    fn pathdiff_up(from: &std::path::Path, target: &std::path::Path) -> String {
        let ups = from.components().count() - 1;
        format!("{}{}", "../".repeat(ups), target.display().to_string().trim_start_matches('/'))
    }

    #[test]
    fn an_imported_repository_can_import_another() {
        let (_inner, inner_url, _) = test_repo(&[("leaf.api", "url has localhost\nGET /leaf\n")]);
        let (_outer, outer_url, _) = test_repo(&[(
            "top.api",
            &format!("import git dep {{ \"url\": \"{inner_url}\", \"ref\": \"1.0\" }}\nGET /top\ndep/leaf.api\n"),
        )]);
        let dir = tempfile::tempdir().unwrap();
        let src = format!("import git lib {{ \"url\": \"{outer_url}\", \"ref\": \"1.0\" }}\nlib/top.api\n");
        let program = split_bulk_requests(&src, Some(dir.path())).unwrap();
        assert_eq!(requests_of(&program), vec!["GET /top".to_string(), "GET /leaf".to_string()]);
        assert_eq!(program.import_notes.len(), 2);
        // The inner repository's gate is its own.
        assert_eq!(program.import_gates.len(), 1);
        assert_eq!(program.import_gates[0].alias, "dep");
    }

    #[test]
    fn a_session_alias_outlives_the_line_and_completes() {
        let (_repo, url, _) = test_repo(&[("sv.api", "GET /sv\n"), ("seeds/a.api", "GET /a\n"), ("notes.txt", "x")]);
        let line = format!("import git zzsession {{ \"url\": \"{url}\", \"ref\": \"1.0\" }}");
        assert!(matches!(classify_prompt_line(&line, None), PromptLine::Program));
        let program = split_bulk_requests_in_session(&line, None).unwrap();
        assert!(program.steps.is_empty());
        assert_eq!(program.import_notes.len(), 1);

        // A later line includes from it…
        let program = split_bulk_requests_in_session("zzsession/sv.api", None).unwrap();
        assert_eq!(requests_of(&program), vec!["GET /sv".to_string()]);
        // …and a line that never declared it elsewhere still can't.
        assert!(split_bulk_requests("zzsession/sv.api", None).is_err());

        assert_eq!(get_include_completions("zzsess"), vec!["zzsession/".to_string()]);
        assert_eq!(
            get_include_completions("zzsession/"),
            vec!["zzsession/seeds/".to_string(), "zzsession/sv.api".to_string()]
        );
        assert_eq!(get_include_completions("zzsession/seeds/"), vec!["zzsession/seeds/a.api".to_string()]);

        // Declaring it again at the prompt replaces it.
        assert!(split_bulk_requests_in_session(&line, None).is_ok());
    }

    #[test]
    fn the_prompt_looks_a_branch_up_again_for_every_import_line() {
        let (repo, url, first) = test_repo(&[("a.api", "GET /first\n")]);
        let import = format!("import git moving {{ \"url\": \"{url}\", \"ref\": \"main\" }}\nmoving/a.api\n");
        let dir = tempfile::tempdir().unwrap();
        let ran = |program: BulkProgram| (requests_of(&program), program.import_notes[0].text.clone());

        let (requests, note) = ran(split_bulk_requests(&import, Some(dir.path())).unwrap());
        assert_eq!(requests, vec!["GET /first".to_string()]);
        assert!(note.ends_with(&format!("({})", &first[..7])), "{note}");

        // The branch moves.
        fs::write(repo.path().join("a.api"), "GET /second\n").unwrap();
        test_git(repo.path(), &["commit", "-q", "-am", "second"]);
        let second = test_git(repo.path(), &["rev-parse", "HEAD"]);

        // A line run at the prompt asks the remote again. (That a batch asks
        // only once is tested in tests/imports.rs, by counting what git was
        // asked: here another test may clear what this process remembers.)
        let at_prompt = import.replace(" moving ", " zzmoving ").replace("moving/a.api", "zzmoving/a.api");
        let (requests, note) = ran(split_bulk_requests_in_session(&at_prompt, None).unwrap());
        assert_eq!(requests, vec!["GET /second".to_string()]);
        assert!(note.ends_with(&format!("({})", &second[..7])), "{note}");

        // An include on a later line uses what the alias was bound to; only
        // an `import` typed again looks the branch up.
        fs::write(repo.path().join("a.api"), "GET /third\n").unwrap();
        test_git(repo.path(), &["commit", "-q", "-am", "third"]);
        let program = split_bulk_requests_in_session("zzmoving/a.api", None).unwrap();
        assert_eq!(requests_of(&program), vec!["GET /second".to_string()]);
        let (requests, _) = ran(split_bulk_requests_in_session(&at_prompt, None).unwrap());
        assert_eq!(requests, vec!["GET /third".to_string()]);
    }

    /// Set a file's or a directory's modification time to `days` ago.
    #[cfg(unix)]
    fn age(path: &std::path::Path, days: u64) {
        let then = std::time::SystemTime::now() - Duration::from_secs(days * 24 * 60 * 60);
        fs::File::open(path).unwrap().set_modified(then).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prune_import_cache_removes_what_went_unused_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path();
        let repo = cache.join("https_example.com_r-0123456789abcdef");
        let archives = cache.join("archives");
        let sha = |c: char, n: usize| c.to_string().repeat(n);
        // (directory, days since its marker was touched; None for no marker)
        let stale = repo.join(sha('a', 40));
        let recent = repo.join(sha('b', 40));
        let unmarked_old = repo.join(sha('c', 40));
        let unmarked_new = repo.join(sha('d', 40));
        let kept = repo.join(sha('e', 40));
        let stale_archive = archives.join(sha('f', 64));
        let recent_archive = archives.join(sha('0', 64));
        let dead_fetch = repo.join(".tmp-1-2-3");
        let live_fetch = repo.join(".tmp-4-5-6");
        let refs = repo.join("refs");
        for path in [
            &stale, &recent, &unmarked_old, &unmarked_new, &kept, &stale_archive, &recent_archive, &dead_fetch,
            &live_fetch, &refs,
        ] {
            fs::create_dir_all(path).unwrap();
            fs::write(path.join("file"), "x").unwrap();
        }
        for (path, days) in [(&stale, 31), (&recent, 29), (&kept, 400), (&stale_archive, 90), (&recent_archive, 1)] {
            mark_import_used(path);
            age(&import_used_marker(path), days);
        }
        // Without a marker the directory's own age stands in.
        for path in [&unmarked_old, &dead_fetch, &refs] {
            age(path, 60);
        }
        // An old directory that was used yesterday is not old.
        age(&recent, 400);

        prune_import_cache(cache, &kept, IMPORT_CACHE_MAX_AGE);

        for gone in [&stale, &unmarked_old, &stale_archive, &dead_fetch] {
            assert!(!gone.exists(), "{} should have been pruned", gone.display());
        }
        assert!(!import_used_marker(&stale).exists());
        assert!(!import_used_marker(&stale_archive).exists());
        // The one this run fetched stays whatever its marker says; `refs` is
        // not a checkout, however old.
        for stays in [&recent, &unmarked_new, &kept, &recent_archive, &live_fetch, &refs] {
            assert!(stays.join("file").is_file(), "{} should have been kept", stays.display());
        }
        assert!(import_used_marker(&recent).is_file());

        // A cache that doesn't exist is nothing to prune.
        prune_import_cache(&cache.join("nope"), &kept, IMPORT_CACHE_MAX_AGE);
        assert_eq!(IMPORT_CACHE_MAX_AGE, Duration::from_secs(30 * 24 * 60 * 60));
    }

    #[test]
    fn using_an_import_marks_it_used_beside_the_checkout_not_in_it() {
        let (_repo, url, sha) = test_repo(&[("a.api", "GET /a\n")]);
        let dir = tempfile::tempdir().unwrap();
        let src = format!("import git r {{ \"url\": \"{url}\", \"ref\": \"1.0\" }}\nr/a.api\n");
        split_bulk_requests(&src, Some(dir.path())).unwrap();
        let checkout = import_cache_dir().unwrap().join(import_cache_key(&url)).join(&sha);
        assert!(import_used_marker(&checkout).is_file());
        assert_eq!(import_used_marker(&checkout).file_name().unwrap().to_string_lossy(), format!("{sha}.used"));
        let inside: Vec<String> = fs::read_dir(&checkout)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(inside, vec!["a.api".to_string()]);
    }

    // ----- --export -----

    const SEED: &str = "com.heads.seedID";

    /// `json` after `--export`, compact, and where its masked values were.
    fn exported(json: &str) -> (String, Vec<String>) {
        let mut value: Value = serde_json::from_str(json).unwrap();
        let mut masked = Vec::new();
        export_value(&mut value, SEED, &mut String::new(), &mut masked);
        (serde_json::to_string(&value).unwrap(), masked)
    }

    #[test]
    fn a_namespaced_key_is_what_the_server_takes_for_one() {
        // The server's rule: ^\w+\.[\w-]+\.[\w$-]+$, at most 128 characters.
        for name in [
            "com.heads.seedID", "com.example.id", "a.b.c", "com.my-org.seed-id", "1.2.3", "com.heads.seed_ID",
            "my_co.heads.id", "com.heads.id$", "com.heads.$",
        ] {
            assert!(is_namespaced_key(name), "{name}");
        }
        for name in [
            "", "GET", "seedID", "com.heads", "com.heads.seed.ID", "com..seedID", ".heads.seedID", "com.heads.",
            "com.heads.seed ID", "com/heads/seedID", "com.heads.seedID\n", " com.heads.seedID",
            // `-` is for the second and third segment, `$` for the third.
            "my-co.heads.id", "com.he$ds.id", "c$m.heads.id",
            // Letters of the ASCII alphabet only, as `\w` has it.
            "com.heads.nyckelö", "key?", "com.heads.key?",
        ] {
            assert!(!is_namespaced_key(name), "{name:?}");
        }
        let long = |n: usize| format!("com.heads.{}", "x".repeat(n - "com.heads.".len()));
        assert!(is_namespaced_key(&long(128)));
        assert!(!is_namespaced_key(&long(129)));
    }

    #[test]
    fn export_writes_a_lone_key_as_key_and_as_the_external_identifier() {
        // No other identifier: `key?` finds the record where it was read, and
        // the name finds it everywhere else from the second write on.
        assert_eq!(
            exported(r#"{"identifiers":{"key":"abc"},"name":"Ann"}"#).0,
            r#"{"identifiers":{"key?":"abc","com.heads.seedID":"abc"},"name":"Ann"}"#
        );
        // `@type` is not an identifier, and the two take the key's place.
        assert_eq!(
            exported(r#"{"@type":"person","identifiers":{"@type":"common identifiers","key":"abc"}}"#).0,
            r#"{"@type":"person","identifiers":{"@type":"common identifiers","key?":"abc","com.heads.seedID":"abc"}}"#
        );
        assert_eq!(
            exported(r#"{"identifiers":{"key":"abc","@type":"common identifiers"}}"#).0,
            r#"{"identifiers":{"key?":"abc","com.heads.seedID":"abc","@type":"common identifiers"}}"#
        );
        // A key that is a number is kept as it is.
        assert_eq!(
            exported(r#"{"identifiers":{"key":7}}"#).0,
            r#"{"identifiers":{"key?":7,"com.heads.seedID":7}}"#
        );
    }

    #[test]
    fn export_drops_the_key_of_a_record_that_has_another_identifier() {
        // The record is found by its other identifier, where it was read and
        // anywhere else. No name is made from its key, so it gets no `key?`.
        assert_eq!(
            exported(r#"{"identifiers":{"key":"abc","com.mi6.id":"007"},"name":"James"}"#).0,
            r#"{"identifiers":{"com.mi6.id":"007"},"name":"James"}"#
        );
        // Any other member of `identifiers` counts, namespaced or not.
        assert_eq!(
            exported(r#"{"identifiers":{"@type":"user identifiers","key":"abc","userId":"U1"}}"#).0,
            r#"{"identifiers":{"@type":"user identifiers","userId":"U1"}}"#
        );
        // The external identifier itself, already there, is left alone.
        assert_eq!(
            exported(r#"{"identifiers":{"key":"abc","com.heads.seedID":"ours"}}"#).0,
            r#"{"identifiers":{"com.heads.seedID":"ours"}}"#
        );
        assert_eq!(
            exported(r#"{"identifiers":{"com.a.b":"1","key":"abc","com.c.d":"2"}}"#).0,
            r#"{"identifiers":{"com.a.b":"1","com.c.d":"2"}}"#
        );
    }

    #[test]
    fn key_is_written_only_where_the_name_is_made_from_the_key() {
        // One response, both kinds of record: `key?` stands beside the name
        // it was made with, and nowhere else.
        let (out, _) = exported(
            r#"[{"identifiers":{"key":"k1"}},{"identifiers":{"key":"k2","com.x.y":"1"}},{"identifiers":{"key":"k3","com.heads.seedID":"s"}}]"#,
        );
        assert_eq!(
            out,
            r#"[{"identifiers":{"key?":"k1","com.heads.seedID":"k1"}},{"identifiers":{"com.x.y":"1"}},{"identifiers":{"com.heads.seedID":"s"}}]"#
        );
        let value: Value = serde_json::from_str(&out).unwrap();
        for record in value.as_array().unwrap() {
            let identifiers = record["identifiers"].as_object().unwrap();
            match identifiers.get("key?") {
                Some(key) => assert_eq!(identifiers.get(SEED), Some(key)),
                None => assert!(!identifiers.values().any(|v| v == "k2" || v == "k3")),
            }
        }
    }

    #[test]
    fn export_does_not_take_a_null_identifier_for_one_the_record_has() {
        let exported = |body: &str| export_body(body, SEED, false, true).text;
        // What `-i` answers for a record with only a key: the unset
        // identifier is listed, as null. The record still has only its key.
        assert_eq!(
            exported(r#"{"identifiers":{"key":"k1","clientID":null},"name":"a"}"#),
            r#"{"identifiers":{"key?":"k1","com.heads.seedID":"k1","clientID":null},"name":"a"}"#
        );
        // Several nulls, and `@type` among them, change nothing.
        assert_eq!(
            exported(r#"{"identifiers":{"@type":"t","clientID":null,"key":"k1","userId":null}}"#),
            r#"{"identifiers":{"@type":"t","clientID":null,"key?":"k1","com.heads.seedID":"k1","userId":null}}"#
        );
        // One real identifier beside a null one is still the one to go by.
        assert_eq!(
            exported(r#"{"identifiers":{"key":"k2","clientID":"mock","userId":null}}"#),
            r#"{"identifiers":{"clientID":"mock","userId":null}}"#
        );
        // An identifier that was masked is null by now and finds nothing either.
        assert_eq!(
            exported(r#"{"identifiers":{"key":"k3","token":"********"}}"#),
            r#"{"identifiers":{"key?":"k3","com.heads.seedID":"k3","token":null}}"#
        );
        // `false` and an empty string are values the server gave, and count.
        assert_eq!(exported(r#"{"identifiers":{"key":"k4","flag":false}}"#), r#"{"identifiers":{"flag":false}}"#);
    }

    #[test]
    fn export_never_leaves_key_and_key_side_by_side() {
        // The API refuses `key` beside `key?`. No answer carries `key?`, but
        // if one did, the key read beside it is the one that is written.
        for (body, expected) in [
            (r#"{"identifiers":{"key?":"old","key":"abc"}}"#, r#"{"identifiers":{"key?":"abc","com.heads.seedID":"abc"}}"#),
            (r#"{"identifiers":{"key":"abc","key?":"old","com.x.y":"1"}}"#, r#"{"identifiers":{"com.x.y":"1"}}"#),
        ] {
            let (out, _) = exported(body);
            assert_eq!(out, expected);
            assert!(!out.contains("\"key\""), "{out}");
        }
        // What was exported once is not changed by exporting it again.
        for body in [
            r#"[{"identifiers":{"key":"u1"},"agent":{"identifiers":{"key":"a1","com.x.y":"root"}},"secret":"********"}]"#,
            r#"{"identifiers":{"key":"abc","userId":"U1"}}"#,
        ] {
            let once = exported(body).0;
            assert_eq!(exported(&once).0, once);
        }
    }

    #[test]
    fn export_reaches_every_record_however_deep() {
        let (out, _) = exported(
            r#"[{"identifiers":{"key":"u1"},"agent":{"identifiers":{"key":"a1","com.heads.seedID":"root"},"name":"System"},
                "clients":[{"identifiers":{"key":"c1"},"node":{"identifiers":{"key":"n1"}}},{"identifiers":{"key":"c2","clientID":"x"}}]}]"#,
        );
        assert_eq!(
            out,
            concat!(
                r#"[{"identifiers":{"key?":"u1","com.heads.seedID":"u1"},"#,
                r#""agent":{"identifiers":{"com.heads.seedID":"root"},"name":"System"},"#,
                r#""clients":[{"identifiers":{"key?":"c1","com.heads.seedID":"c1"},"node":{"identifiers":{"key?":"n1","com.heads.seedID":"n1"}}},"#,
                r#"{"identifiers":{"clientID":"x"}}]}]"#
            )
        );
        assert!(!out.contains("\"key\""));
    }

    #[test]
    fn export_leaves_what_is_no_record_key_alone() {
        for unchanged in [
            // No `identifiers`, or one that holds no key.
            r#"{"key":"abc","name":"x"}"#,
            r#"{"identifiers":{"com.mi6.id":"007"}}"#,
            r#"{"identifiers":{}}"#,
            // An `identifiers` that is no object.
            r#"{"identifiers":"abc"}"#,
            r#"{"identifiers":null}"#,
            r#"{"identifiers":["key"]}"#,
            // A key that holds nothing is not a key to write.
            r#"{"identifiers":{"key":null}}"#,
            r#"{"identifiers":{"key":false}}"#,
            // A member called `key` anywhere else.
            r#"{"settings":{"key":"abc"},"kv":[{"key":"a","value":1}]}"#,
            // Seed data as it is: nothing more to do to it.
            r#"{"identifiers":{"key?":"abc","com.heads.seedID":"abc"}}"#,
            // Scalars and empties.
            "null", "true", "213", r#""text""#, "[]", "{}", r#"[1,"two",null]"#,
        ] {
            let (out, masked) = exported(unchanged);
            assert_eq!(out, unchanged);
            assert!(masked.is_empty(), "{unchanged}");
        }
    }

    #[test]
    fn text_is_cut_to_a_width_from_either_end() {
        assert_eq!(fit_to_width("abcdef", 6), "abcdef");
        assert_eq!(fit_to_width("abcdef", 5), "abcd…");
        assert_eq!(fit_to_width("abcdef", 1), "…");
        assert_eq!(fit_to_width("abcdef", 0), "");
        assert_eq!(fit_to_width("", 0), "");
        assert_eq!(fit_tail_to_width("abcdef", 6), "abcdef");
        assert_eq!(fit_tail_to_width("abcdef", 5), "…cdef");
        assert_eq!(fit_tail_to_width("abcdef", 1), "…");
        assert_eq!(fit_tail_to_width("abcdef", 0), "");
        // Columns, not bytes.
        assert_eq!(fit_to_width("Möööör", 4), "Möö…");
        assert_eq!(fit_tail_to_width("Möööör", 4), "…öör");
        // The body on a request line is cut the same way, once on one line.
        assert_eq!(fit_body_to_width("{\n  \"a\": 1\n}", 6), fit_to_width(&collapse_newlines_for_log("{\n  \"a\": 1\n}"), 6));
    }

    #[test]
    fn an_inline_input_line_keeps_to_the_width_it_is_given() {
        let prompt = "› Export with external identifier: ";
        let line = |value: &str, cols: usize| {
            let (prompt, value) = inline_input_line(prompt, value, Some(cols));
            format!("{}{}", prompt, value)
        };
        // It fits: as written, with room for the cursor block and the margin.
        assert_eq!(line("com.heads.seedID", 80), format!("{prompt}com.heads.seedID"));
        assert_eq!(line("", 37), prompt);
        // Too long: the end of the value stays, the line stops two short.
        let long = "x".repeat(200) + "Z";
        for cols in [200, 84, 60, 44, 39] {
            let shown = line(&long, cols);
            assert_eq!(char_len(&shown), cols - 2, "{cols}");
            assert!(shown.starts_with(prompt) && shown.ends_with('Z'), "{cols}: {shown}");
            assert!(shown[prompt.len()..].starts_with('…'), "{cols}: {shown}");
        }
        // One column left for the value: the ellipsis alone.
        assert_eq!(line(&long, 38), format!("{prompt}…"));
        // Narrower than the prompt: the prompt gives way, and nothing wraps.
        for cols in [36, 20, 3, 2, 1, 0] {
            assert!(char_len(&line(&long, cols)) <= cols.saturating_sub(2), "{cols}");
        }
        // No width given: nothing is cut.
        assert_eq!(inline_input_line(prompt, &long, None), (prompt.to_string(), long.clone()));
    }

    #[test]
    fn the_footer_marker_is_export_while_export_is_on_and_streaming_otherwise() {
        let mut state = AppState::new(Config::default());
        state.width = 80;
        let shown = |state: &AppState| -> String {
            let line = streaming_indicator(state, 20);
            let mut plain = String::new();
            let mut chars = line.chars();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    for skipped in chars.by_ref() {
                        if skipped == 'm' {
                            break;
                        }
                    }
                } else {
                    plain.push(c);
                }
            }
            plain.trim_start().to_string()
        };
        assert_eq!((footer_indicator(&state), shown(&state).as_str()), (None, ""));
        state.config.streaming = true;
        assert_eq!((footer_indicator(&state), shown(&state).as_str()), (Some("streaming"), "streaming"));
        // Export reads a response whole, so it takes the marker's place.
        state.config.export_id = Some(SEED.to_string());
        assert_eq!((footer_indicator(&state), shown(&state).as_str()), (Some("export"), "export"));
        state.config.streaming = false;
        assert_eq!((footer_indicator(&state), shown(&state).as_str()), (Some("export"), "export"));
        // It ends where the streaming marker does, the margin in from the edge.
        assert_eq!(visible_len(&streaming_indicator(&state, 20)), 80 - 2 - 20 - STREAMING_INDICATOR_MARGIN);
        assert!(transient_hint_line(&state, "waiting", None).ends_with(&EXPORT_INDICATOR.dimmed().to_string()));
        // Too narrow for both: the text on the left is kept.
        state.width = 30;
        assert_eq!(shown(&state), "");
        state.config.export_id = None;
        assert_eq!(footer_indicator(&state), None);
    }

    #[test]
    fn a_session_started_with_export_knows_the_name_and_one_without_has_none() {
        assert_eq!(AppState::new(Config::default()).export_name, None);
        let started = AppState::new(Config { export_id: Some(SEED.to_string()), ..Config::default() });
        assert_eq!(started.export_name.as_deref(), Some(SEED));
        assert_eq!(started.config.export_id.as_deref(), Some(SEED));
    }

    #[test]
    fn export_puts_identifiers_first_and_keeps_the_servers_order_otherwise() {
        // Behind `@type` when there is one, wherever the two were.
        assert_eq!(
            exported(r#"{"zeta":1,"name":"x","identifiers":{"com.a.b":"1"},"alpha":2,"@type":"person"}"#).0,
            r#"{"@type":"person","identifiers":{"com.a.b":"1"},"zeta":1,"name":"x","alpha":2}"#
        );
        // First when there is none.
        assert_eq!(
            exported(r#"{"zeta":1,"identifiers":{"com.a.b":"1"},"alpha":2}"#).0,
            r#"{"identifiers":{"com.a.b":"1"},"zeta":1,"alpha":2}"#
        );
        // Whatever `identifiers` holds.
        assert_eq!(exported(r#"{"name":"x","identifiers":null}"#).0, r#"{"identifiers":null,"name":"x"}"#);
        // An object without `identifiers` is not reordered, `@type` included.
        let untouched = r#"{"zeta":1,"@type":"thing","alpha":{"b":1,"a":2}}"#;
        assert_eq!(exported(untouched).0, untouched);
        // Nor are the members of `identifiers` itself.
        assert_eq!(
            exported(r#"{"identifiers":{"zeta.a.b":"1","key":"k","alpha.a.b":"2","@type":"t"}}"#).0,
            r#"{"identifiers":{"zeta.a.b":"1","alpha.a.b":"2","@type":"t"}}"#
        );
    }

    #[test]
    fn export_nulls_masked_values_and_says_where_they_were() {
        let (out, masked) = exported(
            r#"{"secret":"********","nested":{"password":"*******","apiKey":"********","fine":"*****"},
                "list":["********","kept"],"secret2":"********x","name":"********"}"#,
        );
        assert_eq!(
            out,
            r#"{"secret":null,"nested":{"password":null,"apiKey":null,"fine":"*****"},"list":[null,"kept"],"secret2":"********x","name":null}"#
        );
        // Paths from the top, in the order they were met; a value in a list
        // is at the list's path.
        assert_eq!(masked, ["secret", "nested/password", "nested/apiKey", "list", "name"]);

        // A list adds no position, so what every record has is named once,
        // at any depth, and the response being a list itself adds nothing.
        let (out, masked) = exported(
            r#"[{"clients":[{"secret":"********"},{"secret":"********","node":{"pin":"*******"}}],"creds":[{"apiKey":"********"}]},
                {"clients":[{"secret":"********"}],"creds":[]}]"#,
        );
        assert_eq!(masked, ["clients/secret", "clients/node/pin", "creds/apiKey"]);
        assert!(!out.contains('*'), "{out}");
        let (_, masked) = exported(r#"[{"secret":"********"},{"secret":"********"}]"#);
        assert_eq!(masked, ["secret"]);
        // The same name in two places is two paths.
        let (_, masked) = exported(r#"{"a":{"secret":"********"},"b":{"secret":"********"}}"#);
        assert_eq!(masked, ["a/secret", "b/secret"]);
        // A body that is one masked value has no path below the top.
        for body in [r#""********""#, r#"["********"]"#] {
            assert_eq!(exported(body).1, ["(root)"], "{body}");
        }
        assert_eq!(exported(r#""********""#).0, "null");

        // A masked key is nothing to write: it becomes null and stays, and
        // neither `key?` nor an external identifier is made from it.
        let (out, masked) = exported(r#"{"identifiers":{"key":"********"},"name":"x"}"#);
        assert_eq!(out, r#"{"identifiers":{"key":null},"name":"x"}"#);
        assert_eq!(masked, ["identifiers/key"]);
    }

    #[test]
    fn export_body_prints_json_indented_or_compact_and_ndjson_by_line() {
        let json = r#"[{"identifiers":{"key":"a"},"n":1}]"#;
        let pretty = export_body(json, SEED, false, false);
        assert_eq!(
            pretty.text,
            "[\n  {\n    \"identifiers\": {\n      \"key?\": \"a\",\n      \"com.heads.seedID\": \"a\"\n    },\n    \"n\": 1\n  }\n]"
        );
        assert!(pretty.is_json && pretty.masked.is_empty());
        assert_eq!(export_body(json, SEED, false, true).text, r#"[{"identifiers":{"key?":"a","com.heads.seedID":"a"},"n":1}]"#);
        // The server's own indentation is read like any other.
        assert_eq!(export_body(&pretty.text, SEED, false, true).text, r#"[{"identifiers":{"key?":"a","com.heads.seedID":"a"},"n":1}]"#);

        // NDJSON: one compact value per line, blank lines and the final
        // newline as they were, whatever `compact` says.
        let ndjson = "{\"identifiers\":{\"key\":\"a\"}}\n\n{\"identifiers\":{\"key\":\"b\",\"com.x.y\":\"1\"},\"secret\":\"********\"}\n";
        let by_line = export_body(ndjson, SEED, true, false);
        assert_eq!(by_line.text, "{\"identifiers\":{\"key?\":\"a\",\"com.heads.seedID\":\"a\"}}\n\n{\"identifiers\":{\"com.x.y\":\"1\"},\"secret\":null}\n");
        assert_eq!(by_line.masked, ["secret"]);
        assert_eq!(export_body(ndjson.trim_end(), SEED, true, false).text, by_line.text.trim_end());
        // Lines of JSON are read as NDJSON also when nothing said they were.
        assert_eq!(export_body(ndjson, SEED, false, false).text, by_line.text);
        // One line is both: what was asked for decides how it is printed.
        let one = r#"{"identifiers":{"key":"a"}}"#;
        assert_eq!(export_body(one, SEED, true, false).text, r#"{"identifiers":{"key?":"a","com.heads.seedID":"a"}}"#);
        assert!(export_body(one, SEED, false, false).text.contains("\n  \"identifiers\": {"));
        // An indented JSON body asked for as NDJSON is still JSON.
        assert_eq!(export_body(&pretty.text, SEED, true, true).text, r#"[{"identifiers":{"key?":"a","com.heads.seedID":"a"},"n":1}]"#);
    }

    #[test]
    fn export_body_leaves_what_is_not_json_unchanged_and_says_so() {
        for text in ["@type,givenName\nperson,Ann\n", "INSERT INTO people VALUES (1);\n", "<html></html>", "{\"cut\": "] {
            let body = export_body(text, SEED, false, false);
            assert_eq!((body.text.as_str(), body.is_json), (text, false));
            assert_eq!(
                export_warning(&body).as_deref(),
                Some("WARNING: --export left a response that is not JSON unchanged")
            );
        }
        // One bad line makes the whole body not NDJSON; no line is rewritten.
        let mixed = "{\"identifiers\":{\"key\":\"a\"},\"secret\":\"********\"}\nnot json\n";
        let body = export_body(mixed, SEED, true, false);
        assert_eq!((body.text.as_str(), body.is_json), (mixed, false));
        assert!(body.masked.is_empty());

        // An empty body (a 204) is nothing to export and nothing to warn about.
        for empty in ["", "\n", "  "] {
            let body = export_body(empty, SEED, false, false);
            assert_eq!((body.text.as_str(), body.is_json), (empty, true));
            assert_eq!(export_warning(&body), None);
        }
        assert_eq!(export_warning(&export_body("[1]", SEED, false, false)), None);
        assert_eq!(
            export_warning(&export_body(r#"{"b":"********","a":{"c":"*******"}}"#, SEED, false, false)).as_deref(),
            Some("Response had masked data, now null at b, a/c")
        );
        // Two places are named and the rest counted.
        let warned = |json: &str| export_warning(&export_body(json, SEED, false, false));
        assert_eq!(warned(r#"{"a":"********"}"#).as_deref(), Some("Response had masked data, now null at a"));
        assert_eq!(
            warned(r#"{"a":"********","b":"********","c":"********"}"#).as_deref(),
            Some("Response had masked data, now null at a, b and 1 other place")
        );
        assert_eq!(
            warned(r#"{"a":"********","b":{"x":"********","y":"********"},"c":["********"],"d":"********"}"#).as_deref(),
            Some("Response had masked data, now null at a, b/x and 3 other places")
        );
        // Places are counted, not values: one path in many records is one.
        assert_eq!(
            warned(r#"[{"a":"********","b":"********"},{"a":"********","b":"********"}]"#).as_deref(),
            Some("Response had masked data, now null at a, b")
        );
        // NDJSON lines share one list: a path is named once across them.
        assert_eq!(
            export_warning(&export_body("{\"s\":\"********\"}\n{\"s\":\"********\",\"t\":\"********\"}\n", SEED, true, false))
                .as_deref(),
            Some("Response had masked data, now null at s, t")
        );
    }

    #[test]
    fn fail_fast_trips_on_any_error_status_except_an_answer_to_a_question() {
        let plain = Config { fail_fast: true, ..Config::default() };
        for status in [400, 401, 404, 409, 422, 429, 500, 503] {
            assert!(fail_fast_trips(&plain, status), "{status}");
        }
        for status in [200, 201, 204, 301, 304, 399] {
            assert!(!fail_fast_trips(&plain, status), "{status}");
        }
        // Off unless asked for.
        assert!(!fail_fast_trips(&Config::default(), 500));

        // A question may be answered "no"…
        let question = Config { fail_fast: true, expect_falsy: true, ..Config::default() };
        for status in [400, 404, 409, 422] {
            assert!(!fail_fast_trips(&question, status), "{status}");
        }
        // …but a status that is never an answer still ends the run.
        for status in [401, 403, 408, 429, 500, 502] {
            assert!(fail_fast_trips(&question, status), "{status}");
        }

        // A poll and an `assert` report their own failures.
        let poll = Config { fail_fast: true, quiet: true, ..Config::default() };
        let check = Config { fail_fast: true, check_only: true, ..Config::default() };
        assert!(!fail_fast_trips(&poll, 500));
        assert!(!fail_fast_trips(&check, 404));

        // At the prompt the rule is applied to the last status received.
        let seen = |status| Config { fail_fast: true, last_status: status, ..Config::default() };
        assert!(fail_fast_tripped_at_prompt(&seen(Some(409))));
        assert!(!fail_fast_tripped_at_prompt(&seen(Some(200))));
        assert!(!fail_fast_tripped_at_prompt(&seen(None)));
    }

    #[test]
    fn import_is_a_directive_not_an_include_path() {
        assert!(is_program_line("import git cl {}"));
        assert!(could_become_a_keyword("imp"));
        let ctx = extract_file_path_context("import git cl", 13);
        assert!(ctx.is_none_or(|c| !c.is_include));
        // Unclosed JSON is reported like an unclosed body.
        let err = split_bulk_requests("import git cl {\n  \"url\": \"x\"\n", None).unwrap_err();
        assert!(err.starts_with("unclosed body"), "{err}");
    }

    // ----- import dir -----

    #[test]
    fn import_dir_uses_a_directory_where_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let lib = base.join("elsewhere/lib");
        fs::create_dir_all(lib.join("data")).unwrap();
        fs::write(lib.join("sv.api"), "url has localhost\nGET /sv\nPUT /sv @data/sv.json\n").unwrap();
        fs::write(lib.join("data/sv.json"), "{}").unwrap();
        fs::write(lib.join("escape.api"), "PUT /x @../outside.json\n").unwrap();
        fs::write(base.join("elsewhere/outside.json"), "{}").unwrap();
        let project = base.join("project");
        fs::create_dir_all(&project).unwrap();

        // Relative to the declaring file, like an include.
        let src = "import dir cl { \"path\": \"../elsewhere/lib\" }\ncl/sv.api\n";
        let program = split_bulk_requests(src, Some(&project)).unwrap();
        assert_eq!(
            requests_of(&program),
            vec!["GET /sv".to_string(), format!("PUT /sv @{}", lib.join("data/sv.json").display())]
        );
        // Nothing is fetched or copied: the log names the directory itself.
        assert_eq!(
            program.import_notes,
            vec![ImportNote { text: format!("import cl {}", lib.display()), stale: false }]
        );
        // The same rules as any import: its `url` line only narrows…
        assert!(program.url_conditions.is_empty());
        assert!(evaluate_program_gates(&program, "https://api.heads.com").is_err());
        // …and its files stay inside it.
        let err = split_bulk_requests(
            "import dir cl { \"path\": \"../elsewhere/lib\" }\ncl/escape.api\n",
            Some(&project),
        )
        .unwrap_err();
        assert!(err.contains("must be a relative path inside the import"), "{err}");

        // An absolute path works from anywhere.
        let src = format!("import dir cl {{ \"path\": \"{}\" }}\ncl/sv.api\n", lib.display());
        assert_eq!(requests_of(&split_bulk_requests(&src, Some(&project)).unwrap()).len(), 2);

        let err = split_bulk_requests("import dir cl { \"path\": \"../nope\" }\n", Some(&project)).unwrap_err();
        assert_eq!(err, "import cl: not a directory: ../nope");
        let err = split_bulk_requests(
            "import dir cl { \"path\": \"../elsewhere/lib/sv.api\" }\n",
            Some(&project),
        )
        .unwrap_err();
        assert_eq!(err, "import cl: not a directory: ../elsewhere/lib/sv.api");
    }

    #[test]
    fn an_imported_file_may_import_a_directory_of_its_own_import_only() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let lib = base.join("lib");
        fs::create_dir_all(lib.join("parts")).unwrap();
        fs::write(lib.join("parts/p.api"), "GET /part\n").unwrap();
        fs::write(lib.join("ok.api"), "import dir parts_of { \"path\": \"parts\" }\nparts_of/p.api\n").unwrap();
        fs::write(lib.join("up.api"), "import dir out { \"path\": \"..\" }\n").unwrap();
        fs::write(lib.join("abs.api"), "import dir out { \"path\": \"/etc\" }\n").unwrap();
        fs::write(lib.join("home.api"), "import dir out { \"path\": \"~/\" }\n").unwrap();
        let import = format!("import dir lib {{ \"path\": \"{}\" }}\n", lib.display());

        // Run from a directory that has no `lib` of its own next to it.
        let project = base.join("project");
        fs::create_dir_all(&project).unwrap();
        let program = split_bulk_requests(&format!("{import}lib/ok.api\n"), Some(&project)).unwrap();
        assert_eq!(requests_of(&program), vec!["GET /part".to_string()]);
        for file in ["up.api", "abs.api", "home.api"] {
            let err = split_bulk_requests(&format!("{import}lib/{file}\n"), Some(&project)).unwrap_err();
            assert_eq!(err, "import out: `path` must be a relative path inside the import", "{file}");
        }
    }

    #[test]
    fn a_directory_import_that_leads_back_to_its_file_is_an_include_loop() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        fs::write(base.join("root.api"), "import dir me { \"path\": \".\" }\nGET /once\nme/root.api\n").unwrap();
        let err = split_bulk_requests("root.api\n", Some(&base)).unwrap_err();
        assert_eq!(err, format!("include loop detected: {}", base.join("root.api").display()));
    }

    // ----- import archive -----

    /// A `.tar.gz` of `files`, with whatever else `extra` appends to it.
    fn tar_gz(files: &[(&str, &str)], extra: impl FnOnce(&mut tar::Builder<flate2::write::GzEncoder<Vec<u8>>>)) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(gz);
        for (name, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, contents.as_bytes()).unwrap();
        }
        extra(&mut builder);
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn zip_of(files: &[(&str, &str)]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        for (name, contents) in files {
            writer.start_file(*name, options).unwrap();
            writer.write_all(contents.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    /// Write `bytes` to a file of its own and return its guard and `file://` url.
    fn archive_file(bytes: &[u8], name: &str) -> (tempfile::TempDir, String) {
        use_test_import_cache();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join(name);
        fs::write(&path, bytes).unwrap();
        (dir, format!("file://{}", path.display()))
    }

    #[test]
    fn import_archive_unpacks_a_release_tarball_under_its_alias() {
        // Packed the way a release is: everything under one directory.
        let bytes = tar_gz(
            &[
                ("cloddy-2.1.0/sv.api", "url has localhost\nGET /sv\nPUT /sv @data/sv.json\n"),
                ("cloddy-2.1.0/data/sv.json", "{\"a\":1}"),
                ("cloddy-2.1.0/seeds/a.api", "GET /a\n"),
            ],
            |_| {},
        );
        let sha = sha256_hex(&bytes);
        let (_guard, url) = archive_file(&bytes, "cloddy-2.1.0.tar.gz");
        let dir = tempfile::tempdir().unwrap();

        let src = format!("import archive cl {{ \"url\": \"{url}\" }}\ncl/sv.api\n");
        let program = split_bulk_requests(&src, Some(dir.path())).unwrap();
        let top = import_cache_dir().unwrap().canonicalize().unwrap().join("archives").join(&sha).join("cloddy-2.1.0");
        assert_eq!(
            requests_of(&program),
            vec!["GET /sv".to_string(), format!("PUT /sv @{}", top.join("data/sv.json").display())]
        );
        assert_eq!(
            program.import_notes,
            vec![ImportNote { text: format!("import cl {url} (sha256 {})", &sha[..7]), stale: false }]
        );
        assert_eq!(program.import_gates[0].conditions, vec![UrlCondition::Has("localhost".to_string())]);

        // `path` picks a subdirectory, under the single top directory.
        let src = format!("import archive s {{ \"url\": \"{url}\", \"path\": \"seeds\" }}\ns/*.api\n");
        assert_eq!(requests_of(&split_bulk_requests(&src, Some(dir.path())).unwrap()), vec!["GET /a".to_string()]);
        let src = format!("import archive s {{ \"url\": \"{url}\", \"path\": \"nope\" }}\n");
        let err = split_bulk_requests(&src, Some(dir.path())).unwrap_err();
        assert_eq!(err, format!("import s: no directory `nope` in {url}"));
    }

    #[test]
    fn import_archive_checks_a_sha256_and_then_needs_no_download() {
        let bytes = zip_of(&[("sv.api", "GET /zipped\n"), ("more/b.api", "GET /b\n")]);
        let sha = sha256_hex(&bytes);
        let (guard, url) = archive_file(&bytes, "lib.zip");
        let dir = tempfile::tempdir().unwrap();

        // The wrong hash is an error, and nothing is unpacked for it.
        let wrong = "0".repeat(64);
        let src = format!("import archive z {{ \"url\": \"{url}\", \"sha256\": \"{wrong}\" }}\n");
        let err = split_bulk_requests(&src, Some(dir.path())).unwrap_err();
        assert_eq!(err, format!("import archive {url}: sha256 mismatch (expected {wrong}, got {sha})"));
        assert!(!import_cache_dir().unwrap().join("archives").join(&wrong).exists());

        // Upper case is the same hash. A zip with no single top directory
        // starts at its top.
        let src = format!(
            "import archive z {{ \"url\": \"{url}\", \"sha256\": \"{}\" }}\nz/sv.api\nz/more/b.api\n",
            sha.to_uppercase()
        );
        let program = split_bulk_requests(&src, Some(dir.path())).unwrap();
        assert_eq!(requests_of(&program), vec!["GET /zipped".to_string(), "GET /b".to_string()]);

        // Pinned and cached: the same hash from a url that no longer answers
        // (and was never asked before) is served from the cache.
        drop(guard);
        let gone = format!("{url}.moved");
        let src = format!("import archive z {{ \"url\": \"{gone}\", \"sha256\": \"{sha}\" }}\nz/sv.api\n");
        let program = split_bulk_requests(&src, Some(dir.path())).unwrap();
        assert_eq!(requests_of(&program), vec!["GET /zipped".to_string()]);
        assert!(!program.import_notes[0].stale);

        // Pinned and not cached: unreachable is an error.
        let other = "1".repeat(64);
        let src = format!("import archive z {{ \"url\": \"{gone}\", \"sha256\": \"{other}\" }}\n");
        let err = split_bulk_requests(&src, Some(dir.path())).unwrap_err();
        assert!(err.starts_with(&format!("could not reach import {gone}:")), "{err}");
    }

    #[test]
    fn unpack_archive_writes_files_only_and_refuses_to_leave_its_directory() {
        let dir = tempfile::tempdir().unwrap();

        // Links are skipped; a plain .tar is read as well as a .tar.gz.
        let bytes = tar_gz(&[("a.api", "GET /a\n")], |builder| {
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            builder.append_link(&mut link, "passwd", "/etc/passwd").unwrap();
        });
        let dest = dir.path().join("links");
        unpack_archive(&bytes, &dest).unwrap();
        assert!(dest.join("a.api").is_file());
        assert!(fs::symlink_metadata(dest.join("passwd")).is_err());

        let mut plain = Vec::new();
        io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&bytes[..]), &mut plain).unwrap();
        let dest = dir.path().join("plain");
        unpack_archive(&plain, &dest).unwrap();
        assert!(dest.join("a.api").is_file());

        // An entry named outside the archive, in either format. The tar
        // builder refuses to write such a name, so the header is set by hand.
        let bytes = tar_gz(&[], |builder| {
            let mut header = tar::Header::new_gnu();
            let name = b"../escaped.api";
            header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name);
            header.set_size(2);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &b"hi"[..]).unwrap();
        });
        let dest = dir.path().join("sub/tar");
        let err = unpack_archive(&bytes, &dest).unwrap_err();
        assert_eq!(err, "archive entry leaves the archive: ../escaped.api");
        assert!(!dir.path().join("sub/escaped.api").exists());

        let bytes = zip_of(&[("../escaped.api", "hi"), ("ok.api", "GET /ok\n")]);
        let dest = dir.path().join("sub/zip");
        let err = unpack_archive(&bytes, &dest).unwrap_err();
        assert_eq!(err, "archive entry leaves the archive: ../escaped.api");
        assert!(!dir.path().join("sub/escaped.api").exists());

        let err = unpack_archive(b"GET /not-an-archive\n", &dir.path().join("text")).unwrap_err();
        assert_eq!(err, "not a .tar.gz, .tar or .zip archive");
    }

    #[test]
    fn an_archive_may_only_unpack_to_so_much() {
        let dir = tempfile::tempdir().unwrap();
        let files = [("a.api", "GET /aaaaaaaa\n"), ("b.api", "GET /bbbbbbbb\n")];
        let total: u64 = files.iter().map(|(_, c)| c.len() as u64).sum();
        for (name, bytes) in [("tar", tar_gz(&files, |_| {})), ("zip", zip_of(&files))] {
            // Exactly what it holds is fine; the limit is on the sum of the
            // files, so the second one is what goes over.
            unpack_archive_within(&bytes, &dir.path().join(format!("{name}-fits")), total).unwrap();
            let dest = dir.path().join(format!("{name}-over"));
            let err = unpack_archive_within(&bytes, &dest, total - 1).unwrap_err();
            assert_eq!(err, "archive unpacks to more than 1 GB", "{name}");
            assert!(dest.join("a.api").is_file(), "{name}");
        }
        // The limit in force is the one the message names.
        assert_eq!(ARCHIVE_UNPACKED_LIMIT, 1024 * 1024 * 1024);
    }

    #[test]
    fn import_archive_reports_a_file_that_is_no_archive_and_a_missing_token() {
        let (_guard, url) = archive_file(b"GET /just-a-file\n", "sv.api");
        let dir = tempfile::tempdir().unwrap();
        let src = format!("import archive x {{ \"url\": \"{url}\" }}\n");
        let err = split_bulk_requests(&src, Some(dir.path())).unwrap_err();
        assert_eq!(err, format!("import archive {url}: not a .tar.gz, .tar or .zip archive"));

        let src = format!(
            "import archive x {{ \"url\": \"{url}\", \"token_env\": \"API_TEST_TOKEN_THAT_IS_NOT_SET\" }}\n"
        );
        let err = split_bulk_requests(&src, Some(dir.path())).unwrap_err();
        assert_eq!(
            err,
            format!("import archive {url}: environment variable API_TEST_TOKEN_THAT_IS_NOT_SET is not set")
        );
    }

    // ----- describe blocks, -m, --describe and --assert -----

    fn describe_of(src: &str) -> DescribeBlock {
        split_bulk_requests(src, None).unwrap().describe.expect("a describe block")
    }

    #[test]
    fn a_describe_block_is_read_before_the_first_request_and_never_sent() {
        let src = "# seed\nurl has localhost\n{\n  \"title\": { \"sv-SE\": \"Katalog\" }, // name\n  \"description\": { \"sv-SE\": \"rad ett\nrad två\" }\n}\n\nGET /a\nPUT /b { \"x\": 1 }\n";
        let program = split_bulk_requests(src, None).unwrap();
        assert_eq!(
            program.steps,
            vec![BulkStep::Request("GET /a".to_string()), BulkStep::Request("PUT /b { \"x\": 1 }".to_string())]
        );
        assert_eq!(program.url_conditions, vec![UrlCondition::Has("localhost".to_string())]);
        let block = program.describe.unwrap();
        assert_eq!(block["title"]["sv-SE"], "Katalog");
        // A raw newline in a string is kept, as in a body.
        assert_eq!(block["description"]["sv-SE"], "rad ett\nrad två");
        assert!(program.describe_warnings.is_empty());
        // A file without one has none.
        assert!(split_bulk_requests("GET /a\n", None).unwrap().describe.is_none());
    }

    #[test]
    fn a_describe_block_anywhere_else_stops_the_file() {
        let late = "a describe block must come before the first request";
        for (src, says) in [
            ("GET /a\n\n{ \"title\": {} }\n", late.to_string()),
            ("sleep 1ms\n{ \"title\": {} }\n", late.to_string()),
            ("confirm\n{ \"title\": {} }\n", late.to_string()),
            ("export com.heads.seedID\n{ \"title\": {} }\n", late.to_string()),
            ("import dir d { \"path\": \".\" }\n{ \"title\": {} }\n", late.to_string()),
            // Under a request with no body it is most likely the body.
            ("PUT /a\n{ \"x\": 1 }\n", format!("{late} (a body starts on the request line)")),
            ("PATCH /a\n{\n  \"x\": 1\n}\n", format!("{late} (a body starts on the request line)")),
            // A blank line or a comment between them, a body on the request,
            // or a method that takes none: no such hint.
            ("PUT /a\n\n{ \"x\": 1 }\n", late.to_string()),
            ("PUT /a\n# note\n{ \"x\": 1 }\n", late.to_string()),
            ("PUT /a {}\n{ \"x\": 1 }\n", late.to_string()),
            ("GET /a\n{ \"x\": 1 }\n", late.to_string()),
            ("{ \"title\": {} }\n{ \"title\": {} }\n", "a file has one describe block, and this is a second".to_string()),
            ("[ { \"title\": {} } ]\nGET /a\n", "a describe block is a JSON object, not an array".to_string()),
            ("PUT /a\n[1]\n", "a describe block is a JSON object, not an array (a body starts on the request line)".to_string()),
            ("{ \"title\": {\n", "unclosed describe block (depth 2)".to_string()),
        ] {
            assert_eq!(split_bulk_requests(src, None).unwrap_err(), says, "{src:?}");
            // `--describe` reads the file alone and judges it the same.
            if !src.starts_with("import") {
                assert_eq!(scan_describe_block(src).unwrap_err(), says, "scan {src:?}");
            }
        }
        for src in ["{ \"title\": }\nGET /a\n", "{ \"title\": {} } trailing\nGET /a\n"] {
            let err = split_bulk_requests(src, None).unwrap_err();
            assert!(err.starts_with("invalid describe block: "), "{err}");
            assert_eq!(scan_describe_block(src).unwrap_err(), err);
        }
    }

    #[test]
    fn a_describe_block_is_checked_and_what_is_off_is_a_warning() {
        let (block, warnings) = check_describe_block(
            parse_describe_block(
                r#"{ "title": { "sv-se": "Katalog", "EN": "Catalog", "zh-hans-cn": "目录", "es-419": "Catálogo" },
                     "description": { "sv-SE": "x" }, "docsLink": "https://link-to-docs.com" }"#,
            )
            .unwrap(),
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        // Locale keys are read in any case and printed in one.
        let keys: Vec<&String> = block["title"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["sv-SE", "en", "zh-Hans-CN", "es-419"]);
        // Members keep the order they were written in.
        assert_eq!(block.keys().collect::<Vec<_>>(), ["title", "description", "docsLink"]);

        let (block, warnings) = check_describe_block(
            parse_describe_block(
                r#"{ "title": { "sv_SE": "a", "sv": 3, "SV": "b" }, "description": "plain",
                     "docsLink": "ftp://x", "Title": {}, "owner": "me" }"#,
            )
            .unwrap(),
        );
        assert_eq!(
            warnings,
            [
                "title/sv_SE is not a locale",
                "title/sv is not a text",
                "title/SV is given twice",
                "description is not an object of texts by locale, like { \"sv-SE\": \"…\" }",
                "docsLink is not an http(s) link",
                "Title is not a member of a describe block (title, description, docsLink)",
                "owner is not a member of a describe block (title, description, docsLink)",
            ]
        );
        // Nothing but the repeated locale is dropped.
        assert_eq!(block["owner"], "me");
        assert_eq!(block["description"], "plain");
        assert_eq!(block["title"], serde_json::json!({ "sv_SE": "a", "sv": 3 }));
        for link in [serde_json::json!(1), serde_json::json!(null), serde_json::json!("link-to-docs.com")] {
            let (_, warnings) = check_describe_block(parse_describe_block(&format!("{{\"docsLink\":{link}}}")).unwrap());
            assert_eq!(warnings, ["docsLink is not an http(s) link"]);
        }
    }

    #[test]
    fn canonical_locale_reads_any_case_and_refuses_what_is_no_locale() {
        for (key, name) in [
            ("sv-SE", "sv-SE"),
            ("SV-se", "sv-SE"),
            ("en", "en"),
            ("FIL", "fil"),
            ("zh-HANS", "zh-Hans"),
            ("zh-hans-cn", "zh-Hans-CN"),
            ("es-419", "es-419"),
        ] {
            assert_eq!(canonical_locale(key).as_deref(), Some(name), "{key}");
        }
        for key in ["", "s", "sv_SE", "sv-", "sv-S", "sv-SE-x", "svenska", "sv-1234", "s1", "sv-SE-SE", "sv--SE", "sv-åä"] {
            assert_eq!(canonical_locale(key), None, "{key}");
        }
    }

    #[test]
    fn a_describe_block_in_an_included_file_is_checked_and_stays_that_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("inc.api"), "{ \"title\": \"Included\" }\nGET /inc\n").unwrap();
        std::fs::write(dir.path().join("bad.api"), "GET /inc\n{ \"title\": {} }\n").unwrap();

        let src = "{ \"title\": { \"en\": \"Top\" } }\ninc.api\nGET /a\n";
        let program = split_bulk_requests(src, Some(dir.path())).unwrap();
        assert_eq!(program.describe.unwrap()["title"]["en"], "Top");
        assert_eq!(
            program.describe_warnings,
            ["describe block in inc.api: title is not an object of texts by locale, like { \"sv-SE\": \"…\" }"]
        );
        assert_eq!(program.steps.len(), 2);

        // A file that has none does not take an included file's.
        let program = split_bulk_requests("inc.api\n", Some(dir.path())).unwrap();
        assert!(program.describe.is_none());
        assert!(!program.only_describes());
        // Each file has a top of its own: the included one may open with a
        // block after the including file has sent requests.
        assert!(split_bulk_requests("GET /a\ninc.api\n", Some(dir.path())).is_ok());
        // A misplaced block in an included file stops the batch too.
        assert_eq!(
            split_bulk_requests("bad.api\n", Some(dir.path())).unwrap_err(),
            "a describe block must come before the first request"
        );
    }

    #[test]
    fn scan_describe_block_reads_the_file_without_opening_what_it_names() {
        // Neither the include nor the import exists; the block is read anyway.
        let src = "# top\nurl is http://localhost:5000\n{ \"title\": { \"sv-se\": \"Katalog\" }, \"x\": 1 }\nimport git cl {\n  \"url\": \"https://example.invalid/x\",\n  \"ref\": \"1\"\n}\nnope/missing.api\nPUT /a {\n  \"b\": [1, 2]\n}\nGET /a && PUT /b { \"c\": 1 }\n";
        let (block, warnings) = scan_describe_block(src).unwrap().unwrap();
        assert_eq!(block["title"]["sv-SE"], "Katalog");
        assert_eq!(warnings, ["x is not a member of a describe block (title, description, docsLink)"]);
        assert_eq!(scan_describe_block("GET /a\nPUT /b {\n \"x\": 1\n}\n").unwrap(), None);
        assert_eq!(scan_describe_block("").unwrap(), None);
        // The same block the batch parser reads.
        let src = "{ \"title\": { \"SV-se\": \"Katalog\" }, \"docsLink\": \"https://x\" }\nGET /a\n";
        assert_eq!(scan_describe_block(src).unwrap().unwrap().0, describe_of(src));
    }

    #[test]
    fn a_describe_block_alone_is_a_program_that_sends_nothing() {
        assert!(split_bulk_requests("{ \"title\": {} }", None).unwrap().only_describes());
        assert!(split_bulk_requests("# note\n{ \"title\": {} }\n", None).unwrap().only_describes());
        assert!(!split_bulk_requests("{ \"title\": {} }\nGET /a", None).unwrap().only_describes());
        assert!(!split_bulk_requests("{ \"title\": {} }\nurl has x", None).unwrap().only_describes());
        assert!(!split_bulk_requests("# note", None).unwrap().only_describes());
        // At the prompt it is a program, not a request to send.
        assert!(matches!(classify_prompt_line("{ \"title\": {} }", None), PromptLine::Program));
        assert!(matches!(
            classify_prompt_line("{ \"title\": {} }\nGET /a", None),
            PromptLine::Request(r) if r == "GET /a"
        ));
    }

    #[test]
    fn a_pasted_file_that_opens_with_a_describe_block_is_api_text() {
        assert!(paste_is_api_text("{ \"title\": {} }\nGET /a"));
        assert!(paste_is_api_text("{\n  \"title\": { \"sv-SE\": \"}\" } // }\n}\n\n# note\nGET /a\n"));
        // An object alone is a body, whatever it holds and however long.
        assert!(!paste_is_api_text("{ \"title\": {} }"));
        assert!(!paste_is_api_text("{\n  \"a\": 1\n}\n\n"));
        assert!(!paste_is_api_text("{\n  \"a\": 1"));
        assert!(!paste_is_api_text("[1]\nGET /a"));
    }

    #[test]
    fn localized_text_picks_the_readers_locale_then_language_then_english() {
        let texts = serde_json::json!({ "de-DE": "Katalog", "en-US": "Catalog", "sv-SE": "Katalog sv", "sv-FI": "Katalog fi", "nb": 5 });
        let pick = |locale: Option<&str>| localized_text(Some(&texts), locale);
        assert_eq!(pick(Some("sv-FI")), Some("Katalog fi"));
        assert_eq!(pick(Some("sv-fi")), Some("Katalog fi"));
        assert_eq!(pick(Some("sv")), Some("Katalog sv"));
        assert_eq!(pick(Some("sv-NO")), Some("Katalog sv"));
        assert_eq!(pick(Some("fr-FR")), Some("Catalog"));
        assert_eq!(pick(None), Some("Catalog"));
        // A value that is no text is never shown.
        assert_eq!(pick(Some("nb")), Some("Catalog"));
        let no_english = serde_json::json!({ "de-DE": "Katalog", "sv-SE": "Katalog sv" });
        assert_eq!(localized_text(Some(&no_english), Some("fr")), Some("Katalog"));
        assert_eq!(localized_text(Some(&serde_json::json!({})), None), None);
        assert_eq!(localized_text(Some(&serde_json::json!("plain")), None), None);
        assert_eq!(localized_text(None, Some("sv")), None);
    }

    #[test]
    fn describe_first_lines_are_the_title_the_wrapped_description_and_the_link() {
        colored::control::set_override(false);
        let block = describe_of(
            "{ \"title\": { \"sv-SE\": \"Katalog\" }, \"description\": { \"sv-SE\": \"Innehåller x y z och andra saker.\nKör bananer också.\" }, \"docsLink\": \"https://link-to-docs.com\" }\nGET /a",
        );
        assert_eq!(
            describe_first_lines(&block, Some("sv-SE"), 20),
            ["Katalog", "Innehåller x y z och", "andra saker.", "Kör bananer också.", "https://link-to-docs.com"]
        );
        // Only what the block has.
        assert_eq!(describe_first_lines(&describe_of("{ \"docsLink\": \"https://x\" }\nGET /a"), None, 80), ["https://x"]);
        assert!(describe_first_lines(&describe_of("{ \"title\": {} }\nGET /a"), None, 80).is_empty());
        // A word longer than the width is not cut.
        assert_eq!(wrap_words("a bbbbbbbbbb c", 4), ["a", "bbbbbbbbbb", "c"]);
        assert_eq!(wrap_words("åäö åäö", 7), ["åäö åäö"]);
    }

    #[test]
    fn is_assert_uri_knows_the_endpoint_however_it_is_written() {
        for uri in ["/assert", "assert", "/v1/assert", "v1/assert", "/api/v1/assert", "api/v2/assert", "/assert/", "/assert > /tmp/out.json"] {
            assert!(is_assert_uri("/api/v1", uri), "{uri}");
        }
        assert!(is_assert_uri("/api/me/v1", "/assert"));
        for uri in ["/asserts", "/people/assert", "/assert/x", "/assert~count", "/api/assert", "/", ""] {
            assert!(!is_assert_uri("/api/v1", uri), "{uri}");
        }
    }

    #[test]
    fn collect_assertions_takes_every_put_assert_body_as_written() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("asserts.json");
        std::fs::write(&file, "{ \"api/v1/file\": { \"is\": 1 } // from a file\n}").unwrap();
        std::fs::write(dir.path().join("inc.api"), "PUT v1/assert {\"api/v1/now\":{\"is not\":null}}\n").unwrap();
        let src = format!(
            "{{ \"title\": {{}} }}\nPUT /assert {{ \"api/v1/people~count\": {{ \"is\": 3 }} }}\nGET /assert\nPUT /people/x {{ \"a\": 1 }}\ninc.api\nassert GET /people~count\nGET /a && PUT /api/v1/assert {{\n  \"z\": {{ \"is\": 1 }}, // z first\n  \"api/v1/people~count\": {{ \"is not\": 3, \"suggest\": [4] }}\n}} > /tmp/out.json\nPUT /assert @{}\n",
            file.display()
        );
        let program = split_bulk_requests(&src, Some(dir.path())).unwrap();
        let assertions = collect_assertions(&program, "/api/v1").unwrap();
        assert_eq!(
            serde_json::to_string(&assertions).unwrap(),
            concat!(
                r#"[{"api/v1/people~count":{"is":3}},"#,
                r#"{"api/v1/now":{"is not":null}},"#,
                // Two requests that assert the same path stay two, and the
                // members of one keep their order.
                r#"{"z":{"is":1},"api/v1/people~count":{"is not":3,"suggest":[4]}},"#,
                r#"{"api/v1/file":{"is":1}}]"#
            )
        );
        // A file that asserts nothing asserts an empty list.
        let program = split_bulk_requests("GET /a\nassert /b\n", None).unwrap();
        assert!(collect_assertions(&program, "/api/v1").unwrap().is_empty());
        // A body that can't be read is an error, not a gap in the list.
        let program = split_bulk_requests("PUT /assert { \"a\": }\n", None).unwrap();
        let err = collect_assertions(&program, "/api/v1").unwrap_err();
        assert!(err.starts_with("the body of `PUT /assert` is not JSON: "), "{err}");
        let program = split_bulk_requests("PUT /assert @/nowhere/asserts.json\n", None).unwrap();
        assert!(collect_assertions(&program, "/api/v1").is_err());
    }
}
