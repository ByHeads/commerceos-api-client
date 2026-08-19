#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Read as IoRead, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cli_clipboard;
use reqwest::blocking::Client;
use atty::Stream;
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

/// Rows the ctrl+h panel occupies: the ruler, its 25 fixed lines, and the
/// streaming section (a blank separator plus its text) when streaming is on.
/// Derived rather than hardcoded so the clear span always matches what's drawn.
///
/// The streaming lines are measured against the terminal width rather than
/// counted: the docs link carries the connection's host, and a long one would
/// wrap into rows the clear span didn't know about.
fn help_line_count(state: &AppState) -> u16 {
    let base = 26;
    if !state.config.streaming {
        return base;
    }
    let rows: u16 = streaming_help_lines(&state.config.base_uri)
        .iter()
        .map(|line| visual_line_count(line, state.width as usize))
        .sum();
    base + 1 + rows
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

    /// HTTP method (GET, POST, PUT, PATCH, DELETE)
    #[arg(value_name = "METHOD")]
    method: Option<String>,

    /// URI path (e.g., /people)
    #[arg(value_name = "URI")]
    uri: Option<String>,

    /// Request body (JSON)
    #[arg(value_name = "BODY")]
    body: Option<String>,

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
        }
    }
}

/// Default request timeout. Set explicitly because reqwest's *blocking* client
/// otherwise applies its own 30s default — far too short for large exports.
const DEFAULT_TIMEOUT_SECS: u64 = 600; // 10 minutes

/// Build the HTTP client. The timeout is always passed explicitly, so reqwest's
/// hidden default can never apply; `0` disables it (`--timeout 0`).
fn build_request_client(timeout_secs: u64) -> Client {
    let timeout = if timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(timeout_secs))
    };
    Client::builder()
        .timeout(timeout)
        .build()
        .unwrap_or_else(|_| Client::new())
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
    client_id: String,   // OAuth2 client ID (empty for key/token)
}

// All connection data stored in a single keychain entry
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct KeychainData {
    #[serde(alias = "environments")]
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

fn load_keychain_data() -> KeychainData {
    KEYCHAIN_CACHE.with(|cache| {
        if let Some(ref data) = *cache.borrow() {
            return data.clone();
        }
        let data = if let Some(path) = no_keychain_file() {
            // File-backed mode: missing/unreadable file is treated as empty.
            match fs::read_to_string(&path) {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => KeychainData::default(),
            }
        } else {
            match keychain_entry().get_password() {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => KeychainData::default(),
            }
        };
        *cache.borrow_mut() = Some(data.clone());
        data
    })
}

fn save_keychain_data(data: &KeychainData) -> Result<(), String> {
    let json = serde_json::to_string(data).map_err(|e| e.to_string())?;
    if let Some(path) = no_keychain_file() {
        fs::write(&path, &json).map_err(|e| format!("credentials file error: {}", e))?;
    } else {
        keychain_entry().set_password(&json).map_err(|e| format!("keychain error: {}", e))?;
    }
    KEYCHAIN_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(data.clone());
    });
    Ok(())
}

fn list_connections() -> Vec<String> {
    load_keychain_data().connections.iter().map(|e| e.name.clone()).collect()
}

fn load_connection(name: &str) -> Option<SavedConnection> {
    load_keychain_data().connections.iter().find(|e| e.name == name).cloned()
}

fn save_connection(env: &SavedConnection) -> Result<(), String> {
    let mut data = load_keychain_data();
    if let Some(existing) = data.connections.iter_mut().find(|e| e.name == env.name) {
        *existing = env.clone();
    } else {
        data.connections.push(env.clone());
    }
    save_keychain_data(&data)
}

fn delete_connection(name: &str) -> Result<(), String> {
    let mut data = load_keychain_data();
    data.connections.retain(|e| e.name != name);
    if data.default == name {
        data.default.clear();
    }
    save_keychain_data(&data)
}

fn get_default_connection() -> Option<String> {
    let data = load_keychain_data();
    if data.default.is_empty() { None } else { Some(data.default) }
}

fn set_default_connection(name: &str) -> Result<(), String> {
    let mut data = load_keychain_data();
    data.default = name.to_string();
    save_keychain_data(&data)
}

// OAuth2 client credentials token exchange
fn oauth2_token_exchange(base_uri: &str, client_id: &str, client_secret: &str) -> Result<(String, u64), String> {
    let token_url = format!("{}/oauth2/v1/token", base_uri.trim_end_matches('/'));
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .post(&token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            client_id, client_secret
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
    paths: HashMap<String, PathItem>,
    components: Option<Components>,
    tags: Option<Vec<TagItem>>,
}

#[derive(Debug, Deserialize, Default)]
struct TagItem {
    name: String,
    #[serde(rename = "x-type")]
    x_type: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Components {
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
    ctrl_c_pending: bool,
    ctrl_c_at: Option<std::time::Instant>,
    width: u16,
    height: u16,
    prev_width: u16,
    output_history: Vec<OutputBlock>,  // Logged requests, re-rendered on resize
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
    body_input_method: String,
    body_input_uri: String,
    // OAuth2 credentials for token refresh
    oauth2_client_id: String,
    oauth2_client_secret: String,
    // Bracketed-paste identifier-expansion state
    // Cycles through identifiers when the same JSON is re-pasted within 10s.
    last_paste_raw: String,
    last_paste_cycle_idx: usize,
    last_paste_at: Option<std::time::Instant>,
}

impl AppState {
    fn new(config: Config) -> Self {
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
            ctrl_c_pending: false,
            ctrl_c_at: None,
            width: 80,
            height: 24,
            prev_width: 80,
            output_history: Vec::new(),
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
            body_input_method: String::new(),
            body_input_uri: String::new(),
            oauth2_client_id: String::new(),
            oauth2_client_secret: String::new(),
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
    let collapsed = collapse_newlines_for_log(body);
    if char_len(&collapsed) <= budget {
        return collapsed;
    }
    // Reserve one column for the ellipsis itself.
    let head: String = collapsed.chars().take(budget.saturating_sub(1)).collect();
    format!("{}…", head)
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

fn load_history() -> Vec<String> {
    if let Some(path) = get_history_path() {
        if let Ok(file) = fs::File::open(&path) {
            let reader = io::BufReader::new(file);
            return reader.lines().filter_map(|l| l.ok()).collect();
        }
    }
    Vec::new()
}

fn save_history(history: &[String]) {
    if let Some(path) = get_history_path() {
        if let Ok(mut file) = fs::File::create(&path) {
            for entry in history.iter().rev().take(1000).collect::<Vec<_>>().iter().rev() {
                let _ = writeln!(file, "{}", entry);
            }
        }
    }
}

fn append_history(entry: &str) {
    if let Some(path) = get_history_path() {
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(file, "{}", entry);
        }
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
                let host_display = if display_url.len() > host_space { &display_url[display_url.len() - host_space..] } else { display_url };
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
                let host_display = if display_url.len() > host_space { &display_url[display_url.len() - host_space..] } else { display_url };
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
            let display_url = if url.len() > max_url_len {
                &url[url.len() - max_url_len..]
            } else {
                url.as_str()
            };
            let ghost_budget = max_url_len.saturating_sub(display_url.len());
            let display_ghost = if ghost.len() > ghost_budget { &ghost[..ghost_budget] } else { ghost.as_str() };
            execute!(stdout, Print(format!("{}{:<14}{}\x1b[2m{}\x1b[0m\x1b[48;5;247m\x1b[38;5;0m \x1b[0m\r\n",
                prefix, "URL:".dimmed(), display_url, display_ghost)))?;
        } else if url.is_empty() {
            execute!(stdout, Print(format!("{}{:<14}\r\n", prefix, "URL:".dimmed())))?;
        } else {
            let display_url = if url.len() > max_url_len {
                &url[url.len() - max_url_len..]
            } else {
                url.as_str()
            };
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
            let client = Client::builder().timeout(Duration::from_secs(10)).build().ok();
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
        apply_connection_to_config(&mut test_config, env);
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
            let _ = Command::new("open").arg("https://dev.heads.com/api-docs").spawn();
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
                    // Add scheme if not present
                    if !self.setup_url.starts_with("http://") && !self.setup_url.starts_with("https://") {
                        if self.setup_url.starts_with("localhost") || self.setup_url.starts_with("127.0.0.1") || self.setup_url.starts_with("[::1]") || self.setup_url.contains(':') {
                            self.setup_url = format!("http://{}", self.setup_url);
                        } else {
                            self.setup_url = format!("https://{}", self.setup_url);
                        }
                    }
                    // Strip /api/v1 and anything after - we only need base URL
                    // Strip path suffixes - we only need base URL
                    let trimmed = if let Some(idx) = self.setup_url.find("/api/v1") {
                        self.setup_url.truncate(idx);
                        true
                    } else if let Some(idx) = self.setup_url.find("/api") {
                        self.setup_url.truncate(idx);
                        true
                    } else if self.setup_url.ends_with("/") {
                        self.setup_url.pop();
                        true
                    } else {
                        false
                    };
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
                KeyCode::Char(c) => {
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
                KeyCode::Char(c) => {
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
                KeyCode::Char(c) => {
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
                        print!("\x1b[2J\x1b[3J\x1b[H");
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

/// Add a scheme to a bare base URI: http for localhost/127.0.0.1 or anything
/// carrying an explicit port, https for everything else. Already-schemed URIs
/// pass through untouched.
fn normalize_base_uri(uri: &str) -> String {
    if uri.starts_with("http://") || uri.starts_with("https://") {
        return uri.to_string();
    }
    if uri.starts_with("localhost") || uri.starts_with("127.0.0.1") || uri.contains(':') {
        format!("http://{}", uri)
    } else {
        format!("https://{}", uri)
    }
}

/// Bail out when there's no host to send to. Without this the request goes to a
/// bare path, reqwest fails, and the caller asks whether COS is running on the
/// empty string.
fn require_base_uri(config: &Config) {
    if config.base_uri.is_empty() {
        eprintln!("{}", "Error: no base URL specified. Use -b <url> or -c <connection>.".red());
        std::process::exit(1);
    }
}

// Apply a saved connection to a Config
fn apply_connection_to_config(config: &mut Config, env: &SavedConnection) {
    config.base_uri = normalize_base_uri(&env.url);
    match env.auth_type.as_str() {
        "token" => {
            config.token = env.credential.clone();
            config.api_key = String::new();
        }
        "oauth2" => {
            // Exchange for token at startup
            match oauth2_token_exchange(&config.base_uri, &env.client_id, &env.credential) {
                Ok((token, _expires)) => {
                    config.token = token;
                    config.api_key = String::new();
                }
                Err(e) => {
                    eprintln!("OAuth2 token exchange failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            // "key" or anything else
            config.api_key = env.credential.clone();
            config.token = String::new();
        }
    }
}

fn main() {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) => {
            // Help and version are "success" errors in clap — print them normally
            if e.kind() == clap::error::ErrorKind::DisplayHelp || e.kind() == clap::error::ErrorKind::DisplayVersion {
                print!("{}", e);
                std::process::exit(0);
            }
            // For unexpected arguments, print a simple message
            let msg = e.to_string();
            if let Some(arg) = msg.split('\'').nth(1) {
                eprintln!("error: unexpected option {}", arg);
            } else {
                eprintln!("error: {}", msg.lines().next().unwrap_or("invalid arguments"));
            }
            std::process::exit(1);
        }
    };

    if args.version {
        println!("v{}", VERSION);
        std::process::exit(0);
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
        if let Some(key) = args.key {
            config.api_key = key;
        }
        if let Some(token) = args.token {
            config.token = token;
        }
    }

    // Parse positional args like bash client
    let (method, uri, mut body) = parse_positional_args(args.method, args.uri, args.body);

    // `-t` used to take a bearer token and now means --stream, so an old
    // invocation leaves the token sitting in the method slot. Say so rather
    // than letting it become a request to a nonsense method.
    if args.stream && looks_like_bearer_token(&method) {
        eprintln!(
            "{}",
            "error: -t is now --stream. Use --token <TOKEN> for a bearer token.".red()
        );
        std::process::exit(1);
    }

    // Read from stdin if available and no body provided (and not bulk mode)
    if body.is_empty() && args.all.is_none() && !atty::is(Stream::Stdin) {
        let mut stdin_content = String::new();
        if io::stdin().read_to_string(&mut stdin_content).is_ok() {
            body = stdin_content.trim().to_string();
        }
    }

    // If method expects a body but none provided, read interactively from stdin
    if body.is_empty()
        && atty::is(Stream::Stdin)
        && ["POST", "PUT", "PATCH"].contains(&method.as_str())
        && !uri.is_empty()
    {
        eprintln!("Reading body from stdin (ctrl+d to finish):");
        let mut stdin_content = String::new();
        if io::stdin().read_to_string(&mut stdin_content).is_ok() {
            body = stdin_content.trim().to_string();
        }
    }

    // Handle -c flag: load saved connection by alias or URL
    if let Some(ref connection_selector) = args.connection {
        let envs = list_connections();
        let mut found = false;
        // Try exact alias match first
        for name in &envs {
            if name == connection_selector {
                if let Some(env) = load_connection(name) {
                    apply_connection_to_config(&mut config, &env);
                    loaded_connection_alias = name.clone();
                    found = true;
                    break;
                }
            }
        }
        // Try URL match if no alias match
        if !found {
            for name in &envs {
                if let Some(env) = load_connection(name) {
                    let url_bare = env.url.trim_start_matches("https://").trim_start_matches("http://");
                    if env.url == *connection_selector || url_bare == *connection_selector {
                        apply_connection_to_config(&mut config, &env);
                        loaded_connection_alias = name.clone();
                        found = true;
                        break;
                    }
                }
            }
        }
        if !found {
            eprintln!("Connection \"{}\" not found. Saved connections: {}", connection_selector,
                if envs.is_empty() { "none".to_string() } else { envs.join(", ") });
            std::process::exit(1);
        }
        // Show UI immediately with async loading (like 1P and picker)
        if !loaded_connection_alias.is_empty() && uri.is_empty() && atty::is(Stream::Stdout) {
            connecting_to = Some(loaded_connection_alias.clone());
        }
    }

    // If -b provided without auth, go straight to setup with URL pre-filled
    if has_explicit_uri && !has_explicit_auth && uri.is_empty() && atty::is(Stream::Stdout) {
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
                if let Some(rc) = resolved_config {
                    config = rc;
                } else {
                    apply_connection_to_config(&mut config, &env);
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
                std::process::exit(0);
            }
            Err(e) => {
                let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                terminal::disable_raw_mode().unwrap();
                execute!(stdout, cursor::Show).unwrap();
                eprintln!("Error: {}", e);
                std::process::exit(1);
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
                        apply_connection_to_config(&mut config, &env);
                    }
                }
            } else if !has_explicit_auth && uri.is_empty() && atty::is(Stream::Stdout) {
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
                        if let Some(rc) = resolved_config {
                            config = rc;
                        } else {
                            apply_connection_to_config(&mut config, &env);
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
                        std::process::exit(0);
                    }
                    Err(e) => {
                        let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                        execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                        terminal::disable_raw_mode().unwrap();
                        execute!(stdout, cursor::Show).unwrap();
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        } else if !has_explicit_auth && uri.is_empty() && atty::is(Stream::Stdout) {
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
                    if let Some(rc) = resolved_config {
                        config = rc;
                    } else {
                        apply_connection_to_config(&mut config, &env);
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
                    std::process::exit(0);
                }
                Err(e) => {
                    let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                    execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                    terminal::disable_raw_mode().unwrap();
                    execute!(stdout, cursor::Show).unwrap();
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
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
                    std::process::exit(1);
                }
            }
        }
        if bulk_arg == "-" {
            let mut stdin_content = String::new();
            if io::stdin().read_to_string(&mut stdin_content).is_err() {
                eprintln!("error: could not read stdin");
                std::process::exit(1);
            }
            // No base_dir for stdin — includes can still use absolute paths
            run_bulk_from_str(&mut config, &stdin_content, None);
        } else {
            run_bulk(&mut config, bulk_arg);
        }
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
                    std::process::exit(1);
                }
            }
        }
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
        std::process::exit(1);
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

fn get_1password_credentials(selector: &str) -> Result<(String, String), String> {
    // Check if op command exists. `which` exits non-zero when it isn't found, so
    // the exit status is what matters — `output()` itself only fails if `which`
    // is missing, which would let a missing `op` through.
    let has_op = Command::new("which")
        .arg("op")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_op {
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

            return Ok((url.to_string(), api_key));
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
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| Client::new());

    let url = format!("{}{}/about", config.base_uri, config.api_path);

    let mut request = client.get(&url);

    if !config.token.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", config.token));
    } else if !config.api_key.is_empty() {
        let encoded = BASE64.encode(format!(":{}", config.api_key));
        request = request.header("Authorization", format!("Basic {}", encoded));
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
fn parse_request_line(line: &str) -> Option<(String, String, String)> {
    let mut working = line.trim().to_string();
    if working.is_empty() || working.starts_with('#') {
        return None;
    }

    // Strip ` > outfile` / ` >> outfile` from the end (matches parse_input),
    // preserving which marker it was so append survives the round-trip.
    let outfile_suffix: String = if let Some(idx) = working.rfind(" >") {
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
            let uri_end = after_method.find(|c: char| c.is_whitespace()).unwrap_or(after_method.len());
            let uri = after_method[..uri_end].to_string();
            let body = after_method[uri_end..].trim_start_matches(|c: char| c == ' ' || c == '\t').to_string();
            (first_upper, uri, body)
        }
    } else if first_word.starts_with('/') {
        let uri = first_word.to_string();
        let body = working[first_end..].trim_start_matches(|c: char| c == ' ' || c == '\t').to_string();
        ("GET".to_string(), uri, body)
    } else {
        return None;
    };

    // Append outfile suffix to URI so run_non_interactive's `uri.find(" >")` picks it up
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
fn resolve_request_path(api_path: &str, uri: &str) -> String {
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
    },
}

/// How much of a streamed body is retained for `classify_response`. Every falsy
/// payload (`false`, `null`, `0`, `""`) is a handful of bytes, so a body that
/// overflows this can only be truthy — the prefix decides chains exactly as a
/// fully buffered read would.
const CLASSIFY_PREFIX_BYTES: usize = 4096;

/// What a streamed copy left behind, since the body itself was never held.
struct StreamedBody {
    /// The leading `CLASSIFY_PREFIX_BYTES` of the body.
    prefix: String,
    /// The body was longer than the prefix.
    overflowed: bool,
    /// Last byte written, so stdout can match the buffered path's trailing
    /// newline. `None` for an empty body.
    last_byte: Option<u8>,
}

/// Copy a streaming response into `sink` without holding the whole body, keeping
/// the leading `CLASSIFY_PREFIX_BYTES` so `&&`/`||` chains still see a payload
/// to judge.
fn stream_to_sink(mut resp: impl IoRead, sink: &mut dyn Write) -> io::Result<StreamedBody> {
    let mut prefix: Vec<u8> = Vec::new();
    let mut overflowed = false;
    let mut last_byte = None;
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
        sink.write_all(&buf[..n])?;
    }
    sink.flush()?;

    Ok(StreamedBody {
        prefix: String::from_utf8_lossy(&prefix).into_owned(),
        overflowed,
        last_byte,
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

/// - target missing or empty → plain write, identical to `>`
/// - `.ndjson`/`.njson` target → a JSON-array payload is exploded to one compact
///   object per line, a single JSON value becomes one compact line, and
///   anything else (already-NDJSON) is text-appended
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
        return fs::write(path, new_content);
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
    let merged = if path_lower.ends_with(".ndjson") || path_lower.ends_with(".njson") {
        // NDJSON: keep the one-value-per-line shape whatever shape the payload
        // arrived in.
        match serde_json::from_str::<Value>(new_content.trim()) {
            Ok(Value::Array(items)) => {
                let lines: Vec<String> = items
                    .iter()
                    .filter_map(|v| serde_json::to_string(v).ok())
                    .collect();
                text_append(&existing, &format!("{}\n", lines.join("\n")))
            }
            Ok(single) => {
                let line = serde_json::to_string(&single).unwrap_or_else(|_| new_content.trim().to_string());
                text_append(&existing, &format!("{}\n", line))
            }
            Err(_) => text_append(&existing, new_content),
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
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
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
    Ok(Duration::from_secs_f64(secs))
}

/// If `line` (already trimmed, known not to be a request) is a `url has`/`url is`
/// gate directive, parse it. Returns `Ok(Some(cond))` for a url directive,
/// `Ok(None)` if it isn't one (so the caller falls through to include handling),
/// or `Err` for a malformed `url` directive.
fn parse_url_condition(trimmed: &str) -> Result<Option<UrlCondition>, String> {
    let mut it = trimmed.splitn(3, char::is_whitespace);
    if it.next() != Some("url") {
        return Ok(None);
    }
    let op = it.next().unwrap_or("");
    let value = it.next().unwrap_or("").trim();
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

/// Resolve an include directive into the actual file paths to load.
fn resolve_include_paths(
    include_spec: &str,
    base_dir: Option<&std::path::Path>,
) -> Result<Vec<std::path::PathBuf>, String> {
    let expanded = if include_spec.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            format!("{}{}", home.display(), &include_spec[1..])
        } else {
            include_spec.to_string()
        }
    } else {
        include_spec.to_string()
    };

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
    chain: &mut std::collections::HashSet<std::path::PathBuf>,
    program: &mut BulkProgram,
) -> Result<(), String> {
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    let mut current = String::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if current.is_empty() {
            // Between requests: skip blank lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Decide: request line, directive (sleep/url), or include?
            let first_word = trimmed.split_whitespace().next().unwrap_or("");
            let first_upper = first_word.to_uppercase();
            let is_request =
                methods.contains(&first_upper.as_str()) || first_word.starts_with('/');

            if !is_request {
                // `sleep N` — timing directive.
                if first_word.eq_ignore_ascii_case("sleep") {
                    let rest = trimmed["sleep".len()..].trim();
                    let dur = parse_sleep_directive(rest)?;
                    program.steps.push(BulkStep::Sleep(dur));
                    continue;
                }
                // `url has`/`url is` — environment gate, collected globally.
                if first_word.eq_ignore_ascii_case("url") {
                    if let Some(cond) = parse_url_condition(trimmed)? {
                        program.url_conditions.push(cond);
                        continue;
                    }
                }
                // Otherwise treat as include directive (load and inline another file).
                let paths = resolve_include_paths(trimmed, base_dir)?;
                for path in paths {
                    let canonical = path.canonicalize().unwrap_or(path.clone());
                    if chain.contains(&canonical) {
                        return Err(format!("include loop detected: {}", path.display()));
                    }
                    let included = fs::read_to_string(&canonical)
                        .map_err(|e| format!("could not read include {}: {}", path.display(), e))?;
                    chain.insert(canonical.clone());
                    let new_base = canonical.parent().map(|p| p.to_path_buf());
                    split_bulk_requests_inner(
                        &included,
                        new_base.as_deref(),
                        chain,
                        program,
                    )?;
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
            let segments = split_request_chain(&assembled);
            program.steps.push(if segments.len() > 1 {
                BulkStep::Chain(segments)
            } else {
                BulkStep::Request(assembled)
            });
            current.clear();
        }
    }

    if !current.trim().is_empty() {
        let (_, depth) = strip_body_comments_and_count(&current);
        return Err(format!(
            "unclosed body at end of bulk file (depth {})",
            depth
        ));
    }

    Ok(())
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
    let mut program = BulkProgram::default();
    let mut chain = std::collections::HashSet::new();
    split_bulk_requests_inner(contents, base_dir, &mut chain, &mut program)?;
    Ok(program)
}

/// Format a single request as `METHOD URI [body]` for preview display.
/// The body is compacted (JSON re-serialized without whitespace) when possible,
/// matching the bulk-silent status-line format.
fn format_request_preview(method: &str, uri: &str, body: &str) -> String {
    let display_body = compact_body_for_display(body);
    if display_body.is_empty() {
        format!("{} {}", method, uri)
    } else {
        format!("{} {} {}", method, uri, display_body)
    }
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
}

impl OutputBlock {
    /// The full block as printed: request line fitted to `width`, then the
    /// stored head and tail. Always ends with the newline that closes the
    /// request line, so blocks concatenate cleanly.
    fn render(&self, width: usize) -> String {
        format!(
            "{}\n{}{}",
            format_request_log_line(
                &self.method,
                &self.uri,
                &self.body,
                &self.display_outfile,
                self.outfile_append,
                width,
            ),
            self.head,
            self.tail,
        )
    }

    fn has_body(&self) -> bool {
        !self.tail.is_empty()
    }

    fn strip_body(&mut self) {
        self.tail.clear();
    }
}

/// The response body as an `OutputBlock` tail: a blank line above, one below.
///
/// The payload's own trailing newline is dropped so this spacing is the only
/// thing that decides it. Whether a body carries one varies by content type,
/// status, and streaming — pretty-printing drops it, `-r` and NDJSON keep it,
/// streamed JSON and error bodies arrive without one — and that difference
/// otherwise surfaced as an extra blank line under the response.
fn format_body_block(output: &str) -> String {
    format!("\n{}\n\n", output.trim_end_matches('\n'))
}

/// Push a finished block, evicting the oldest past `OUTPUT_HISTORY_LIMIT`.
fn push_output_block(state: &mut AppState, block: OutputBlock) {
    state.output_history.push(block);
    if state.output_history.len() > OUTPUT_HISTORY_LIMIT {
        state.output_history.remove(0);
    }
}

/// Show a preview of the request line(s) and ask the user to confirm before
/// sending. Output and prompt go to stderr so piped stdout stays clean. Reads
/// the answer from /dev/tty (falling back to stdin) so it works even when stdin
/// is a piped bulk file. Defaults to yes: an empty line (Enter) accepts.
/// Returns true to proceed, false to abort.
fn confirm_preview(lines: &[String], base_uri: &str) -> bool {
    if atty::is(Stream::Stderr) {
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
    eprint!("{} ", "Run? [Y/n]".bold());
    let _ = io::stderr().flush();

    // Read a single line of input, preferring /dev/tty so a piped stdin
    // (e.g. `-a -`) does not consume the request data as the answer.
    let mut answer = String::new();
    let read_ok = match fs::File::open("/dev/tty") {
        Ok(tty) => {
            let mut reader = io::BufReader::new(tty);
            reader.read_line(&mut answer).is_ok()
        }
        Err(_) => io::stdin().read_line(&mut answer).is_ok(),
    };
    if !read_ok {
        // No way to ask — treat as decline to be safe.
        eprintln!("aborted (could not read confirmation)");
        return false;
    }
    let a = answer.trim().to_lowercase();
    let proceed = a.is_empty() || a == "y" || a == "yes";
    if !proceed {
        eprintln!("aborted");
    }
    proceed
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
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };

    // URL gate: validate the configured base URI against all collected conditions
    // before any output or requests, so test data can't reach the wrong environment.
    if let Err(e) = evaluate_url_gate(&program.url_conditions, &config.base_uri) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }

    // Preview: show all resolved requests (and sleeps) and confirm once before
    // sending. Done before any stdout output so a declined run leaves stdout clean.
    if config.preview {
        let preview_lines: Vec<String> = program
            .steps
            .iter()
            .flat_map(|step| match step {
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
            })
            .collect();
        if !confirm_preview(&preview_lines, &config.base_uri) {
            return;
        }
        // Confirmed for the whole batch — avoid re-prompting per request.
        config.preview = false;
    }

    if config.bulk_silent && !config.base_uri.is_empty() {
        // Ensure colors work even when stdout is piped
        if atty::is(Stream::Stderr) {
            colored::control::set_override(true);
        }
        println!("{}", format!("[{}]", config.base_uri).dimmed());
    }

    for step in &program.steps {
        match step {
            BulkStep::Sleep(d) => {
                if config.bulk_silent {
                    println!("{}", format!("sleep {}", format_duration(*d)).dimmed());
                }
                thread::sleep(*d);
            }
            BulkStep::Request(request) => {
                run_bulk_request(config, request);
            }
            BulkStep::Chain(segments) => {
                // Outcome of the last EXECUTED segment; skipped segments leave
                // it alone (that's what makes `a && b || c` an if-then-else).
                let mut prev: Option<RequestOutcome> = None;
                let mut skipped = 0usize;
                for (op, segment) in segments.iter() {
                    if !chain_segment_should_run(prev, *op) {
                        skipped += 1;
                        continue;
                    }
                    match run_bulk_request(config, segment) {
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
                        Some(RequestOutcome::Errored) => std::process::exit(1),
                        // Preview declined — the user said no, so it isn't a failure.
                        Some(RequestOutcome::Aborted) => break,
                    }
                }
                note_skipped_chain(config, skipped);
            }
        }
    }
}

/// Run one bulk request line, echoing it first in `-a` mode. `None` when the
/// line isn't a request at all.
fn run_bulk_request(config: &mut Config, request: &str) -> Option<RequestOutcome> {
    let (method, uri, body) = parse_request_line(request)?;
    if config.bulk_silent {
        // Compact the body for display: parse as JSON and re-serialize without whitespace,
        // falling back to the raw body if it's not JSON (e.g., @file references).
        // Unstyled, like the TUI log.
        let display_body = compact_body_for_display(&body);
        if display_body.is_empty() {
            println!("{} {}", method, uri);
        } else {
            println!("{} {} {}", method, uri, display_body);
        }
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
        println!("{}", note);
    } else {
        eprintln!("{}", note);
    }
}

/// Format a Duration for display: whole seconds as `Ns`, sub-second as `Nms`.
fn format_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms % 1000 == 0 {
        format!("{}s", ms / 1000)
    } else {
        format!("{}ms", ms)
    }
}

fn run_bulk(config: &mut Config, file_path: &str) {
    let path = if file_path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            format!("{}{}", home.display(), &file_path[1..])
        } else {
            file_path.to_string()
        }
    } else {
        file_path.to_string()
    };

    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: could not read {}: {}", path, e);
            std::process::exit(1);
        }
    };

    let base_dir = std::path::Path::new(&path).parent().map(|p| p.to_path_buf());
    run_bulk_from_str(config, &contents, base_dir.as_deref());
}

/// Send one request and report what it means for a `&&` chain. Errors are
/// printed here; deciding whether they end the run is the caller's business
/// (bulk exits 1, the TUI stops the chain and stays open).
fn run_non_interactive(config: &mut Config, method: &str, uri: &str, body: &str) -> RequestOutcome {
    let is_tty = atty::is(Stream::Stdout);

    // Ensure colors work on stderr even when stdout is piped
    if atty::is(Stream::Stderr) {
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

    // Parse > / >> outfile from URI (space required before >, optional after;
    // `>>` appends instead of overwriting)
    let (actual_uri, outfile, display_outfile, outfile_append) = if let Some(idx) = uri.find(" >") {
        let mut rest = &uri[idx + 2..];
        let append = rest.starts_with('>');
        if append {
            rest = &rest[1..];
        }
        let display_path = rest.trim().to_string();
        let outfile_path = if display_path.starts_with("~/") {
            if let Some(home) = dirs::home_dir() {
                format!("{}{}", home.display(), &display_path[1..])
            } else {
                display_path.clone()
            }
        } else {
            display_path.clone()
        };
        (uri[..idx].trim(), Some(outfile_path), Some(display_path), append)
    } else {
        (uri, None, None, false)
    };

    // Streaming is opt-in and already resolved from --stream/API_STREAMING, so
    // there is no per-request feature-flag round trip here. A server that
    // doesn't stream ignores the unknown `;stream=true` media-type parameter.
    config.streaming = config.stream_requested;

    let client = build_request_client(config.timeout_secs);

    let url = format!("{}{}", config.base_uri, resolve_request_path(&config.api_path, actual_uri));

    let mut request = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "PATCH" => client.patch(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        _ => client.get(&url),
    };

    // Set auth header
    if !config.token.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", config.token));
    } else if !config.api_key.is_empty() {
        if config.api_key.starts_with("ey") && config.api_key.len() > 180 {
            request = request.header("Authorization", format!("Bearer {}", config.api_key));
        } else {
            let encoded = BASE64.encode(format!(":{}", config.api_key));
            request = request.header("Authorization", format!("Basic {}", encoded));
        }
    }

    // Set content type and accept headers
    let mut content_type = "application/json".to_string();
    let mut accept = "application/json".to_string();

    if config.ndjson {
        content_type = "application/x-ndjson".to_string();
        accept = "application/x-ndjson".to_string();
    }

    // Handle @ file input for body
    if body.starts_with("@ ") || body.starts_with("@") {
        // Parse ~func(arg) suffixes (e.g. ~map(name)) — only for @file bodies
        let (file_body, extra_headers) = parse_body_functions(body);
        for (name, value) in &extra_headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let file_path_raw = file_body.trim_start_matches("@ ").trim_start_matches('@').trim();
        match resolve_at_file_body(file_path_raw) {
            Ok(res) => {
                if let Some(ct) = res.content_type {
                    content_type = ct;
                }
                if let Some(ac) = res.accept_type {
                    accept = ac;
                }
                request = request.body(res.contents);
            }
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    } else if !body.is_empty() {
        request = request.body(body.to_string());
    }

    // Override accept based on outfile extension
    if let Some(ref outfile) = outfile {
        if outfile.ends_with(".ndjson") {
            accept = "application/x-ndjson".to_string();
        } else if outfile.ends_with(".csv") {
            accept = "text/csv".to_string();
        } else if outfile.ends_with(".sql") {
            accept = "application/sql".to_string();
        }
    }

    if config.streaming {
        content_type.push_str(";stream=true");
        accept.push_str(";stream=true");
    }

    if config.include_nulls {
        accept.push_str(";skipNulls=false");
    }

    request = request
        .header("Content-Type", &content_type)
        .header("Accept", &accept);

    let start = Instant::now();

    match request.send() {
        Ok(resp) => {
            let status = resp.status();
            let elapsed = start.elapsed();

            // `> clipboard` is a special outfile target — route to system clipboard.
            let is_clipboard = display_outfile
                .as_deref()
                .map(is_clipboard_target)
                .unwrap_or(false);

            // Streaming needs a sink that accepts bytes as they arrive, which
            // rules out everything that must see the whole body first: pretty
            // printing, `>>` merging, and the clipboard. Non-2xx buffers too, so
            // an error payload never streams into an outfile.
            let stream_body = config.streaming
                && status.is_success()
                && !is_clipboard
                && !outfile_append
                && (outfile.is_some()
                    || config.bulk_silent
                    || config.raw
                    || config.ndjson
                    || !is_tty);

            // Print status
            if !config.silent {
                let status_str = if status.is_success() {
                    format!("{} {}", status.as_u16(), status.canonical_reason().unwrap_or(""))
                        .green()
                        .to_string()
                } else {
                    format!("{} {}", status.as_u16(), status.canonical_reason().unwrap_or(""))
                        .red()
                        .to_string()
                };

                if config.bulk_silent {
                    // Bulk silent mode: print compact status to stdout with box-draw prefix
                    println!(
                        "{}HTTP/1.1 {} {}",
                        "└─".dimmed(),
                        status_str,
                        format!("{:.2}s", elapsed.as_secs_f64()).dimmed()
                    );
                } else {
                    eprintln!(
                        "HTTP/1.1 {} {}",
                        status_str,
                        format!("{:.2}s", elapsed.as_secs_f64()).dimmed()
                    );
                    // No blank line before "> outfile" — that line itself acts as the separator
                    if outfile.is_none() {
                        eprintln!();
                    }
                }
            }

            if stream_body {
                let streamed = if let Some(ref file_path) = outfile {
                    match fs::File::create(file_path) {
                        Ok(file) => {
                            let mut writer = io::BufWriter::new(file);
                            let res = stream_to_sink(resp, &mut writer);
                            if res.is_ok() && !config.silent && !config.bulk_silent {
                                // Match the buffered path: status line, then `> outfile`.
                                let display = display_outfile.as_deref().unwrap_or(file_path);
                                eprintln!("{}", format!("> {}", display).dimmed());
                            }
                            res
                        }
                        Err(e) => Err(e),
                    }
                } else if config.bulk_silent {
                    // Bodies are suppressed here, but the response still has to be
                    // drained before the next request reuses the connection.
                    stream_to_sink(resp, &mut io::sink())
                } else {
                    let stdout = io::stdout();
                    let mut lock = stdout.lock();
                    let res = stream_to_sink(resp, &mut lock);
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

                return match streamed {
                    Ok(body) => {
                        classify_streamed(status.as_u16(), &body.prefix, body.overflowed)
                    }
                    Err(e) => {
                        // A half-written outfile is worse than a loud failure —
                        // the caller decides whether this ends a bulk run.
                        eprintln!("Error streaming response: {}", e);
                        RequestOutcome::Errored
                    }
                };
            }

            // Read once, up front: the outcome depends on the body, and the
            // branches below each need it (or would drain it anyway).
            let body_text = resp.text().unwrap_or_default();
            let outcome = classify_response(status.as_u16(), &body_text);

            // Get response body — in bulk_silent mode, only write to outfile (no stdout)
            if config.bulk_silent {
                if let Some(ref file_path) = outfile {
                    {
                        let body_text = body_text.clone();
                        let output = if config.raw || config.ndjson {
                            body_text
                        } else if let Ok(json) = serde_json::from_str::<Value>(&body_text) {
                            serde_json::to_string_pretty(&json).unwrap_or(body_text)
                        } else {
                            body_text
                        };
                        if is_clipboard {
                            if outfile_append {
                                eprintln!("error: cannot append to clipboard — use > clipboard");
                                std::process::exit(1);
                            }
                            if let Err(e) = cli_clipboard::set_contents(output) {
                                eprintln!("Error copying to clipboard: {}", e);
                            }
                        } else {
                            let res = if outfile_append {
                                append_to_outfile(file_path, &output)
                            } else {
                                fs::write(file_path, &output)
                            };
                            if let Err(e) = res {
                                eprintln!("Error writing to {}: {}", file_path, e);
                            }
                        }
                    }
                }
            } else {
                let body_text = body_text.clone();
                let output = if config.raw || config.ndjson {
                    body_text
                } else if is_tty || outfile.is_some() {
                    // Pretty print for TTY or file output
                    if let Ok(json) = serde_json::from_str::<Value>(&body_text) {
                        serde_json::to_string_pretty(&json).unwrap_or(body_text)
                    } else {
                        body_text
                    }
                } else {
                    // Raw for pipes
                    body_text
                };

                // Write to file, clipboard, or stdout
                if is_clipboard {
                    if outfile_append {
                        eprintln!("error: cannot append to clipboard — use > clipboard");
                        std::process::exit(1);
                    }
                    match cli_clipboard::set_contents(output) {
                        Ok(()) => {
                            if !config.silent {
                                eprintln!("{}", "> clipboard".dimmed());
                            }
                        }
                        Err(e) => {
                            eprintln!("error: clipboard unavailable: {}", e);
                            std::process::exit(1);
                        }
                    }
                } else if let Some(ref file_path) = outfile {
                    let res = if outfile_append {
                        append_to_outfile(file_path, &output)
                    } else {
                        fs::write(file_path, &output)
                    };
                    if let Err(e) = res {
                        eprintln!("Error writing to {}: {}", file_path, e);
                    } else if !config.silent {
                        // Match interactive output: status line already printed,
                        // now print ">/>> outfile" (dimmed) on the next line.
                        let display = display_outfile.as_deref().unwrap_or(file_path);
                        let marker = if outfile_append { ">>" } else { ">" };
                        eprintln!("{}", format!("{} {}", marker, display).dimmed());
                    }
                } else {
                    print!("{}", output);
                    if !output.ends_with('\n') {
                        println!();
                    }
                    if is_tty && !config.silent {
                        eprintln!();
                    }
                }
            }

            outcome
        }
        Err(e) => {
            eprintln!();
            if e.is_timeout() {
                eprintln!(
                    "Timed out after {} — raise it with --timeout <seconds> (0 = no timeout)\n",
                    describe_timeout(config.timeout_secs)
                );
            } else {
                let host = config.base_uri.trim_start_matches("https://").trim_start_matches("http://");
                eprintln!("Is COS running on {}? 🤔\n", host);
            }
            std::process::exit(1);
        }
    }
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
            std::process::exit(1);
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
                    std::process::exit(1);
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
                        let new_config = if let Some(rc) = resolved_config {
                            rc
                        } else {
                            let mut nc = config.clone();
                            apply_connection_to_config(&mut nc, &env);
                            nc
                        };
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
                            std::process::exit(1);
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
                        std::process::exit(0);
                    }
                    Err(e) => {
                        let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                        execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                        terminal::disable_raw_mode().unwrap();
                        execute!(stdout, cursor::Show).unwrap();
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("{}", err);
                std::process::exit(1);
            }
        } else if !result.connected && !from_setup {
            // Connection failed - exit
            let host = config.base_uri.trim_start_matches("https://").trim_start_matches("http://");
            eprintln!("{}", format!("Could not connect to {}", host).red());
            std::process::exit(1);
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

    // Enter raw mode
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
    }

    // Enable bracketed paste so multi-character pastes arrive as one Event::Paste —
    // lets us recognize and expand pasted JSON identifier structures.
    let _ = execute!(stdout, EnableBracketedPaste);

    let mut state = AppState::new(config.clone());
    state.width = width;
    state.height = height;
    state.history = load_history();

    state.connection_alias = connection_alias.clone();

    // Store OAuth2 credentials for token refresh
    if let Some((client_id, client_secret)) = oauth2_creds {
        // From setup flow or passed explicitly
        state.oauth2_client_id = client_id;
        state.oauth2_client_secret = client_secret;
    } else if !connection_alias.is_empty() {
        // From saved connection
        if let Some(env) = load_connection(&connection_alias) {
            if env.auth_type == "oauth2" {
                state.oauth2_client_id = env.client_id.clone();
                state.oauth2_client_secret = env.credential.clone();
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
                    state.width = w;
                    state.height = h;

                    // Disable raw mode first (same as original working code)
                    terminal::disable_raw_mode()?;

                    // Clear screen and scrollback, move cursor to home
                    print!("\x1b[2J\x1b[3J\x1b[H");
                    io::stdout().flush().ok();

                    // Re-print splash with current terminal width
                    print_splash_with_width(&state.config, w);

                    // Re-print previous output, re-fitting each request line to the
                    // new width rather than replaying it at the old one.
                    for block in &state.output_history {
                        print!("{}", block.render(w as usize));
                    }

                    // Placeholder lines for input area (match actual input height)
                    let input_lines = state.input.split('\n').count() as u16;
                    let placeholder_count = 2 + input_lines; // ruler + input lines + hint
                    for _ in 0..placeholder_count {
                        println!();
                    }
                    io::stdout().flush().ok();

                    // Re-enable raw mode
                    terminal::enable_raw_mode()?;

                    // Reset prev_input_lines so render clears the right amount
                    state.prev_input_lines = input_lines;

                    // Render input area
                    render(&mut stdout, &mut state)?;
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
                    if enhanced_keyboard {
                        let _ = execute!(stdout, PopKeyboardEnhancementFlags);
                    }
                    let _ = execute!(stdout, DisableBracketedPaste);
                    // Move up to top of splash and clear from there down
                    let total_up = state.prev_input_lines + 7;
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
                    std::process::exit(1);
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

            // Always update splash URL line after background load completes
            {
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
                    let host_display = if host.len() > host_space { &host[..host_space] } else { host };
                    let host_padded = format!("{:width$}", host_display, width = host_space);
                    format!("{}{}{}{}{}", "│ ".dimmed(), host_padded.dimmed(), " │ ".dimmed(), hint.dimmed(), " │".dimmed())
                } else {
                    let host_space = actual_width.saturating_sub(4);
                    let host_display = if host.len() > host_space { &host[..host_space] } else { host };
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

    // Clear input area before exiting (move up and clear to end)
    let help_lines: u16 = help_line_count(&state);
    let lines_to_clear: u16 = if state.show_help { help_lines } else { 2 + state.prev_input_lines };
    execute!(
        stdout,
        cursor::MoveUp(lines_to_clear.min(state.height.saturating_sub(1))),
        cursor::MoveToColumn(0),
        Clear(ClearType::FromCursorDown),
        cursor::Show
    )?;

    // Restore terminal
    if enhanced_keyboard {
        let _ = execute!(stdout, PopKeyboardEnhancementFlags);
    }
    let _ = execute!(stdout, DisableBracketedPaste);
    terminal::disable_raw_mode()?;

    Ok(())
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
                parse_input(state, &input);
                state.history.push(input.clone());
                append_history(&input);
                state.history_idx = -1;
                state.prev_method = state.method.clone();
                state.prev_uri = state.uri.clone();
                state.prev_body = state.body.clone();
                state.prev_outfile = state.config.outfile.clone();

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
            state.prev_method = state.method.clone();
            state.prev_uri = state.uri.clone();
            state.prev_body = state.body.clone();
            state.prev_outfile = state.config.outfile.clone();
            state.method = "GET".to_string();
            state.body.clear();
            state.method_auto_promoted = false;

            execute_request(state, stdout)?;
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
            let _ = Command::new("open").arg(&url).spawn();
        }

        // Open last file
        (KeyModifiers::CONTROL, KeyCode::Char('o')) => {
            if !state.last_outfile.is_empty() {
                let _ = Command::new("open").arg(&state.last_outfile).spawn();
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

        // Save connection (ctrl+s)
        (KeyModifiers::CONTROL, KeyCode::Char('s')) => {
            handle_save_connection(state, stdout)?;
        }

        // Clear all output (ctrl+l)
        (KeyModifiers::CONTROL, KeyCode::Char('l')) => {
            if !state.output_history.is_empty() {
                state.output_history.clear();

                terminal::disable_raw_mode()?;
                print!("\x1b[2J\x1b[3J\x1b[H");
                io::stdout().flush().ok();
                print_splash_with_width(&state.config, state.width);
                let input_lines = state.input.split('\n').count() as u16;
                for _ in 0..(2 + input_lines) { println!(); }
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
                print!("\x1b[2J\x1b[3J\x1b[H");
                io::stdout().flush().ok();
                print_splash_with_width(&state.config, state.width);
                for block in &state.output_history {
                    print!("{}", block.render(state.width as usize));
                }
                let input_lines = state.input.split('\n').count() as u16;
                for _ in 0..(2 + input_lines) { println!(); }
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
                let line_start = state.input[..byte_idx].rfind('\n').unwrap(); // safe: not first line
                let col = byte_idx - line_start - 1;
                let prev_line_start = state.input[..line_start].rfind('\n')
                    .map_or(0, |p| p + 1);
                let prev_line_len = line_start - prev_line_start;
                let target_col = col.min(prev_line_len);
                state.cursor_pos = char_len(&state.input[..prev_line_start + target_col]);
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
                let line_start = state.input[..byte_idx].rfind('\n')
                    .map_or(0, |p| p + 1);
                let col = byte_idx - line_start;
                let next_newline = byte_idx + state.input[byte_idx..].find('\n').unwrap(); // safe: not last line
                let next_line_start = next_newline + 1;
                let next_line_end = state.input[next_line_start..].find('\n')
                    .map_or(state.input.len(), |p| next_line_start + p);
                let next_line_len = next_line_end - next_line_start;
                let target_col = col.min(next_line_len);
                state.cursor_pos = char_len(&state.input[..next_line_start + target_col]);
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

                let segments = split_request_chain(&input);
                let is_chain = segments.len() > 1;

                parse_input(state, if is_chain { &segments[0].1 } else { &input });

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
                    state.prev_method = state.method.clone();
                    state.prev_uri = state.uri.clone();
                    state.prev_body = state.body.clone();
                    state.prev_outfile = state.config.outfile.clone();

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

        // Word navigation back (ctrl+left or alt+b)
        (KeyModifiers::CONTROL, KeyCode::Left) | (KeyModifiers::ALT, KeyCode::Char('b')) => {
            state.cursor_pos = word_boundary_back(&state.input, state.cursor_pos);
            render(stdout, state)?;
        }

        // Word navigation forward (ctrl+right or alt+f)
        (KeyModifiers::CONTROL, KeyCode::Right) | (KeyModifiers::ALT, KeyCode::Char('f')) => {
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
/// Returns an empty vec when the paste isn't JSON, isn't an object, or doesn't
/// match either shape. Order follows the source JSON because `serde_json` is
/// built with the `preserve_order` feature.
fn extract_identifier_pairs(s: &str) -> Vec<(String, String)> {
    let value = match parse_pasted_json_fragment(s) {
        Some(v) => v,
        None => return Vec::new(),
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

/// True if `paste` begins with an HTTP method token followed by whitespace
/// (e.g. "GET /people..."), meaning it's a full request line that should replace
/// the current input rather than be inserted at the cursor.
fn paste_starts_with_method(paste: &str) -> bool {
    let trimmed = paste.trim_start();
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    match trimmed.split_once(|c: char| c.is_whitespace()) {
        Some((first, _rest)) => methods.contains(&first.to_uppercase().as_str()),
        None => false,
    }
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
    let inside_body = cursor_inside_brackets(&state.input, state.cursor_pos);

    // Pasting a full request line (starts with an HTTP method) outside a JSON body
    // replaces the entire input rather than inserting at the cursor — so pasting
    // "GET /people..." over a "GET /" prompt yields the pasted line, not a
    // duplicated method. Method detection is skipped inside a body so a JSON
    // string beginning with "GET " is pasted verbatim.
    if !inside_body && paste_starts_with_method(paste) {
        // Normalize the method to uppercase, like typed promotion does.
        state.input = uppercase_method_token(paste.trim_end());
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
    if let Some(idx) = input.rfind(" >") {
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
            if state.config.outfile.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    state.config.outfile = format!("{}{}", home.display(), &state.config.outfile[1..]);
                }
            }
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
            let uri_end = after_method_trimmed.find(|c: char| c.is_whitespace()).unwrap_or(after_method_trimmed.len());
            state.uri = after_method_trimmed[..uri_end].to_string();
            // Body is everything after URI; trim leading spaces/tabs but preserve newlines
            let after_uri = &after_method_trimmed[uri_end..];
            let body = after_uri.trim_start_matches(|c: char| c == ' ' || c == '\t');
            state.body = if body.trim().is_empty() { String::new() } else { body.to_string() };
        }
    } else if first_word.starts_with('/') {
        state.method = "GET".to_string();
        state.uri = first_word.to_string();
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
        body: state.body.clone(),
        display_outfile: state.display_outfile.clone(),
        outfile_append: state.config.outfile_append,
        ..Default::default()
    };

    // Build request
    let client = build_request_client(state.config.timeout_secs);

    let url = format!("{}{}", state.config.base_uri, resolve_request_path(&state.config.api_path, &state.uri));

    let mut request = match state.method.as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "PATCH" => client.patch(&url),
        "DELETE" => client.delete(&url),
        "HEAD" => client.head(&url),
        _ => client.get(&url),
    };

    // Set auth header
    if !state.config.token.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", state.config.token));
    } else if !state.config.api_key.is_empty() {
        if state.config.api_key.starts_with("ey") && state.config.api_key.len() > 180 {
            request = request.header("Authorization", format!("Bearer {}", state.config.api_key));
        } else {
            let encoded = BASE64.encode(format!(":{}", state.config.api_key));
            request = request.header("Authorization", format!("Basic {}", encoded));
        }
    }

    // Set content type and accept headers
    let mut content_type = "application/json".to_string();
    let mut accept = "application/json".to_string();

    if state.config.ndjson {
        content_type = "application/x-ndjson".to_string();
        accept = "application/x-ndjson".to_string();
    }

    // Handle @ file input for body
    let mut file_error: Option<String> = None;
    if state.body.starts_with("@ ") || state.body.starts_with("@") {
        // Parse ~func(arg) suffixes (e.g. ~map(name)) — only for @file bodies
        let (file_body, extra_headers) = parse_body_functions(&state.body);
        for (name, value) in &extra_headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let file_path_raw = file_body.trim_start_matches("@ ").trim_start_matches('@').trim();
        match resolve_at_file_body(file_path_raw) {
            Ok(res) => {
                if let Some(ct) = res.content_type {
                    content_type = ct;
                }
                if let Some(ac) = res.accept_type {
                    accept = ac;
                }
                request = request.body(res.contents);
            }
            Err(e) => {
                file_error = Some(e);
            }
        }
    } else if !state.body.is_empty() {
        request = request.body(state.body.clone());
    }

    // Override accept based on outfile extension
    if !state.config.outfile.is_empty() {
        if state.config.outfile.ends_with(".ndjson") {
            accept = "application/x-ndjson".to_string();
        } else if state.config.outfile.ends_with(".csv") {
            accept = "text/csv".to_string();
        } else if state.config.outfile.ends_with(".sql") {
            accept = "application/sql".to_string();
        }
    }

    if state.config.streaming {
        content_type.push_str(";stream=true");
        accept.push_str(";stream=true");
    }

    if state.config.include_nulls {
        accept.push_str(";skipNulls=false");
    }

    request = request
        .header("Content-Type", &content_type)
        .header("Accept", &accept);

    let start = Instant::now();

    // If file error, show it and return
    if let Some(err) = file_error {
        block.head = format!("\n{}\n\n", err);
        let display_output = block.render(state.width as usize);
        push_output_block(state, block);

        // Update input with last command (chain-aware, outfile marker included)
        restore_input_after_send(state);

        // Clear input area, print output, render new input (stay in raw mode)
        let clear_lines = 2 + state.prev_input_lines;
        queue!(stdout, cursor::Hide, cursor::MoveUp(clear_lines.min(state.height.saturating_sub(1))), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;
        // Print output with \r\n line endings for raw mode
        let raw_output = display_output.replace('\n', "\r\n");
        queue!(stdout, Print(&raw_output))?;
        let input_lines = visual_line_count(&state.input, state.width as usize);
        for _ in 0..(2 + input_lines) { queue!(stdout, Print("\r\n"))?; }
        state.prev_input_lines = input_lines;
        // No flush here — render() will flush everything atomically
        render(stdout, state)?;
        // The @file couldn't be read, so nothing was sent.
        return Ok(RequestOutcome::Errored);
    }

    // With no outfile the renderer owns the screen, so there's nothing to stream
    // into and the body stays buffered. `>>` and clipboard both need the whole
    // body, and a non-2xx buffers so an error payload never lands in the file.
    let stream_outfile: Option<String> = if state.config.streaming
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
    let response_result: Arc<std::sync::Mutex<Option<Result<(reqwest::StatusCode, String, BodyDelivery), reqwest::Error>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let response_result_clone = Arc::clone(&response_result);
    let request_handle = thread::spawn(move || {
        let result = request.send().and_then(|resp| {
            let status = resp.status();
            if let Some(path) = stream_outfile {
                if status.is_success() {
                    // Stream straight to the file. An io failure here is
                    // reported through BodyDelivery — it isn't a request error.
                    let streamed = fs::File::create(&path).and_then(|file| {
                        let mut writer = io::BufWriter::new(file);
                        stream_to_sink(resp, &mut writer)
                    });
                    return Ok(match streamed {
                        Ok(body) => (
                            status,
                            body.prefix,
                            BodyDelivery::Streamed {
                                overflowed: body.overflowed,
                                error: None,
                            },
                        ),
                        Err(e) => (
                            status,
                            String::new(),
                            BodyDelivery::Streamed {
                                overflowed: false,
                                error: Some(e.to_string()),
                            },
                        ),
                    });
                }
            }
            let body = resp.text()?;
            Ok((status, body, BodyDelivery::Buffered))
        });
        *response_result_clone.lock().unwrap() = Some(result);
    });

    // Poll for completion, show spinner after 3 seconds, handle ctrl+c
    let mut frame_idx = 0;
    let mut showing_spinner = false;
    let mut aborted = false;

    loop {
        // Check if request completed
        {
            let guard = response_result.lock().unwrap();
            if guard.is_some() {
                break;
            }
        }

        // Check for ctrl+c to abort (short poll to stay responsive)
        if event::poll(Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
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

        // Show spinner after 0.5 seconds in the hint area (bottom line)
        if start.elapsed() >= Duration::from_millis(500) {
            showing_spinner = true;
            let frame = SPINNER_FRAMES[frame_idx % SPINNER_FRAMES.len()];
            // Overwrite the hint line with spinner
            execute!(
                stdout,
                cursor::MoveToColumn(0),
                Clear(ClearType::CurrentLine),
                Print(format!("  {}", format!("{} waiting for response...", frame).dimmed()))
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
            Print(format!("  {}", state.status_msg.dimmed()))
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
    let mut response_opt = response_result.lock().unwrap().take();

    // Handle OAuth2 token refresh on 401
    if let Some(Ok((status, _, _))) = &response_opt {
        if status.as_u16() == 401 && !state.oauth2_client_id.is_empty() && !state.oauth2_client_secret.is_empty() {
            // Attempt token refresh
            if let Ok((new_token, _)) = oauth2_token_exchange(&state.config.base_uri, &state.oauth2_client_id, &state.oauth2_client_secret) {
                state.config.token = new_token.clone();

                // Retry the request with new token
                let client = build_request_client(state.config.timeout_secs);

                let url = format!("{}{}", state.config.base_uri, resolve_request_path(&state.config.api_path, &state.uri));
                let mut retry_request = match state.method.as_str() {
                    "GET" => client.get(&url),
                    "POST" => client.post(&url),
                    "PUT" => client.put(&url),
                    "PATCH" => client.patch(&url),
                    "DELETE" => client.delete(&url),
                    "HEAD" => client.head(&url),
                    _ => client.get(&url),
                };

                retry_request = retry_request.header("Authorization", format!("Bearer {}", new_token));
                retry_request = retry_request.header("Content-Type", "application/json");
                retry_request = retry_request.header("Accept", "application/json");

                if !state.body.is_empty() && !state.body.starts_with("@") {
                    retry_request = retry_request.body(state.body.clone());
                }

                // Execute retry synchronously (token refresh should be quick)
                if let Ok(resp) = retry_request.send() {
                    let retry_status = resp.status();
                    if let Ok(retry_body) = resp.text() {
                        // The retry buffers regardless — it is a short,
                        // plain-header request sent after the token refresh.
                        response_opt = Some(Ok((retry_status, retry_body, BodyDelivery::Buffered)));
                    }
                }
            }
        }
    }


    // What this request means for a `&&` chain. Captured before the body is
    // consumed by the outfile/clipboard branches below.
    let outcome = match &response_opt {
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

    match response_opt {
        Some(Ok((status, body_text, delivery))) => {
            let elapsed = start.elapsed();

            let status_str = if status.is_success() {
                format!("{} {}", status.as_u16(), status.canonical_reason().unwrap_or(""))
                    .green()
                    .to_string()
            } else {
                format!("{} {}", status.as_u16(), status.canonical_reason().unwrap_or(""))
                    .red()
                    .to_string()
            };

            // Handle outfile — including the `> clipboard` special target.
            if is_clipboard_target(&state.display_outfile) && state.config.outfile_append {
                // `>> clipboard` is meaningless — there's nothing to append to.
                block.head = "cannot append to clipboard — use > clipboard\n".to_string();
            } else if is_clipboard_target(&state.display_outfile) {
                // Pretty-print JSON for clipboard so it's pasteable as-is.
                let clipboard_text = if state.config.raw || state.config.ndjson {
                    body_text.clone()
                } else if let Ok(json) = serde_json::from_str::<Value>(&body_text) {
                    serde_json::to_string_pretty(&json).unwrap_or_else(|_| body_text.clone())
                } else {
                    body_text.clone()
                };
                match cli_clipboard::set_contents(clipboard_text) {
                    Ok(()) => {
                        if !state.config.silent {
                            block.head = format!(
                                "HTTP/1.1 {} {}\n{}\n\n",
                                status_str,
                                format!("{:.2}s", elapsed.as_secs_f64()).dimmed(),
                                "> clipboard".dimmed()
                            );
                        }
                        state.status_msg = "copied to clipboard".to_string();
                        state.status_msg_at = Some(Instant::now());
                    }
                    Err(e) => {
                        block.head = format!("clipboard unavailable: {}\n", e);
                    }
                }
            } else if !state.config.outfile.is_empty() {
                // A streamed body is already on disk — only its io error, if
                // any, is still to be reported.
                let write_result = match delivery {
                    BodyDelivery::Streamed { error: Some(ref e), .. } => {
                        Err(io::Error::new(io::ErrorKind::Other, e.clone()))
                    }
                    BodyDelivery::Streamed { .. } => Ok(()),
                    BodyDelivery::Buffered => {
                        if state.config.outfile_append {
                            append_to_outfile(&state.config.outfile, &body_text)
                        } else {
                            fs::write(&state.config.outfile, &body_text)
                        }
                    }
                };
                if let Err(e) = write_result {
                    block.head = format!("Error writing to {}: {}\n", state.config.outfile, e);
                } else {
                    state.last_outfile = state.config.outfile.clone();
                    state.last_display_outfile = state.display_outfile.clone();

                    if !state.config.silent {
                        let marker = if state.config.outfile_append { ">>" } else { ">" };
                        block.head = format!(
                            "HTTP/1.1 {} {}\n{}\n\n",
                            status_str,
                            format!("{:.2}s", elapsed.as_secs_f64()).dimmed(),
                            format!("{} {}", marker, state.display_outfile).dimmed()
                        );
                    }
                    state.status_msg = "ctrl+o to open file".to_string();
                    state.status_msg_at = Some(Instant::now());
                }
            } else {
                // Build status line
                if !state.config.silent {
                    block.head = format!(
                        "HTTP/1.1 {} {}\n",
                        status_str,
                        format!("{:.2}s", elapsed.as_secs_f64()).dimmed()
                    );
                }

                // Build body. The trailing blank line belongs to the head when
                // there's no body, so `has_body()` stays false and ctrl+j
                // correctly finds nothing to erase.
                if !body_text.is_empty() {
                    let output = if state.config.raw || state.config.ndjson {
                        body_text
                    } else if let Ok(json) = serde_json::from_str::<Value>(&body_text) {
                        serde_json::to_string_pretty(&json).unwrap_or(body_text)
                    } else {
                        body_text
                    };
                    block.tail = format_body_block(&output);
                } else {
                    block.head.push('\n');
                }
            }
        }
        Some(Err(e)) => {
            block.head = if e.is_timeout() {
                format!(
                    "\nTimed out after {} — raise it with --timeout <seconds> (0 = no timeout)\n\n",
                    describe_timeout(state.config.timeout_secs)
                )
            } else {
                let host = state.config.base_uri.trim_start_matches("https://").trim_start_matches("http://");
                format!("\nIs COS running on {}? 🤔\n\n", host)
            };
        }
        None => {
            // Request was aborted or something went wrong
            block.head = "\nRequest failed\n".to_string();
        }
    }

    // Refresh mapped type names after mutating /mapped-types
    if state.uri.starts_with("/mapped-types")
        && matches!(state.method.as_str(), "PUT" | "POST" | "PATCH")
    {
        let config = state.config.clone();
        let names = fetch_mapped_type_names(&config);
        state.mapped_types = names;
    }

    // Render once, then store the parts so a resize can re-fit the request line.
    let display_output = block.render(state.width as usize);
    push_output_block(state, block);

    // Update input with last command — or, mid-chain, keep the full chain on
    // the line so it doesn't flash the just-sent segment between requests.
    restore_input_after_send(state);

    // Now clear input area, print output, and render new input - all at once
    let clear_lines = 2 + state.prev_input_lines;
    queue!(
        stdout,
        cursor::Hide,
        cursor::MoveUp(clear_lines.min(state.height.saturating_sub(1))),
        cursor::MoveToColumn(0),
        Clear(ClearType::FromCursorDown)
    )?;

    // Print output with \r\n line endings (stay in raw mode to avoid flash)
    let raw_output = display_output.replace('\n', "\r\n");
    queue!(stdout, Print(&raw_output))?;

    // Print placeholder lines and render input area
    let input_lines = visual_line_count(&state.input, state.width as usize);
    for _ in 0..(2 + input_lines) { queue!(stdout, Print("\r\n"))?; }
    state.prev_input_lines = input_lines;
    // No flush here — render() will flush everything atomically
    render(stdout, state)?;

    Ok(outcome)
}

/// Run a `&&` chain in the TUI: each segment sends only if the previous was
/// truthy. Returns once the chain finishes or is cut short.
///
/// Each segment prints its own block, so the log reads the same as if the
/// requests had been sent one at a time.
fn execute_request_chain(
    state: &mut AppState,
    stdout: &mut io::Stdout,
    segments: &[(ChainOp, String)],
    full_chain: &str,
) -> io::Result<()> {
    // Published so every per-segment input restore shows the whole chain.
    state.chain_input = Some(full_chain.to_string());
    let result: io::Result<usize> = (|| {
        // Outcome of the last EXECUTED segment; skipped segments leave it
        // alone (that's what makes `a && b || c` an if-then-else).
        let mut prev: Option<RequestOutcome> = None;
        let mut skipped = 0usize;
        for (i, (op, segment)) in segments.iter().enumerate() {
            if !chain_segment_should_run(prev, *op) {
                skipped += 1;
                continue;
            }
            parse_input(state, segment);
            let outcome = execute_request(state, stdout)?;
            match outcome {
                RequestOutcome::Truthy | RequestOutcome::Falsy => prev = Some(outcome),
                // Errored or aborted ends the chain — a following `||` does
                // NOT catch it. The reason is already on screen.
                RequestOutcome::Errored | RequestOutcome::Aborted => {
                    skipped += segments.len() - i - 1;
                    break;
                }
            }
        }
        Ok(skipped)
    })();
    // Cleared on every exit, including an Err from execute_request — a stale
    // Some() would make the NEXT single request restore the old chain.
    state.chain_input = None;
    let skipped = result?;
    if skipped > 0 {
        let plural = if skipped == 1 { "request" } else { "requests" };
        state.status_msg = format!("↳ skipped {} {}", skipped, plural);
        state.status_msg_at = Some(Instant::now());
        render(stdout, state)?;
    }
    Ok(())
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
    if typed.is_whitespace() || typed == '>' || typed == '&' || typed == '|' {
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
    // `&` starts a `&&` chain separator, not a body — wrapping would corrupt the
    // line to `PUT /x [&`.
    if typed.is_whitespace() || typed == '[' || typed == '@' || typed == '&' || typed == '|' {
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
    // Only when the target endpoint returns an array (per the loaded OpenAPI spec).
    if !state.array_endpoints.contains(tokens[1]) {
        return;
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
    if !state.array_endpoints.contains(tokens[1]) {
        return;
    }
    let body_trimmed = state.input[body_start..body_end].trim_end();
    if body_trimmed.is_empty() {
        return;
    }
    // Complete JSON only, and not already an array (covers `@file` too — it
    // doesn't parse as JSON).
    match serde_json::from_str::<Value>(body_trimmed) {
        Ok(v) if !v.is_array() => {}
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

// Read a line of input in raw mode (already in raw mode when called from interactive)
fn read_inline_input(stdout: &mut io::Stdout, prompt: &str, mask: bool, prefill: &str) -> io::Result<Option<String>> {
    let mut buf = prefill.to_string();

    let render_line = |stdout: &mut io::Stdout, prompt: &str, buf: &str, mask: bool| -> io::Result<()> {
        execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
        let display = if mask && !buf.is_empty() { "•".repeat(buf.len()) } else { buf.to_string() };
        execute!(stdout, Print(format!("{}{}\x1b[48;5;247m\x1b[38;5;0m \x1b[0m", prompt, display)))?;
        stdout.flush()?;
        Ok(())
    };

    render_line(stdout, prompt, &buf, mask)?;

    loop {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != event::KeyEventKind::Press { continue; }
                if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
                    execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
                    execute!(stdout, cursor::Show)?;
                    terminal::disable_raw_mode()?;
                    std::process::exit(0);
                }
                match key.code {
                    KeyCode::Enter => {
                        execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
                        let display = if mask && !buf.is_empty() { "•".repeat(buf.len()) } else { buf.clone() };
                        execute!(stdout, Print(format!("{}{}\r\n", prompt, display)))?;
                        return Ok(Some(buf));
                    }
                    KeyCode::Esc => {
                        execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
                        execute!(stdout, Print("\r\n"))?;
                        return Ok(None);
                    }
                    KeyCode::Char(c) => { buf.push(c); }
                    KeyCode::Backspace => { buf.pop(); }
                    _ => {}
                }
            }
        }

        render_line(stdout, prompt, &buf, mask)?;
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
                    std::process::exit(0);
                }
                match key.code {
                    KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                        execute!(stdout, Print("y\r\n"))?;
                        return Ok(true);
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        execute!(stdout, Print("n\r\n"))?;
                        return Ok(false);
                    }
                    _ => {}
                }
            }
        }
    }
}

fn handle_save_connection(state: &mut AppState, stdout: &mut io::Stdout) -> io::Result<()> {
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
    execute!(stdout, Print("\r\n"))?; // placeholder for prompt line
    execute!(stdout, Print(format!("{}\r\n", ruler_line)))?; // bottom ruler
    execute!(stdout, Print(format!("  {}", "enter to save, esc to cancel".dimmed())))?; // hint
    // Move back up to prompt line
    execute!(stdout, cursor::MoveUp(2), cursor::MoveToColumn(0))?;

    let name = match read_inline_input(stdout, &prompt, false, &prefill)? {
        Some(n) if !n.is_empty() => n,
        _ => {
            // Restore normal command area
            execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;
            for _ in 0..input_lines { execute!(stdout, Print("\r\n"))?; }
            state.status_msg = "cancelled".to_string();
            state.status_msg_at = Some(Instant::now());
            render(stdout, state)?;
            return Ok(());
        }
    };

    // Check if overwriting a different alias
    let envs = list_connections();
    if envs.contains(&name) && name != state.connection_alias {
        // Move down past bottom ruler, replace hint with confirm prompt
        execute!(stdout, Print("\r\n"), cursor::MoveDown(1), cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
        if !confirm_inline(stdout, &format!("  \"{}\" already exists. Overwrite?", name))? {
            execute!(stdout, cursor::MoveUp(1), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;
            for _ in 0..input_lines { execute!(stdout, Print("\r\n"))?; }
            state.status_msg = "cancelled".to_string();
            state.status_msg_at = Some(Instant::now());
            render(stdout, state)?;
            return Ok(());
        }
        // Move back up to prompt line area for cleanup
        execute!(stdout, cursor::MoveUp(2), cursor::MoveToColumn(0))?;
    }

    // Determine auth type from current config
    let (auth_type, credential, client_id) = if !state.oauth2_client_id.is_empty() && !state.oauth2_client_secret.is_empty() {
        // OAuth2 client credentials - save the credentials, not the token
        ("oauth2".to_string(), state.oauth2_client_secret.clone(), state.oauth2_client_id.clone())
    } else if !state.config.token.is_empty() {
        ("token".to_string(), state.config.token.clone(), String::new())
    } else {
        ("key".to_string(), state.config.api_key.clone(), String::new())
    };

    // If alias changed, delete old entry
    if !state.connection_alias.is_empty() && name != state.connection_alias {
        let _ = delete_connection(&state.connection_alias);
    }

    let env = SavedConnection {
        name: name.clone(),
        url: state.config.base_uri.clone(),
        auth_type,
        credential,
        client_id,
    };

    match save_connection(&env) {
        Ok(()) => {
            state.connection_alias = name.clone();
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
    Ok(())
}

fn handle_switch_connection(state: &mut AppState, stdout: &mut io::Stdout) -> io::Result<Option<std::sync::mpsc::Receiver<BackgroundLoadResult>>> {
    let envs = list_connections();
    if envs.is_empty() {
        state.status_msg = "no saved connections".to_string();
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

            // Store OAuth2 credentials for token refresh
            if env.auth_type == "oauth2" {
                state.oauth2_client_id = env.client_id.clone();
                state.oauth2_client_secret = env.credential.clone();
            } else {
                state.oauth2_client_id.clear();
                state.oauth2_client_secret.clear();
            }

            // Use resolved config if available (avoids duplicate token exchange)
            if let Some(rc) = resolved_config {
                state.config = rc;
            } else {
                apply_connection_to_config(&mut state.config, &env);
            }

            // Use preloaded result if available, otherwise load now
            let result = preloaded.unwrap_or_else(|| background_load(&state.config, None));
            apply_background_result(state, result);

            // Full screen clear and fresh start for new connection
            state.output_history.clear();
            terminal::disable_raw_mode()?;
            print!("\x1b[2J\x1b[3J\x1b[H");
            io::stdout().flush().ok();
            print_splash_with_width(&state.config, state.width);
            println!();
            println!();
            println!();
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
            print!("\x1b[2J\x1b[3J\x1b[H");
            io::stdout().flush().ok();
            execute!(stdout, cursor::Show)?;
            std::process::exit(0);
        }
    }
}

fn copy_curl(state: &AppState) -> bool {
    if state.prev_uri.is_empty() {
        return false;
    }

    // Build content type and accept headers
    let mut content_type = "application/json".to_string();
    let mut accept = "application/json".to_string();

    if state.config.ndjson {
        content_type = "application/x-ndjson".to_string();
        accept = "application/x-ndjson".to_string();
    }

    // Parse file body info early so we can detect content-type from extension
    let mut file_path_clean = String::new();
    let mut body_extra_headers: Vec<(String, String)> = Vec::new();
    let is_file_body = state.prev_body.starts_with("@") || state.prev_body.starts_with("@ ");
    if is_file_body {
        let (clean_body, extra_headers) = parse_body_functions(&state.prev_body);
        file_path_clean = clean_body.trim_start_matches("@ ").trim_start_matches('@').trim().to_string();
        body_extra_headers = extra_headers;

        // Auto-detect content type from input file extension
        if file_path_clean.ends_with(".ndjson") || file_path_clean.ends_with(".njson") {
            content_type = "application/x-ndjson".to_string();
            accept = "application/x-ndjson".to_string();
        } else if file_path_clean.ends_with(".csv") {
            content_type = "text/csv".to_string();
        }
    }

    // Override accept based on outfile extension
    if !state.prev_outfile.is_empty() {
        if state.prev_outfile.ends_with(".ndjson") {
            accept = "application/x-ndjson".to_string();
        } else if state.prev_outfile.ends_with(".csv") {
            accept = "text/csv".to_string();
        } else if state.prev_outfile.ends_with(".sql") {
            accept = "application/sql".to_string();
        }
    }

    if state.config.streaming {
        content_type.push_str(";stream=true");
        accept.push_str(";stream=true");
    }

    if state.config.include_nulls {
        accept.push_str(";skipNulls=false");
    }

    let mut cmd = format!(
        "curl -gfsSL -X {} \"{}{}\"",
        state.prev_method,
        state.config.base_uri,
        resolve_request_path(&state.config.api_path, &state.prev_uri)
    );

    if !state.config.token.is_empty() {
        cmd.push_str(&format!(" -H \"Authorization: Bearer {}\"", state.config.token));
    } else if !state.config.api_key.is_empty() {
        cmd.push_str(&format!(" -u \":{}\"", state.config.api_key));
    }

    cmd.push_str(&format!(" -H \"Accept: {}\"", accept));

    if ["PUT", "PATCH", "POST"].contains(&state.prev_method.as_str()) {
        cmd.push_str(&format!(" -H \"Content-Type: {}\"", content_type));
    }

    if !state.prev_body.is_empty() {
        if is_file_body {
            for (name, value) in &body_extra_headers {
                cmd.push_str(&format!(" -H \"{}: {}\"", name, value));
            }
            cmd.push_str(&format!(" --data-binary @{}", file_path_clean));
        } else {
            cmd.push_str(&format!(" --data-binary '{}'", state.prev_body));
        }
    }

    // Output file
    if !state.prev_outfile.is_empty() {
        cmd.push_str(&format!(" -o '{}'", state.prev_outfile));
    }

    // Copy to clipboard
    if cli_clipboard::set_contents(cmd.clone()).is_ok() {
        return true;
    }

    false
}

fn render_input_content(state: &mut AppState, width: usize) -> (String, u16, String) {
    // Ghost text is computed per `&&` segment, FIRST — the view mutates
    // `state.input` in place, so it must run before any slices are taken.
    // Inside the view, "cursor at end" means at the end of the cursor's SEGMENT
    // (e.g. just before ` && …`), so editing an earlier segment gets the same
    // ghosts as a standalone line.
    let ghost = with_chain_segment_view(state, |state| {
        let in_file_mode = extract_file_path_context(&state.input, state.cursor_pos).is_some();
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
    if !state.config.streaming {
        return String::new();
    }
    let width = state.width as usize;
    let used = 2 + left_width + STREAMING_INDICATOR.len() + STREAMING_INDICATOR_MARGIN;
    if width < used + 1 {
        // Not enough room — the left-hand text is the more useful of the two.
        return String::new();
    }
    let pad = width - used;

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
                Some(s) => format!("\x1b[38;5;{}m{}\x1b[0m", s, STREAMING_INDICATOR),
                None => STREAMING_INDICATOR.dimmed().to_string(),
            }
        }
        None => STREAMING_INDICATOR.dimmed().to_string(),
    };

    // No trailing spaces needed — render clears the area first, so the margin is
    // simply columns we decline to write into.
    format!("{}{}", " ".repeat(pad), styled)
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
    if !state.config.base_uri.is_empty() && state.config.base_uri.len() + 11 <= width {
        let host_text = &state.config.base_uri;
        let host = format!(" {} ", host_text);
        let host_len = host.len();
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
        queue!(
            stdout,
            Print("\r\n"),
            Print(format!("{}\r\n", "  enter      Send request".dimmed())),
            Print(format!("{}\r\n", "  opt+enter  New line (multiline body) [or ctrl+n]".dimmed())),
            Print(format!("{}\r\n", "  up/down    Navigate input history".dimmed()))
        )?;
        queue!(stdout, Print(format!("{}\r\n", "  tab        Complete URI (endpoints, operators, properties)".dimmed())))?;
        queue!(
            stdout,
            Print(format!("{}\r\n", "  ctrl+space Cycle method: GET → POST → PATCH → PUT".dimmed())),
            Print(format!("{}\r\n", "  ctrl+g     Quick GET current URI".dimmed())),
            Print(format!("{}\r\n", "  ctrl+x     Clear body (keep method and URI)".dimmed())),
            Print(format!("{}\r\n", "  ctrl+f     Clear all (reset to GET /)".dimmed())),
            Print(format!("{}\r\n", "  ctrl+u     Clear entire input line (empty)".dimmed())),
            Print(format!("{}\r\n", "  ctrl+k     Kill from cursor to end of line".dimmed())),
            Print(format!("{}\r\n", "  alt+←/→    Move by word (or ctrl+←/→, alt+b/f)".dimmed())),
            Print(format!("{}\r\n", "  alt+bksp   Delete word backward (or ctrl+w)".dimmed())),
            Print(format!("{}\r\n", "  alt+d      Delete word forward".dimmed())),
            Print(format!("{}\r\n", "  ctrl+y     Copy last request as curl command".dimmed())),
            Print(format!("{}\r\n", "  ctrl+j     Erase last response body".dimmed())),
            Print(format!("{}\r\n", "  ctrl+l     Erase all output".dimmed())),
            Print(format!("{}\r\n", "  ctrl+s     Save connection".dimmed())),
            Print(format!("{}\r\n", "  ctrl+q     Switch connection".dimmed())),
            Print(format!("{}\r\n", "  ctrl+b     Open API docs in browser".dimmed())),
            Print(format!("{}\r\n", "  ctrl+o     Open last saved file".dimmed())),
            Print(format!("{}\r\n", "  ctrl+t     Toggle response streaming".dimmed())),
            Print(format!("{}\r\n", "  ctrl+c     Quit".dimmed())),
            Print("\r\n"),
            Print(format!("{}\r\n", "  ctrl+h or esc to close".dimmed()))
        )?;
        // Only worth the rows when it applies — see `help_line_count`.
        if state.config.streaming {
            queue!(stdout, Print("\r\n"))?;
            for line in streaming_help_lines(&state.config.base_uri) {
                queue!(stdout, Print(format!("{}\r\n", line.dimmed())))?;
            }
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

        // Hint line (only if terminal is wide enough - "ctrl+h for shortcuts" is 21 chars + 2 indent)
        if width >= 22 {
            if !state.status_msg.is_empty() {
                let msg_style = if state.status_msg.contains("ctrl+c again") {
                    // Stay white for the full duration
                    format!("\x1b[97m{}\x1b[0m", state.status_msg)
                } else if state.status_msg.starts_with("connected to:") {
                    // No flash, just dimmed gray for 3 seconds
                    state.status_msg.dimmed().to_string()
                } else if let Some(at) = state.status_msg_at {
                    let ms = at.elapsed().as_millis() as u16;
                    // Two smooth pulses: 0-150ms and 200-350ms
                    // Each pulse fades from 240 (dim) up to 250 (light) and back
                    let base: u16 = 240;
                    let peak: u16 = 250;
                    let range = peak - base;
                    if ms < 150 {
                        let t = ms as f32 / 150.0;
                        let v = (t * std::f32::consts::PI).sin();
                        let shade = base + (v * range as f32) as u16;
                        format!("\x1b[38;5;{}m{}\x1b[0m", shade, state.status_msg)
                    } else if ms >= 200 && ms < 350 {
                        let t = (ms - 200) as f32 / 150.0;
                        let v = (t * std::f32::consts::PI).sin();
                        let shade = base + (v * range as f32) as u16;
                        format!("\x1b[38;5;{}m{}\x1b[0m", shade, state.status_msg)
                    } else {
                        state.status_msg.dimmed().to_string()
                    }
                } else {
                    state.status_msg.dimmed().to_string()
                };
                queue!(stdout, Print(format!("  {}", msg_style)))?;
                queue!(stdout, Print(streaming_indicator(state, visible_len(&state.status_msg))))?;
            } else {
                let hint = "ctrl+h for shortcuts";
                queue!(stdout, Print(format!("  {}", hint.dimmed())))?;
                queue!(stdout, Print(streaming_indicator(state, hint.len())))?;
            }
        }
    }

    // Re-enable auto-wrap now that the fixed-height block has been drawn.
    queue!(stdout, Print("\x1b[?7h"))?;
    stdout.flush()?;

    Ok(())
}

fn print_splash_with_width(config: &Config, term_width: u16) {
    let full_width = 60usize;
    let min_width = 36usize; // Minimum to show title properly
    let hint_section_width = 20usize; // " │ ctrl+b for docs │" length

    let term_w = term_width as usize;

    // Don't print splash if terminal is too narrow
    if term_w < min_width {
        println!();
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

    println!();
    println!(
        "{}{}{}{}",
        "╭───".dimmed(),
        format!(" {} {} ", title.bold(), version.dimmed()),
        "─".repeat(top_padding.max(1)).dimmed(),
        "╮".dimmed()
    );

    if show_hint {
        // Full width with hint
        let host_space = actual_width - 7 - hint.len();
        let host_display = if host.len() > host_space { &host[..host_space] } else { host };
        let host_padded = format!("{:width$}", host_display, width = host_space);
        // Use \x1b[K to clear to end of line (prevents artifacts from previous content)
        println!(
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
        let host_display = if host.len() > host_space {
            &host[..host_space]
        } else {
            host
        };
        let host_padded = format!("{:width$}", host_display, width = host_space);
        println!(
            "{}{}{}",
            "│ ".dimmed(),
            host_padded.dimmed(),
            " │".dimmed()
        );
    }

    println!("{}", format!("╰{}╯", "─".repeat(actual_width - 2)).dimmed());
    println!();
}

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
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| Client::new());

    let url = format!("{}{}/mapped-types", config.base_uri, config.api_path);
    let mut request = client.get(&url);

    if !config.token.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", config.token));
    } else if !config.api_key.is_empty() {
        let encoded = BASE64.encode(format!(":{}", config.api_key));
        request = request.header("Authorization", format!("Basic {}", encoded));
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
    state.config.complete = result.complete;
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
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| Client::new());

    let url = format!("{}/openapi/spec.json", config.base_uri);

    let mut request = client.get(&url);

    if !config.token.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", config.token));
    } else if !config.api_key.is_empty() {
        let encoded = BASE64.encode(format!(":{}", config.api_key));
        request = request.header("Authorization", format!("Basic {}", encoded));
    }

    if let Ok(resp) = request.send() {
        if let Ok(spec) = resp.json::<ApiSpec>() {
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
    let FilePathContext { path_start, path_end, partial, is_outfile, is_append } = ctx;

    // Check for ~ operator on body file argument
    if let Some(tilde_idx) = partial.rfind('~') {
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
        // Append targets get plain file completions — the virtual `clipboard`
        // entry only makes sense for `>`, where it can be overwritten.
        state.completions = if is_outfile && !is_append {
            get_outfile_completions(&partial)
        } else {
            get_file_completions(&partial)
        };
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
    let FilePathContext { path_start, path_end, partial, .. } = ctx;

    if state.completion_idx == 0 {
        state.completion_idx = state.completions.len() - 1;
    } else {
        state.completion_idx -= 1;
    }

    let completion = state.completions[state.completion_idx].clone();

    // Handle ~map() completions: reconstruct with file path prefix
    if let Some(tilde_idx) = partial.rfind('~') {
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
        let partial = ctx.partial;
        // Check for ~ operator on body file argument
        if let Some(tilde_idx) = partial.rfind('~') {
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
            fresh = if ctx.is_outfile && !ctx.is_append {
                get_outfile_completions(&partial)
            } else {
                get_file_completions(&partial)
            };
            &fresh
        };
        if let Some(first) = completions.first() {
            if first.starts_with(&partial) {
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

    let is_array = state.array_endpoints.contains(uri);
    let (schema, _, _) = resolve_type_at_path(state, &format!("{}/", uri.trim_end_matches('/')));
    let is_object = schema.as_ref()
        .and_then(|s| {
            if let Some(indexer) = state.indexer_info.get(s) {
                indexer.return_type.as_ref().map(|rt| rt.trim_end_matches('?').to_string())
            } else {
                Some(s.clone())
            }
        })
        .map_or(false, |s| state.schema_props.contains_key(&s));

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
        if let Some(idx) = segment.rfind(marker) {
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
            });
        }
    }
    None
}

/// Get file/directory completions for a partial path.
/// Returns full paths (from the partial's perspective) suitable for replacing the partial.
fn get_file_completions(partial: &str) -> Vec<String> {
    let expanded = if partial.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            format!("{}{}", home.display(), &partial[1..])
        } else {
            partial.to_string()
        }
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
    let expanded = if path_raw.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            format!("{}{}", home.display(), &path_raw[1..])
        } else {
            path_raw.to_string()
        }
    } else {
        path_raw.to_string()
    };

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
        // Multi-line pasted JSON wraps around the whole block; a trailing
        // newline stays outside the `]`. Non-ASCII content keeps the cursor math
        // correct (char vs byte).
        let mut state = test_state();
        state.array_endpoints.insert("/people".to_string());
        state.input = "GET /people ".to_string();
        state.cursor_pos = char_len(&state.input);
        let mut out = sink();
        handle_paste(&mut state, "{\n  \"name\": \"Zoë\"\n}\n", &mut out).unwrap();
        assert_eq!(state.input, "PUT /people [{\n  \"name\": \"Zoë\"\n}]\n");
        // Cursor sits right after the `]`.
        let after_bracket = state.input.rfind(']').unwrap() + 1;
        assert_eq!(state.cursor_pos, char_len(&state.input[..after_bracket]));
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
    fn extract_identifier_pairs_array_returns_empty() {
        // Top-level array isn't identifier-shaped.
        assert_eq!(
            extract_identifier_pairs(r#"[{"com.heads.id": "x"}]"#),
            Vec::<(String, String)>::new()
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
        assert_eq!(without, "\n{\"a\":1}\n\n");

        // Streamed JSON and error bodies arrive with no trailing newline;
        // NDJSON always has one. All land on the same spacing.
        assert_eq!(format_body_block("{\"error\":\"nope\"}"), "\n{\"error\":\"nope\"}\n\n");

        // A multi-line body keeps its internal breaks — only the final run goes.
        assert_eq!(
            format_body_block("{\"a\":1}\n{\"b\":2}\n"),
            "\n{\"a\":1}\n{\"b\":2}\n\n"
        );

        // A blank line the server actually sent inside the payload is still
        // trailing whitespace here; collapsing it keeps the block height fixed.
        assert_eq!(format_body_block("x\n\n\n"), "\nx\n\n");

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
        };

        let rendered = block.render(80);
        assert!(rendered.starts_with("PUT /people @data.json > out.json\n"), "got: {rendered:?}");
        assert!(rendered.contains("HTTP/1.1 200 OK"), "status line lost: {rendered:?}");
        assert!(rendered.contains("> out.json"), "outfile note lost: {rendered:?}");
        // No response body was printed, so ctrl+j has nothing to erase.
        assert!(!block.has_body());
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
        let plain = help_line_count(&state);

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
}
