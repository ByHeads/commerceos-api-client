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
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers, KeyboardEnhancementFlags, PushKeyboardEnhancementFlags, PopKeyboardEnhancementFlags},
    execute,
    style::Print,
    terminal::{self, Clear, ClearType},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

    /// Bearer token for authentication
    #[arg(short = 't', long = "token")]
    token: Option<String>,

    /// Use a saved connection (by alias or URL)
    #[arg(short = 'c', long = "connection", value_name = "ALIAS_OR_URL")]
    connection: Option<String>,

    /// Get base-uri and key from 1Password
    #[arg(long = "1p", value_name = "SELECTOR", hide = true)]
    one_password: Option<String>,

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
    streaming: bool,
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
            streaming: false,
        }
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

fn load_keychain_data() -> KeychainData {
    match keychain_entry().get_password() {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => KeychainData::default(),
    }
}

fn save_keychain_data(data: &KeychainData) -> Result<(), String> {
    let json = serde_json::to_string(data).map_err(|e| e.to_string())?;
    keychain_entry().set_password(&json).map_err(|e| format!("keychain error: {}", e))
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
    ctrl_c_pending: bool,
    ctrl_c_at: Option<std::time::Instant>,
    width: u16,
    height: u16,
    prev_width: u16,
    output_history: Vec<String>,  // Store all output for redraw on resize
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
    mapped_types: Vec<String>,  // mapped type names for ~map() completion
    completions: Vec<String>,
    completion_idx: usize,
    last_tab_input: String,
    completion_uri_suffix: String,  // URI text after cursor for mid-URI completion
    completion_hint: String,  // Hint to show when placeholder expected
    connection_alias: String,  // Current connection alias (for Ctrl+S pre-fill)
    last_was_splash: bool,  // True if last output was a splash (for consecutive env switches)
    // OAuth2 credentials for token refresh
    oauth2_client_id: String,
    oauth2_client_secret: String,
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
            mapped_types: Vec::new(),
            completions: Vec::new(),
            completion_idx: 0,
            last_tab_input: String::new(),
            completion_uri_suffix: String::new(),
            completion_hint: String::new(),
            connection_alias: String::new(),
            last_was_splash: false,
            oauth2_client_id: String::new(),
            oauth2_client_secret: String::new(),
        }
    }
}

// Convert character index to byte index for safe UTF-8 string slicing
fn char_to_byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(i, _)| i)
        .unwrap_or(s.len())
}

// Get character count (not byte length)
fn char_len(s: &str) -> usize {
    s.chars().count()
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
    caret_visible: bool,
    caret_toggle_at: Instant,

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
            caret_visible: true,
            caret_toggle_at: Instant::now() + Duration::from_millis(500),
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
            caret_visible: true,
            caret_toggle_at: Instant::now() + Duration::from_millis(500),
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

        let hint_text = "ctrl+d for docs";
        let host_space = box_width - 7 - hint_text.len();
        let display_url = if self.in_setup && !self.setup_url.is_empty() {
            self.setup_url.as_str()
        } else {
            " "
        };
        let host_display = if display_url.len() > host_space { &display_url[..host_space] } else { display_url };
        execute!(stdout, Print(format!("{}{:width$}{}{}{}\r\n",
            "│ ".dimmed(),
            host_display.dimmed(),
            " │ ".dimmed(),
            hint_text.dimmed(),
            " │".dimmed(),
            width = host_space
        )))?;
        execute!(stdout, Print(format!("{}\r\n", format!("╰{}╯", "─".repeat(box_width - 2)).dimmed())))?;
        execute!(stdout, Print("\r\n"))?;

        Ok(())
    }

    fn render_picker(&self, stdout: &mut io::Stdout, ruler: &str, _first: bool) -> io::Result<()> {
        let w = self.width as usize;

        // Top ruler with embedded title (always "Choose a connection"), right-aligned
        let title = " [Choose a connection] ";
        let title_len = title.len();
        let right = 7;
        let left = w.saturating_sub(title_len).saturating_sub(right);
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

        // Top ruler with embedded title (offset 3 spaces left of center)
        let title = " [New connection] ";
        let title_len = title.len();
        let left = (w.saturating_sub(title_len)) / 2 - 3;
        let right = w.saturating_sub(title_len).saturating_sub(left);
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

        let cursor_char = if self.caret_visible { "\x1b[7m \x1b[0m" } else { " " };
        let prefix = if is_active { "  › " } else { "    " };

        if is_active {
            execute!(stdout, Print(format!("{}{:<14}{}\x1b[2m{}\x1b[0m{}\r\n",
                prefix, "URL:".dimmed(), url, ghost, cursor_char)))?;
        } else if url.is_empty() {
            execute!(stdout, Print(format!("{}{:<14}\r\n", prefix, "URL:".dimmed())))?;
        } else {
            execute!(stdout, Print(format!("{}{:<14}{} ✓\r\n", prefix, "URL:".dimmed(), url)))?;
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
            "•".repeat(value.len())
        } else {
            value.to_string()
        };

        let prefix = if is_active { "  › " } else { "    " };
        let cursor_char = if self.caret_visible { "\x1b[7m \x1b[0m" } else { " " };

        if is_active {
            execute!(stdout, Print(format!("{}{:<14}{}{}\r\n", prefix, label.dimmed(), display_val, cursor_char)))?;
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

        // Ctrl+D opens docs
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('d') {
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
        // Reset caret on keypress
        self.caret_visible = true;
        self.caret_toggle_at = Instant::now() + Duration::from_millis(500);

        match &self.setup_active_field {
            SetupField::Url => match key.code {
                KeyCode::Enter if !self.setup_url.is_empty() => {
                    // Add scheme if not present
                    if !self.setup_url.starts_with("http://") && !self.setup_url.starts_with("https://") {
                        if self.setup_url.starts_with("localhost") || self.setup_url.starts_with("127.0.0.1") || self.setup_url.starts_with("[::1]") {
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
                    self.setup_status = "Testing connection...".to_string();
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

            // Blink caret in setup mode
            if self.in_setup && Instant::now() >= self.caret_toggle_at {
                self.caret_visible = !self.caret_visible;
                self.caret_toggle_at = Instant::now() + Duration::from_millis(500);
                self.render(stdout, false)?;
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

// Apply a saved connection to a Config
fn apply_connection_to_config(config: &mut Config, env: &SavedConnection) {
    config.base_uri = env.url.clone();
    if !config.base_uri.starts_with("http://") && !config.base_uri.starts_with("https://") {
        config.base_uri = format!("https://{}", config.base_uri);
    }
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

    let mut config = Config::default();

    // Apply CLI args to config
    if let Some(ref uri) = args.base_uri {
        config.base_uri = uri.clone();
        if !config.base_uri.starts_with("http://") && !config.base_uri.starts_with("https://") {
            // Use http for localhost/127.0.0.1, https for everything else
            if config.base_uri.starts_with("localhost") || config.base_uri.starts_with("127.0.0.1") {
                config.base_uri = format!("http://{}", config.base_uri);
            } else {
                config.base_uri = format!("https://{}", config.base_uri);
            }
        }
    }
    config.silent = args.silent;
    config.raw = args.raw;
    config.include_nulls = args.include_nulls;
    config.ndjson = args.ndjson;

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

    // Read from stdin if available and no body provided
    if body.is_empty() && !atty::is(Stream::Stdin) {
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
        let url = config.base_uri.trim_start_matches("https://").trim_start_matches("http://");
        let (term_width, _) = terminal::size().unwrap_or((80, 24));
        let envs: Vec<String> = Vec::new();
        let mut flow = ConnectionFlow::for_startup(&envs, term_width, true);
        // Pre-fill URL in setup and focus on auth method
        flow.setup_url = url.to_string();
        flow.setup_active_field = SetupField::Auth;

        let mut stdout = io::stdout();
        terminal::enable_raw_mode().unwrap();
        execute!(stdout, cursor::Hide).unwrap();

        match flow.run(&mut stdout) {
            Ok(ConnectionFlowResult::Connected(env, _preloaded, resolved_config)) => {
                let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                terminal::disable_raw_mode().unwrap();
                execute!(stdout, cursor::Show).unwrap();

                // Store OAuth2 credentials for token refresh
                if env.auth_type == "oauth2" {
                    oauth2_creds = Some((env.client_id.clone(), env.credential.clone()));
                }
                if let Some(rc) = resolved_config {
                    config = rc;
                } else {
                    apply_connection_to_config(&mut config, &env);
                }

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

    // If no explicit auth/uri args, check saved connections
    if args.connection.is_none() && !has_explicit_auth && !has_explicit_uri && op_selector.is_none() {
        let envs = list_connections();
        let default_connection = get_default_connection();

        if !envs.is_empty() {
            // If there's a default connection, auto-load it
            if let Some(ref def) = default_connection {
                if let Some(env) = load_connection(def) {
                    loaded_connection_alias = env.name.clone();
                    apply_connection_to_config(&mut config, &env);
                }
            } else if uri.is_empty() && atty::is(Stream::Stdout) {
                // No default set + interactive: show unified connection flow
                let (term_width, _) = terminal::size().unwrap_or((80, 24));
                let mut flow = ConnectionFlow::for_startup(&envs, term_width, true);

                let mut stdout = io::stdout();
                terminal::enable_raw_mode().unwrap();
                execute!(stdout, cursor::Hide).unwrap();

                match flow.run(&mut stdout) {
                    Ok(ConnectionFlowResult::Connected(env, preloaded, resolved_config)) => {
                        // Clear the flow UI
                        let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                        execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                        terminal::disable_raw_mode().unwrap();
                        execute!(stdout, cursor::Show).unwrap();

                        if env.name.is_empty() {
                            // From setup - new connection
                            from_setup = true;
                        } else {
                            // From picker - existing connection
                            loaded_connection_alias = env.name.clone();
                            from_setup = true;  // Also skip main splash print
                        }

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

                        // Pass preloaded result to avoid duplicate requests
                        startup_preloaded = preloaded;

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
        } else if uri.is_empty() && atty::is(Stream::Stdout) {
            // No saved connections + interactive: show unified connection flow (setup only)
            let (term_width, _) = terminal::size().unwrap_or((80, 24));
            let envs: Vec<String> = Vec::new();
            let mut flow = ConnectionFlow::for_startup(&envs, term_width, true);

            let mut stdout = io::stdout();
            terminal::enable_raw_mode().unwrap();
            execute!(stdout, cursor::Hide).unwrap();

            match flow.run(&mut stdout) {
                Ok(ConnectionFlowResult::Connected(env, _preloaded, resolved_config)) => {
                    // Clear flow UI including splash
                    let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                    execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                    terminal::disable_raw_mode().unwrap();
                    execute!(stdout, cursor::Show).unwrap();

                    // Apply config first so splash shows correct URL
                    if let Some(rc) = resolved_config {
                        config = rc;
                    } else {
                        apply_connection_to_config(&mut config, &env);
                    }

                    // Print fresh splash with the connected URL
                    print_splash_with_width(&config, term_width);
                    io::stdout().flush().ok();

                    from_setup = true;
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
    if let Err(e) = run_interactive(config, op_selector, from_setup, loaded_connection_alias, connecting_to, oauth2_creds, startup_preloaded, has_explicit_auth && has_explicit_uri) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
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

fn get_1password_credentials(selector: &str) -> Result<(String, String), String> {
    // Check if op command exists
    if Command::new("which").arg("op").output().is_err() {
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
    let output = Command::new("op")
        .args(["read", "op://Shared/COS environments/environments.json"])
        .output()
        .map_err(|e| format!("could not read from 1Password: {}", e))?;

    if !output.status.success() {
        return Err("could not read from 1Password".to_string());
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
            let key_output = Command::new("op")
                .args(["read", key_ref])
                .output()
                .map_err(|e| format!("could not read API key from 1Password: {}", e))?;

            let api_key = String::from_utf8_lossy(&key_output.stdout)
                .trim()
                .to_string();

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

fn fetch_feature_flags(config: &Config) -> bool {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| Client::new());

    let url = format!("{}/api/v1/about/feature-flags", config.base_uri);

    let mut request = client.get(&url);

    if !config.token.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", config.token));
    } else if !config.api_key.is_empty() {
        let encoded = BASE64.encode(format!(":{}", config.api_key));
        request = request.header("Authorization", format!("Basic {}", encoded));
    }

    match request.send() {
        Ok(resp) => {
            if let Ok(flags) = resp.json::<Vec<String>>() {
                flags.contains(&"response:streaming".to_string())
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn run_non_interactive(config: &mut Config, method: &str, uri: &str, body: &str) {
    let is_tty = atty::is(Stream::Stdout);

    // Ensure colors work on stderr even when stdout is piped
    if atty::is(Stream::Stderr) {
        colored::control::set_override(true);
    }

    // Parse > outfile from URI (space required before >, optional after)
    let (actual_uri, outfile) = if let Some(idx) = uri.find(" >") {
        let mut outfile_path = uri[idx + 2..].trim().to_string();
        if outfile_path.starts_with("~/") {
            if let Some(home) = dirs::home_dir() {
                outfile_path = format!("{}{}", home.display(), &outfile_path[1..]);
            }
        }
        (uri[..idx].trim(), Some(outfile_path))
    } else {
        (uri, None)
    };

    // Fetch feature flags
    config.streaming = fetch_feature_flags(config);

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| Client::new());

    let url = format!("{}{}{}", config.base_uri, config.api_path, actual_uri);

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
        let file_path = if file_path_raw.starts_with("~/") {
            if let Some(home) = dirs::home_dir() {
                format!("{}{}", home.display(), &file_path_raw[1..])
            } else {
                file_path_raw.to_string()
            }
        } else {
            file_path_raw.to_string()
        };
        match fs::read(&file_path) {
            Ok(contents) => {
                if file_path.ends_with(".ndjson") || file_path.ends_with(".njson") {
                    content_type = "application/x-ndjson".to_string();
                    accept = "application/x-ndjson".to_string();
                } else if file_path.ends_with(".csv") {
                    content_type = "text/csv".to_string();
                }
                request = request.body(contents);
            }
            Err(_) => {
                eprintln!("File not found: {}", file_path_raw);
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

            // Print status to stderr
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

                eprintln!(
                    "HTTP/1.1 {} {}",
                    status_str,
                    format!("{:.2}s", elapsed.as_secs_f64()).dimmed()
                );
                eprintln!();
            }

            // Get response body
            if let Ok(body_text) = resp.text() {
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

                // Write to file or stdout
                if let Some(ref file_path) = outfile {
                    if let Err(e) = fs::write(file_path, &output) {
                        eprintln!("Error writing to {}: {}", file_path, e);
                    } else {
                        eprintln!("Wrote to {}", file_path);
                    }
                } else {
                    print!("{}", output);
                    if !output.ends_with('\n') {
                        println!();
                    }
                    if is_tty {
                        eprintln!();
                    }
                }
            }
        }
        Err(_) => {
            let host = config.base_uri.trim_start_matches("https://").trim_start_matches("http://");
            eprintln!();
            eprintln!("Is COS running on {}? 🤔\n", host);
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
        let result = background_load(&config, None);
        if let Some(err) = &result.error {
            // Auth error (401/403)
            if err.contains("401") || err.contains("403") {
                // If explicit -b and -k were provided, show standard response and exit
                if from_cli_auth {
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
                // Otherwise launch connection flow with picker
                let (term_width, _) = terminal::size().unwrap_or((80, 24));
                let envs = list_connections();
                let mut flow = ConnectionFlow::for_startup(&envs, term_width, true);

                let mut stdout = io::stdout();
                terminal::enable_raw_mode().unwrap();
                execute!(stdout, cursor::Hide).unwrap();

                match flow.run(&mut stdout) {
                    Ok(ConnectionFlowResult::Connected(env, preloaded, resolved_config)) => {
                        let total_lines = flow.last_rendered_lines + if flow.show_splash { ConnectionFlow::splash_lines() } else { 0 };
                        execute!(stdout, cursor::MoveUp(total_lines), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown)).unwrap();
                        terminal::disable_raw_mode().unwrap();
                        execute!(stdout, cursor::Show).unwrap();

                        let new_config = if let Some(rc) = resolved_config {
                            rc
                        } else {
                            let mut nc = config.clone();
                            apply_connection_to_config(&mut nc, &env);
                            nc
                        };
                        // Use preloaded result if available, otherwise load now
                        let new_result = preloaded.unwrap_or_else(|| background_load(&new_config, None));
                        if let Some(new_err) = &new_result.error {
                            eprintln!("{}", new_err);
                            std::process::exit(1);
                        }
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

                    // Re-print previous output (last 5 requests)
                    for output in &state.output_history {
                        print!("{}", output);
                    }

                    // Placeholder lines for input area
                    println!();
                    println!();
                    println!();
                    io::stdout().flush().ok();

                    // Re-enable raw mode
                    terminal::enable_raw_mode()?;

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
                    let hint = "ctrl+d for docs";
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
        // Auto-clear status message after 3 seconds, animate spinner while active
        if let Some(at) = state.status_msg_at {
            if at.elapsed() >= Duration::from_secs(3) {
                state.status_msg.clear();
                state.status_msg_at = None;
                state.ctrl_c_pending = false;
                state.ctrl_c_at = None;
            }
            render(&mut stdout, &mut state)?;
        }
    }

    // Clear input area before exiting (move up and clear to end)
    let help_lines: u16 = 18;
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
    terminal::disable_raw_mode()?;

    Ok(())
}

fn handle_key_event(
    state: &mut AppState,
    key: KeyEvent,
    stdout: &mut io::Stdout,
) -> io::Result<(bool, Option<std::sync::mpsc::Receiver<BackgroundLoadResult>>)> {
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
                if extract_file_path_context(&state.input).is_some() {
                    handle_file_tab_completion_reverse(state);
                } else if state.config.complete {
                    handle_tab_completion_reverse(state);
                }
                render(stdout, state)?;
            }
        }

        // Tab: autocomplete only
        (_, KeyCode::Tab) => {
            // Check if we're in file completion mode (after > or @)
            if extract_file_path_context(&state.input).is_some() {
                handle_file_tab_completion(state);
                render(stdout, state)?;
            } else if !state.config.complete {
                state.status_msg = "completion not available on this server".to_string();
                state.status_msg_at = Some(std::time::Instant::now());
                render(stdout, state)?;
            } else {
                let had_completions = !state.completions.is_empty();
                let parts: Vec<&str> = state.input.split_whitespace().collect();
                let uri = if parts.len() >= 2 { parts[1] } else if parts.len() == 1 && parts[0].starts_with('/') { parts[0] } else { "" };
                // Complete if URI contains a delimiter (we're typing after /, (, or ~)
                let has_delim = uri.rfind(|c| c == '/' || c == '(' || c == '~').is_some();
                let should_complete = has_delim || had_completions;

                if !state.endpoints.is_empty() && should_complete {
                    handle_tab_completion(state);
                    render(stdout, state)?;
                }
            }
        }

        // Cycle method (ctrl+t or ctrl+z)
        (KeyModifiers::CONTROL, KeyCode::Char('t')) |
        (KeyModifiers::CONTROL, KeyCode::Char('z')) => {
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

            execute_request(state, stdout)?;
        }

        // Clear body
        (KeyModifiers::CONTROL, KeyCode::Char('x')) => {
            let parts: Vec<&str> = state.input.split_whitespace().collect();
            if parts.len() >= 2 {
                state.input = format!("{} {}", parts[0], parts[1]);
                state.cursor_pos = char_len(&state.input);
            }
            render(stdout, state)?;
        }

        // Clear full
        (KeyModifiers::CONTROL, KeyCode::Char('f')) => {
            state.input = "GET /".to_string();
            state.cursor_pos = 5;
            state.method = "GET".to_string();
            state.uri = "/".to_string();
            state.body.clear();
            render(stdout, state)?;
        }

        // Open docs
        (KeyModifiers::CONTROL, KeyCode::Char('d')) => {
            // Use current base_uri, fallback to dev.heads.com only if no base_uri
            let url = if state.config.base_uri.is_empty() {
                "https://dev.heads.com/api-docs".to_string()
            } else {
                format!("{}/api-docs", state.config.base_uri)
            };
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

        // Save connection (ctrl+s)
        (KeyModifiers::CONTROL, KeyCode::Char('s')) => {
            handle_save_connection(state, stdout)?;
        }

        // Switch connection (ctrl+l)
        (KeyModifiers::CONTROL, KeyCode::Char('l')) => {
            if let Some(rx) = handle_switch_connection(state, stdout)? {
                return Ok((false, Some(rx)));
            }
        }

        // History up
        (_, KeyCode::Up) => {
            if !state.history.is_empty() && state.history_idx < state.history.len() as i32 - 1 {
                state.history_idx += 1;
                let idx = state.history.len() - 1 - state.history_idx as usize;
                state.input = state.history[idx].clone();
                state.cursor_pos = char_len(&state.input);
                render(stdout, state)?;
            }
        }

        // History down
        (_, KeyCode::Down) => {
            if state.history_idx > 0 {
                state.history_idx -= 1;
                let idx = state.history.len() - 1 - state.history_idx as usize;
                state.input = state.history[idx].clone();
                state.cursor_pos = char_len(&state.input);
                render(stdout, state)?;
            } else if state.history_idx == 0 {
                state.history_idx = -1;
                state.input = format!("{} {}", state.method, state.uri);
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

        // Enter - execute request
        (KeyModifiers::NONE, KeyCode::Enter) => {
            let input = state.input.trim().to_string();
            let input = if input.is_empty() { "GET /".to_string() } else { input };

            parse_input(state, &input);
            state.history.push(input.clone());
            append_history(&input);
            state.history_idx = -1;
            state.prev_method = state.method.clone();
            state.prev_uri = state.uri.clone();
            state.prev_body = state.body.clone();
            state.prev_outfile = state.config.outfile.clone();

            execute_request(state, stdout)?;
        }

        // Backspace
        (_, KeyCode::Backspace) => {
            if state.cursor_pos > 0 {
                let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos - 1);
                state.input.remove(byte_idx);
                state.cursor_pos -= 1;
                render(stdout, state)?;
            }
        }

        // Delete
        (_, KeyCode::Delete) => {
            let input_char_len = char_len(&state.input);
            if state.cursor_pos < input_char_len {
                let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
                state.input.remove(byte_idx);
                render(stdout, state)?;
            }
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
            let byte_idx = char_to_byte_idx(&state.input, state.cursor_pos);
            state.input.insert(byte_idx, c);
            state.cursor_pos += 1;
            state.status_msg.clear();
            state.status_msg_at = None;
            render(stdout, state)?;
        }

        _ => {}
    }

    Ok((false, None))
}

fn parse_input(state: &mut AppState, input: &str) {
    let mut input = input.to_string();

    // Parse > outfile from the end (space required before >, optional after)
    state.config.outfile.clear();
    state.display_outfile.clear();
    if let Some(idx) = input.rfind(" >") {
        let after_gt = &input[idx + 2..];
        let outfile_raw = after_gt.trim_start().trim_end().to_string();
        if !outfile_raw.is_empty() {
            state.display_outfile = outfile_raw.clone();
            state.config.outfile = outfile_raw;
            if state.config.outfile.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    state.config.outfile = format!("{}{}", home.display(), &state.config.outfile[1..]);
                }
            }
            input = input[..idx].trim().to_string();
        }
    }

    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    let first_upper = parts[0].to_uppercase();

    if methods.contains(&first_upper.as_str()) {
        state.method = first_upper;
        state.uri = parts.get(1).map(|s| s.to_string()).unwrap_or_else(|| "/".to_string());
        state.body = parts.get(2..).map(|p| p.join(" ")).unwrap_or_default();
    } else if parts[0].starts_with('/') {
        state.method = "GET".to_string();
        state.uri = parts[0].to_string();
        state.body = parts.get(1..).map(|p| p.join(" ")).unwrap_or_default();
    }
}

fn execute_request(state: &mut AppState, stdout: &mut io::Stdout) -> io::Result<()> {
    // Clear splash tracking since we're printing output
    state.last_was_splash = false;

    // Build output string to store for resize redraw
    let mut output_lines = String::new();

    // Prepare request line
    let request_line = format!("{} {}", state.method, state.uri);
    output_lines.push_str(&request_line);
    output_lines.push('\n');

    // Build request
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| Client::new());

    let url = format!("{}{}{}", state.config.base_uri, state.config.api_path, state.uri);

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
        let file_path = if file_path_raw.starts_with("~/") {
            if let Some(home) = dirs::home_dir() {
                format!("{}{}", home.display(), &file_path_raw[1..])
            } else {
                file_path_raw.to_string()
            }
        } else {
            file_path_raw.to_string()
        };
        match fs::read(&file_path) {
            Ok(contents) => {
                // Auto-detect content type from extension
                if file_path.ends_with(".ndjson") || file_path.ends_with(".njson") {
                    content_type = "application/x-ndjson".to_string();
                    accept = "application/x-ndjson".to_string();
                } else if file_path.ends_with(".csv") {
                    content_type = "text/csv".to_string();
                }
                request = request.body(contents);
            }
            Err(_) => {
                file_error = Some(format!("File not found: {}", file_path_raw));
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

    // Buffer for display output (will print all at once)
    let mut display_output = request_line.clone();
    display_output.push('\n');

    // If file error, show it and return
    if let Some(err) = file_error {
        display_output.push_str(&format!("\n{}\n\n", err));
        output_lines.push_str(&format!("\n{}\n\n", err));
        state.output_history.push(display_output.clone());
        if state.output_history.len() > 5 { state.output_history.remove(0); }

        // Update input with last command
        state.input = format!("{} {}", state.method, state.uri);
        if !state.body.is_empty() {
            state.input.push_str(&format!(" {}", state.body));
        }
        state.cursor_pos = char_len(&state.input);

        // Clear input area, print output, render new input (same as normal flow)
        let clear_lines = 2 + state.prev_input_lines;
        execute!(stdout, cursor::Hide, cursor::MoveUp(clear_lines.min(state.height.saturating_sub(1))), cursor::MoveToColumn(0), Clear(ClearType::FromCursorDown))?;
        terminal::disable_raw_mode()?;
        print!("{}", display_output);
        io::stdout().flush()?;
        terminal::enable_raw_mode()?;
        execute!(stdout, Print("\r\n\r\n\r\n"))?;
        render(stdout, state)?;
        return Ok(());
    }

    // Run HTTP request + body read in a thread so we can handle spinner and ctrl+c
    // Both send() and text() can block — send() waits for headers, text() reads the full body
    let response_result: Arc<std::sync::Mutex<Option<Result<(reqwest::StatusCode, String), reqwest::Error>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let response_result_clone = Arc::clone(&response_result);
    let request_handle = thread::spawn(move || {
        let result = request.send().and_then(|resp| {
            let status = resp.status();
            let body = resp.text()?;
            Ok((status, body))
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

        // Show spinner after 1 second in the hint area (bottom line)
        if start.elapsed() >= Duration::from_secs(1) {
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
        return Ok(());
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
    if let Some(Ok((status, _))) = &response_opt {
        if status.as_u16() == 401 && !state.oauth2_client_id.is_empty() && !state.oauth2_client_secret.is_empty() {
            // Attempt token refresh
            if let Ok((new_token, _)) = oauth2_token_exchange(&state.config.base_uri, &state.oauth2_client_id, &state.oauth2_client_secret) {
                state.config.token = new_token.clone();

                // Retry the request with new token
                let client = Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap_or_else(|_| Client::new());

                let url = format!("{}{}{}", state.config.base_uri, state.config.api_path, state.uri);
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
                        response_opt = Some(Ok((retry_status, retry_body)));
                    }
                }
            }
        }
    }

    match response_opt {
        Some(Ok((status, body_text))) => {
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

            // Handle outfile
            if !state.config.outfile.is_empty() {
                if let Err(e) = fs::write(&state.config.outfile, &body_text) {
                    display_output.push_str(&format!("Error writing to {}: {}\n", state.config.outfile, e));
                } else {
                    state.last_outfile = state.config.outfile.clone();
                    state.last_display_outfile = state.display_outfile.clone();

                    if !state.config.silent {
                        display_output.push_str(&format!(
                            "HTTP/1.1 {} {}\n{}\n\n",
                            status_str,
                            format!("{:.2}s", elapsed.as_secs_f64()).dimmed(),
                            format!("> {}", state.display_outfile).dimmed()
                        ));
                    }
                    state.status_msg = "ctrl+o to open file".to_string();
                    state.status_msg_at = Some(Instant::now());
                }
            } else {
                // Build status line
                if !state.config.silent {
                    let status_line = format!(
                        "HTTP/1.1 {} {}",
                        status_str,
                        format!("{:.2}s", elapsed.as_secs_f64()).dimmed()
                    );
                    display_output.push_str(&status_line);
                    display_output.push('\n');
                    output_lines.push_str(&status_line);
                    output_lines.push('\n');
                }

                // Build body
                if !body_text.is_empty() {
                    let output = if state.config.raw || state.config.ndjson {
                        body_text
                    } else if let Ok(json) = serde_json::from_str::<Value>(&body_text) {
                        serde_json::to_string_pretty(&json).unwrap_or(body_text)
                    } else {
                        body_text
                    };
                    display_output.push_str(&format!("\n{}\n\n", output));
                    output_lines.push('\n');
                    output_lines.push_str(&output);
                    output_lines.push_str("\n\n");
                } else {
                    // Add blank line after status when no body
                    display_output.push('\n');
                    output_lines.push('\n');
                }
            }
        }
        Some(Err(_)) => {
            let host = state.config.base_uri.trim_start_matches("https://").trim_start_matches("http://");
            let err_msg = format!("\nIs COS running on {}? 🤔\n\n", host);
            display_output.push_str(&err_msg);
            output_lines.push_str(&err_msg);
        }
        None => {
            // Request was aborted or something went wrong
            let err_msg = "\nRequest failed\n";
            display_output.push_str(err_msg);
            output_lines.push_str(err_msg);
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

    // Store output for resize redraw (keep last 5)
    state.output_history.push(output_lines);
    if state.output_history.len() > 5 {
        state.output_history.remove(0);
    }

    // Update input with last command (use display_outfile to keep ~ unexpanded)
    state.input = format!("{} {}", state.method, state.uri);
    if !state.body.is_empty() {
        state.input.push_str(&format!(" {}", state.body));
    }
    if !state.display_outfile.is_empty() {
        state.input.push_str(&format!(" > {}", state.display_outfile));
    }
    state.cursor_pos = char_len(&state.input);

    // Now clear input area, print output, and render new input - all at once
    let clear_lines = 2 + state.prev_input_lines;
    execute!(
        stdout,
        cursor::Hide,
        cursor::MoveUp(clear_lines.min(state.height.saturating_sub(1))),
        cursor::MoveToColumn(0),
        Clear(ClearType::FromCursorDown)
    )?;

    // Disable raw mode for clean output printing
    terminal::disable_raw_mode()?;
    print!("{}", display_output);
    io::stdout().flush()?;

    // Re-enable raw mode for UI
    terminal::enable_raw_mode()?;

    // Print placeholder lines and render input area
    execute!(stdout, Print("\r\n\r\n\r\n"))?;
    render(stdout, state)?;

    Ok(())
}

fn cycle_method(state: &mut AppState) {
    let parts: Vec<&str> = state.input.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    let current = parts[0].to_uppercase();
    let new_method = match current.as_str() {
        "GET" => "PUT",
        "PUT" => "PATCH",
        "PATCH" => "POST",
        _ => "GET",
    };

    state.input = if parts.len() > 1 {
        format!("{} {}", new_method, parts[1..].join(" "))
    } else {
        format!("{} /", new_method)
    };
    state.cursor_pos = char_len(&state.input);
    state.method = new_method.to_string();
}

fn cycle_method_reverse(state: &mut AppState) {
    let parts: Vec<&str> = state.input.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    let current = parts[0].to_uppercase();
    let new_method = match current.as_str() {
        "GET" => "POST",
        "POST" => "PATCH",
        "PATCH" => "PUT",
        _ => "GET",
    };

    state.input = if parts.len() > 1 {
        format!("{} {}", new_method, parts[1..].join(" "))
    } else {
        format!("{} /", new_method)
    };
    state.cursor_pos = char_len(&state.input);
    state.method = new_method.to_string();
}

// Read a line of input in raw mode (already in raw mode when called from interactive)
fn read_inline_input(stdout: &mut io::Stdout, prompt: &str, mask: bool, prefill: &str) -> io::Result<Option<String>> {
    let mut buf = prefill.to_string();
    let mut caret_visible = true;
    let mut caret_toggle_at = Instant::now() + Duration::from_millis(500);

    let render_line = |stdout: &mut io::Stdout, prompt: &str, buf: &str, mask: bool, caret: bool| -> io::Result<()> {
        execute!(stdout, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
        let display = if mask && !buf.is_empty() { "•".repeat(buf.len()) } else { buf.to_string() };
        let cursor_char = if caret { "\x1b[7m \x1b[0m" } else { " " };
        execute!(stdout, Print(format!("{}{}{}", prompt, display, cursor_char)))?;
        stdout.flush()?;
        Ok(())
    };

    render_line(stdout, prompt, &buf, mask, caret_visible)?;

    loop {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != event::KeyEventKind::Press { continue; }
                caret_visible = true;
                caret_toggle_at = Instant::now() + Duration::from_millis(500);
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

        // Blink caret
        if Instant::now() >= caret_toggle_at {
            caret_visible = !caret_visible;
            caret_toggle_at = Instant::now() + Duration::from_millis(500);
        }

        render_line(stdout, prompt, &buf, mask, caret_visible)?;
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
    execute!(stdout, Print("\r\n"))?; // placeholder for prompt line
    execute!(stdout, Print(format!("{}\r\n", ruler.dimmed())))?; // bottom ruler
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

    if state.config.streaming {
        content_type.push_str(";stream=true");
        accept.push_str(";stream=true");
    }

    if state.config.include_nulls {
        accept.push_str(";skipNulls=false");
    }

    let mut cmd = format!(
        "curl -gfsSL -X {} \"{}{}{}\"\n",
        state.prev_method, state.config.base_uri, state.config.api_path, state.prev_uri
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
        cmd.push_str(&format!(" --data-binary '{}'", state.prev_body));
    }

    // Copy to clipboard
    if cli_clipboard::set_contents(cmd.clone()).is_ok() {
        return true;
    }

    false
}

fn render(stdout: &mut io::Stdout, state: &mut AppState) -> io::Result<()> {
    let width = state.width as usize;
    state.prev_width = state.width;

    // Determine how many lines to clear:
    // - Normal input area: 2 + input_lines (ruler + input line(s) + hint)
    // - Help menu: 14 lines (15 with tab completion)
    let help_lines: u16 = 18;
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

    // Hide cursor first to prevent flicker, then move up and clear
    execute!(
        stdout,
        cursor::Hide,
        cursor::MoveUp(lines_to_clear.min(state.height.saturating_sub(1))),
        cursor::MoveToColumn(0),
        Clear(ClearType::FromCursorDown)
    )?;

    // Top ruler
    let ruler = "─".repeat(width);
    if !state.config.base_uri.is_empty() {
        let host = format!(" [{}] ", state.config.base_uri);
        let host_len = host.len();
        let right = 7;
        let left = width.saturating_sub(host_len).saturating_sub(right);
        execute!(
            stdout,
            Print(format!(
                "{}{}{}\r\n",
                "─".repeat(left).dimmed(),
                host.dimmed(),
                "─".repeat(right).dimmed()
            ))
        )?;
    } else {
        execute!(stdout, Print(format!("{}\r\n", ruler.dimmed())))?;
    }

    // Input line or help
    if state.loading {
        let frame = SPINNER_FRAMES[state.loading_frame % SPINNER_FRAMES.len()];
        let msg = if let Some(ref env_name) = state.loading_connection_name {
            if state.config.base_uri.is_empty() {
                format!(" {} Loading connection {} from 1P...", frame, env_name)
            } else {
                format!(" {} Connecting to {}...", frame, env_name)
            }
        } else {
            format!(" {} Loading environment from 1P...", frame)
        };
        execute!(stdout, Print(format!("{}\r\n", msg.dimmed())))?;
    } else if state.show_help {
        execute!(
            stdout,
            Print("\r\n"),
            Print(format!("{}\r\n", "  enter      Send request".dimmed())),
            Print(format!("{}\r\n", "  opt+enter  New line (multiline body) [or ctrl+n]".dimmed())),
            Print(format!("{}\r\n", "  up/down    Navigate input history".dimmed()))
        )?;
        execute!(stdout, Print(format!("{}\r\n", "  tab        Complete URI (endpoints, operators, properties)".dimmed())))?;
        execute!(
            stdout,
            Print(format!("{}\r\n", "  ctrl+g     Quick GET current URI".dimmed())),
            Print(format!("{}\r\n", "  ctrl+t     Cycle method: GET → POST → PATCH → PUT".dimmed())),
            Print(format!("{}\r\n", "  ctrl+x     Clear body (keep method and URI)".dimmed())),
            Print(format!("{}\r\n", "  ctrl+f     Clear all (reset to GET /)".dimmed())),
            Print(format!("{}\r\n", "  ctrl+y     Copy last request as curl command".dimmed())),
            Print(format!("{}\r\n", "  ctrl+s     Save the current connection for easy access later".dimmed())),
            Print(format!("{}\r\n", "  ctrl+l     Switch connection".dimmed())),
            Print(format!("{}\r\n", "  ctrl+d     Open API docs in browser".dimmed())),
            Print(format!("{}\r\n", "  ctrl+o     Open last saved file".dimmed())),
            Print(format!("{}\r\n", "  ctrl+c     Quit".dimmed())),
            Print("\r\n"),
            Print(format!("{}\r\n", "  ctrl+h or esc to close".dimmed()))
        )?;
    } else {
        // Input with cursor (using reverse video block cursor)
        // Use character-based indexing for safe UTF-8 handling
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

        // Get ghost text for completion
        let in_file_mode = extract_file_path_context(&state.input).is_some();
        let cursor_at_end = state.cursor_pos == input_char_len;
        let ghost = if cursor_at_end
            && (in_file_mode || (state.config.complete && !state.endpoints.is_empty()))
        {
            get_completion_ghost(state)
        } else if !cursor_at_end && state.config.complete && !state.endpoints.is_empty() {
            // Mid-cursor ghost: compute completions based on URI text before cursor
            get_completion_ghost_at_cursor(state)
        } else {
            String::new()
        };

        // Build the input with ghost text and cursor
        let mut rendered = String::new();
        rendered.push_str(before_cursor);

        if !ghost.is_empty() {
            if cursor_at_end {
                // Cursor at end: ghost replaces the block cursor
                let ghost_chars: Vec<char> = ghost.chars().collect();
                if state.completions.len() > 1 {
                    rendered.push_str(&format!("\x1b[48;5;240m{}\x1b[0m", ghost_chars[0]));
                } else {
                    rendered.push_str(&format!("\x1b[7m{}\x1b[0m", ghost_chars[0]));
                }
                if ghost_chars.len() > 1 {
                    rendered.push_str(&format!("\x1b[38;5;240m{}\x1b[0m", ghost_chars[1..].iter().collect::<String>()));
                }
            } else {
                // Mid-cursor: show ghost inline, then cursor + after_cursor
                rendered.push_str(&format!("\x1b[38;5;240m{}\x1b[0m", ghost));
                if at_cursor == '\n' {
                    rendered.push_str("\x1b[7m \x1b[0m");
                    rendered.push('\n');
                    rendered.push_str(after_cursor.trim_start_matches('\n'));
                } else {
                    rendered.push_str(&format!("\x1b[7m{}\x1b[0m", at_cursor));
                    rendered.push_str(after_cursor);
                }
            }
        } else {
            if at_cursor == '\n' {
                // Cursor is on a newline - show block cursor as space at end of current line
                rendered.push_str("\x1b[7m \x1b[0m");
                rendered.push('\n');
                rendered.push_str(after_cursor.trim_start_matches('\n'));
            } else {
                rendered.push_str(&format!("\x1b[7m{}\x1b[0m", at_cursor));
                rendered.push_str(after_cursor);
            }
        }

        // Split into logical lines (by newline characters)
        let lines: Vec<&str> = rendered.split('\n').collect();

        // Calculate visual line count accounting for terminal width wrapping
        let input_line_count = visual_line_count(&rendered, width);

        // Print all lines except last
        for line in &lines[..lines.len() - 1] {
            execute!(stdout, Print(format!("{}\r\n", line)))?;
        }

        // Last line gets hints/counter appended
        let last_line = lines.last().unwrap_or(&"");
        let mut final_line = last_line.to_string();

        // Hints only on last line — use last line's visible char count
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

        execute!(stdout, Print(final_line), Print("\r\n"))?;

        // Track input line count for clearing on next render
        state.prev_input_lines = input_line_count;
    }

    // Bottom ruler and hint (only when not showing help - help has its own)
    if !state.show_help {
        execute!(stdout, Print(format!("{}\r\n", ruler.dimmed())))?;

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
                execute!(stdout, Print(format!("  {}", msg_style)))?;
            } else {
                execute!(stdout, Print(format!("  {}", "ctrl+h for shortcuts".dimmed())))?;
            }
        }
    }

    stdout.flush()?;
    Ok(())
}

fn print_splash_with_width(config: &Config, term_width: u16) {
    let full_width = 60usize;
    let min_width = 36usize; // Minimum to show title properly
    let hint_section_width = 20usize; // " │ ctrl+d for docs │" length

    let term_w = term_width as usize;

    // Don't print splash if terminal is too narrow
    if term_w < min_width {
        println!();
        return;
    }

    let host = config.base_uri.as_str();

    let title = "CommerceOS API Client";
    let version = format!("v{}", VERSION);
    let hint = "ctrl+d for docs";

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

    if let Some(selector) = op_selector {
        match get_1password_credentials(&selector) {
            Ok((uri, key)) => {
                config.base_uri = uri.clone();
                config.api_key = key.clone();
                base_uri = Some(uri);
                api_key = Some(key);
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
        mapped_types: Vec::new(),
        spec: None,
    };

    if complete {
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
    state.config.streaming = result.streaming;
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

fn extract_schema_name(ref_path: &str) -> Option<String> {
    const PREFIX: &str = "#/components/schemas/";
    if ref_path.starts_with(PREFIX) {
        Some(ref_path[PREFIX.len()..].to_string())
    } else {
        None
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

fn handle_file_tab_completion(state: &mut AppState) {
    let (path_start, partial) = match extract_file_path_context(&state.input) {
        Some(ctx) => ctx,
        None => return,
    };

    let prefix = &state.input[..path_start];

    // Check for ~ operator on body file argument
    if let Some(tilde_idx) = partial.rfind('~') {
        let file_part = &partial[..tilde_idx];
        let after_tilde = &partial[tilde_idx + 1..];
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
                let completion = &state.completions[state.completion_idx];
                state.input = format!("{}{}~map({}", prefix, file_part, completion);
                state.cursor_pos = char_len(&state.input);
            }
            return;
        }
        // Only complete map( on body file args
        if !after_tilde.contains('(') && "map(".starts_with(after_tilde) && *after_tilde != *"map(" {
            state.input = format!("{}{}~map(", prefix, file_part);
            state.cursor_pos = char_len(&state.input);
            return;
        }
    }

    // Check if cycling through completions
    let is_cycling = if !state.completions.is_empty() && !state.last_tab_input.is_empty() {
        state.completions.iter().enumerate().any(|(i, comp)| {
            let expected = format!("{}{}", prefix, comp);
            if state.input == expected {
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
        state.completions = get_file_completions(&partial);
        state.completion_idx = 0;
        state.last_tab_input = state.input.clone();
    }

    if !state.completions.is_empty() {
        let completion = &state.completions[state.completion_idx];
        state.input = format!("{}{}", prefix, completion);
        state.cursor_pos = char_len(&state.input);
    }
}

fn handle_file_tab_completion_reverse(state: &mut AppState) {
    if state.completions.is_empty() {
        return;
    }

    let (path_start, _) = match extract_file_path_context(&state.input) {
        Some(ctx) => ctx,
        None => return,
    };

    let prefix = &state.input[..path_start].to_string();

    if state.completion_idx == 0 {
        state.completion_idx = state.completions.len() - 1;
    } else {
        state.completion_idx -= 1;
    }

    let completion = &state.completions[state.completion_idx];
    state.input = format!("{}{}", prefix, completion);
    state.cursor_pos = char_len(&state.input);
}

fn get_completion_ghost(state: &AppState) -> String {
    // File completion ghost text (works even without API completion)
    if let Some((_, partial)) = extract_file_path_context(&state.input) {
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
        let completions = get_file_completions(&partial);
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

    // Only show ghost text if URI contains a delimiter (we're typing after /, (, or ~)
    if uri.rfind(|c| c == '/' || c == '(' || c == '~').is_none() {
        return String::new();
    }

    // Get completions for current input
    let completions = get_completions(state, &uri);
    if completions.is_empty() {
        return String::new();
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

    String::new()
}

fn get_completion_ghost_at_cursor(state: &AppState) -> String {
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
    if cursor_in_uri >= uri_chars.len() {
        return String::new();
    }
    let uri_before: String = uri_chars[..cursor_in_uri].iter().collect();
    if uri_before.is_empty() {
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

    let uri_after: String = uri_chars[cursor_in_uri..].iter().collect();

    let completion = &completions[0];
    if completion.starts_with(&uri_before) {
        let uri_before_chars = uri_before.chars().count();
        let ghost: String = completion.chars().skip(uri_before_chars).collect();
        // Suppress ghost if the text after cursor already starts with it
        if !ghost.is_empty() && !uri_after.starts_with(&ghost) {
            return ghost;
        }
    }

    String::new()
}

/// Extract the file path portion being typed after ">" or "@" in the input.
/// Returns Some((prefix_before_path, partial_path)) if in file completion mode.
/// Triggers directly after " >" or " @" (space not required after the symbol).
fn extract_file_path_context(input: &str) -> Option<(usize, String)> {
    // Check for " >" (outfile) - must have space before > but not necessarily after
    if let Some(idx) = input.rfind(" >") {
        let after_gt = idx + 2;
        // Skip optional space after >
        let path_start = if input[after_gt..].starts_with(' ') { after_gt + 1 } else { after_gt };
        let after = &input[path_start..];
        return Some((path_start, after.to_string()));
    }
    // Check for " @" (file body input) - must have space before @ but not necessarily after
    if let Some(idx) = input.rfind(" @") {
        let after_at = idx + 2;
        let path_start = if input[after_at..].starts_with(' ') { after_at + 1 } else { after_at };
        let after = &input[path_start..];
        return Some((path_start, after.to_string()));
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

    // If current type expects an index, offer array members and identifier completions
    if expects_index {
        // Add array members (like count, add, after)
        if let Some(members) = state.array_members.get(&schema_name) {
            for member_name in members.keys() {
                if member_name.starts_with(partial) {
                    completions.push(format!("{}/{}", base_path, member_name));
                }
            }
        }

        // Add identifier property completions (e.g., currencyCode=)
        let identifier_completions = get_identifier_completions_for_schema(state, &schema_name, base_path, partial);
        completions.extend(identifier_completions);
    } else {
        // Complete with properties of current schema
        if let Some(props) = state.schema_props.get(&schema_name) {
            for prop in props {
                if prop.starts_with('@') {
                    continue;
                }
                if prop.starts_with(partial) {
                    completions.push(format!("{}/{}", base_path, prop));
                }
            }
        }

        // Also offer primitive members (e.g., string.length, string.upper)
        if let Some(members) = state.primitive_members.get(&schema_name) {
            for member_name in members.keys() {
                if member_name.starts_with(partial) {
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
    for ec in &endpoint_completions {
        if !completions.contains(ec) {
            completions.push(ec.clone());
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
            // Fallback to endpoint_types for singleton endpoints without tag x-type
            schema_name = Some(name.clone());
            start_idx = i;
        }
    }

    let mut current_schema = match schema_name {
        Some(s) => s,
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

        // Otherwise, this segment is likely an index value
        // After indexing, we get the returnType from x-indexer or stay at same type
        if let Some(indexer) = state.indexer_info.get(&current_schema) {
            if let Some(return_type) = &indexer.return_type {
                current_schema = return_type.trim_end_matches('?').to_string();
            }
        } else if let Some(_key_type) = state.additional_props_key.get(&current_schema) {
            // For additionalProperties, the value type comes from items or stays same
            // For now, assume we can't navigate further
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

fn get_identifier_completions(state: &AppState, uri: &str) -> Vec<String> {
    // Get completions for identifier properties followed by =
    // e.g., for /currencies/ -> currencyCode=
    let path_parts: Vec<&str> = uri.split('/').collect();
    if path_parts.len() < 2 {
        return Vec::new();
    }

    let base = format!("/{}", path_parts[1]);
    let partial = if path_parts.len() >= 3 { path_parts[2] } else { "" };

    // Check if this is a collection endpoint
    let is_collection = state.param_types.keys().any(|ep| ep.starts_with(&format!("{}/", base)));
    if !is_collection {
        return Vec::new();
    }

    // Get schema name via endpoint_schemas
    let schema_name = match state.endpoint_schemas.get(&base) {
        Some(name) => name,
        None => return Vec::new(),
    };

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
    // e.g., "currency code or currency identifiers" -> look up "currency identifiers"
    let mut completions = Vec::new();

    for type_name in index_type.split(" or ") {
        let type_name = type_name.trim();
        if type_name.ends_with(" identifiers") || type_name == "common identifiers" {
            // Look up this identifier schema's properties
            if let Some(props) = state.schema_props.get(type_name) {
                for prop in props {
                    // Skip @type and key
                    if prop.starts_with('@') || prop == "key" {
                        continue;
                    }
                    let completion = format!("{}=", prop);
                    if completion.starts_with(partial) {
                        completions.push(format!("{}/{}", base, completion));
                    }
                }
            }
        }
    }

    completions
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
    let root_schema = get_schema_for_path(state, base_path);
    if root_schema.is_empty() {
        return Vec::new();
    }

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
                completions.push(format!("{}{}", prefix_part, current_selector.replace(current_prefix, name)));
            }
        }
        if completions.is_empty() && current_prefix.is_empty() {
            for name in &completions_from {
                if used.contains(name.as_str()) {
                    continue;
                }
                completions.push(format!("{}{}", prefix_part, name));
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
