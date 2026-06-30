# Changelog

## 2.6.8

- **Smart method switching while typing a body** (interactive): starting to type a request body on a `GET` auto-promotes it to `PUT` (a body implies a write). The trigger is the first non-whitespace body character (`{`, `[`, `"`, `@`, numbers, `true`/`false`/`null`, etc.); the `>` outfile operator is excluded. `ctrl+space` still cycles `PUT → PATCH → POST → GET`.
- **Auto-wrap array bodies**: on a `PUT`/`PATCH` to an array endpoint, typing the first body character prepends an opening `[` (e.g. `PUT /people {` → `PUT /people [{`). Type `[` yourself and nothing is added; the closing `]` is left to tab completion.
- **Paste a full request line to replace the input**: pasting text that starts with an HTTP method (outside a JSON body) replaces the whole line instead of inserting at the cursor — so pasting `GET /people/...` over a `GET /` prompt no longer duplicates the method.
- **Smarter identifier paste**: pasting an `identifiers` JSON object now targets the URI's index slot — appending `/key=value` on a collection, or replacing the current `key=value` in place — so repeated pastes never accumulate duplicate segments. Re-pasting the same JSON within 10s cycles through multiple identifiers in place. A separating `/` is always added when missing, and JSON-LD metadata keys (`@type`, `@id`, ...) are never treated as identifiers.
- **`-p` / `--preview` flag**: preview the resolved request(s) and confirm (`Run? [Y/n]`, default yes) before sending. Intended for bulk runs (`api -spa file.api`). The header summarizes the methods used (e.g. `Preview — 5 requests | PUT GET`); preview output and prompt go to stderr (piped stdout stays clean) and the answer is read from `/dev/tty`.
- **`--no-keychain` flag**: route all credential I/O to a plaintext JSON file (`API_CREDENTIALS_FILE`, else `./.api-credentials.json`) instead of the OS keychain — so automated runs and tests never trigger a keychain unlock prompt. A `.api-credentials-sample.json` template is included; the real file is gitignored.
- **Tab completion for `> clipboard`**: in an outfile redirect, typing a prefix of `clipboard` suggests/completes the `clipboard` target. Purely additive — real files and folders beginning with `clip` are preserved and still cycle-reachable.
- Fixed the input area drifting upward when navigating history (up/down) after a multi-line or wrapping paste: the renderer now hard-wraps the input itself with terminal auto-wrap disabled, and no longer miscounts blank lines, so the block stays anchored.
- **Paste-expand identifiers in the URL field**: pasting JSON like `{"identifiers":{"com.heads.seedID":"x"}}` auto-expands to `com.heads.seedID=x`; repeated pastes within 10s cycle through multiple identifiers.
- **`@glob` bodies skip OS junk**: `.DS_Store`, `Thumbs.db`, `desktop.ini`, `._*` are ignored so `@dir/*` doesn't choke on macOS/Windows metadata files.
- **`> clipboard` outfile target** (case-insensitive): copies the response to the system clipboard instead of writing a file.
- **`--timeout <SECONDS>` flag**: request timeout is now indefinite by default (was 30s); ancillary calls (env discovery, feature flags) keep their short caps.

## 2.6.7

- **Include directives in `.api` batch files**: a bare line that isn't a comment, blank, or HTTP request is treated as an include — the named file is loaded and its requests inlined at that point. Paths resolve relative to the parent `.api` file. Supports `~/`, absolute paths, and globs (`example*.api`). Recursive includes work; loops are detected and reported.

## 2.6.6

- **Glob support in `@file` bodies**: `@dir/*.json` matches multiple files and combines them. Objects/values from each file are flattened into a single JSON array; arrays are concatenated. Files matching `*.ndjson`/`*.njson` are concatenated as a single NDJSON stream instead. Files processed in sorted order.
- Errors clearly: `no files match: ...` for empty globs, `invalid JSON in <path>: ...` for malformed files.
- Request log line now includes the original `@file` / glob expression (e.g. `PUT /people @j*.json`) so it's visible alongside the response.

## 2.6.5

- **Multi-line request bodies in bulk files (`.api`)**: a request body with unbalanced `{}` / `[]` brackets continues onto subsequent lines until balanced. Arrays and nested objects supported. Raw newlines, tabs, and carriage returns inside JSON strings are auto-escaped to `\n` / `\t` / `\r` so the body stays valid JSON (useful for PEM contents, multi-line descriptions, etc.).
- **Compact body display in silent bulk mode** (`-sa`): JSON bodies are minified for display (no extra whitespace or indentation), making per-request output a single tidy line. Non-JSON bodies (e.g. `@file`) pass through unchanged.
- Unclosed body at EOF of a bulk file now errors with a clear message instead of silently dropping the request.
- Suppressed URI tab-completion ghost text when the input already contains content after the URI (was leaking property suggestions past the body).

## 2.6.4

- **Standard readline shortcuts** added to the input line:
  - `ctrl+k` — kill from cursor to end of line
  - `ctrl+w` / `alt+backspace` — delete word backward
  - `alt+d` — delete word forward
  - `ctrl+←` / `alt+b` — move cursor backward by word
  - `ctrl+→` / `alt+f` — move cursor forward by word
- `ctrl+u` now clears the entire input line (was unbound). `ctrl+f` still resets to `GET /`.
- `--no-streaming` flag forces non-streaming Accept/Content-Type headers even when the server advertises streaming
- Silent bulk mode (`-sa`) now writes response bodies to outfiles (`> path`) instead of dropping them

## 2.6.2

- **Silent bulk mode** (`-sa` / `--silent --all`): compact progress-style output. Prints the env URL in gray brackets at the top, then each request line followed by an indented `└─HTTP/1.1 <status> <time>s` line (gray box-draw, status colored). Response bodies are suppressed.
- Non-interactive outfile output now matches interactive format: `> path` (dimmed, with `~/` preserved) instead of `Wrote to /full/expanded/path`
- Tests can now bypass keychain prompts by setting `API_TEST_BASE_URI` + `API_TEST_KEY` env vars

## 2.5.14

- **Bulk mode (`-a` / `--all`)**: execute multiple requests from a file, one per line. Supports `#` comments, blank lines, `@file` bodies, and `> outfile` per line. Same parsing as interactive client.
- **Bulk from stdin**: `cat requests.txt | api -a` (or `api -a -`) reads request lines from stdin instead of a file.
- **Integration test suite**: 25 end-to-end tests in `tests/cli.rs` covering all methods, body modes (inline/stdin/`@file`), output flags (`--silent`, `--raw`, `--ndjson`), outfile (`>`), URL operators, and bulk mode. Runs against a local COS via the default connection (`cargo test --test cli`).

## 2.5.13

- Fixed Shift+Tab clearing input when cycling `~map(type)` completions (now mirrors forward Tab behavior)
- Fixed parser treating extra spaces between URI and body as part of the body (e.g. `PUT /foo  @file.json` now correctly recognizes `@file.json` as a file body)
- Fixed body input mode rendering when text wraps beyond terminal width (used line-count that ignored wrapping, causing screen artifacts)

## 2.5.12

- **Body stash on GET**: switching to GET via `ctrl+space` hides the body from the input; switching back restores it. Cleared on request send.
- **curl copy improvements** (`ctrl+y`):
  - `@file~map(type)` bodies now emit `X-Request-Map` header and clean file path instead of passing `~map()` in `--data-binary`
  - Content-Type auto-detected from input file extension (`.csv` → `text/csv`, `.ndjson` → `application/x-ndjson`)
  - Accept auto-detected from outfile extension (`.csv`, `.ndjson`, `.sql`)
  - Outfile included as `-o` flag

## 2.5.11

- **Output erase commands**: `ctrl+w` erases last request+response, `ctrl+j` erases last response body only, `ctrl+l` erases all output
- **Keyboard shortcut changes**: `ctrl+space` cycles method (replaces `ctrl+t`), `ctrl+q` switches connection (replaces `ctrl+l`), `ctrl+l` clears all output
- **Smart method cycling**: `ctrl+space` resets to GET if >5 seconds since last cycle and not already on GET
- Tab completion now works after `!` negation prefix in operators (e.g. `~where(!prop`)
- Fixed `ctrl+k` clear not sticking when followed by other keys

## 2.5.10

- **Body input mode**: `PATCH`, `POST`, and `PUT` without a body now prompt for body input with a cursor, instead of sending an empty request. `ctrl+d` to submit, `esc` to cancel.
- **CLI stdin body**: non-interactive mode reads body from stdin for body-methods when no body argument is given (e.g. `echo '{}' | api PATCH /people`)
- Fixed `ctrl+y` curl copy: removed stray line break before `-u`/`-H` flags

## 2.5.6

- Animated spinner during connection setup loading (threaded background load with 80ms frame updates)
- Loading/status text lowercase and dimmed (`loading...`, `testing connection...`)
- Fixed ruler styling inconsistency in save-connection prompt (matched `\x1b[38;5;239m` gray)
- Fixed crash on Ghostty with narrow terminals: UTF-8 multi-byte character slicing in masked password fields (`•` is 3 bytes)
- Fixed narrow terminal rendering: URL overflow in connection form causing repeated titles
- Fixed subtraction overflow crash in `render_splash` at very narrow widths
- Compact splash layout for terminals narrower than 37 columns (centered title only)
- Centered ruler titles in picker/setup at narrow widths (< 37)
- Top ruler URL text omitted when terminal is narrower than the URL + 11 characters
- Release script updated to link to CHANGELOG in GitHub release notes

## 2.5.5

- **JSON body editing**: multiline reformatting, auto-indent on Enter, smart bracket insertion/closing on Tab, ghost text for suggesting opening brackets
- **JSON syntax highlighting** with colors for keys, strings, numbers, booleans, brackets, and `@type`
- **`-x` / `--experimental` flag** gating body completion, syntax highlighting, Tab/Shift+Tab JSON completion, ghost text in body, auto-close brackets, and auto-indent
- Keychain caching (thread-local) to avoid repeated keychain reads
- OpenAPI spec parsing for enums, subtypes (`x-child-types`), parent types (`x-parent-type`), and array endpoint detection
- History stash: preserves unsent input when browsing history
- `ctrl+k` to clear scrollback
- Connection setup form cursor changed from reverse-video to gray-background block
- Bracket titles changed from `[Choose a connection]` / `[New connection]` to unbracketed style

## 2.5.4

- Extracted `render_input_content` into its own function (refactor for clarity)
- Fixed `prev_input_lines` not being reset after request execution, which caused render artifacts
- Fixed resize handler to use dynamic placeholder line count matching actual input height
- Added `*member` projection support in completions (e.g., `/pos-profiles/*name`)
- Added `*member` awareness to param hints (no index hint for star-prefixed segments)

## 2.5.3

- Version bump (no functional changes)

## 2.5.2

- Changed docs shortcut from `ctrl+d` to `ctrl+b`
- Removed blinking caret in connection setup form and inline input (now always-visible block cursor)
- Right-aligned `[New connection]` title in setup form (matching picker style)

## 2.5.1

First public release. Core features:

- Interactive REPL with `METHOD URI [BODY] [> OUTFILE]` input format
- Tab completion for endpoints, API operators (`~with(`, `~where(`, etc.), and schema properties
- Ghost text (inline completion preview) for URIs
- Request history with up/down arrow navigation
- Saved connections with OS keychain credential storage (`ctrl+s` / `ctrl+l`)
- 1Password integration for credential retrieval (`-1` flag)
- Connection setup flow with picker and new-connection form
- One-shot (non-interactive) mode for scripting
- Streaming response support, NDJSON mode, file output (`> file.json`)
- OpenAPI spec loading for endpoint/schema discovery
- `*member` projection completion (e.g., `/people/*name`)
- Cross-platform: macOS, Linux, Windows
