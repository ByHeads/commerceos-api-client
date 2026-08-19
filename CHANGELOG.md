# Changelog

## 3.1.0

- **Breaking: `-t` is now `--stream`, not `--token`.** Bearer tokens are long-form only: `api --token YOUR_TOKEN`. The short flag moved because streaming had none, and `-t` is the natural letter for it — it also makes bundles like `-str` (silent + stream + raw) work. An old `api -t <token> GET /people` no longer sends the token; a JWT left in the method slot is detected and reported (`-t is now --stream. Use --token <TOKEN> for a bearer token.`) rather than sent as a nonsense method. The detection is deliberately narrow — three dot-separated segments, over 40 characters, no slashes — so no real method or path can trip it, which also means an **opaque** (non-JWT) token passed to `-t` is not caught. Update scripts to `--token`.
- **Response streaming**: with `--stream` the body is written out as it arrives instead of being read into memory and pretty-printed first, which is what large exports and `~map(...)` transformations want. Off unless asked for, via `--stream` or `API_STREAMING` (`1`, `true`, `yes`, or `on`, any case); `--no-streaming` overrides both, so a single run can opt out without unsetting the variable. It's requested as a `;stream=true` media-type parameter on `Accept` and `Content-Type`, which a server that doesn't stream simply ignores. Where the bytes go: `> file` and piped stdout stream, as does stdout with `-r`; a terminal without `-r` still buffers and pretty-prints; `>> file` and `> clipboard` buffer because both need the whole body; and **any non-2xx buffers**, so an error page never streams into an outfile. Streamed stdout is byte-for-byte identical to the buffered path, trailing newline included.
- **Streaming keeps `&&`/`||` chains working** without holding the body: the leading 4KB is retained and judged exactly as a full read would be. Every falsy payload (`false`, `null`, `0`, `""`) is a handful of bytes, so anything that overflows the prefix can only be truthy — a streamed segment decides a chain identically to a buffered one, and `streaming still writes an outfile for a chain` is covered by the test suite.
- **`ctrl+t` toggles streaming in interactive mode**, with a `streaming` marker at the bottom right while it's on. It's gated on the server actually advertising the `response:streaming` feature flag in `/about` — otherwise the toggle declines with `streaming not available on this server` instead of silently doing nothing. While streaming is active, `ctrl+h` grows a section spelling out the caveats, linking to `<base-uri>/api-docs#description/streaming`.
- **Two streaming caveats worth knowing** (also in the README and `AGENTS.md`): a streamed `> file.json` is **not** pretty-printed — the file holds the server's bytes verbatim, so parse it rather than eyeballing it, or drop `--stream`; and a streaming response commits to its status line before the body is generated, so **a `200` can still carry an error inside the payload**. Check the content, not just the status.
- **A key or token without `-b` now uses the default connection's URL.** Previously `--key`/`--token` suppressed saved-connection loading entirely, leaving no base URI at all — supplying credentials shouldn't discard the saved host. Only the URL is taken; the credential from the command line wins, and an OAuth2 default connection no longer performs a token exchange whose result would be thrown away. A 401 in this case reports the error rather than reopening the connection picker, since the credential came from the command line.
- **A missing base URL says so**: `Error: no base URL specified. Use -b <url> or -c <connection>.` on the non-interactive and bulk paths, which previously fell through to a request against a bare path and asked whether COS was running on the empty string (`Is COS running on ? 🤔`). That message is now reserved for genuine connection failures, as intended since 3.0.6.
- Fixed `-s` emitting a trailing blank line. The blank after the body is the bottom margin of the status envelope — the counterpart to the one printed under `HTTP/1.1 200 OK` — but it was gated only on output being a terminal, not on silent, so `-s` dropped the header and its separator and kept the trailing gap. It goes to stderr, which is why redirecting to a file never showed it. Silent output now ends at the body's own newline, in all three shapes (streamed, raw, pretty).

## 3.0.6

- **`&&` request chaining**: `GET /people/123 && PUT /people/123 { "name": "Joe" }` runs the PUT only when the GET was truthy. Works in the TUI and in `.api` bulk files — the main use is conditioning a write on a read. Truthiness follows JavaScript: `false`, `null`, `0`, and `""` are falsy; `[]`, `{}`, and everything else on a 2xx are truthy — so `GET /people~where(givenName=X)~count && DELETE /people~where(givenName=X)` skips the delete when the count is 0. A non-2xx status is a plain "no" (404 → falsy, chain stops quietly), but auth failures (401/403), 5xx, 408/429, and timeouts are errors: they abort the whole run (exit 1 in bulk) instead of silently skipping the write. Skipped segments are reported (`↳ skipped 1 request`). `-p` preview lists every segment with its marker; `&&` inside a JSON string or body is never a separator; multi-line bodies work in any segment.
- **`||` chaining**: runs the next request only when the previous was falsy — `GET /people/123 || PUT /people/123 {…}` creates the person only if missing. Mixed chains evaluate left-to-right like a shell (a skipped segment doesn't change the outcome), so `GET /x && PUT /x {…} || POST /x {…}` is if-then-else. Errors abort exactly as with `&&` — `||` never catches a 401 or a timeout.
- **`>> file` appends** instead of overwriting, merging by content. JSON merges into a single array as a textual splice — `"a"` then `"b"` gives `["a","b"]`; arrays concatenate, single values are wrapped/pushed — without re-serializing existing bytes, so formatting like `1e2` survives. `.ndjson` targets get JSON-array payloads exploded to one compact object per line; `.csv` appends drop the payload's duplicate header row; anything non-JSON text-appends. The first write to a missing or empty file is identical to `>`. `>> clipboard` is rejected. Tab completion works after `>>`, and the recalled input line keeps the `>>` so a re-send stays an append.
- **The default request timeout is now 10 minutes** (previously reqwest's hidden 30s default applied), and hitting it says so: `Timed out after 600s — raise it with --timeout <seconds> (0 = no timeout)` instead of the misleading "Is COS running?", which now appears only for genuine connection failures. `--timeout 0` disables the timeout entirely.
- **The loading spinner reports the step that's actually running**: `Loading connection X from 1P…` → `Connecting to X…` → `Loading API spec from X…`, instead of blaming 1Password for the whole wait. 1Password CLI calls are bounded at 30s with an actionable message (`Is op signed in? Try: op signin`) and surface `op`'s own stderr on failure; previously a wedged `op` hung the client forever with its errors swallowed. Also fixed the missing-`op` check, which could never trigger.
- **Chain-aware editing**: GET→PUT body auto-promotion — plus its revert and the array `[` wrap — applies only to the last `&&`/`||` segment. Typing ` && ` after a GET no longer turns it into a PUT, and deleting a promoted trailing segment can never revert an explicitly typed method elsewhere on the line. Tab completion and ghost text work per segment (outfile completion mid-chain, URI completion in the last segment), and completing a path in an earlier segment preserves the rest of the chain. The input area keeps the full chain visible while it executes instead of flashing individual segments.
- Fixed the `@file`-error path dropping ` > outfile` from the restored input line.

## 3.0.5

- **Request bodies stay on the request line in the log**: a sent request now echoes its body after the method and URI (`PUT /people/*givenName "A new name"`), instead of dropping everything but `@file` references. The body is shown as typed — no reformatting — and fitted to the terminal width, so the line always occupies exactly one row: the method, URI, and `> outfile` are never cut, and the body absorbs the shortfall, truncated with `…` at the right edge. A multi-line body has its line breaks collapsed to single spaces (the minimum needed to keep it on one row); everything else, including odd spacing and invalid JSON, is echoed verbatim. When too few columns remain to say anything useful the body is dropped rather than stubbed. Truncation is display-only: the request itself and the recalled input line still carry the full body.
- **`> outfile` appears on the request line**, in addition to the existing confirmation line under the status.
- **Resize re-renders the log**: widening or narrowing the terminal now re-fits every request line in scrollback to the new width, revealing more of a body or re-truncating it, instead of replaying lines rendered at the old width. Retained blocks went from 5 to 10.
- **Identifier paste tolerates trailing commas**: copying one entry out of a larger JSON document leaves a `},` behind; that trailing comma no longer prevents identifier expansion.
- **Identifier paste accepts a bare `"identifiers":` property**: a selection that includes the property label the identifiers sit under (`"identifiers": { … },`) now expands too. Only that one key is repaired — an object nested under any other name is pasted verbatim, so `"address": { "street": "Main" }` is left alone.
- Fixed responses written to an outfile or the clipboard losing their status line on a resize redraw: those branches wrote only to the printed output and never to the stored history, leaving a bare request line behind. Printed and stored output are now the same text and can no longer drift apart.
- Fixed ctrl+j (erase last response body) slicing the stored block by a wrap-aware line count against logical lines, which disagreed whenever the request line wrapped. It now tracks the body directly, and a repeated press is a no-op instead of redrawing.

## 3.0.4

- **Pasted bodies are array-wrapped on array endpoints**: pasting a complete JSON body at the body position of a PUT/PATCH to an array endpoint wraps it in `[` … `]` (both brackets — unlike typing, a pasted body isn't still being composed): `GET /people ` + paste `{ "name": "Joe" }` → `PUT /people [{ "name": "Joe" }]` (the GET → PUT promotion from 3.0.3 applies first). Already-array pastes, partial JSON, and `@file` references are never wrapped.

## 3.0.3

- **`@` file references at the body position promote `GET` → `PUT` again** (reverts half of 3.0.2): `@` at the body slot always denotes a file-reference request body (`GET /people @data.json` sends the file), which implies a write — so it now promotes exactly like `{`, `[`, or `"`. The other half stands: no `[` is auto-prepended before `@` on array endpoints, since the file already provides the full body shape.
- **Auto-promotion now arms the ctrl+space cycle**: pressing ctrl+space right after a body auto-promotion cycles `PUT → PATCH` as specified, instead of resetting to GET and stashing the just-typed body.
- **Auto-revert on body clear**: deleting the body after an automatic `GET → PUT` promotion reverts the method to GET (backspace, delete, word-delete, kill-to-end, and ctrl+x clear-body all trigger it). Manually chosen methods (ctrl+space, ctrl+g, pasted request lines) are never reverted.
- **Pasting a body promotes too**: pasting a request body (JSON, `@file`, etc.) at the body position now promotes `GET → PUT`, matching the typing behavior. No `[` array auto-wrap on paste — a pasted body is already complete.
- **URI-only lines promote**: starting a body on a URI-only line (`/people {`) prepends an explicit `PUT `.
- **Identifier paste no longer destroys operator URIs**: an `=` inside an operator expression (e.g. `/people~where(name=Joe)`) is not treated as a replaceable identifier slot — the expanded identifier is appended as a new segment instead.
- **Identifier paste requires the cursor at the end of the URI token**: pasting mid-token no longer splices `key=value` into the middle of the URI.
- **ctrl+space preserves multi-line bodies**: cycling methods no longer flattens a multi-line JSON body into one line (stash/restore keeps it verbatim too), and cycling a URI-only line no longer loses the URI.
- **Pasted request lines normalize the method to uppercase** (`get /x` → `GET /x`).
- Removed the unused reverse method-cycle code path.

## 3.0.2

- **`@` file references are excluded from body auto-behaviors**: typing `@` as the first body character no longer promotes `GET` to `PUT` or prepends `[` on array endpoints, since `@` starts a file reference rather than a literal JSON body (e.g. `GET /elements/properties @file`).
- **Paste at a body position inserts verbatim**: identifier expansion on paste now requires the cursor to be attached to the URI token (the current whitespace-delimited token contains `/`), not just any `/` earlier in the line. Pasting an object after `PUT /people ` now inserts it as the request body instead of mangling the URI.

## 3.0.1

- **`sleep` and `url` gate directives in `.api` batch files**: `sleep N` pauses between requests (accepts `5`, `2s`, `500ms`, fractional). `url has <value>` (substring, `*value*`) and `url is <value>` (literal) declare allowed target environments — collected from anywhere in the file (and includes) and validated once, before any request, against the configured base URI. Multiple conditions form an allowlist (proceed if at least one matches); a non-matching base aborts the whole batch before sending, so test data can't reach production. `sleep` lines appear in the `-p` preview but don't count toward the request total.

## 3.0.0

New major version 🥳

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
