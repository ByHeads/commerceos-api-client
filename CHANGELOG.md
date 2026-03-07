# Changelog

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
