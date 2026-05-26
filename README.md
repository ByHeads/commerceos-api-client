# CommerceOS API Client

An interactive command-line client for the CommerceOS API built on Rust. Supports interactive REPL mode with tab completion, one-shot commands for scripting, batch request files, saved connections with OS keychain integration, and cross-platform binaries for macOS, Linux, and Windows.

You can find more information about the CommerceOS API in the global API documentation:

https://dev.heads.com/api-docs

or in the companion reference repo:

https://github.com/ByHeads/commerceos-api-reference

## Quick-install

You can install the latest version of the API client using the `api-client-install.sh` bundled with each instance of COS. Use `dev.heads.com` for global access.

```
curl -fsSL https://my-tenant.app.heads.com/api-client-install.sh | bash
# or
curl -fsSL https://dev.heads.com/api-client-install.sh | bash
```

## Install

Download the binary for your platform from the [latest release](https://github.com/byheads/commerceos-api-client/releases/latest):

| Platform | Binary |
|---|---|
| macOS (Apple Silicon) | `api-macos-arm64` |
| macOS (Intel) | `api-macos-x86_64` |
| Linux (x86_64) | `api-linux-x86_64` |
| Linux (ARM64) | `api-linux-arm64` |
| Windows (x86_64) | `api-windows-x86_64.exe` |

On macOS and Linux, make it executable and move it to your PATH:

```sh
chmod +x api-macos-arm64
sudo mv api-macos-arm64 /usr/local/bin/api
```

On Windows, rename `api-windows-x86_64.exe` to `api.exe` and add its location to your PATH.

### Build from source

Requires the [Rust toolchain](https://rustup.rs/).

```sh
cargo build --release
# Binary at: target/release/api
```

## Usage

### Quick start

```sh
# Start interactive mode, connecting to a CommerceOS instance
api -b https://your-instance.example.com -k YOUR_API_KEY

# Or just start interactively and set up a connection
api
```

### One-shot commands

```sh
api GET /users -b https://your-instance.example.com -k YOUR_API_KEY
api POST /people '[{"name":"Jane"}]'
api /users                    # GET is the default method
api PUT /people/123 '{"name":"Updated"}'
```

### Body input

A request body can be supplied four ways:

```sh
# Inline argument
api PUT /people/123 '{"name":"Updated"}'

# From a file (the `@` prefix)
api PUT /people/123 @body.json

# From stdin (when the body argument is omitted)
echo '{"name":"Updated"}' | api PUT /people/123

# Interactive prompt (terminal-attached stdin, no inline body)
api PATCH /people/123          # prompts: "Reading body from stdin (ctrl+d to finish):"
```

The `@file` form auto-detects content type from the extension (`.csv`, `.ndjson`).
Append `~map(typeName)` to a file body to send the type name as an `X-Request-Map`
header (used for streamed transformations):

```sh
api PUT /sync-webhooks @data.csv~map(com.heads.csv-product)
```

### Output to file

Append `> path` to write the response body to a file:

```sh
api GET /products > products.json
api GET /products~map(com.heads.sql-product) > products.sql
```

The output extension also drives the `Accept` header (`.csv` → `text/csv`,
`.ndjson` → `application/x-ndjson`, `.sql` → `application/sql`).

### Bulk mode

Run a sequence of requests from a text file with `-a`:

```sh
api -a requests.txt
cat requests.txt | api -a       # stdin
api -a -                        # explicit stdin
```

Each non-empty line is a full request, parsed exactly like interactive input.
Lines starting with `#` are comments; blank lines are skipped.

```
# requests.txt
GET /people
PUT /people/com.heads.seedID=joe {"name":"Joe"} > ~/Downloads/joe.json
PATCH /sync-webhooks @webhooks/foo.json
```

### Silent bulk mode

Combine `-s` with `-a` for compact progress-style output: each request line is
echoed, followed by an indented status line. Response bodies are suppressed.

```sh
api -sa requests.txt
```

```
PUT /people [{"name": "Joe"}]
└─HTTP/1.1 200 OK 0.08s
GET /people
└─HTTP/1.1 200 OK 0.07s
```

Useful for running large batches where you only care about status codes.

### Interactive mode

Start `api` without a URI to enter interactive mode. The prompt accepts input in the format:

```
METHOD URI [BODY] [> OUTFILE]
```

Examples at the prompt:

```
GET /users
POST /people [{"name":"Jane"}]
GET /orders > orders.json
PATCH /people/123 {"name":"Updated"}
```

For `PATCH`, `POST`, and `PUT` without a body, pressing `enter` opens an inline
body editor: type the body (multiline supported), `ctrl+d` to send, `esc` to
cancel.

Switching to GET via `ctrl+space` hides the current body from the input and
stashes it. Switching back to a body method restores it. Sending a request
clears the stash.

Press `ctrl+h` for the full list of key bindings:

| Key | Action |
|---|---|
| `enter` | Send request |
| `opt+enter` | New line (multiline body) \[or `ctrl+n`\] |
| `tab` | Auto-complete endpoints, operators, properties |
| `up` / `down` | Browse request history |
| `ctrl+space` | Cycle method (GET → PUT → PATCH → POST). Resets to GET if >5s since last cycle. |
| `ctrl+g` | Quick GET on current URI |
| `ctrl+x` | Clear body (keep method and URI) |
| `ctrl+f` | Clear all (reset to `GET /`) |
| `ctrl+y` | Copy last request as curl command |
| `ctrl+w` | Erase last request+response from output |
| `ctrl+j` | Erase last response body (keep request+status headers) |
| `ctrl+l` | Erase all output back to splash |
| `ctrl+s` | Save the current connection |
| `ctrl+q` | Switch connection |
| `ctrl+b` | Open API docs in browser |
| `ctrl+o` | Open last saved file |
| `ctrl+h` | Toggle help |
| `ctrl+c` | Quit (double-press) |

### Saved connections

Save a connection with `ctrl+s` during interactive mode. Switch between saved connections with `ctrl+q`, or use the `-c` flag:

```sh
api -c my-connection
api -c my-connection GET /users
```

Credentials are stored securely in your OS keychain (macOS Keychain, Windows Credential Manager, or Linux file-based keyring).

### Authentication

- **API key**: `api -k YOUR_API_KEY` (sent as Basic auth)
- **Bearer token**: `api -t YOUR_TOKEN`
- **Interactive**: when no key or token is provided, you'll be prompted during connection setup

### Options

```
Usage: api [method] [uri [body]] [options]

Options:
  -b, --base-uri <URI>            Base URI for the API
  -k, --key <KEY>                 API key (Basic auth)
  -t, --token <TOKEN>             Bearer token
  -c, --connection <ALIAS_OR_URL> Use a saved connection
  -a, --all [FILE]                Bulk mode: run requests from FILE (or stdin if omitted/`-`)
  -s, --silent                    Do not print status info
  -r, --raw                       Output raw JSON (no pretty printing)
  -i, --include-nulls             Include null values in response
  -x, --experimental              Enable experimental body completion / syntax highlighting
      --me                        Use /api/me/v1 instead of /api/v1
      --ndjson                    Use NDJSON for request and response
  -v, --version                   Print version
  -h, --help                      Print help
```

## Tests

Integration tests in `tests/cli.rs` exercise the binary against a running local
CommerceOS instance via the `/echo-all` endpoint (which round-trips request
bodies, so nothing is persisted).

```sh
cargo test --test cli
```

By default the tests use the saved default connection, which means every test
invocation prompts for keychain access. To skip the keychain entirely, pass
credentials via environment variables:

```sh
API_TEST_BASE_URI=http://localhost:5000 API_TEST_KEY=your-local-key cargo test --test cli
```

When both env vars are set, the test harness adds `-b` and `-k` flags to every
`api` invocation so no keychain lookup happens.

## License

[MIT](LICENSE)

