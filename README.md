# CommerceOS API Client

An interactive command-line client for the CommerceOS API. Supports interactive REPL mode with tab completion, one-shot commands for scripting, saved connections with OS keychain integration, and cross-platform binaries for macOS, Linux, and Windows.

You can find more information about the CommerceOS API in the global API documentation

https://dev.heads.com/api-docs

or in the companion reference repo:

https://github.com/ByHeads/commerceos-api-reference

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

Press `ctrl+h` for the full list of key bindings:

| Key | Action |
|---|---|
| `enter` | Send request |
| `opt+enter` | New line (multiline body) \[or `ctrl+n`\] |
| `tab` | Auto-complete endpoints, operators, and properties |
| `up` / `down` | Browse request history |
| `ctrl+g` | Quick GET current URI |
| `ctrl+t` | Cycle method: GET, POST, PATCH, PUT |
| `ctrl+x` | Clear body (keep method and URI) |
| `ctrl+f` | Clear all (reset to GET /) |
| `ctrl+y` | Copy last request as curl command |
| `ctrl+s` | Save the current connection |
| `ctrl+l` | Switch connection |
| `ctrl+d` | Open API docs in browser |
| `ctrl+o` | Open last saved file |
| `ctrl+c` | Quit (double-press) |

### Saved connections

Save a connection with `ctrl+s` during interactive mode. Switch between saved connections with `ctrl+l`, or use the `-c` flag:

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
  -s, --silent                    Do not print status info
  -r, --raw                       Output raw JSON (no pretty printing)
  -i, --include-nulls             Include null values in response
      --me                        Use /api/me/v1 instead of /api/v1
      --ndjson                    Use NDJSON for request and response
  -v, --version                   Print version
  -h, --help                      Print help
```

## License

[MIT](LICENSE)
