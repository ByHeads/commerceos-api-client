# CommerceOS API Client

`api` is a command-line client for the CommerceOS API, written in Rust. It has an
interactive mode with tab completion, a one-shot mode for scripting, `.api` batch
files, saved connections in the OS keychain, and binaries for macOS, Linux, and Windows.

API documentation: https://dev.heads.com/api-docs — companion reference repo:
https://github.com/ByHeads/commerceos-api-reference

## Install

Every CommerceOS instance serves an install script; `dev.heads.com` works for everyone:

```sh
curl -fsSL https://my-tenant.app.heads.com/api-client-install.sh | bash
# or
curl -fsSL https://dev.heads.com/api-client-install.sh | bash
```

Or download a binary from the [latest release](https://github.com/byheads/commerceos-api-client/releases/latest):

| Platform | Binary |
|---|---|
| macOS (Apple Silicon) | `api-macos-arm64` |
| macOS (Intel) | `api-macos-x86_64` |
| Linux (x86_64) | `api-linux-x86_64` |
| Linux (ARM64) | `api-linux-arm64` |
| Windows (x86_64) | `api-windows-x86_64.exe` |

```sh
chmod +x api-macos-arm64
sudo mv api-macos-arm64 /usr/local/bin/api
```

On Windows, rename the file to `api.exe` and put it on your PATH.

To build from source you need the [Rust toolchain](https://rustup.rs/); `cargo build --release` produces `target/release/api`.

## Quick start

```sh
api -b https://your-instance.example.com -k YOUR_API_KEY   # interactive, explicit credentials
api                                                        # interactive, saved connection
api GET /people                                            # one-shot
```

## One-shot requests

```
api [METHOD] URI [BODY] [options]
```

```sh
api /people                                   # GET is the default
api GET /people~take(5)
api PUT /people/123 '{"name":"Updated"}'
api POST /people '[{"name":"Jane"}]'
api PUT /people/123 @body.json                # body from a file
echo '{"name":"X"}' | api PUT /people/123     # body from stdin
api PATCH /people/123                         # terminal stdin: prompts for the body, ctrl+d to send
```

The URI may omit its leading slash and the `/api/v1` prefix, so a path copied from a browser or a log works as-is.

### Bodies

- `@file` reads the body from a file. Content type follows the extension (`.json`, `.csv`, `.ndjson`).
- `@dir/*.json` combines matching files into one JSON array; `@dir/*.ndjson` concatenates them.
- `@file~map(typeName)` sends the type as an `X-Request-Map` header for streamed transformations:

```sh
api PUT /sync-webhooks @data.csv~map(com.heads.csv-product)
```

### Output to file or clipboard

The client parses `> path` off the end of the request line itself. In a shell that means
the redirect must be **inside the quoted URI argument**, otherwise the shell takes it:

```sh
api GET "/products > products.json"        # handled by api: Accept header, size marker, ~/ expansion
api GET /products > products.json          # handled by the shell: plain stdout capture, no Accept override
```

| Target | Effect |
|---|---|
| `> file` | write the body to `file` (`~/` is expanded) |
| `>> file` | append: JSON merges into one array, NDJSON gets one object per line, CSV drops the duplicate header, other text appends |
| `> clipboard` | copy the body to the system clipboard (case-insensitive) |

The extension of the target sets the `Accept` header: `.csv` → `text/csv`,
`.ndjson` → `application/x-ndjson`, `.sql` → `application/sql`, anything else JSON.
So `GET "/products~map(com.heads.sql-product) > products.sql"` asks for SQL.

After the status line the client prints the target and the size written, e.g.
`> products.json (47.1 KB)` or `>> products.json (+1.2 KB)`.

### Chaining

In interactive mode and in batch files, `&&` runs the next request only if the previous one
was truthy and `||` only if it was falsy. Truthy means a 2xx whose body is not `false`,
`null`, `0`, or `""`. A 404 is falsy; 401/403, 5xx, and timeouts abort the whole line.
Chains evaluate left to right like a shell, and separators inside JSON are ignored.

```
GET /people/123 || PUT /people/123 { "name": "Joe" }                       # create if missing
GET /people~where(givenName=X)~count && DELETE /people~where(givenName=X)  # delete only if any
```

One-shot arguments are not chained; pipe the line into `api -a` instead.

### Streaming

Off by default. With `--stream` (or `API_STREAMING=1`; `--no-streaming` overrides both)
the body is written as it arrives, which is what large exports and `~map(...)` want.

| Destination | Streamed? |
|---|---|
| `> file`, piped stdout, stdout with `-r` | yes |
| terminal stdout without `-r` | no, buffered and pretty-printed |
| `>> file`, `> clipboard`, any non-2xx | no, both need the whole body |

A streamed `> file.json` holds the server's bytes verbatim, not pretty-printed. A streaming
response commits to its status before the body exists, so a `200` can still carry an error in
the payload.

## Batch files

`api -a file.api` runs the requests in a file top to bottom; `-a -` or a pipe reads stdin.
`-s` makes it a compact log of one status line per request; `-p` previews the requests and
asks before sending.

```sh
api -sa seed.api
api -spa seed.api        # preview first
```

```
# seed.api
url has localhost:5000                        # refuse to run against anything else
assert GET /companies/com.heads.seedID=ours   # stop unless this exists

PUT /people/com.heads.seedID=joe { "name": "Joe" }
PUT /people [
  { "identifiers": { "com.heads.seedID": "ann" }, "name": "Ann" }
]
PUT /people @people/*.json

POST /imports { "source": "erp" }
sleep 20 while GET /imports~where(state=running)~count

shared/*.api                                  # include other files
GET /people~take(5) > /tmp/people.json
```

| Line | Meaning |
|---|---|
| `METHOD URI [BODY] [> file]` | a request; multi-line bodies continue until brackets balance |
| `# …` | comment; `//`, `#`, and `/* */` also work inside JSON bodies |
| `path/to/file.api` | include, relative to the including file; globs allowed |
| `sleep N` | pause (`2`, `500ms`, `1.5s`) |
| `sleep [N] while [not] <request>` | poll every N seconds (default 5) until the answer flips |
| `assert [not] <request>` | exit 1 unless the answer is truthy (falsy with `not`) |
| `url has <text>` / `url is <url>` | allowlist of base URLs; no match aborts before anything runs |

`AGENTS.md` is the full reference for the file format.

## Interactive mode

Start `api` without a URI. The prompt takes the same `METHOD URI [BODY] [> file]` line as
one-shot mode, with tab completion for endpoints, operators, properties, and file paths.

- **Typing a body promotes GET to PUT**; on an array endpoint the opening `[` is added for you.
- **`ctrl+space` cycles** PUT → PATCH → POST → GET. Switching to GET stashes the body; switching back restores it.
- **Enter on a body method without a body** opens a multi-line editor: `ctrl+d` sends, `esc` cancels.

### Copy and paste identifiers

Paste JSON onto the URI and the client turns it into an index segment. Any of these shapes work:

```json
{ "identifiers": { "com.heads.seedID": "joe", "com.erp.id": "42" }, "name": "Joe" }
"identifiers": { "com.heads.seedID": "joe" },
{ "com.heads.seedID": "joe" }
[{ "identifiers": { "com.heads.seedID": "joe" } }]
```

Pasting the first one onto `GET /people` gives `GET /people/com.heads.seedID=joe`. Paste it
again within 10 seconds to cycle to `com.erp.id=42`. An existing `key=value` segment is
replaced, so repeated pastes never pile up. Trailing commas from a copied fragment are fine,
and `@type`/`@id` are never used as identifiers.

Pasting a whole request line (`GET /people/...`) replaces the input. Pasting a JSON body after
the URI inserts it verbatim and promotes the method. `ctrl+y` copies the last request as a
`curl` command.

### Key bindings (`ctrl+h`)

| Key | Action |
|---|---|
| `enter` | Send |
| `opt+enter` / `ctrl+n` | New line in body |
| `tab` | Complete |
| `up` / `down` | History |
| `ctrl+space` | Cycle method; resets to GET if the last cycle was over 5s ago |
| `ctrl+g` | GET the current URI |
| `ctrl+x` | Clear body |
| `ctrl+f` | Reset to `GET /` |
| `ctrl+u` | Clear the input line |
| `ctrl+k` | Kill to end of line |
| `ctrl+a` / `ctrl+e` | Start / end of line |
| `alt+←` / `alt+→` | Move by word (also `ctrl+←/→`, `alt+b/f`) |
| `alt+backspace` / `ctrl+w` | Delete word backward |
| `alt+d` | Delete word forward |
| `ctrl+y` | Copy last request as curl |
| `ctrl+j` | Erase last response body |
| `ctrl+l` | Clear output |
| `ctrl+o` | Open the last saved file |
| `ctrl+b` | Open API docs in the browser |
| `ctrl+t` | Toggle streaming |
| `ctrl+s` | Save connection |
| `ctrl+q` | Switch connection |
| `ctrl+c` | Quit (press twice) |

## Connections and authentication

- `-b URL -k KEY` sends the key as Basic auth. `--token TOKEN` sends a Bearer token (long form only; `-t` is `--stream`).
- With neither, the client prompts for credentials; `ctrl+s` saves the connection, `ctrl+q` switches.
- `-c alias` (or `-c url`) picks a saved connection: `api -c staging GET /people`.
- A key or token without `-b` uses the default saved connection's URL.
- Credentials live in the OS keychain. `--no-keychain` uses a plaintext JSON file instead
  (`API_CREDENTIALS_FILE`, else `./.api-credentials.json`), for CI and agents. See `AGENTS.md`.

## Options

```
Usage: api [OPTIONS] [METHOD] [URI] [BODY]

  -b, --base-uri <URI>            Base URI
  -k, --key <KEY>                 API key (Basic auth)
      --token <TOKEN>             Bearer token
  -c, --connection <ALIAS|URL>    Use a saved connection
      --no-keychain               Read/write connections from a plaintext JSON file
      --me                        Use /api/me/v1 instead of /api/v1
  -a, --all [FILE]                Run requests from FILE (stdin if omitted or `-`)
  -s, --silent                    No status output; with -a, one status line per request
  -p, --preview                   Show the request(s) and confirm before sending
  -r, --raw                       No pretty-printing
  -i, --include-nulls             Include null values in the response
      --ndjson                    NDJSON request and response
  -t, --stream                    Stream the response body
      --no-streaming              Force streaming off
      --timeout <SECONDS>         Request timeout, 0 disables (default 600)
  -x, --experimental              Experimental body completion and highlighting
  -v, --version
  -h, --help
```

| Variable | Effect |
|---|---|
| `API_STREAMING` | `1`/`true`/`yes`/`on` turns streaming on |
| `API_CREDENTIALS_FILE` | Credentials file path, used with `--no-keychain` |

## Tests

```sh
cargo test --bin api                                     # unit tests
API_TEST_BASE_URI=http://localhost:5000 API_TEST_KEY=… cargo test --test cli   # end-to-end, needs a local COS
```

The end-to-end tests go through `/echo-all`, so nothing is persisted. Without the two
variables they use the default saved connection and prompt for keychain access.

## License

[MIT](LICENSE)
