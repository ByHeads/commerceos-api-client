# CommerceOS API Client

`api` is a command-line client for the CommerceOS API, written in Rust. It has an
interactive mode with tab completion, a one-shot mode for scripting, `.api` batch
files, saved connections in the OS keychain, and binaries for macOS, Linux, and Windows.

API documentation: https://dev.heads.com/api-docs — companion reference repo:
https://github.com/ByHeads/commerceos-api-reference

## Install

Every CommerceOS instance serves an install script that works for mac or linux.

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

The arguments are read as one `.api` line, so everything a batch file accepts works here too:

```sh
api "GET /people/123 || PUT /people/123 {\"name\":\"Joe\"}"   # chain, quoted whole
api GET /people/123 "||" PUT /people/123 '{"name":"Joe"}'    # or with the separator quoted
api assert /companies/com.heads.seedID=ours                  # exit 1 unless truthy
api sleep 5 while not /imports~count                         # poll until it flips
api seed.api                                                 # run a file, same as -a seed.api
```

`--export <external-id>` turns a response into seed data that can be `PUT` back where it was read or
to another environment: database keys are dropped, a record with no other identifier keeps its key
under the name you give and as `key?` (a key that may name nothing), and masked values become `null`
(it says where). The name is a namespaced key such as `com.heads.seedID`. At the prompt,
`ctrl+r` turns it on and off and asks for the name the first time. In a `.api` file, a line
`export com.heads.seedID` turns it on for the requests below it in that file, and `export off` ends it.

```sh
api --export com.heads.seedID GET /users > users.json
```

A first word that is neither a method nor a path is an error (`not a request or .api file`),
not a request to a nonsense path. Bodies are read as in a batch file, comments stripped and
raw newlines inside strings escaped, and a `> file` may sit in any argument. A body piped
on stdin is sent as it is: no comments stripped, no newlines escaped.

### Bodies

- `@file` reads the body from a file. Content type follows the extension (`.json`, `.csv`, `.ndjson`), read in any case.
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
| `>> file` | append: JSON merges into one array, NDJSON gets one object per line, CSV drops the duplicate header, other text appends. A non-2xx body is not appended: it is shown, and the file is left as it was |
| `> clipboard` | copy the body to the system clipboard (case-insensitive) |

The extension of the target sets the `Accept` header: `.csv` → `text/csv`,
`.ndjson` → `application/x-ndjson`, `.sql` → `application/sql`, anything else JSON.
So `GET "/products~map(com.heads.sql-product) > products.sql"` asks for SQL.

After the status line the client prints the target and the size written, e.g.
`> products.json (47.1 KB)` or `>> products.json (+1.2 KB)`.

The `>` takes a blank in front of it (a space or a tab) and a path behind it; a `>` with
no path is an error. Numbers in a body written to a file keep the digits the server sent.

### Chaining

In interactive mode and in batch files, `&&` runs the next request only if the previous one
was truthy and `||` only if it was falsy. Truthy means a 2xx whose body is not `false`,
`null`, `0`, or `""`. A 404 is falsy; 401/403, 408/429, 5xx, and timeouts abort the whole line.
Chains evaluate left to right like a shell, and separators inside JSON are ignored.

```
GET /people/123 || PUT /people/123 { "name": "Joe" }                       # create if missing
GET /people~where(givenName=X)~count && DELETE /people~where(givenName=X)  # delete only if any
```

One-shot arguments chain too, as long as the shell doesn't eat the separator: quote the whole
line or the `&&` itself (see [One-shot requests](#one-shot-requests)).

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

### Progress

A request that takes longer than half a second shows a progress line until it is done:

```
⠋ waiting for response... 4s
⠙ 200 OK, received 12.4 MB
⠹ 200 OK, received 12.4 MB of 47.1 MB (26%)
```

The percentage needs a `Content-Length`, which CommerceOS itself does not send, so against
it the line counts bytes. Without `--stream` the server prepares the whole body before it
answers and most of the time is spent waiting; with `--stream` the status arrives early and
the count runs for as long as the body is being produced.

In interactive mode the line sits in the hint area, and `esc` or `ctrl+c` aborts at any point.
With streaming on, the `streaming` label stays at the right of that line and pulses while
bytes are arriving; it sits still while waiting and when the transfer stalls.
One-shot and batch runs draw it on stderr and erase it again, leaving the log as it was. It is
only drawn when stderr is a terminal, never with `-s`, and not while a streamed body is being
printed to the terminal.

## Batch files

`api -a file.api` runs the requests in a file top to bottom; `-a -` or a pipe reads stdin.
`-s` makes it a compact log of one status line per request; `-p` previews the requests and
asks before sending. It is not a dry run: Enter sends them. With no terminal the answer is
read from stdin (`echo n | api -spa seed.api` prints the program and sends nothing), and a
question nobody answered sends nothing and exits 1.

```sh
api -sa seed.api
api -spa seed.api        # preview first
api -spma seed.api       # say what the file is, then preview
api --describe seed.api  # its describe block as JSON, nothing sent
api --assert seed.api    # every PUT /assert body it sends, as one JSON array, nothing sent
api --imports seed.api   # every import it reads and the directory it resolved to, nothing sent
```

```
# seed.api
{                                             # describe block: what the file is, never sent
  "title": { "en-US": "People seed" },
  "description": { "en-US": "Seeds Joe and Ann and waits for the ERP import." },
  "docsLink": "https://link-to-docs.com"
}

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
| `{ "title": {…}, "description": {…}, "docsLink": "…" }` | describe block: one per file, before its first request, import or include; texts are keyed by locale |
| `path/to/file.api` | include, relative to the including file; globs allowed |
| `import git <alias> {"url":…,"ref":…}` | fetch a git repository (tag, branch or SHA) and include from it as `alias/file.api`; the JSON may be `@file.json` |
| `import dir <alias> {"path":…}` | the same for a local directory, used where it is |
| `import archive <alias> {"url":…,"sha256":…}` | the same for a downloaded `.tar.gz`, `.tar` or `.zip`; `sha256` pins it, `token_env` names a bearer-token variable |
| `sleep N` | pause (`2`, `500ms`, `1.5s`) |
| `sleep [N] while [not] <request>` | poll every N seconds (default 5) until the answer flips |
| `assert [not] <request>` | exit 1 unless the answer is truthy (falsy with `not`) |
| `confirm [message]` | pause and ask for confirmation before continuing |
| `export <external-id>` / `export off` | export mode for the requests below it in this file |
| `url has <text>` / `url is <url>` | allowlist of base URLs; no match aborts before anything runs |

`AGENTS.md` is the full reference for the file format.

## Interactive mode

Start `api` without a URI. The prompt takes the same `METHOD URI [BODY] [> file]` line as
one-shot mode, with tab completion for endpoints, operators, properties, and file paths.

- **Typing a body promotes GET to PUT**; on an array endpoint the opening `[` is added for you.
- **`ctrl+space` cycles** PUT → PATCH → POST → GET. Switching to GET stashes the body; switching back restores it.
- **Enter on a body method without a body** opens a multi-line editor: `ctrl+d` sends, `esc` cancels. A `> file` on the line is kept and applied when the body is sent.
- **Batch-file syntax works at the prompt too.** A line that isn't a request is read as `.api`
  syntax: `confirm Ready?` asks in the hint line, `sleep 5 while not /imports~count` polls,
  `assert /companies/x` checks (logged as `assert GET /companies/x`, with
  `↳ assertion failed (404 Not Found)` under the status line when it fails), and `seed.api`
  runs the file, includes and all. `import git cl {…}` keeps its alias for the session, so
  `cl/sv.api` runs on a later line and `tab` completes inside the repository; run the `import`
  line again to pick up a branch that has moved. A pasted block
  of several lines runs line by line. Pasting a request line, a directive or a block replaces
  whatever is on the line, so a paste over the starting `GET /` is just the paste. `esc` stops a wait; a failed assert or a declined confirm
  stops the rest of the line. A mistyped request says `not a request or .api file` instead of
  re-sending the last one.
- **`tab` completes the file to run.** On a line that is a path (`se`, `shared/`, `~/seeds/`,
  `../`) it offers directories and `.api` files. A path starting with `/` completes as a URI,
  so reach an absolute file through `~/` or a relative path.

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
replaced, so repeated pastes never pile up. A value stays one segment: a blank, `/`, `?`, `#`
and `%` in it are percent-encoded (`"A B"` becomes `com.x.name=A%20B`). Trailing commas from a copied fragment are fine,
and `@type`/`@id` are never used as identifiers.

Pasting a whole request line (`GET /people/...`) replaces the input. Pasting a JSON body after
the URI inserts it verbatim and promotes the method. `ctrl+y` copies the last request as a
`curl` command.

### Key bindings (`ctrl+h`)

`ctrl+h` opens and closes this list at the prompt. On a terminal too short for
all of it, the last row says how many rows are missing. A terminal set to send
`ctrl+h` for Backspace (the byte `0x08`) opens it with Backspace too, since the
two can't be told apart: set the terminal to send DEL (`0x7f`) for Backspace.

| Key | Action |
|---|---|
| `enter` | Send |
| `opt+enter` / `ctrl+n` | New line in body |
| `tab` | Complete |
| `up` / `down` | History |
| `ctrl+space` | Cycle method; resets to GET if the last cycle was over 5s ago |
| `ctrl+g` | GET the URI on the line, whatever its method, body or outfile; the line stays as typed |
| `ctrl+x` | Clear body |
| `ctrl+f` | Reset to `GET /` |
| `ctrl+u` | Clear the input line |
| `ctrl+k` | Kill to end of line |
| `ctrl+a` / `ctrl+e` | Start / end of line |
| `alt+←` / `alt+→` | Move by word (also `ctrl+←/→`, `alt+b/f`) |
| `alt+backspace` / `ctrl+w` | Delete word backward |
| `alt+d` | Delete word forward |
| `ctrl+y` | Copy the last request sent as a curl command. It holds the credential, and every value is quoted for the shell |
| `ctrl+j` | Erase last response body |
| `ctrl+l` | Clear output |
| `ctrl+o` | Open the last saved file |
| `ctrl+b` | Open API docs in the browser |
| `ctrl+t` | Toggle streaming |
| `ctrl+r` | Toggle export mode; asks for the external identifier name the first time |
| `ctrl+s` | Save connection; under a new name it is renamed, and stays the default if it was |
| `ctrl+q` | Switch connection; the flags the session was started with (`-i`, `-f`, `--timeout`, `--export`…) stay |
| `ctrl+c` | Quit (press twice) |

## Connections and authentication

- `-b URL -k KEY` sends the key as Basic auth. `--token TOKEN` sends a Bearer token (long form only; `-t` is `--stream`).
- With neither, the client prompts for credentials; `ctrl+s` saves the connection, `ctrl+q` switches.
- `-c alias` (or `-c url`) picks a saved connection: `api -c staging GET /people`.
  A URL that several saved connections share is an error that lists their aliases.
- A key or token without `-b` uses the default saved connection's URL.
- `-k`, `--token` and `-b` win over what a saved connection has stored, with `-c` too:
  `api -c staging -k OTHERKEY GET /people`.
- An OAuth2 connection renews its token when it runs out, at the prompt and in a batch.
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
  -f, --fail-fast                 Stop at the first response of 400 or above: print its body, exit 1
  -m, --describe-first            With -a: print the file's describe block before running it
      --describe <FILE>           Print the describe block of FILE as JSON; sends nothing
      --assert <FILE>             Print every `PUT /assert` body FILE sends as one JSON array; sends nothing
      --imports <FILE>            Print every import FILE reads and where it resolved to, as one JSON array; sends nothing
      --export <EXTERNAL_ID>      Rewrite responses as seed data: keys dropped, a lone one kept as `key?` and EXTERNAL_ID
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
perl -e 'alarm 900; exec @ARGV' cargo test --test parity # what is sent, printed and written, from a file, arguments and the prompt
cargo test --test imports                                # import git/dir/archive
cargo test --test cli -- --skip clipboard                # end-to-end, most of it against a local COS
cargo test --test cli -- clipboard --test-threads=1      # the tests that copy to the clipboard
```

What each suite needs:

| Suite | Needs |
|---|---|
| `--bin api` | This machine only, and `git` on the `PATH`. |
| `--test parity` | This machine only, and `git`. It drives the binary, prompt included (through a pseudo-terminal, unix only), against a recording server of its own on `127.0.0.1`. Run it under a time limit: a prompt test that hangs takes the suite with it. |
| `--test imports` | `git`. Five of its tests fetch this repository from github.com and need the network; `API_TEST_OFFLINE=1` skips them. One of the five goes over ssh and also needs an ssh key GitHub accepts; without one it skips itself. A skipped test prints a line starting with `SKIPPED` on stderr (`-- --nocapture` shows it). |
| `--test cli` | A local COS with the `/assert` endpoint, and credentials for it, for about fifty of its tests: they fail with instructions when either is missing. The rest start a small server of their own. The four tests named `…clipboard…` copy to the system clipboard, overwriting what it held, and are run on their own, one at a time. |

No test sends anything to a host other than this machine, apart from the five that read
from github.com.

The tests against the local COS go through `/echo-all`, `/about` and `/assert`, so nothing
is persisted. They always run with `--no-keychain`, on the credentials file
`.api-credentials.json` in the repository root (gitignored; copy
`.api-credentials-sample.json` and put in the key of the local COS). `API_TEST_BASE_URI`
and `API_TEST_KEY`, when both are set, are passed as `-b` and `-k` and win over the file.
Without the file and without the variables the tests that need the server fail: the
keychain is never asked.

## License

[MIT](LICENSE)
