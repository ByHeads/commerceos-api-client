# Writing `.api` batch files

This is a guide for AI agents (and humans) writing `.api` files for the CommerceOS
API client. A `.api` file is a sequence of HTTP requests, one per logical entry,
that gets executed in order by `api -a <file>`.

## 1. Quick anatomy

```
METHOD URI [BODY] [> OUTFILE]
```

- `METHOD` is one of `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`.
- If the first token starts with `/`, `GET` is implied — `/people` is the same as `GET /people`.
- `URI` may be written **with or without its leading slash**, and with or without the `/api/v1` prefix — `GET api/v1/people`, `GET /api/v1/people`, `GET v1/people`, and `GET /people` all request the same thing. That makes a path copied out of a browser URL or a log usable as-is. In a `.api` file this needs an explicit method, because a bare line that doesn't start with `/` is an [include](#6-includes).
- A method needs a URI behind it. `DELETE` alone is an error (`DELETE needs a URI`), in a file, as arguments and at the prompt: it is not a request to `/`.
- `BODY` and `OUTFILE` are optional. If both are present, `BODY` comes first; the `> path` suffix is parsed off the end. A ` >` inside a JSON string, inside brackets or inside the parentheses of a URI operator is not an outfile: `PUT /x {"a":"b > c"}` and `GET /x~where(name="a > b")` are sent as written.
- The `>` needs a blank in front of it, a space or a tab, and a path behind it. A `>` or `>>` that names no file (`GET /x >`) stops the batch before anything is sent: ``a `>` or `>>` needs a path to write to``. That holds for a plain line, a chain segment, an `assert` and a `sleep while`.
- A body starts on the request line. A `{` that starts a line of its own is a [describe block](#describe-block), which belongs at the top of the file.
- A line may hold several requests joined by `&&` / `||`, see [chaining](#5-chaining).

```
# Smallest possible file
GET /about
```

## 2. Comments and blank lines

### Top-level (between requests)

```
# Lines starting with # are comments.
# Blank lines between requests are ignored.

GET /people~take(5)
```

### Behind a line

A ` # …` behind a request, a directive or an include is a comment to the end
of the line. The `#` needs a blank in front of it and counts only outside a
JSON string, brackets and the parentheses of a URI operator, like ` >`:

```
GET /people > /tmp/people.json   # a comment
shared/checks.api                # a comment
sleep 2                          # a comment
GET /people#x                    # the `#x` is no comment: no blank in front
PUT /x {"note":"a # b"}          # the string is sent whole
```

The `#x` of `GET /people#x` stays in the URI, where it is a fragment, and a
fragment is not sent to a server: what arrives is `GET /people`.

A `confirm` line has none: all of it is the question.

### Inside JSON bodies

Three comment styles are supported inside `{}` / `[]` bodies and stripped before
the request is sent. They are string-aware — markers inside `"..."` are kept verbatim.

```
PUT /things {
  // JS-style line comment
  "name": "Alice",
  # shell-style line comment
  "url": "https://heads.com",   // tail comment
  /* block comment
     spanning lines */
  "keep": "// not a comment, inside string"
}
```

Commented-out brackets are correctly ignored by the body parser, so this works:

```
PUT /things {
  "a": 1
  // }       ← does NOT end the body
}
```

## 3. Bodies

### Inline JSON

```
PUT /people/com.mi6.id=007 { "name": "James Bond" }
POST /people [{ "name": "Alec Trevelyan" }]
PATCH /people/com.mi6.id=007 { "rank": "Commander" }
```

### Multi-line bodies (objects and arrays)

A body whose `{` or `[` isn't closed on the same line continues onto subsequent
lines until brackets balance:

```
PUT /people [
  {
    "identifiers": { "com.mi6.id": "006" },
    "name": "Alec Trevelyan"
  },
  {
    "identifiers": { "com.mi6.id": "007" },
    "name": "James Bond"
  }
]
```

Nested objects/arrays inside a body just extend the depth — no special syntax.

### Raw newlines in JSON strings

Strict JSON doesn't allow real newlines, tabs, or carriage returns inside string
literals — but `.api` files do. The client auto-escapes them on send:

```
PUT /people/com.mi6.id=006/addresses/main {
  "line1": "Janus Syndicate HQ",
  "line2": "
    Entrance through black door between
    the two demonic face symbols
  ",
  "postalCode": "40502"
}
```

The `line2` value above is sent as `"\n    Entrance through ...\n  "` — useful for
PEM contents, multi-line descriptions, etc.

### File bodies (`@`)

```
# Single file — content-type auto-detected by extension
PUT /sync-webhooks @webhooks/main.json
PUT /upload      @data.csv
PUT /events      @log.ndjson

# Glob: all matching .json files combined into a single JSON array
# (objects → element, arrays → flattened)
PUT /people @people/*.json

# Glob of .ndjson files: concatenated as one NDJSON stream
PUT /events @events/*.ndjson

# X-Request-Map header via ~map(type) suffix on a file body
PUT /sync-webhooks @data.csv~map(com.heads.csv-product)
```

`~map(type)` is the only function an `@file` body takes. Any other
(`@backup~old(1)`) is an error and the request is not sent: `unknown body
function ~old(1)`.

Globs are processed in **sorted order** and skip OS junk (`.DS_Store`,
`Thumbs.db`, `desktop.ini`, `._*`). `.njson` counts as NDJSON too, and the
extension is read in any case, as an outfile's is: `@ROWS.CSV` is sent as
`text/csv`. Empty match sets and invalid JSON (`invalid JSON in <file>: …`)
are hard errors: the run exits non-zero and the request is not sent.

A UTF-8 byte order mark in front of a file body is not sent: not of a single
file that is text (UTF-8 throughout, whatever its extension), and not of any
file of a glob. A file that is not text is sent as the bytes it holds.

A number in a combined glob body is sent with the digits its file has
(`12345678901234567890123`, `0.10`), as a single `@file` is sent byte for byte.

## 4. Output to file (`> path`)

Append `> outfile` to write the response body to a file instead of stdout. The
client parses the redirect itself; no shell is involved in a `.api` file.

```
GET /people > people.json                # Accept: application/json
GET /events~map(com.heads.csv) > out.csv # Accept: text/csv
GET /events~map(com.heads.sql) > out.sql # Accept: application/sql
GET /events > stream.ndjson              # Accept: application/x-ndjson
GET /people >> people.json               # append (see below)
GET /people > clipboard                  # system clipboard, case-insensitive
```

- The extension drives the `Accept` header as above; anything else asks for JSON.
  It is read in any case (`out.CSV` is a CSV file), and `.njson` is NDJSON too.
- An outfile that can't be written (a directory that doesn't exist, a file
  that is read-only, a full disk) is reported as `Error writing to <path>: …`,
  with `--stream` as without. For a single request and
  under `-f` that is exit 1; a chain stops there; a plain batch line is
  reported and the next line runs, as after a failed request.
- `~/` expands to the home directory (on Windows `~\` does too).
- `>> file` appends by content: JSON is spliced into one array, `.ndjson`/`.njson`
  targets get one compact object per line, `.csv` appends drop the duplicate
  header row, anything else is text-appended. `>> clipboard` is rejected
  when the line is read, before anything is sent.
- **An error is written by `>` and never appended by `>>`.** Without `-f`, a
  `> file` holds whatever was answered, a 404's body too, so check the status
  (or run with `-f`) before trusting the file. A `>> file` collects answers,
  and a non-2xx body is not one: the file is left as it was, whatever its
  format, and one that is not there is not created. The body goes where it
  would have gone without the redirect (stdout; nowhere in `-sa` mode, where
  the status line says what happened), and `>> people.json (not appended)`
  stands on stderr in the place of the size line. The batch carries on as
  after any failed request. Under `-f` neither `>` nor `>>` gets an error:
  see [fail-fast](#stopping-at-the-first-failure--f---fail-fast). The one
  error `-f` lets through is a "no" that was asked for, the 404 of a chain
  segment with another after it (`GET /x > f.json || …`): that is written by
  `>` as without `-f`, and not appended by `>>`.
- **Numbers are written as they came.** A JSON body that is indented, turned
  into NDJSON lines or rewritten by `--export` keeps every number's digits:
  `12345678901234567890123` and `0.10` are not rounded to what a double holds.
  Only an exponent's spelling is made uniform (`1E2` and `1e2` are written
  `1e+2`).
- A `.ndjson`/`.njson` target holds one compact JSON value per line, after
  `>` and after any number of `>>`: a single record is one line, and a list
  is one line per element. Other JSON targets are indented. Not under
  `--stream`, where a `> file` of either kind holds the bytes the server
  sent (see below).
- Under the status line the client prints the target and the size written, on
  stderr: `> people.json (47.1 KB)`, `>> people.json (+1.2 KB)`. `-s` suppresses it.

### Always pipe GET responses to a file

In `-sa` mode response bodies are not printed at all, and in `-a` mode stdout is
pretty-printed and colored; neither is meant to be parsed. To read data back,
write it to a file and read the file:

```
GET /people~where(active=true)~with(com.heads.*) > /tmp/active-people.json
```

Use `/tmp/` with a distinct name per step so a batch leaves an audit trail, and
match the extension to the format you want (`.csv`, `.sql`, `.ndjson`).
Re-running the batch overwrites the files.

### Streaming large exports (`--stream`)

Off unless asked for, via `--stream` or `API_STREAMING=1` (`--no-streaming`
overrides both). With it, a response bound for `> file` is written as it
arrives instead of being held in memory first:

```sh
api --stream -sa export.api
```

- A streamed `> file.json` holds the server's bytes verbatim, not pretty-printed.
  Parse it rather than eyeballing it, or drop `--stream`. A streamed
  `> file.ndjson` is verbatim too: it holds one value per line only if that
  is how the server sent it. A list that arrives as one JSON array stays one
  array; it is rewritten to lines only when buffered.
- A streaming response sends its status line before the body exists, so a `200`
  can still carry an error inside the payload. Check the content.
- `>> file`, `> clipboard`, and any non-2xx response buffer even with `--stream`.
- A streamed outfile gets its name only when the body has ended. A transfer
  that fails partway leaves the target as it was (the bytes went to
  `<file>.<pid>.part` beside it, which is removed), and ends the run with
  exit 1. The file keeps the mode the target had, and a target that is a
  symlink is written where the link points.
- A transfer that is interrupted leaves the target as it was too, and no
  `.part` file: ctrl+c or a `kill` (SIGINT, SIGTERM) during a batch, which
  still ends the run as an interrupted program ends (a shell reports 130
  for ctrl+c), and esc during the request at the prompt. A `kill -9` can't
  be answered and leaves the `.part` file behind.
- Two kinds of target are written as they stand, and are cut short by a
  transfer that fails or is interrupted: one that is not a regular file (`> /dev/null`, a
  fifo), and a file in a directory that no file can be created in.

## 5. Chaining

`GET /a && PUT /b {…}` runs the PUT only if the GET was truthy; `||` runs the
next request only if the previous was falsy. Mixed chains evaluate left to right
like a shell, so `GET /x && PUT /x {…} || POST /x {…}` is if-then-else.

```
# Create only if missing
GET /people/com.mi6.id=007 || PUT /people/com.mi6.id=007 { "name": "James Bond" }

# Delete only if there is something to delete
GET /people~where(givenName=Test)~count && DELETE /people~where(givenName=Test)
```

- Truthy: a 2xx whose body is not `false`, `null`, `0`, or `""`. `[]` and `{}`
  are truthy, so condition on a `~count` or a single item, never on a list.
- Falsy: those bodies, or a plain non-2xx such as 404. The rest of the chain is
  skipped quietly and noted as `↳ skipped 1 request`.
- Error: 401/403, 5xx, 408/429, or a timeout aborts the whole batch with exit 1.
  `||` never catches an error.
- `&&`/`||` inside a JSON string or body are not separators, and neither are
  they inside the parentheses of a URI operator: `GET /x~where(a=1||b=2)` is
  one request. Multi-line bodies work in any segment, and a `> outfile`
  belongs to the segment it follows.
- Every segment must be a request. A directive or an include in a chain
  (`GET /a && sleep 2`) is an error, not a step that is quietly dropped.
- A chain is one line. A `&&` or `||` with nothing behind it (`GET /a ||`,
  with the write on the next line) stops the batch before anything is sent:
  ``a `&&` or `||` needs a request on both sides, on one line``. An `assert`
  or a `sleep while` whose request ends in one (`assert GET /a ||`) is
  refused the same way.

The same truthiness rule drives `sleep while` and `assert` below.

## 6. Includes

A line that isn't a comment, isn't blank, and doesn't start with a method or `/`
is treated as an **include**: the named file is loaded and its requests are
inlined at that point. A `/path` that ends in `.api` is an include too — that
suffix is what tells `/tmp/seed.api` from a URI.

```
# parent.api
GET /about

shared/seed-people.api
shared/seed-products.api

PATCH /people/com.heads.foo=123 { "name": "after seeds" }
```

- Paths resolve **relative to the file doing the including**.
- `~/path/file.api` and absolute paths work, as long as the file is named
  `.api` (any case).
- Glob includes work: `shared/*.api` includes all matching files in sorted order.
- Recursive includes are supported. Loops are detected and reported as errors.

### Imports (`import git`, `import dir`, `import archive`)

`import <kind> <alias> <json>` makes `.api` files that live somewhere else
includable under an alias, as if the alias were a directory next to the file:

```
import git cl {
  "url": "https://github.com/Polyjuice/cloddy",
  "ref": "2.1.0"
}

cl/sv.api
cl/seeds/*.api
```

There are three kinds. Whichever one an alias comes from, it is used the same
way, so a batch can swap one `import` line for another and keep its includes.

| Kind | Where the files come from | Keys |
|---|---|---|
| `git` | a git repository | `url`, `ref`, optional `path` |
| `dir` | a directory on this machine, used where it is | `path` |
| `archive` | a downloaded `.tar.gz`, `.tar` or `.zip` | `url`, optional `sha256`, `token_env`, `path` |

The JSON may also come from a file, read exactly like a request's `@file` body
(so the path is relative to the **working directory**, and `~/` expands):

```
import git cl @cloddy.json
```

#### `import git`

| Key | |
|---|---|
| `url` | required. `https://…`, `ssh://…`, `git@host:path`, or `file://…` |
| `ref` | required. A tag, a branch, or a full 40-character commit SHA |
| `path` | optional. A subdirectory of the repository for the alias to stand for |

- Fetching uses the `git` on the `PATH` and your normal git credentials; it
  never stops to ask for a password.
- A remote that goes quiet does not hang the batch: a transfer of less than a
  byte a second for a minute, an ssh connection that is not made in 30
  seconds, or any one git command that takes more than five minutes, is given
  up on. (An ssh command of your own, in `GIT_SSH_COMMAND` or `GIT_SSH`, is
  used as it is.)
- A `\` in a `url` is refused, here and for an archive: it is a `/` to one
  URL parser and part of the host to another.
- A commit SHA already in the cache needs no network. A tag or a branch costs
  one `git ls-remote` per run and is fetched only when it points at a new
  commit. A branch is therefore looked up again on every run: pin a tag or a
  SHA when the batch must be repeatable.

#### `import dir`

```
import dir cl { "path": "../cloddy" }
```

| Key | |
|---|---|
| `path` | required. The directory: relative to the file that declares it (like an include), `~/…`, or absolute |

- Nothing is fetched, copied or cached; the files are read where they are, so
  an edit shows up on the next run. This is the kind to use while writing
  files that others will `import git`: point the alias at your working copy.
- At the prompt and in one-shot arguments, a relative `path` is relative to
  the working directory.

#### `import archive`

```
import archive cl {
  "url": "https://example.com/releases/cloddy-2.1.0.tar.gz",
  "sha256": "9f2c…"
}
```

| Key | |
|---|---|
| `url` | required. `https://…` or `file:///…`. Plain `http://` only for `localhost`/`127.0.0.1`/`[::1]`. A `file://` url names a file of this machine: its path may hold a blank, `%20` and the like are decoded, and `file://host/…` is refused |
| `sha256` | optional. The archive's SHA-256, 64 hex characters |
| `token_env` | optional. The **name** of an environment variable whose value is sent as `Authorization: Bearer …` |
| `path` | optional. A subdirectory of the archive for the alias to stand for |

- Needs no `git`. The format is told from the content, not from the name.
- **With `sha256`** the archive is pinned, like a commit: a download whose
  hash differs is an error, and once it is in the cache a run needs no
  network (and no token). **Without it** the URL is treated like a branch:
  downloaded on every run, with the hash it had printed in the log.
- An archive that holds exactly one directory at its top (`cloddy-2.1.0/…`,
  the way release tarballs are packed) starts inside that directory, so
  `cl/sv.api` is `cloddy-2.1.0/sv.api`. `path` applies below it. What a file
  manager leaves beside that directory does not count: a name that starts
  with a dot (`.DS_Store`) and `__MACOSX`.
- The token goes only to the archive's host. The client's own API key is
  never sent there, and the token is never sent to the API. Keep the token
  itself out of the file: `token_env` takes a variable name, and a missing
  variable is an error.
- Only files and directories are unpacked. Links are skipped, an entry named
  outside the archive (`../x`) is an error, and so is an archive that unpacks
  to more than 1 GB or to more than 100,000 files and directories. A download
  of more than 1 GB is refused too (`the archive is larger than 1 GB`), on
  its `Content-Length` or when that much has arrived.

#### Rules for every kind

- **Resolved before anything runs.** Every import is fetched while the file is
  read, ahead of the `url` gate, the `-p` preview and the first request. A bad
  URL, a missing ref, a wrong hash or a failed login stops the batch with exit
  1 and nothing sent.
- **The log says what was used.** In `-sa` mode each import prints one line,
  and `-p` lists it above the requests:
  `import cl https://github.com/Polyjuice/cloddy 2.1.0 (a1b2c3d)` for git,
  `import cl https://example.com/cloddy.tar.gz (sha256 9f2c1ab)` for an
  archive, `import cl /Users/me/Source/cloddy` for a directory.
- **Cached by content.** Git checkouts and unpacked archives live in
  `~/.cache/api/imports` (override with `API_IMPORT_CACHE`), keyed by commit
  or by SHA-256. If a remote gives no answer at all (its name does not
  resolve, nothing accepts the connection, it times out, or a `file://` path
  is not there), the copy that a tag, a branch or an unpinned archive URL
  last resolved to is used, and the log line says `cached copy: remote
  unreachable`. A remote that answers is taken at its word: a `404` or a
  `401` for an archive, a refused login or a missing repository for git, or
  any other failure, stops the batch with `could not reach import …` and the
  reason, cached copy or not.
- **The cache cleans up after itself.** Every run that uses a checkout or an
  unpacked archive marks it used. A run that fetches something new then
  removes the ones last used more than 30 days ago, so a branch that moves
  every day doesn't leave a copy per commit behind. Nothing is lost: a pruned
  commit or archive is simply fetched again the next time it is asked for.
  Only what the client marked as its own is removed (the `<name>.used` file
  beside a checkout): anything else in the directory is left alone, whatever
  it is called, and so is a checkout from a version that wrote no marker
  until it is used again. The whole directory is safe to delete at any time.
- **A ref is looked up once per run, and once per line at the prompt.** A
  batch that imports the same branch in several files asks the remote once
  and runs them all against the same commit. An interactive session can
  outlast a push, so there every line asks again: type the `import` line
  again to get the new commit. An alias keeps the commit it was bound to
  until then.
- **An alias belongs to the file that declares it**, from that line down. An
  included file doesn't see it and declares its own; an imported file may
  import too. Declaring an alias twice in one file is an error, and so is an
  alias that names a real file or directory next to the `.api` file, since
  `cl/sv.api` could then mean either.
- **An imported file stays inside its import.** Its includes and its `@file`
  bodies resolve relative to the imported file itself, and one that points
  outside (`@/etc/hosts`, `@~/…`, `../../x.api`) is an error, by what the
  line says: it is refused before anything is looked up, whether a file is
  there or not (`include leaves the import: …`). Its own
  `import dir` may only name a directory inside the same import. Symlinks in
  a repository or an archive are not followed. In an `import dir`, whose
  files are used where they are, a link is followed only when it stays
  inside the directory: an include or an `@file` through a link that leads
  out of it is an error. `path` only says where the
  alias starts: the boundary is still the whole repository or archive, so a
  file under `path` may include or send a file above it.
- **An imported file imports only from where it came from.** A file fetched
  from a host (`import git`, `import archive`) may itself import from that
  host and no other, and not from this machine (`file://`, `localhost`):
  `a file imported from github.com can import only from github.com, not …`.
  Nor may its `url` hold a user or a password (`https://user@host/…`,
  `ssh://git@host/…`); `git@host:path` is fine.
  No imported file may name a `token_env`, whatever it came from: a token is
  named by the file that is run. Imports are fetched while the file is read,
  before `-p` shows anything, so this is what keeps a token and a request of
  yours from going where a third party's file points. Files of this machine
  (an `import dir`, a `file://` or loopback URL) are your own and may import
  from anywhere.
- **An imported `url` line can only narrow.** The `url` lines of an import
  form a gate of their own that must pass *as well as* yours. An import can
  refuse to run somewhere; it can never add an environment to your allowlist.
- **Circular imports are an error.** An import that leads back to a file
  already being read is reported as `include loop detected`.
- **`> outfile` in an imported file is not restricted** and writes where it
  says, relative to the working directory. Read an import with `-p` before
  running it for the first time: it sends requests with your credentials.

## Describe block

A file may open with one JSON object that says what the file is. It is never
sent. It is there for people and for tools that list or run `.api` files:

```
# Catalog seed
{
  "title": {
    "sv-SE": "Katalog",
    "en-US": "Catalog"
  },
  "description": {
    "sv-SE": "Innehåller x y z och andra intressanta saker, se till att köra bananer också."
  },
  "docsLink": "https://link-to-docs.com"
}

PUT /products @products/*.json
```

| Member | |
|---|---|
| `title` | an object of texts by locale: `{ "sv-SE": "…", "en-US": "…" }` |
| `description` | the same, for a longer text |
| `docsLink` | a string, an `http://` or `https://` link |

All three are optional. A locale key is a language with an optional script
and region (`sv`, `sv-SE`, `zh-Hans-CN`), read in any case: `sv-se` is `sv-SE`.

**Where it goes.** Before the file's first request, import, include or
directive. Only comments, blank lines and `url` lines may stand above it, and
a file has one. It is written like a body: it may span lines, hold `//`, `#`
and `/* */` comments, and have raw newlines in its strings.

**What stops the batch** (exit 1, before anything is sent):

- a `{` that starts a line after the first request, import, include or
  directive: `a describe block must come before the first request`. Directly
  under a `PUT`, `POST` or `PATCH` that has no body the message adds `(a body
  starts on the request line)`, since that is what it most likely was;
- a second describe block in the same file;
- a line that starts with `[`: `a describe block is a JSON object, not an array`;
- JSON that can't be read (`invalid describe block: …`), or a block that is
  never closed.

**What is only a warning** (stderr, and the batch runs): anything in the block
that is not the shape above. One line each, naming the place:

```
warning: describe block: title/sv_SE is not a locale
warning: describe block: description is not an object of texts by locale, like { "sv-SE": "…" }
warning: describe block: docsLink is not an http(s) link
warning: describe block: owner is not a member of a describe block (title, description, docsLink)
```

A member the client does not know is warned about and kept, so a file written
for a later version still runs. A locale written twice (`sv-SE` and `sv-se`)
keeps the first.

**It is the file's own.** A describe block in an included or imported file is
checked (its warnings say `describe block in shared/users.api: …`) and
otherwise left alone: it describes that file, not the batch that includes it.

### Reading it: `--describe <file>`

```sh
api --describe catalog.api          # indented
api -r --describe catalog.api       # on one line
```

Prints the file's describe block on stdout as JSON, or `null` when the file
has none, and exits 0. Nothing is sent and no connection is needed. Includes
are not opened and imports are not fetched, so it is quick and works offline;
`-` reads the file from stdin. Locale keys are printed in one spelling
(`sv-SE`), whatever case the file has them in. Shape warnings go to stderr,
still with exit 0; a block that would stop a run (out of place, invalid) is
`error: …` on stderr with exit 1 and nothing on stdout.

### Showing it before a run: `-m`

`-m` (`--describe-first`) prints the block of the file being run, on stderr,
before anything else, so above the `-p` preview when both are given:

```sh
api -spma catalog.api
```

```
Katalog
Innehåller x y z och andra intressanta saker, se till att köra bananer också.
https://link-to-docs.com

Preview — 1 request | PUT [http://localhost:5000]
  PUT /products @products/*.json
Run? [Y/n]
```

- Each text is shown in the reader's locale, from `LC_ALL`, `LC_MESSAGES` or
  `LANG`: that locale's text, else one in the same language, else English,
  else the first the file has. `title` and `description` are picked
  separately, so a file with an English title and only a Swedish description
  shows both.
- It works without `-p` too (`api -sma catalog.api`), and for a file named as
  a one-shot argument (`api -m catalog.api`).
- A file without a describe block prints nothing for it. A block in an
  included file is not printed.
- It has no effect at the interactive prompt.

### At the prompt and as an argument

A pasted file that opens with a describe block runs as the file would, with
the block read and not sent. A JSON object pasted alone is a body, as before.
A describe block as the whole of a typed line or of the arguments
(`api '{"title":{}}'`) would send nothing and is an error.

## Listing a file's assertions: `--assert <file>`

```sh
api --assert seed.api
```

Prints the body of every `PUT /assert` the file sends, in the order it sends
them, as one JSON array on stdout. Nothing is sent and no connection is needed.

```
# seed.api
PUT /assert { "api/v1/people~count": { "is": 3 } }
PUT /people/com.mi6.id=008 { "name": "Bill" }
PUT /assert {
  "api/v1/people~count": { "is": 4 },
  "api/v1/people/com.mi6.id=008/givenName": { "is": "Bill" }
}
```

```json
[
  {
    "api/v1/people~count": {
      "is": 3
    }
  },
  {
    "api/v1/people~count": {
      "is": 4
    },
    "api/v1/people/com.mi6.id=008/givenName": {
      "is": "Bill"
    }
  }
]
```

- **One element per request, each exactly as it is written** (comments
  stripped, members in their order). They are not merged into one object: two
  requests may assert the same path, and an object holds one value per key.
  Each element can be sent back as it is with `PUT /assert`.
- **Includes and imports are followed**, since the question is what a run
  asserts. An import that is not in the cache is fetched, and one that can't
  be is an error.
- A `PUT /assert` in a `&&`/`||` chain is listed, whether or not the chain
  would reach it. An `@file` body is read.
- The endpoint is recognised however it is written: `/assert`, `v1/assert`,
  `/api/v1/assert`.
- The `assert` keyword is not listed: only `PUT /assert` requests are.
- A file that asserts nothing prints `[]`. `-r` prints the array on one line.
- A body that is not JSON, or anything that would stop the file from being
  read (a missing include, a misplaced describe block), is `error: …` on
  stderr with exit 1 and nothing on stdout.

## 7. Directives: `sleep`, `sleep while`, `assert`, `confirm`, `export`, `url`

Besides requests and includes, a few control lines are recognised. `sleep while`
and `assert` send a request whose answer is only judged, never printed as data.
`confirm` pauses and asks for user confirmation before continuing.

### `sleep N`

Pause before the next step. `N` is seconds by default; `s`, `ms`, and fractions
work (`sleep 2`, `sleep 500ms`, `sleep 1.5s`).

### `sleep [N] while [not] <request>`

Wait for something asynchronous on the server by polling a request every `N`
seconds (default 5) until its answer flips, then carry on with the next line.
The first check happens immediately.

```
POST /imports { "source": "erp" }

# Wait until the import queue is empty…
sleep 20 while GET /imports~where(state=running)~count

# …or until the data has arrived.
sleep while not GET /people~count

GET /people~take(5) > /tmp/people.json
```

- `while X` loops **while X is truthy**; `while not X` loops **while X is falsy**.
  Truthiness is the same as for `&&`/`||` chains: `false`, `null`, `0`, `""` and
  non-2xx statuses like 404 are falsy; everything else on a 2xx is truthy.
- The request is any single-line request (implied `GET` included, bodies allowed).
  It can't be a `&&`/`||` chain and can't write to an outfile.
- Polls print nothing. In `-sa` mode the loop logs one line when it starts and one
  when it ends (`↳ waited 1m40s (5 checks)`), so a long pause is explained.
- There is no maximum wait; ctrl+c stops the run.
- A 401/403, 5xx, 408/429, or timeout during a poll aborts the whole run with
  exit 1, exactly as in a chain. Retrying an unanswerable question forever would
  hide a broken token or server.

### `assert [not] <request>`

Run a request once and stop the batch unless the answer is truthy (`not`: unless
it's falsy). Put it at the top as a pre-check that the environment holds what
the batch depends on, or after a write to verify the result.

```
assert GET /companies/com.heads.seedID=ourcompany
assert not GET /people~where(givenName=Test)~count

PUT /people [ … ]
```

- Truthiness is the chain rule again, so `assert GET /companies/…` fails on a
  404 and `assert not GET /…~count` fails once the count is non-zero.
- The request follows the `sleep while` rules: one line, implied `GET` allowed,
  no `&&`/`||`, no `> outfile`.
- The status line is printed like any request's; the body never is, so an
  assert can't pollute a batch's stdout.
- A status the line was prepared for prints orange instead of red: the 404
  that lets `assert not` pass, and a 404 on any chain segment that has another
  after it (`GET /x || PUT /x {…}`). Red is kept for a "no" nobody asked for
  and for 401/403/408/429/5xx, which are never an answer.
- Failure exits 1 before anything else runs, naming the reason — the status
  (`assertion failed: assert GET /companies/x (404 Not Found)`) or the falsy
  body (`(0)`, `(null)`). A 401/403, 5xx, or timeout also exits 1.

### `confirm [message]`

Pause and ask for user confirmation before continuing. Useful for manual approval
gates in longer batch runs. If a message is provided, it becomes the prompt; if
not, the default is "Continue?". The prompt defaults to `? [Y/n]` unless the
message already ends with `?`.

```
PUT /release { "version": "1.0.0" }

confirm Ready to deploy to production?

POST /deploy { "go": true }
```

- Everything after `confirm` on the line is the message, a `&&` or `||`
  included: `confirm Seed a && b?` asks exactly that, and is not a chain.
- Enter, `y`, or `yes` continues; anything else prints `aborted` and stops the
  batch with exit 0 (the user declined, so it's not a failure).
- In `-sa` mode the confirm line is echoed, then the prompt appears on stderr.
- The answer is read from the terminal. With no terminal (CI, cron, an agent's
  shell) it is read from stdin, so it can be piped: `yes | api -sa file.api`
  answers every `confirm` with yes, `echo n | api -sa file.api` declines the
  first.
- **A question nobody answered is not a yes.** End of input (no terminal and
  stdin empty or closed, or ctrl+D at a terminal) stops the batch with
  `aborted (could not read confirmation)` and **exit 1**: nothing after the
  `confirm` is sent. An empty line is Enter and still accepts.
- When the program itself is on stdin (`api -a -`, `cat file.api | api -a`)
  there is nothing left there to answer with, so without a terminal a `confirm`
  in it always stops the run.

### `export <external-id>` / `export off`

Turn [export mode](#exporting-seed-data---export-external-id) on for the
requests that follow in this file, as `--export <external-id>` does for a
whole run, so that one file can read some things as seed data and others as
they are:

```
GET /about > /tmp/about.json                 # as the server answers

export com.heads.seedID

GET /users > /tmp/users.json                 # seed data
shared/checks.api                            # another file: not exported
GET /companies > /tmp/companies.json         # seed data again

export off

GET /people~count > /tmp/count.json          # as the server answers
```

- It holds **from the line down, to `export off` or the end of the file**. A
  second `export <name>` replaces the name from there on.
- It is **the file's own**. A file it includes, and a file of an import, runs
  without it, and export is back on when the including file carries on. An
  included or imported file may have an `export` line of its own, which ends
  with that file and never reaches the file that included it.
- The name is a namespaced key, as for `--export`. A name that is not one, a
  missing name, or an `export` line as a segment of a `&&`/`||` chain stops
  the batch with exit 1 before anything is sent.
- **`--export` on the command line overrides every `export` line**: the whole
  run, included files too, is exported under the command line's name, and
  `export off` does not turn it off. The `-sa` log says so under each line:
  `↳ ignored: --export com.heads.seedID is set`.
- Each request under it behaves as with `--export`: a 2xx JSON response is
  rewritten wherever it goes, an error body is left alone, `&&`/`||`,
  `assert` and `sleep while` judge what the server answered, and the request
  is not streamed.
- The `-p` preview and the `-sa` log list the line where it is written.
- **At the prompt** the line works the same, with the session in the place of
  the file: `export com.heads.seedID` holds for the lines typed after it until
  `export off` (or ctrl+r), and a file run from the prompt is kept out of it
  like an included file. A session's own export mode, from `--export` or
  ctrl+r, is the command line's and overrides a typed line too: the hint line
  says `export stays <name>`.
- As a one-shot argument on its own (`api export com.heads.seedID`) it would
  send nothing and is an error; use `--export`. In an argument of several
  lines it is a line like any other.

### The same syntax at the prompt and on the command line

Every line in this section, a chain, and an include can also be typed at the
interactive prompt or passed as one-shot arguments. The three entry points read
the same grammar with one parser, so a line means the same request wherever it
is written: body comments are stripped and raw newlines inside strings escaped
everywhere, an absolute `.api` path is an include everywhere, and a chain
segment that isn't a request is an error everywhere. `tests/parity.rs` runs one
table of lines through all three and compares what reached the server.

**Interactive prompt.** The line is read as `.api` syntax. One request is sent
as typed (a body-less `PUT` opens the body editor, which is the prompt's own;
ctrl+d there sends the body, and a body that is not closed is refused as on the
line: nothing is sent and the editor stays open. A `> file` on the line is
kept, and written when the body is sent);
anything else runs in the session: `confirm` asks in the hint line (`y`/enter or
`n`/esc), `sleep` and `sleep while` show a spinner and stop on esc, `assert`
logs the line as typed (`assert GET /x`) with its status but not the body and
leaves `↳ assertion failed (null)` under the status line when it fails, `url`
checks the current
connection, and `seed.api` runs the file with each request logged as if typed.
A pasted block of several lines runs line by line, as a file would; pasting a
request line, a directive or a block replaces whatever is on the line, so a
paste over the starting `GET /` is just the paste. Tab on a
line that is a path (`se`, `shared/`, `~/seeds/`) completes it to a directory
or a `.api` file; a path starting with `/` completes as a URI. A block or a
file carries on past a plain line that is answered with an error status, and
past one whose outfile could not be written (`Error writing to …`), as a
batch does; a chain stops there, and so does the program under `-f`. A stopped program (failed assert, declined confirm, a request
that got no answer, esc) leaves the session open, in the export mode it had
before a file that stopped set one of its own.

**One-shot arguments.** The positional arguments are joined into one line. A
directive, an include, a `&&`/`||` chain, or several lines in one quoted
argument run through the batch runner exactly like a `-a` file, so
`api assert /companies/x` exits 1 on failure and `api seed.api` is `api -a
seed.api`. Quote the `&&` or the whole line so the shell doesn't take it. A plain
`METHOD URI [BODY]` is sent directly, after the same reading: a `> file` may sit
in any argument (`api GET /people ">" out.json`, `api GET /people "> out.json"`,
`api "GET /people > out.json"` are the same), and a body may carry comments or
raw newlines just as in a file. One plain request is that single request
however it is quoted: `api -s "GET /people"` prints what `api -s GET /people`
prints (the body alone, not a `-sa` log), and `echo '{…}' | api "PUT /x"`
sends the piped body.

In both places a mistyped request reports `not a request or .api file`, where
it used to be sent as a GET to a nonsense path or silently re-send the previous
request.

### `url has <text>` / `url is <url>`

Environment gate. Before anything runs, the configured base URL must match at
least one `url` line in the file (or its includes). No match aborts the whole
batch, so test data can't be sent to the wrong environment. Multiple `url`
lines form an allowlist.

```
url has localhost:5000
url has test.app.heads.com
url is https://cos.example.com
```

- A `url` line is a line of its own. In a `&&`/`||` chain (`url has x && PUT
  /y {…}`) it stops the batch before anything is sent, as every directive in
  a chain does.
- `url has <text>` is a substring match against the base URL as the client
  has it (`http://localhost:5000`: scheme in lower case, no trailing `/`, no
  `/api/v1`). The text is compared as written, so `url has localhost:5000/`
  matches nothing.
- `url is <url>` is the whole base URL, and its value is read as a base URL
  is read from `-b`: `url is https://cos.example.com/`, `url is
  HTTPS://COS.example.com/api/v1` and `url is cos.example.com` all name
  `https://cos.example.com`. A host is the same in any case; a path below it
  (`https://host/tenant`) is compared as written.

## 8. Running

```sh
api -a parent.api                     # from a file
cat parent.api | api -a               # from stdin (the dash is implicit)
api -a -                              # explicit stdin
api -sa parent.api                    # silent batch mode (see below)
api -spa parent.api                   # preview the requests, confirm before sending
api -sfa parent.api                   # stop at the first failed request (see below)
api --export com.heads.seedID GET /users > users.json   # a response as seed data (see below)
echo '{"name":"Ann"}' | api PUT /people/com.mi6.id=008  # a body from stdin
```

A single request reads a piped stdin as its body only when it is a `POST`,
`PUT` or `PATCH` and no body argument was given. Any other request leaves
stdin alone, so it never waits for a pipe and can sit inside a `while read`
loop.

**A piped body is sent as it is.** Only the blanks around it are trimmed.
One that starts with `@` is that text, not the name of a file to send.
It is not read the way a body argument or a body in a `.api` file is: `//`,
`#` and `/* */` comments are not stripped, and a raw newline in a string is
not escaped. A piped body is often not JSON at all (CSV, NDJSON), and a
` #` in it is data. JSON with comments goes in a body argument, in a `.api`
file, or through something that strips them before the pipe.

`-a <file>` and a request are two different runs. Both on one command line
(`api -sa seed.api GET /people`) is an error, before anything is sent:
`-a seed.api runs a file and GET /people is a request: give one of the two`.

An option given twice (`-k a -k b`) is an error (`--key was given twice`), and
so is one with no value behind it (`--export needs a value`).

### Previewing (`-p`, `--preview`)

`-p` lists what would be sent (imports and includes followed) and asks
`Run? [Y/n]` once, before the first request. It asks before sending; it is
**not a dry run**: Enter, `y` or `yes` sends everything.

- `n` prints `aborted`, sends nothing and exits 0.
- The header counts the requests of the program and lists their methods:
  `Preview — 3 requests | GET PUT [http://localhost:5000]`. The request of an
  `assert` and of a `sleep while` is one of them; a `sleep`, a `confirm` and
  an `export` line are listed and not counted.
- The answer is read like a `confirm`'s: from the terminal, or from stdin when
  there is none. A question nobody answered (end of input) sends nothing,
  prints `aborted (could not read confirmation)` and exits 1.
- To print the resolved program without sending anything from a shell with no
  terminal: `echo n | api -spa file.api`. To run it unattended:
  `yes | api -spa file.api`, or leave `-p` off.

### Stopping at the first failure (`-f`, `--fail-fast`)

Without `-f` a batch carries on past a request that fails: a 404, a 409 or a
500 on a plain request line prints its status and the next line runs, and the
exit code is 0. With `-f` the first response of **400 or above** ends the run:

```sh
api -sfa seed.api
```

```
[http://localhost:5000]
PUT /people/com.mi6.id=007 {"name":"James Bond"}
└─HTTP/1.1 200 OK 0.02s
PUT /assert {"api/v1/people~count":{"is":3}}
└─HTTP/1.1 409 Conflict 0.01s
{
  "@type": "failed assertion",
  "error": "One or more assertions failed.",
  "details": "1 of 1 assertion failed.",
  "failures": {
    "api/v1/people~count": {
      "was": 2,
      "expected": {
        "is": 3
      }
    }
  }
}
```

- Nothing after the failing request is sent, and the exit code is 1.
- **The failing response's body is the last thing on stdout**, exactly as the
  server sent it, with `-sa` too (where bodies are otherwise not printed). A
  tool driving the client reads the reason from there; the status line stays
  where it always is (stdout in `-sa`, stderr otherwise).
- The server pretty-prints its JSON, so the body is usually several lines. In
  `-sfa` output it is everything after the last `└─HTTP/1.1 …` line. For a
  single request (`api -f PUT /assert @asserts.json`) the status line goes to
  stderr and stdout is the body alone, which is the easiest thing to parse.
- This is how to check conditions with the `/assert` endpoint. `PUT /assert`
  takes a body that maps API paths, written from the base (`api/v1/…`), to
  what they should hold (`is`, `is not`), any number of them in one request:

  ```
  PUT /assert {
    "api/v1/people~count": { "is": 3 },
    "api/v1/people/com.mi6.id=007/givenName": { "is": "James" },
    "api/v1/people/com.mi6.id=006/personalNumber": { "is not": null }
  }
  ```

  Every assertion holding answers `200` with `null` and the batch goes on. A
  failed one answers `409` `failed assertion`, with an entry per failed path
  under `failures` (`was`, `expected`, and a `suggestion` where there is
  one); a request the server can't read answers `400`. `-f` turns both into
  a stopped batch with that body on stdout.
- **Put `PUT /assert` on a line of its own.** A pass is `200` with `null`,
  and `null` is falsy to `&&`/`||`, to `sleep while` and to the `assert`
  keyword. So `PUT /assert {…} && PUT /x {…}` never runs the write, and
  `assert PUT /assert {…}` fails when the assertions hold.
- The `assert` keyword still works and still reports its own failures, with
  or without `-f`. A failed assertion is a verdict and prints no body.
- An `assert` or a `sleep while` poll that gets a status that is never an
  answer (401/403/408/429/5xx) says so on stderr (`… could not be evaluated,
  aborting`) and, under `-f`, the body of that response is the last thing on
  stdout, as for any other response that ends the run.
- **A question may still be answered "no".** A chain segment with another
  after it (`GET /x || PUT /x {…}`), `assert not`, and a `sleep while` poll
  ask something, and a 404 or 409 is their answer, so they don't trip `-f`.
  The last request of a chain is a plain request and does. A status that is
  never an answer (401/403/408/429/5xx) ends the run from anywhere.
- An error is not written to a `> outfile`: under `-f` the file is left
  alone and the body goes to stdout.
- It works for one request too: `api -f PUT /assert '{…}'` exits 1 on a 4xx
  or 5xx where it otherwise exits 0. At the interactive prompt, `api -f` makes a
  pasted block or a `seed.api` run stop at the failing request and says
  `stopped at 409 (--fail-fast)`; the session stays open.

### Exporting seed data (`--export <external-id>`)

A response read from one environment can't be written to another as it is. Every
record carries its database key (`identifiers.key`), and a write that names a
record by a key no record has is refused (`400 failed indexing`). `--export`
rewrites each response so that it can be sent back with `PUT`, to the environment
it was read from or to a different one, any number of times, and find or create
the same records:

```sh
api --export com.heads.seedID GET /users > users.json
api -c staging PUT /users @users.json
```

```
# what the server answers                          # what --export prints
{                                                  {
  "name": "Ann",                                     "@type": "person",
  "@type": "person",                                 "identifiers": {
  "identifiers": {                                     "key?": "98850c77…",
    "key": "98850c77…"                                 "com.heads.seedID": "98850c77…"
  },                                                 },
  "employer": {                                      "name": "Ann",
    "identifiers": {                                 "employer": {
      "key": "27b65eb8…",                              "identifiers": {
      "com.heads.seedID": "ourcompany"                   "com.heads.seedID": "ourcompany"
    }                                                  }
  },                                                 },
  "password": "********"                             "password": null
}                                                  }
```

What it does to every object in the response, however deep:

- **`identifiers.key` is removed.** No `key` is left in an export.
- **A record that has another identifier** (`com.heads.seedID`, a `userId`,
  anything besides `@type`) is found by that one, where it was read and
  anywhere else. It gets nothing in the key's place.
- **A record with no other identifier keeps its key twice**: under the name
  you gave (`com.heads.seedID` above) and as `key?`, the key that may name
  nothing. Where a record has that key, `key?` names it, so the first write
  back to the environment it was read from finds the record and gives it the
  name. Where none has, the API reads the identifiers as if `key?` were not
  there: the first write creates the record with the name, and the next one
  finds it by the name. `key?` is written only here, beside the name made
  from the key.
- **An identifier that is `null` is not one the record has.** With `-i` the
  server lists identifiers a record doesn't have (`"clientID": null`); such a
  record still has only its key and keeps it as `key?` and under the name.
  The `null` member stays in the output, since `-i` asked for it.
- **Neither is an identifier that is masked.** A value the server sent as
  `********` becomes `null` (below), and a record can't be found by it: a
  record whose only other identifier is masked keeps its key as `key?` and
  under the name, like one that has none.
- **A masked value (`********`) becomes `null`**, and a line on stderr says
  where: `Response had masked data, now null at oauth2Clients/secret,
  localCredentials/password and 1 other place`. A path is written from the
  top of the response and leaves out positions in lists, so it is one place
  however many records had it. Two places are named and the rest are
  counted; search the export for `null` to find them all. The secret is not
  in the export; set it some other way.
- **`identifiers` moves to the front of its object**, behind `@type`. Other
  members keep the order the server gave them.

Rules:

- The name is a **namespaced key**, the form the API wants an external
  identifier's name in: exactly three dot-separated segments of letters,
  digits and `_`, at most 128 characters (`com.heads.seedID`). The second
  segment may also hold `-`, the third `-` and `$`. Anything else is an error
  before a request is sent, which is also what catches a forgotten name
  (`api --export GET /users`).
- **The server has to know `key?`** to take an export that holds one. A
  server that doesn't refuses the write with `400 failed coercion` (`The key
  'key?' is not a valid namespaced key`). An export in which every record had
  another identifier holds no `key?` and is not affected.
- It applies to **2xx JSON responses**, wherever they go: stdout, a `> file`,
  `>> file`, the clipboard. An error body is left as the server sent it, so
  `-f` output is unaffected, and request bodies are never touched.
- It works for one request and in a batch (`api --export com.heads.seedID
  -sa export.api`, with a `> file` per request). For only some requests of
  a file, write an [`export` line](#export-external-id--export-off) in it.
- **At the interactive prompt, `ctrl+r` turns export mode on and off**, the
  way `ctrl+t` does streaming, and `export` shows at the right of the hint
  line while it is on. The first time, it asks for the name: there is no
  default. A name that is not a namespaced key is refused with a notice in
  the hint line, and the dialog stays open with the name there to correct,
  until it is given one or left with `esc`. The name is remembered until the
  session ends, so turning export on again doesn't ask. A session started with `--export <name>` starts with export
  on and has its name. The masked-data line shows in the hint line.
- Output is indented; `-r` prints it on one line. NDJSON (`--ndjson`, or a
  `> file.ndjson`) is rewritten line by line.
- A response that is not JSON (a `> file.csv`, a `.sql`) is written unchanged,
  with `WARNING: --export left a response that is not JSON unchanged`.
- `&&`/`||`, `assert` and `sleep while` judge what the server answered, not
  the rewritten body.
- The whole body is needed, so `--stream` is ignored while export is on (at
  the prompt, `export` takes the place of the `streaming` marker).

### Credentials from disk (`--no-keychain`)

By default the client stores connections in the OS keychain, which needs an
unlocked desktop session — no good for an agent, a container, or CI. Passing
`--no-keychain` moves all credential I/O to a plaintext JSON file instead.

```sh
api --no-keychain -sa seed.api
```

The flag is what activates file mode. `API_CREDENTIALS_FILE` alone does
nothing — without `--no-keychain` the client still reads the keychain and
ignores the variable entirely.

**Where the file lives**, in order:

1. `API_CREDENTIALS_FILE`, if set — an absolute path is safest. Set to
   nothing (`API_CREDENTIALS_FILE=`) it is not set.
2. Otherwise `./.api-credentials.json`, relative to the **current working
   directory**. Running from a different directory silently finds no
   credentials, so prefer the env var in scripts.

**File format.** `default` names the connection used when no `-c` is given:

```json
{
  "connections": [
    {
      "name": "local",
      "url": "http://localhost:5000",
      "auth_type": "key",
      "credential": "<api key>",
      "client_id": ""
    }
  ],
  "default": "local"
}
```

- `auth_type` is `"key"` (Basic), `"token"` (Bearer), or `"oauth2"`, read in
  any case (`"Token"`). A connection with any other `auth_type` is not used:
  its credential is not sent as a kind it was not saved as.
- For `"oauth2"`, put the client secret in `credential` and the client ID in
  `client_id`; the client exchanges them for a token at startup, and again
  when a request is answered `401` because the token ran out. That request is
  then sent once more, unchanged, in a batch as at the prompt.
- For `"key"` and `"token"`, `client_id` is `""` or left out.
- A `url` without a scheme gets one inferred: `http` for `localhost`, an IP
  address, or anything with an explicit port; `https` otherwise. A scheme is
  read in any case, and a trailing `/`, `/api` or `/api/v1` (in any case
  too) is dropped, here and for `-b`: the base URL is the host, not the API
  path. A scheme other than `http` and `https` (`ftp://host`), or one that
  is not written whole (`http:/host`), is refused: `-b` with exit 1, a saved
  connection by not being used.
- A UTF-8 byte order mark in front of the file is ignored.

**Using it.** With a `default` set, no connection flags are needed at all:

```sh
export API_CREDENTIALS_FILE=/run/secrets/api-credentials.json
api --no-keychain -sa seed.api                 # uses the default connection
api --no-keychain -c staging GET /people       # pick another by alias
api --no-keychain -k "$API_KEY" GET /people    # URL from file, key from the CLI
```

`-c` takes a connection's alias, or its URL (with or without the scheme) when
exactly one saved connection has that URL. A URL that several connections
share is an error that lists them, exit 1 with nothing sent: which credential
to send is not guessed. An alias always wins over a URL.

```
Connection "cos.example.com" fits several saved connections: staging, staging-admin. Name one of them.
```

A `-k`/`--token` on the command line overrides the stored credential but keeps
the file's URL, so one file can serve several keys, for the default
connection and for one chosen with `-c`. `-b` beside `-c` overrides the URL
and keeps that connection's stored credential. What the command line gives
always wins.

`-b` without `-c` uses no saved connection at all: the default connection's
credential was saved for another host and is not sent to this one. Give the
credential too (`-b … -k …`), or name the connection that lends it (`-c`).

A `-b` that names no host (`-b ""` from a variable that is not set, `-b
http://`) is not a base URL. A request or a batch ends with `Error: no base URL
specified. Use -b <url> or -c <connection>.` and exit 1: it is not sent to the
default connection in its place. Only the interactive prompt opens as it does
without `-b`.

```sh
api --no-keychain -c staging -k "$OTHER_KEY" GET /people      # staging's URL, another key
api --no-keychain -c staging -b http://localhost:5000 GET /people   # staging's credential, another host
```

**No file at all** is also fine — pass both parts explicitly and nothing is read
or written:

```sh
api --no-keychain -b https://cos.example.com -k "$API_KEY" -sa seed.api
```

**Failure modes to know.** A file that does not exist is an empty store, with
no warning: without `-b` you get

```
Error: no base URL specified. Use -b <url> or -c <connection>.
```

If you see that while expecting the file to work, check the path and that
`--no-keychain` was actually passed.

A `default` that names no connection in the file is said to be that, and no
saved connection is used:

```
WARNING: the default connection "locl" is not among the saved connections (local, stage). No saved connection is used.
```

The same is said when the file has no connections at all (`… is not among
the saved connections (none)`).

A connection that can't be used as it is written is named with the reason.
As the default it is a warning and no saved connection is used; asked for
with `-c` it ends the run with exit 1:

```
WARNING: the default connection "local" can't be used: its auth_type "bearer" is not "key", "token" or "oauth2". No saved connection is used.
The connection "local" can't be used: a base URL starts with http:// or https://, not ftp://.
```

A file that exists but can't be read, or is not valid (a trailing comma is
enough), is said to be so and is not used:

```
WARNING: could not read /run/secrets/api-credentials.json: it is not what the client wrote there (trailing comma at line 1 column 105). No saved connection is used.
```

Such a file is never written over. Saving a connection from the prompt
(`ctrl+s`) is refused with the same reason until the file is fixed or removed.

**Security.** The file is plaintext. A file the client creates can be read
by you alone (`0600`); one that was already there keeps the mode it has, so
check a file you made yourself. Keep real keys out of the repo:

```sh
chmod 600 "$API_CREDENTIALS_FILE"     # for a file you created yourself
echo '.api-credentials.json' >> .gitignore
```

A save replaces the file in one step. A file that is a symlink is written
where the link points. Where the file can't be replaced (it is mounted on its
own, as a container secret is, or its directory is not writable) it is
written as it stands.

Prefer a path outside the working tree (`/run/secrets/...`, `$XDG_RUNTIME_DIR`)
for anything but a local dev key. Saving a connection with `ctrl+s` in
interactive mode writes to this file too, so an interactive session can create
it for later non-interactive runs.

### Silent batch mode (`-sa`)

Prints the env URL once, then each request line followed by a compact
`└─HTTP/1.1 <status> <time>` line. Response bodies are suppressed (but still
written to `> outfile` targets when present).

```
[http://localhost:5000]
PUT /people/com.mi6.id=007 {"name":"James Bond"}
└─HTTP/1.1 200 OK 0.02s
GET /people > out.json
└─HTTP/1.1 200 OK 0.04s
```

Use this when you only care that requests succeeded or want a tidy log of a
seeding run.

A request line is logged as it is written, the body on one line and a
`> outfile` last: `PUT /people [{"name":"Ann"}] > /tmp/put.json`. The `-p`
preview and the interactive prompt show it the same way. An `@file` body of
an imported file is logged with the path its line has (`@data/body.json`),
not the path in the import cache it was read from.

A reader that stops reading does not stop the batch. With `api -sa seed.api |
head -2` every request is still sent; what would have been printed after the
pipe closed is dropped, and the exit code is the one the requests earned.

A slow request shows a self-erasing progress line (`⠙ received 12.4 MB`) on
stderr, but only when stderr is a terminal. Captured or piped output never
contains it, so a log holds the same lines however long a request took.

## 9. A complete example

`workshop.api`:

```
# Seed test data and verify
PUT /people/com.mi6.id=007 { "name": "James Bond" }

PUT /people [
  {
    "identifiers": { "com.mi6.id": "006" },
    "name": "Alec Trevelyan",
    "bio": "Former 00 agent.
Defected to the Janus Syndicate."
  }
]

# Address from a glob of JSON snippets
PUT /people/com.mi6.id=006/addresses @addresses/006-*.json

# Bring in additional shared seeds
shared/agencies.api
shared/villains/*.api

# Verify and write a snapshot
GET /people~with(com.heads.*) > ~/workshop-snapshot.json
```

Run it: `api -sa workshop.api`.

## 10. Common pitfalls

- **A body on the line under its request** → `PUT /people/x` with `{ … }` on the next line is not a request with a body: `a describe block must come before the first request (a body starts on the request line)`. Start the body on the request line; it may continue below.
- **A describe block that is not first** → only comments, blank lines and `url` lines may stand above it. Under an `import`, a `sleep` or a request it stops the batch.
- **`"title": "Katalog"` in a describe block** → a warning: `title` and `description` are objects of texts by locale, `{ "sv-SE": "Katalog" }`. The batch still runs.
- **Expecting `--describe` or `-m` to show an included file's block** → both show the block of the file named on the command line only.
- **Expecting `--assert` to list `assert` lines** → it lists `PUT /assert` bodies. The `assert` keyword is a request judged by truthiness and is not part of the list.
- **Trailing comma in JSON** → server returns 500 with a parse error. JSON is strict; don't trail commas in objects/arrays.
- **A `#` with a blank in front, outside a string** → a comment from there to the end of the line (`GET /x # note`). A body that is not JSON and holds ` #` (`PUT /x a # b`) loses what follows; quote it (`"a # b"`) or send it as an `@file`.
- **A chain broken over two lines** → `GET /x ||` with the `PUT` on the next line is an error. Write the chain on one line; a body may still span lines.
- **Piping a body that is not UTF-8** → `error: could not read the body from stdin`, exit 1, nothing sent. Send it as an `@file`.
- **Piping a JSON body with comments, or with a raw newline in a string** → it is sent as piped, and the server answers with a parse error. Only a body argument and a body in a `.api` file have comments stripped and newlines escaped. Give such a body as an argument, or put the request in a `.api` file.
- **Piping a body to a `GET`** → it is not sent. Stdin is read as a body only for `POST`, `PUT` and `PATCH` without a body argument. And `echo '{…}' | api -p PUT /x` with no terminal is an error: stdin can't be the body and the answer to `-p`. Give the body as an argument or an `@file`.
- **A response that stops before its end** → a body cut short by the server or the network, or one that takes longer than `--timeout`, is no answer: `The response was cut short: …` or `Timed out after …`, exit 1, with or without `-f`. Nothing is written to the outfile, a chain or an `assert` does not take it for a "no", and nothing after it is sent.
- **Unclosed brackets** → the whole run fails with `"unclosed body at end of bulk file"`. If a body looks wrong, check that `{}` and `[]` balance.
- **A method with no URI** → `api DELETE`, or a line `DELETE` in a file, is an error and sends nothing. Write the root as `DELETE /` if that is what is meant.
- **Glob with no matches** → hard error. Check the directory and pattern.
- **Include loops** → `a.api` including `b.api` which includes `a.api` is detected and refused.
- **`import … @cloddy.json` run from another directory** → the `@` path is relative to the working directory, like every `@file`, not to the `.api` file. Run from the directory that holds the JSON, or give an absolute or `~/` path.
- **An alias used in an included file** → `include not found: cl/sv.api`. Aliases don't carry into includes; repeat the `import` in the file that uses it.
- **Importing a branch and expecting yesterday's run** → a branch is re-resolved every run. Pin a tag or a SHA, and check the commit in the `import …` log line.
- **An archive URL without `sha256`** → downloaded again on every run, and whatever it serves that day is what runs. Add the `sha256` from the `import …` log line to pin it.
- **`token_env` or another host in an imported file** → refused before anything is fetched. Import the second repository or archive from the file you run, next to the first.
- **`-sa file.api GET /x`** → an error: `-a` runs the file, and the request beside it is neither dropped nor run after it. Give one of the two.
- **`-b ftp://host` or `-b http:/host`** → `error: invalid value for -b: … (a base URL starts with http:// or https://, not ftp://)`. A base URL is `http://` or `https://`, or a host with no scheme at all. The same URL in the credentials file makes that connection unusable, with the same reason.
- **`"auth_type": "bearer"` in the credentials file** → `The connection "x" can't be used: its auth_type "bearer" is not "key", "token" or "oauth2".` A bearer token is `"token"`. The three names are read in any case.
- **`url has localhost:5000/`** → matches nothing: `has` compares text with the base URL as the client has it, which ends at the host. `url is` reads its value as a base URL, so a trailing `/` or `/api/v1` there is fine.
- **A `\` in a URI** → sent as `%5C`. It is not another way to write `/`, so the escaped quote in `~where(name="a \" b")` arrives as `%5C%22`.
- **`-b` alone, expecting the default connection's key** → none is sent, and the request is answered `401`. Add `-k`, or `-c <name>` to lend that connection's credential to the other host.
- **`"token_env": "<the token>"`** → rejected or reported as an unset variable. It takes the *name* of an environment variable, so the secret stays out of the file.
- **`import dir cl { "path": "cl" }`** → `import alias … clashes`. An alias can't share its name with a file or directory next to the `.api` file; name the alias something else.
- **Seeding from a plain `GET`** → the response carries `identifiers.key`, a database key of the environment it was read from. Written elsewhere it is refused (`400 failed indexing`: a `key` that names nothing). Read it with `--export <external-id>`, which takes the key out and keeps a lone one as `key?` and under the name.
- **Writing an export to a server without `key?`** → `400 failed coercion`, `The key 'key?' is not a valid namespaced key`, as soon as the export holds a record that had only a key. Such an export needs a server that knows the optional key.
- **An `export` line and an included file** → the line is for its own file only: `shared/users.api` included under it is not exported. Put an `export` line in the included file as well, or run with `--export`, which applies to every file.
- **An `export` line under `--export`** → the command line wins: the name on the line is not used and `export off` does not turn export off. The `-sa` log notes `↳ ignored: --export … is set`.
- **Expecting secrets in an export** → the API masks them (`********`) and `--export` turns that into `null`, and says where (`Response had masked data, now null at …`). A password, an API key or a client secret has to be set separately.
- **`-p` or `confirm` without a terminal** → up to 3.3.1, end of input was read as Enter, so an unattended `api -spa file.api` or a `confirm` gate sent everything. From 3.3.2 it sends nothing and exits 1 with `aborted (could not read confirmation)`. Pipe the answer (`yes | …`, `echo n | …`); a program read from stdin (`api -a -`) has no stdin left to answer with.
- **Collecting with `>>` and expecting the errors in the file** → a non-2xx body is not appended: the file keeps what it had, and `>> file (not appended)` is printed under the status line. A `> file` does take an error's body when the run has no `-f`.
- **A `>` with nothing behind it** → `GET /x >` is an error (``a `>` or `>>` needs a path to write to``), not a request with the body `>`.
- **Expecting a failed request to stop a batch** → it doesn't, unless the line is an `assert`, a chain or a poll, or the run has `-f`. A plain `PUT /assert {…}` that answers 409 is logged and the next line runs. Run with `-f`.
- **Chaining on `PUT /assert`** → a passing `/assert` answers `200` with `null`, which is falsy, so `PUT /assert {…} && …` skips what follows and `assert PUT /assert {…}` fails on a pass. Write it on its own line and run with `-f`.
- **`assert` on a list endpoint** → `[]` is truthy, so `assert GET /people~where(x)` passes even when nothing matches. Assert a `~count` or a single item by identifier instead.
- **A slashless URI on its own line in a `.api` file** → `api/v1/people` alone is read as an *include* path and fails with `include not found: api/v1/people`. Write `GET api/v1/people`, or lead with the slash: `/api/v1/people`.
- **`sleep while` that never ends** → `[]` and `{}` are truthy, so `sleep while GET /people~where(x)` loops forever once the list is merely empty. Poll a `~count` (or a single scalar field) instead, so the answer can become `0`/`null`.
- **`https://` to a server with a self-signed or private certificate** → `The certificate of <host> is not trusted: it is not signed by a public certificate authority.` The client trusts the public authorities compiled into it and nothing from the machine, so such a certificate can't be made to pass; use `http://` for a local server. `Is COS running on <host>?` is kept for a host that did not answer at all.
- **A server that redirects a request round in circles** → `Too many redirects from <host>: the request was never answered.`, exit 1, in a batch as at the prompt. A redirect that ends is followed: a 307 or 308 arrives as the request it was, with its method, body and `Authorization`.
- **A response with bytes that are not of its charset** → the text shown and written has U+FFFD (`�`) in their place, and stderr says so once for that response: `WARNING: the response held bytes that are not valid UTF-8: each is now U+FFFD (�)`. It is said with `-s` and in `-sa` too, since it is about the data; not for an `assert` or a poll, whose body goes nowhere, nor for a `-sa` line without an outfile. At the prompt it shows in the hint line. `--stream` to a file writes the bytes as they came, so nothing is replaced there.
- **`API_CREDENTIALS_FILE` without `--no-keychain`** → the variable is ignored and the keychain is read instead. A path that names no file fails as silently: no warning, just `Error: no base URL specified`. A file that is there but malformed is reported (`WARNING: could not read …`).

## 11. Tips for agents

- Write anything you need to read back to a file (`> /tmp/step.json`); see §4.
- Keep one logical operation per request line; let the bracket accumulator handle multi-line bodies.
- Use `@file`/`@glob` for large bodies instead of inlining huge JSON blobs.
- For repeated boilerplate, factor it into a `shared/` directory and use includes.
- When generating files programmatically, prefer compact single-line JSON bodies — they're easier to grep and diff.
- Use silent batch mode (`-sa`) when you want to verify that a long seeding script worked without drowning in response bodies.
- To move data between environments, read it with `--export com.heads.seedID` (or under an `export com.heads.seedID` line in the `.api` file) into a file and `PUT` the file. Use the same identifier name every time, so a record exported twice is one record. The same file can be written back where it was read: a record is found by its identifiers, and one that had only a key by its `key?`.
- Add `-f` (`-sfa`) so a failed request stops the batch: check the exit code, and on failure read the error body from the end of stdout (everything after the last `└─HTTP/1.1 …` line; it is usually several lines of JSON). Without it a batch exits 0 however many plain requests failed.
- Open a file with a [describe block](#describe-block) (`title`, `description`, `docsLink`) so a tool or a person can tell what it does; read one with `api --describe file.api`, which sends nothing.
- To see what a file checks without running it, `api --assert file.api` prints every `PUT /assert` body it sends as one JSON array.
- Run with `--no-keychain` and an absolute `API_CREDENTIALS_FILE` so nothing depends on an unlocked keychain or on the working directory.
