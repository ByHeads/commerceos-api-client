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
- `BODY` and `OUTFILE` are optional. If both are present, `BODY` comes first; the `> path` suffix is parsed off the end.

```
# Smallest possible file
GET /about
```

## 2. Comments and blank lines

```
# Lines starting with # are comments.
# Blank lines between requests are ignored.

GET /people~take(5)

# Comments inside an open body are kept as body content — JSON doesn't have
# comments, so don't put `#` lines inside an unclosed `{}` or `[]` unless you
# want them sent literally.
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

Globs are processed in **sorted order**. Empty match sets and invalid JSON are
hard errors (the run exits non-zero).

## 4. Output to file (`> path`)

Append `> outfile` to write the response body to a file. The output file's
extension drives the `Accept` header:

```
GET /people > people.json                # Accept: application/json
GET /events~map(com.heads.csv) > out.csv # Accept: text/csv
GET /events~map(com.heads.sql) > out.sql # Accept: application/sql
GET /events > stream.ndjson              # Accept: application/x-ndjson
```

Paths can use `~/` for the home directory.

### Why agents should always pipe GET responses to a file

When an agent runs `api -sa` to execute a batch, response bodies are not echoed
back — only the status line is shown. To inspect the data returned by a `GET`,
the agent must persist it. The standard pattern:

```
# In the .api file:
GET /people~where(active=true)~with(com.heads.*) > /tmp/active-people.json
```

Then read `/tmp/active-people.json` afterward. This works the same way for `-a`
non-silent mode too — even though stdout shows the body, capturing it to a
file is more reliable than parsing terminal output (ANSI codes, pretty-printing,
truncation in pipes).

Recommended conventions for agents:

- Use `/tmp/` for ephemeral inspection files (e.g. `/tmp/api-{step}.json`)
- Use distinct filenames per step so a multi-step batch leaves a readable audit trail
- Match the file extension to the desired format (`.csv` for CSV exports, `.sql` for SQL, `.ndjson` for streams)
- Re-running the batch overwrites the files, so they're always fresh

## 5. Includes

A line that isn't a comment, isn't blank, and doesn't start with a method or `/`
is treated as an **include**: the named file is loaded and its requests are
inlined at that point.

```
# parent.api
GET /about

shared/seed-people.api
shared/seed-products.api

PATCH /people/com.heads.foo=123 { "name": "after seeds" }
```

- Paths resolve **relative to the file doing the including**.
- `~/path/file.api` and absolute paths work.
- Glob includes work: `shared/*.api` includes all matching files in sorted order.
- Recursive includes are supported. Loops are detected and reported as errors.

## 6. Running

```sh
api -a parent.api                     # from a file
cat parent.api | api -a               # from stdin (the dash is implicit)
api -a -                              # explicit stdin
api -sa parent.api                    # silent batch mode (see below)
```

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

## 7. A complete example

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

## 8. Common pitfalls

- **Trailing comma in JSON** → server returns 500 with a parse error. JSON is strict; don't trail commas in objects/arrays.
- **`>` inside a body** → the parser uses `rfind(" >")` from the end of the request, which can mis-detect outfile when bodies contain `>`. Avoid bare `>` in bodies, or escape it inside strings.
- **Unclosed brackets** → the whole run fails with `"unclosed body at end of bulk file"`. If a body looks wrong, check that `{}` and `[]` balance.
- **Glob with no matches** → hard error. Check the directory and pattern.
- **Include loops** → `a.api` including `b.api` which includes `a.api` is detected and refused.

## 9. Tips for agents

- **Always pipe GET responses to a file** (`> /tmp/something.json`) when you need to read them back. In `-sa` mode, response bodies aren't printed at all; without `> file`, the data is gone.
- Keep one logical operation per request line; let the bracket accumulator handle multi-line bodies.
- Use `@file`/`@glob` for large bodies instead of inlining huge JSON blobs.
- For repeated boilerplate, factor it into a `shared/` directory and use includes.
- When generating files programmatically, prefer compact single-line JSON bodies — they're easier to grep and diff.
- Use silent batch mode (`-sa`) when you want to verify that a long seeding script worked without drowning in response bodies.
