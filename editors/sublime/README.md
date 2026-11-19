# Sublime Text highlighting, completions and formatting for `.api` files

`API.sublime-syntax` highlights `.api` batch files as `AGENTS.md` describes
them, and `api_completions.py` completes what can stand where the cursor is
and lays a file out.

## Install

```sh
api --install-syntax sublime
```

writes them to Sublime's `Packages/User` folder, with `API.sublime-commands`
for the command palette. Files ending in `.api` pick them up. By hand: copy
the three files to that folder
(*Preferences → Browse Packages…*).

## What it covers

| Construct | Scope |
|---|---|
| `GET` `HEAD` `OPTIONS` / `PUT` `POST` `PATCH` / `DELETE`, in any case | `keyword.control.http.read.api` / `.write.api` / `.delete.api` |
| URI, its separators, `*` | `meta.url.api`, `punctuation.separator.path.api`, `constant.character.wildcard.api` |
| `sleep`, `assert`, `confirm`, `set`, `url` | `keyword.control.command.api` |
| `while`, `not` | `keyword.control.loop.api` |
| `url has` / `url is` and the value | `keyword.operator.api`, `string.unquoted.value.api` |
| `confirm` message | `string.unquoted.message.api` |
| `set { … }`, the names of its settings; `set @file.json` | `meta.set.api`, `meta.property-name.setting.api`; `keyword.operator.infile.api`, `meta.path.infile.api` |
| `import`, its kind, its alias, its keys | `keyword.control.import.api`, `storage.type.import.api`, `entity.name.namespace.import.api`, `meta.property-name.import.api` |
| Describe block and its `title`, `description`, `docsLink` | `meta.describe.api`, `meta.property-name.describe.api` |
| Include line | `meta.include.api` |
| `&&`, `\|\|` | `keyword.operator.logical.api` |
| `>`, `>>`, the path, `clipboard` | `keyword.operator.outfile.api`, `meta.path.outfile.api`, `support.constant.clipboard.api` |
| `@file`, `~map(type)` | `keyword.operator.infile.api`, `meta.path.infile.api`, `support.function.map.api` |
| `# …` on a line of its own or behind one | `comment.line.number-sign.api` |
| JSON bodies, with `//`, `#` and `/* */` comments | `*.json` scopes |
| A body that is one bare JSON scalar (`PUT /x true`, `PUT /x 42`) | `constant.language.json`, `constant.numeric.json` |

Marked `invalid.illegal.*`, since each stops a batch: a `&&`/`||` with nothing
on one side, a directive or include in a chain, a `>` with no path, a chain or
outfile in an `assert` or `sleep while`, a `set` line in words (`set
include-nulls`) or with anything behind its object, an unknown
import kind, an alias that is a method or directive, a body function other than
`~map(…)`, and a `{` or `[` that starts a line below the top of the file.

## Not covered

- A known member of a describe block, key of an import or setting of a `set`
  line has a scope of its own (`meta.property-name.*.api`) and the colour of
  any JSON key: a `meta` scope is not one a colour scheme colours by. An unknown
  one is a plain JSON key, not an error. Neither is a value a setting does
  not take.
- Whether an include path or an alias exists.
- A URI's endpoints and members: they are the server's to say, and no server
  is asked. A word of a URI completes from the words of the file, as in any
  file.

## Completions

`api_completions.py` is a plugin: Sublime Text loads it from `Packages/User`
as it is written. It answers in `.api` files only. What can stand where the
cursor is, is the client's to say: the plugin asks it (`api --complete`, see
`AGENTS.md` for what is offered where) and hands the answer to Sublime Text.

- The client is the `api` on the `PATH`, or where one is usually installed
  when Sublime Text was not started from a shell. The setting `api_binary`
  names another.
- It is asked in the project folder the file is in, and without a project in
  the directory of the file. That is what an `@file` and an outfile are
  completed from; a `# @basedir <path>` comment in the file names another
  directory, relative to the file.
- In quotes that are typed already (`"in"`) a name is completed alone. Where
  nothing is quoted yet the member is written whole, with a value to type
  over: `"include-nulls": true`.
- Sublime Text cuts a word at `-` and `/`, so behind `"include-n` the list
  holds `nulls`, with the whole name beside it.
- In a request's body and in a comment the plugin offers nothing of its own,
  and Sublime Text completes as it does in any file. So it does with a
  client from before `--complete`.

`cargo test --test editors` has the `python3` of the machine ask a client
through the plugin, and checks that the file holds nothing the Python 3.3 of
Sublime Text can't read.

## Formatting

*API: Format* in the command palette lays the file out as the client does
(`api --format`, see `AGENTS.md`): bodies indented, the members of a describe
block, a `set` line and an `import` too, and the words of a line a blank
apart. *API: Format, a line for each member* is `--expand`. The command is
`api_format`, with `"args": { "expanded": true }` for the second, in files
of the scope `source.api`:

```json
{ "keys": ["super+enter"], "command": "api_format", "context": [{ "key": "selector", "operand": "source.api" }] }
```

With a client from before `--format` nothing changes, and the status bar
says so.

## Checking a change

`../sample.api` holds one line of every construct, the errors included. Open it
with the syntax applied and run *Tools → Developer → Show Scope Name* on a
token. `cargo test --test editors` runs the syntax through the `syntect`
parser, which reads the same format, against `sample.api` and every `.api`
file in this repository: none of the repository's files gets an
`invalid.illegal` scope. The grammars for the other editors are ports of this
one: see `../README.md` for what a change here means for them.
