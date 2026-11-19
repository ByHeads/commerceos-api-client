# Sublime Text highlighting for `.api` files

`API.sublime-syntax` highlights `.api` batch files as `AGENTS.md` describes them.

## Install

```sh
api --install-syntax sublime
```

writes the syntax to Sublime's `Packages/User` folder. Files ending in `.api`
pick it up. By hand: copy `API.sublime-syntax` to that folder
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
- A `# @basedir <path>` comment is highlighted for a path-completion plugin
  that is not part of this folder. The client does not read it.

## Checking a change

`../sample.api` holds one line of every construct, the errors included. Open it
with the syntax applied and run *Tools → Developer → Show Scope Name* on a
token. `cargo test --test editors` runs the syntax through the `syntect`
parser, which reads the same format, against `sample.api` and every `.api`
file in this repository: none of the repository's files gets an
`invalid.illegal` scope. The grammars for the other editors are ports of this
one: see `../README.md` for what a change here means for them.
