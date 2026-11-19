# Sublime Text highlighting and completions for `.api` files

`API.sublime-syntax` highlights `.api` batch files as `AGENTS.md` describes
them, and `api_completions.py` completes what can stand where the cursor is.

## Install

```sh
api --install-syntax sublime
```

writes both files to Sublime's `Packages/User` folder. Files ending in `.api`
pick them up. By hand: copy the two files to that folder
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
- A URI's endpoints and members: they are the server's to say, and the
  plugin asks no server. A word of a URI completes from the words of the
  file, as in any file.

## Completions

`api_completions.py` is a plugin: Sublime Text loads it from `Packages/User`
as it is written. It answers in `.api` files only, by where the cursor is:

| Where | What is offered |
|---|---|
| The start of a line | the methods, the directives, and what can be included: directories, `.api` files and import aliases |
| In `set { … }` | the settings the object does not have yet; behind a `:`, the values the setting takes |
| Behind `import` | `git`, `dir`, `archive` |
| In the object of an `import` | the keys of its kind |
| In a describe block | `title`, `description`, `docsLink`; in the first two, locales |
| Behind `url`, `sleep`, `assert`, `while`, `&&`, `\|\|` | `has` / `is`, `while`, `not`, the methods |
| Behind a `~` of a URI | the operators the client completes at its prompt |
| Behind `>` | `clipboard` (not behind `>>`) and paths |
| Behind `@` | paths; behind a `~` there, `map(` |

In quotes that are typed already (`"in"`) a name is completed alone. Where
nothing is quoted yet the member is written whole, with a value to type over:
`"include-nulls": true`.

**Paths.** What a path is relative to is what the client takes it to be
relative to:

- An include, and the `"path"` of an `import dir`: the directory of the file.
- Behind an alias (`cl/…`): the directory the alias stands for. For an
  `import dir` that is read from its line. For an `import git` or an `import
  archive` the plugin asks the client (`api --imports`, of the file's
  import lines as they stand, saved or not) in the background, and offers
  nothing until it has the answer. An import that is not in the client's
  cache is fetched by that, as a run would fetch it. The client is the `api` on the `PATH`, or the one the setting
  `api_binary` names.
- An `@file` body, the `@file` of a `set` or an `import`, and an outfile: the
  working directory of the run, which an editor does not know. A comment in
  the file says it, relative to the file:

  ```
  # @basedir ..
  ```

  Without one it is the project folder the file is in, and without a project
  the directory of the file. The client does not read the comment.

In a request's body and in a comment the plugin offers nothing of its own,
and Sublime Text completes as it does in any file.

The half of the plugin that decides what to offer is plain Python that knows
nothing of the editor. `cargo test --test editors` runs it with the `python3`
of the machine, a cursor at a time, and checks that the file holds nothing
the Python 3.3 of Sublime Text can't read.

## Checking a change

`../sample.api` holds one line of every construct, the errors included. Open it
with the syntax applied and run *Tools → Developer → Show Scope Name* on a
token. `cargo test --test editors` runs the syntax through the `syntect`
parser, which reads the same format, against `sample.api` and every `.api`
file in this repository: none of the repository's files gets an
`invalid.illegal` scope. The grammars for the other editors are ports of this
one: see `../README.md` for what a change here means for them.
