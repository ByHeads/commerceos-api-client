# Syntax highlighting for `.api` files

The grammars for the `.api` batch files that `AGENTS.md` describes, one folder
per editor format. They are compiled into the client, which installs them:

```sh
api --install-syntax sublime    # Sublime Text
api --install-syntax vscode     # VS Code
api --install-syntax cursor     # Cursor
api --install-syntax rider      # Rider and the other JetBrains IDEs
api --install-syntax vim        # Vim
api --install-syntax nvim       # Neovim
```

Run it again after the client is updated: it replaces what it wrote before.

| Folder | Format | Read by |
|---|---|---|
| `sublime/` | `API.sublime-syntax`, and `api_completions.py`, a plugin for completions | Sublime Text |
| `vscode/` | a VS Code extension around `syntaxes/api.tmLanguage.json`, a TextMate grammar | VS Code, Cursor, and JetBrains IDEs as a TextMate bundle |
| `vim/` | `syntax/`, `ftdetect/` and `ftplugin/` of a Vim package | Vim, Neovim |

## What each editor gets, and where

| Editor | What is written | What is left to do |
|---|---|---|
| Sublime Text | `API.sublime-syntax` and `api_completions.py` in `Packages/User` of Sublime's data folder | nothing |
| VS Code, Cursor | `~/.local/share/api/editors/commerceos-api.vsix`, then installed with `code --install-extension` (`cursor --install-extension`) | nothing when the editor's command is on the `PATH`. Otherwise: *Extensions: Install from VSIX…* in the command palette, and choose that file |
| Rider | the extension's folder, `~/.local/share/api/editors/commerceos-api` | once: *Settings → Editor → TextMate Bundles*, `+`, and choose that folder. The IDE reads it where it is, so a later install needs no second visit |
| Vim | `~/.vim/pack/commerceos/start/api/` (`~/vimfiles/…` on Windows) | nothing; it needs `syntax on` |
| Neovim | `~/.local/share/nvim/site/pack/commerceos/start/api/` (under `$XDG_DATA_HOME` when set; `nvim-data` on Windows) | nothing |

A file of the same name that is already there is replaced: an
`API.sublime-syntax` or an `api_completions.py` of your own in `Packages/User`
is this one afterwards.

## What is highlighted

The Sublime syntax is the reference; `sublime/README.md` lists its scopes. The
TextMate grammar is a port of it with the same scope names, and marks the same
things as errors (`invalid.illegal.*`): what would stop a batch before
anything is sent. It differs in three places:

- A JSON key has `support.type.property-name.json` as well, the scope VS Code
  themes colour a key by. A known member of a describe block, an import or a
  `set` line has it too, and so the colour of any other key, as in Sublime.
- A second describe block that comes before the first request is not marked.
- A bare JSON scalar is coloured as a body wherever it stands as a word of
  its own behind a request, not only right behind the URI.

The Vim syntax colours what a line is (method, URI, directive, body, comment,
outfile) and marks no errors.

## Changing a grammar

`sample.api` holds one line of every construct, the errors included. The three
grammars follow one syntax, so a change to it is a change to all three.

```sh
cargo test --test editors
```

holds the Sublime syntax to `sample.api` (through `syntect`, which reads the
same format), checks that it finds no error in any `.api` file of this
repository, and holds `--install-syntax`. Where there is a `python3` on the
`PATH` it also asks the Sublime plugin what it completes at a cursor: see
`sublime/README.md`. The TextMate grammar has no parser
in Rust. Its tokens for `sample.api` are kept in `sample.api.snap`, and Node
compares them:

```sh
npx -p vscode-tmgrammar-test vscode-tmgrammar-snap \
    -g editors/vscode/syntaxes/api.tmLanguage.json -s source.api editors/sample.api
```

Add `-u` to write the snapshot again after a change that was meant, and read
its diff. `cargo test --test editors` fails when the snapshot is of another
`sample.api` than the one that is there, when the two grammars mark
different text as an error, and when the grammar has changed since the
snapshot was written: `sample.api.snap.sha256` holds the SHA-256 of the
grammar the snapshot is of, so put the new one there after writing it again
(`shasum -a 256 editors/vscode/syntaxes/api.tmLanguage.json`).

The Vim syntax is held to `sample.api` too: where there is a `vim` on the
`PATH` the tests ask it for the group of each construct, and everywhere they
check that every group the file names is one it defines. To look yourself,
open `sample.api`, or ask for the group under the cursor:
`:echo synIDattr(synID(line('.'), col('.'), 1), 'name')`.

## The extension outside the client

`vscode/package.json` has version `0.0.0`: `--install-syntax` puts the
client's version in, so that an editor takes the extension of a newer client
for an update. The `.vsix` that `api --install-syntax vscode` writes is a
complete extension and can be attached to a release as it is. It is not
published to the VS Code Marketplace or to Open VSX.
