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
| `sublime/` | `API.sublime-syntax` | Sublime Text |
| `vscode/` | a VS Code extension around `syntaxes/api.tmLanguage.json`, a TextMate grammar | VS Code, Cursor, and JetBrains IDEs as a TextMate bundle |
| `vim/` | `syntax/`, `ftdetect/` and `ftplugin/` of a Vim package | Vim, Neovim |

## What each editor gets, and where

| Editor | What is written | What is left to do |
|---|---|---|
| Sublime Text | `API.sublime-syntax` in `Packages/User` of Sublime's data folder | nothing |
| VS Code, Cursor | `~/.local/share/api/editors/commerceos-api.vsix`, then installed with `code --install-extension` (`cursor --install-extension`) | nothing when the editor's command is on the `PATH`. Otherwise: *Extensions: Install from VSIX…* in the command palette, and choose that file |
| Rider | the extension's folder, `~/.local/share/api/editors/commerceos-api` | once: *Settings → Editor → TextMate Bundles*, `+`, and choose that folder. The IDE reads it where it is, so a later install needs no second visit |
| Vim | `~/.vim/pack/commerceos/start/api/` (`~/vimfiles/…` on Windows) | nothing; it needs `syntax on` |
| Neovim | `~/.local/share/nvim/site/pack/commerceos/start/api/` (under `$XDG_DATA_HOME` when set; `nvim-data` on Windows) | nothing |

A file of the same name that is already there is replaced: an
`API.sublime-syntax` of your own in `Packages/User` is this one afterwards.

## What is highlighted

The Sublime syntax is the reference; `sublime/README.md` lists its scopes. The
TextMate grammar is a port of it with the same scope names, and marks the same
things as errors (`invalid.illegal.*`): what would stop a batch before
anything is sent. It differs in two places:

- A JSON key has `support.type.property-name.json` as well, the scope VS Code
  themes colour a key by, and a known member of a describe block or an import
  has `keyword.other.member.api`, so that it stands out from an unknown one.
- A second describe block that comes before the first request is not marked.

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
repository, and holds `--install-syntax`. The TextMate grammar has no parser
in Rust. Its tokens for `sample.api` are kept in `sample.api.snap`, and Node
compares them:

```sh
npx -p vscode-tmgrammar-test vscode-tmgrammar-snap \
    -g editors/vscode/syntaxes/api.tmLanguage.json -s source.api editors/sample.api
```

Add `-u` to write the snapshot again after a change that was meant, and read
its diff. `cargo test --test editors` fails when the snapshot is of another
`sample.api` than the one that is there, and when the two grammars mark
different text as an error.

For the Vim syntax, open `sample.api` and look, or ask for the group under the
cursor: `:echo synIDattr(synID(line('.'), col('.'), 1), 'name')`.

## The extension outside the client

`vscode/package.json` has version `0.0.0`: `--install-syntax` puts the
client's version in, so that an editor takes the extension of a newer client
for an update. The `.vsix` that `api --install-syntax vscode` writes is a
complete extension and can be attached to a release as it is. It is not
published to the VS Code Marketplace or to Open VSX.
