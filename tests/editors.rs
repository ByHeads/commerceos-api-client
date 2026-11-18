//! Syntax highlighting for `.api` files: the grammars of `editors/` and
//! `--install-syntax`, which writes them where an editor reads them.
//!
//! Nothing here needs a server, a network or an editor. An install goes to a
//! home directory made for the test, and the `code` it runs is a script of
//! the test's own, so no editor of this machine is touched.
//!
//! The Sublime Text syntax is run through `syntect`, which reads the same
//! format. The TextMate grammar (VS Code, Rider) has no parser in Rust: its
//! tokens for `editors/sample.api` are kept in `editors/sample.api.snap`,
//! which is written and compared by
//!
//! ```sh
//! npx -p vscode-tmgrammar-test vscode-tmgrammar-snap \
//!     -g editors/vscode/syntaxes/api.tmLanguage.json -s source.api editors/sample.api
//! ```
//!
//! (add `-u` to write it again after a change). What is held here is that the
//! snapshot is of the sample as it stands, and that both grammars mark the
//! same text as an error.
//!
//! Run with: `cargo test --test editors`

use assert_cmd::Command;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use syntect::parsing::{ParseState, ScopeStack, SyntaxDefinition, SyntaxSet, SyntaxSetBuilder};
use tempfile::tempdir;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    fs::read_to_string(repo().join(path)).unwrap_or_else(|e| panic!("{}: {}", path, e))
}

// ------------------------------------------------------------ Sublime syntax

fn sublime_syntax() -> SyntaxSet {
    let definition = SyntaxDefinition::load_from_str(&read("editors/sublime/API.sublime-syntax"), true, None)
        .expect("the Sublime syntax loads");
    let mut builder = SyntaxSetBuilder::new();
    builder.add(definition);
    builder.build()
}

/// Every stretch of `text` with the scopes it has: `(line, text, scopes)`,
/// lines counted from 1, the scopes outermost first.
fn sublime_tokens(text: &str) -> Vec<(usize, String, Vec<String>)> {
    let set = sublime_syntax();
    let mut state = ParseState::new(&set.syntaxes()[0]);
    let mut stack = ScopeStack::new();
    let mut tokens = Vec::new();
    for (number, line) in text.split_inclusive('\n').enumerate() {
        let ops = state.parse_line(line, &set).expect("the line parses");
        let mut at = 0;
        let mut emit = |from: usize, to: usize, stack: &ScopeStack| {
            if to > from && !line[from..to].trim().is_empty() {
                let scopes = stack.as_slice().iter().map(|scope| scope.build_string()).collect();
                tokens.push((number + 1, line[from..to].to_string(), scopes));
            }
        };
        for (position, op) in ops {
            emit(at, position, &stack);
            at = position;
            stack.apply(&op).expect("the scope stack holds");
        }
        emit(at, line.len(), &stack);
    }
    tokens
}

fn is_error(scopes: &[String]) -> bool {
    scopes.iter().any(|scope| scope.starts_with("invalid.illegal"))
}

/// The text a grammar marks as an error, by line, with the blanks around it
/// and between its parts left out: two grammars may cut the same text into
/// different pieces.
fn errors_by_line(tokens: impl Iterator<Item = (usize, String, bool)>) -> BTreeSet<(usize, String)> {
    let mut by_line: std::collections::BTreeMap<usize, String> = Default::default();
    for (line, text, error) in tokens {
        if error {
            by_line.entry(line).or_default().extend(text.chars().filter(|c| !c.is_whitespace()));
        }
    }
    by_line.into_iter().collect()
}

/// What `editors/sample.api` holds that stops a batch, by line.
fn sample_errors() -> BTreeSet<(usize, String)> {
    let sample = read("editors/sample.api");
    let line_of = |text: &str| {
        sample.lines().position(|line| line == text).unwrap_or_else(|| panic!("no line `{}` in the sample", text)) + 1
    };
    [
        ("import archive get { \"url\": \"x\" }", "get"),
        ("import svn cl2 { \"url\": \"x\" }", "svn"),
        ("set nulls", "nulls"),
        ("set raw maybe", "maybe"),
        ("GET /x >", ">"),
        ("PUT /x @backup~old(1)", "~old(1)"),
        ("GET /a && sleep 2", "sleep2"),
        ("GET /a ||", "||"),
        ("{ \"name\": \"body on the line under its request\" }", "{"),
    ]
    .into_iter()
    .map(|(line, error)| (line_of(line), error.to_string()))
    .collect()
}

#[test]
fn the_sublime_syntax_marks_the_errors_of_the_sample_and_nothing_else() {
    let tokens = sublime_tokens(&read("editors/sample.api"));
    let errors = errors_by_line(tokens.iter().map(|(line, text, scopes)| (*line, text.clone(), is_error(scopes))));
    assert_eq!(errors, sample_errors());
}

#[test]
fn the_sublime_syntax_scopes_each_construct_of_the_sample() {
    let sample = read("editors/sample.api");
    let tokens = sublime_tokens(&sample);
    // (the line, a stretch of it, a scope that stretch has)
    let expected = [
        ("url has localhost:5000   # gate", "url", "keyword.control.command.api"),
        ("url has localhost:5000   # gate", "has", "keyword.operator.api"),
        ("url has localhost:5000   # gate", "localhost:5000", "string.unquoted.value.api"),
        ("url has localhost:5000   # gate", "# gate", "comment.line.number-sign.api"),
        ("  \"docsLink\": \"https://link-to-docs.com\",", "docsLink", "support.type.property-name.describe.api"),
        ("import dir p @parts.json   # from a file", "import", "keyword.control.import.api"),
        ("import dir p @parts.json   # from a file", "dir", "storage.type.import.api"),
        ("import dir p @parts.json   # from a file", "p", "entity.name.namespace.import.api"),
        ("import dir p @parts.json   # from a file", "@", "keyword.operator.infile.api"),
        ("  \"ref\": \"2.1.0\"", "ref", "support.type.property-name.import.api"),
        ("cl/seeds/*.api     # glob include", "cl/seeds/", "meta.include.api"),
        ("cl/seeds/*.api     # glob include", "*", "constant.character.wildcard.api"),
        ("/tmp/seed.api", "/tmp/seed.api", "meta.include.api"),
        ("set export com.heads.seedID", "export", "variable.parameter.setting.api"),
        ("set export com.heads.seedID", "com.heads.seedID", "string.unquoted.value.api"),
        ("set fail-fast off   # back off", "off", "constant.language.api"),
        ("set timeout 30", "30", "constant.numeric.api"),
        ("assert not /people~where(givenName=Test)~count   # implied GET", "not", "keyword.control.loop.api"),
        ("sleep 500ms", "500ms", "constant.numeric.api"),
        ("sleep while not GET /people~count", "while", "keyword.control.loop.api"),
        ("sleep while not GET /people~count", "GET", "keyword.control.http.read.api"),
        ("confirm Seed a && b? # all of it is the question", "Seed a && b? # all of it is the question", "string.unquoted.message.api"),
        ("get /people#x                    # the #x is no comment", "get", "keyword.control.http.read.api"),
        ("get /people#x                    # the #x is no comment", "#", "punctuation.separator.path.api"),
        ("GET /x~where(name=\"a > b # c\") >> people.json", "a > b # c", "string.quoted.double.api"),
        ("GET /x~where(name=\"a > b # c\") >> people.json", ">>", "keyword.operator.outfile.api"),
        ("GET /people > clipboard", "clipboard", "support.constant.clipboard.api"),
        ("PUT /sync-webhooks @data.csv~map(com.heads.csv-product) > /tmp/r.json", "PUT", "keyword.control.http.write.api"),
        ("PUT /sync-webhooks @data.csv~map(com.heads.csv-product) > /tmp/r.json", "map", "support.function.map.api"),
        ("  // JS-style line comment", "// JS-style line comment", "comment.line.double-slash.json"),
        ("  \"note\": \"a # b\",", "a # b", "string.quoted.double.json"),
        ("} || POST /things [1, 2]", "||", "keyword.operator.logical.api"),
        ("} || POST /things [1, 2]", "POST", "keyword.control.http.write.api"),
        ("DELETE /people/com.mi6.id=006", "DELETE", "keyword.control.http.delete.api"),
    ];
    for (line, stretch, scope) in expected {
        let number = sample.lines().position(|l| l == line).unwrap_or_else(|| panic!("no line `{}`", line)) + 1;
        let found = tokens
            .iter()
            .any(|(n, text, scopes)| *n == number && text.trim() == stretch && scopes.iter().any(|s| s == scope));
        assert!(found, "`{}` in `{}` is not {}:\n{:#?}", stretch, line, scope, tokens.iter().filter(|t| t.0 == number).collect::<Vec<_>>());
    }
}

/// Every `.api` file of the repository that is meant to run.
fn api_files(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !["target", "dist", ".git", "editors", "scratch"].contains(&name.as_str()) {
                api_files(&path, found);
            }
        } else if name.ends_with(".api") {
            found.push(path);
        }
    }
}

#[test]
fn the_sublime_syntax_finds_no_error_in_the_files_of_the_repository() {
    let mut files = Vec::new();
    api_files(&repo(), &mut files);
    assert!(files.len() > 3, "the example files and the fixtures are there: {:?}", files);
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else { continue };
        let errors: Vec<_> = sublime_tokens(&text).into_iter().filter(|(_, _, scopes)| is_error(scopes)).collect();
        assert!(errors.is_empty(), "{}: {:#?}", file.display(), errors);
    }
}

// ---------------------------------------------------------- TextMate grammar

/// The snapshot's lines: `>` in front of a line of the sample, `#` in front
/// of a line that marks a stretch of it (`#  ^^^ scope scope`).
fn snapshot_tokens() -> (Vec<String>, Vec<(usize, String, Vec<String>)>) {
    let snapshot = read("editors/sample.api.snap");
    let mut source: Vec<String> = Vec::new();
    let mut tokens = Vec::new();
    for line in snapshot.lines() {
        if let Some(text) = line.strip_prefix('>') {
            source.push(text.to_string());
        } else if let Some(marks) = line.strip_prefix('#') {
            let from = marks.chars().take_while(|c| *c == ' ').count();
            let length = marks[from..].chars().take_while(|c| *c == '^').count();
            let text: String = source.last().unwrap().chars().skip(from).take(length).collect();
            let scopes = marks[from + length..].split_whitespace().map(str::to_string).collect();
            tokens.push((source.len(), text, scopes));
        }
    }
    (source, tokens)
}

#[test]
fn the_textmate_snapshot_is_of_the_sample_as_it_stands() {
    let (source, _) = snapshot_tokens();
    let sample = read("editors/sample.api");
    // The snapshot has a line for what stands behind the last newline too.
    assert_eq!(source, sample.split('\n').collect::<Vec<_>>(), "write the snapshot again: see the top of this file");
}

#[test]
fn the_textmate_grammar_marks_the_errors_the_sublime_syntax_marks() {
    let (_, tokens) = snapshot_tokens();
    let errors = errors_by_line(tokens.into_iter().map(|(line, text, scopes)| (line, text, is_error(&scopes))));
    assert_eq!(errors, sample_errors());
}

#[test]
fn the_grammar_files_are_json_and_name_each_other() {
    let package: serde_json::Value = serde_json::from_str(&read("editors/vscode/package.json")).unwrap();
    let grammar_entry = &package["contributes"]["grammars"][0];
    let language = &package["contributes"]["languages"][0];
    assert_eq!(language["extensions"][0], ".api");
    assert_eq!(grammar_entry["language"], language["id"]);
    for path in [grammar_entry["path"].as_str().unwrap(), language["configuration"].as_str().unwrap()] {
        let file = format!("editors/vscode/{}", path.trim_start_matches("./"));
        let _: serde_json::Value = serde_json::from_str(&read(&file)).unwrap_or_else(|e| panic!("{}: {}", file, e));
    }
    let grammar: serde_json::Value = serde_json::from_str(&read("editors/vscode/syntaxes/api.tmLanguage.json")).unwrap();
    assert_eq!(grammar["scopeName"], grammar_entry["scopeName"]);
    // every `#name` a pattern includes is in the repository
    let text = read("editors/vscode/syntaxes/api.tmLanguage.json");
    for include in text.split("\"include\": \"#").skip(1) {
        let name = include.split('"').next().unwrap();
        assert!(grammar["repository"].get(name).is_some(), "#{} is included and not defined", name);
    }
}

/// Every pattern of the TextMate grammar is a pattern. The snapshot holds
/// the grammar to the sample only as it was when the snapshot was made: a
/// later edit that no editor could read would pass every other test here.
#[test]
fn every_pattern_of_the_textmate_grammar_compiles() {
    fn walk(value: &serde_json::Value, at: &str, seen: &mut usize) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, inner) in map {
                    let here = format!("{at}/{key}");
                    match inner {
                        serde_json::Value::String(pattern) if matches!(key.as_str(), "match" | "begin" | "end" | "while") => {
                            // An `end` may refer to a group of its `begin`
                            // (`\\1`), which only exists once that matched.
                            let alone = if key == "end" || key == "while" {
                                (1..=9).fold(pattern.clone(), |text, n| text.replace(&format!("\\{n}"), "x"))
                            } else {
                                pattern.clone()
                            };
                            if let Err(e) = fancy_regex::Regex::new(&alone) {
                                panic!("{here}: {pattern:?} is no pattern: {e}");
                            }
                            *seen += 1;
                        }
                        _ => walk(inner, &here, seen),
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for (n, inner) in items.iter().enumerate() {
                    walk(inner, &format!("{at}/{n}"), seen);
                }
            }
            _ => {}
        }
    }
    let grammar: serde_json::Value = serde_json::from_str(&read("editors/vscode/syntaxes/api.tmLanguage.json")).unwrap();
    let mut seen = 0;
    walk(&grammar, "", &mut seen);
    assert!(seen > 50, "only {seen} patterns were found");
}

/// The Vim syntax reads a file from its start. A body and a describe block
/// are regions of many lines, and without this a jump into the middle of one
/// colours its lines as lines of their own.
#[test]
fn the_vim_syntax_syncs_from_the_start_of_the_file() {
    let syntax = read("editors/vim/syntax/api.vim");
    assert!(syntax.lines().any(|line| line.trim() == "syn sync fromstart"), "no `syn sync fromstart`");
    let sync = syntax.find("syn sync fromstart").unwrap();
    assert!(sync < syntax.find("b:current_syntax = 'api'").unwrap());
}

// ------------------------------------------------------------ --install-syntax

/// The client with `home` as the home directory and nothing of this machine
/// on the `PATH` but what `bin` holds.
fn api(home: &Path, bin: &Path) -> Command {
    let mut cmd = Command::cargo_bin("api").expect("api binary built");
    cmd.env("HOME", home).env("USERPROFILE", home).env("PATH", bin);
    for unset in ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "APPDATA", "LOCALAPPDATA"] {
        cmd.env_remove(unset);
    }
    cmd
}

fn stdout_lines(output: &std::process::Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout).lines().map(str::to_string).collect()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// A `name` in `bin` that writes its arguments, one a line, to `<bin>/<name>.args`
/// and exits with `code`.
#[cfg(unix)]
fn fake_command(bin: &Path, name: &str, code: i32) {
    use std::os::unix::fs::PermissionsExt;
    let script = format!(
        "#!/bin/sh\nfor arg in \"$@\"; do echo \"$arg\" >> \"{}\"; done\necho refused >&2\nexit {}\n",
        bin.join(format!("{}.args", name)).display(),
        code
    );
    let path = bin.join(name);
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn sublime_packages(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Sublime Text/Packages")
    } else {
        home.join(".config/sublime-text/Packages")
    }
}

#[test]
#[cfg(unix)]
fn install_syntax_for_sublime_writes_the_syntax_into_its_user_package() {
    let (home, bin) = (tempdir().unwrap(), tempdir().unwrap());

    // No Sublime Text: nothing is made up for it.
    let output = api(home.path(), bin.path()).args(["--install-syntax", "sublime"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).starts_with("error: Sublime Text has no folder at "), "{}", stderr(&output));
    assert!(stdout_lines(&output).is_empty());
    assert!(!sublime_packages(home.path()).exists());

    fs::create_dir_all(sublime_packages(home.path())).unwrap();
    let target = sublime_packages(home.path()).join("User/API.sublime-syntax");
    for _ in 0..2 {
        let output = api(home.path(), bin.path()).args(["--install-syntax", "Sublime"]).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(stdout_lines(&output), [target.display().to_string()]);
        assert_eq!(fs::read_to_string(&target).unwrap(), read("editors/sublime/API.sublime-syntax"));
    }
}

#[test]
#[cfg(unix)]
fn install_syntax_for_vim_and_neovim_writes_a_package() {
    let (home, bin) = (tempdir().unwrap(), tempdir().unwrap());
    let files = ["syntax/api.vim", "ftdetect/api.vim", "ftplugin/api.vim"];
    for (editor, package) in
        [("vim", ".vim/pack/commerceos/start/api"), ("nvim", ".local/share/nvim/site/pack/commerceos/start/api")]
    {
        let output = api(home.path(), bin.path()).args(["--install-syntax", editor]).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let package = home.path().join(package);
        assert_eq!(stdout_lines(&output), files.map(|file| package.join(file).display().to_string()));
        for file in files {
            assert_eq!(fs::read_to_string(package.join(file)).unwrap(), read(&format!("editors/vim/{}", file)));
        }
    }

    // Neovim's data directory may be somewhere else.
    let data = tempdir().unwrap();
    let output = api(home.path(), bin.path())
        .env("XDG_DATA_HOME", data.path())
        .args(["--install-syntax", "nvim"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(data.path().join("nvim/site/pack/commerceos/start/api/syntax/api.vim").is_file());
}

#[test]
#[cfg(unix)]
fn install_syntax_for_rider_writes_a_bundle_and_says_the_step_that_is_left() {
    let (home, bin) = (tempdir().unwrap(), tempdir().unwrap());
    let output = api(home.path(), bin.path()).args(["--install-syntax", "rider"]).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let bundle = home.path().join(".local/share/api/editors/commerceos-api");
    assert_eq!(
        stdout_lines(&output),
        ["package.json", "language-configuration.json", "syntaxes/api.tmLanguage.json"]
            .map(|file| bundle.join(file).display().to_string())
    );
    assert!(stderr(&output).contains("TextMate Bundles"), "{}", stderr(&output));
    assert!(stderr(&output).trim_end().ends_with(&bundle.display().to_string()), "{}", stderr(&output));
    assert_eq!(
        fs::read_to_string(bundle.join("syntaxes/api.tmLanguage.json")).unwrap(),
        read("editors/vscode/syntaxes/api.tmLanguage.json")
    );
    // The bundle has the client's version, where the file of the repository has none.
    let package: serde_json::Value = serde_json::from_str(&fs::read_to_string(bundle.join("package.json")).unwrap()).unwrap();
    assert_eq!(package["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(package["contributes"]["grammars"][0]["scopeName"], "source.api");
}

/// The files of a `.vsix`, by name.
fn unzip(path: &Path) -> std::collections::BTreeMap<String, String> {
    use std::io::Read;
    let mut archive = zip::ZipArchive::new(fs::File::open(path).unwrap()).expect("the .vsix is a zip");
    (0..archive.len())
        .map(|index| {
            let mut entry = archive.by_index(index).unwrap();
            let mut text = String::new();
            entry.read_to_string(&mut text).unwrap();
            (entry.name().unwrap().to_string(), text)
        })
        .collect()
}

#[test]
#[cfg(unix)]
fn install_syntax_for_vscode_and_cursor_hands_a_vsix_to_the_editors_command() {
    for editor in ["vscode", "cursor"] {
        let command = if editor == "vscode" { "code" } else { "cursor" };
        let (home, bin) = (tempdir().unwrap(), tempdir().unwrap());
        let vsix = home.path().join(".local/share/api/editors/commerceos-api.vsix");

        // The command is not there: the file is written, and the rest is said.
        let output = api(home.path(), bin.path()).args(["--install-syntax", editor]).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(stdout_lines(&output), [vsix.display().to_string()]);
        assert!(stderr(&output).starts_with(&format!("error: `{}` is not on the PATH", command)), "{}", stderr(&output));
        assert!(stderr(&output).contains("Install from VSIX"), "{}", stderr(&output));

        let files = unzip(&vsix);
        assert_eq!(
            files.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "[Content_Types].xml",
                "extension.vsixmanifest",
                "extension/language-configuration.json",
                "extension/package.json",
                "extension/syntaxes/api.tmLanguage.json",
            ]
        );
        let version = env!("CARGO_PKG_VERSION");
        let package: serde_json::Value = serde_json::from_str(&files["extension/package.json"]).unwrap();
        assert_eq!(package["version"], version);
        let manifest = &files["extension.vsixmanifest"];
        assert!(
            manifest.contains(&format!(r#"Id="commerceos-api" Version="{}" Publisher="heads""#, version)),
            "{}",
            manifest
        );
        assert!(manifest.contains(r#"Path="extension/package.json""#), "{}", manifest);
        assert_eq!(files["extension/syntaxes/api.tmLanguage.json"], read("editors/vscode/syntaxes/api.tmLanguage.json"));

        // The command is there: it is asked to install that file.
        fake_command(bin.path(), command, 0);
        let output = api(home.path(), bin.path()).args(["--install-syntax", editor]).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(stdout_lines(&output), [vsix.display().to_string()]);
        assert_eq!(
            fs::read_to_string(bin.path().join(format!("{}.args", command))).unwrap().lines().collect::<Vec<_>>(),
            ["--install-extension", &vsix.display().to_string(), "--force"]
        );

        // The command refuses: what it said is passed on.
        fake_command(bin.path(), command, 3);
        let output = api(home.path(), bin.path()).args(["--install-syntax", editor]).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr(&output).starts_with(&format!("error: `{}` could not install the extension: refused", command)),
            "{}",
            stderr(&output)
        );
    }
}

#[test]
fn install_syntax_refuses_an_editor_it_does_not_know_and_what_stands_beside_it() {
    let (home, bin) = (tempdir().unwrap(), tempdir().unwrap());
    let cases: [(&[&str], &str); 5] = [
        (&["--install-syntax", "emacs"], "error: unknown editor `emacs` (one of sublime, vscode, cursor, rider, vim, nvim)\n"),
        (&["--install-syntax"], "error: --install-syntax needs a value\n"),
        (
            &["--install-syntax", "vim", "GET", "/people"],
            "error: --install-syntax vim installs files and GET /people is a request: give one of the two\n",
        ),
        (
            &["--install-syntax", "vim", "-a", "seed.api"],
            "error: --install-syntax vim installs files and -a seed.api runs a file: give one of the two\n",
        ),
        (
            &["--install-syntax", "vim", "--describe", "seed.api"],
            "error: --install-syntax vim installs files and --describe seed.api prints a document: give one of the two\n",
        ),
    ];
    for (args, said) in cases {
        let output = api(home.path(), bin.path()).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{:?}", args);
        assert_eq!(stderr(&output), said, "{:?}", args);
        assert!(stdout_lines(&output).is_empty(), "{:?}", args);
    }
    // Nothing was written for any of them.
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}
