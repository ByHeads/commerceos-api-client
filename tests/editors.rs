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
        ("set include-nulls", "include-nulls"),
        ("set { \"raw\": true } maybe", "maybe"),
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
        ("  \"docsLink\": \"https://link-to-docs.com\",", "docsLink", "meta.property-name.describe.api"),
        ("import dir p @parts.json   # from a file", "import", "keyword.control.import.api"),
        ("import dir p @parts.json   # from a file", "dir", "storage.type.import.api"),
        ("import dir p @parts.json   # from a file", "p", "entity.name.namespace.import.api"),
        ("import dir p @parts.json   # from a file", "@", "keyword.operator.infile.api"),
        ("  \"ref\": \"2.1.0\"", "ref", "meta.property-name.import.api"),
        ("cl/seeds/*.api     # glob include", "cl/seeds/", "meta.include.api"),
        ("cl/seeds/*.api     # glob include", "*", "constant.character.wildcard.api"),
        ("/tmp/seed.api", "/tmp/seed.api", "meta.include.api"),
        ("set { \"export\": \"com.heads.seedID\" }", "set", "keyword.control.command.api"),
        ("set { \"export\": \"com.heads.seedID\" }", "export", "meta.property-name.setting.api"),
        ("set { \"export\": \"com.heads.seedID\" }", "com.heads.seedID", "string.quoted.double.json"),
        ("  \"fail-fast\": false,", "fail-fast", "meta.property-name.setting.api"),
        ("  \"fail-fast\": false,", "false", "constant.language.json"),
        ("  \"include-nulls\": true,   // nulls too", "// nulls too", "comment.line.double-slash.json"),
        ("  \"timeout\": 30", "30", "constant.numeric.json"),
        ("  \"timeout\": 30", "30", "meta.set.api"),
        ("}   # back off", "# back off", "comment.line.number-sign.api"),
        ("set @settings.json   # from a file", "@", "keyword.operator.infile.api"),
        ("set @settings.json   # from a file", "settings.json", "meta.path.infile.api"),
        ("set @settings.json   # from a file", "# from a file", "comment.line.number-sign.api"),
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
        ("PUT /flags/open true", "true", "constant.language.json"),
        ("PUT /flags/limit 42 > /tmp/limit.json   # a scalar body", "42", "constant.numeric.json"),
        ("PUT /flags/limit 42 > /tmp/limit.json   # a scalar body", ">", "keyword.operator.outfile.api"),
        ("GET /a && PUT /flags/open null || PUT /flags/limit -1.5e3", "null", "constant.language.json"),
        ("GET /a && PUT /flags/open null || PUT /flags/limit -1.5e3", "||", "keyword.operator.logical.api"),
        ("GET /a && PUT /flags/open null || PUT /flags/limit -1.5e3", "-1.5e3", "constant.numeric.json"),
        ("assert PUT /flags/check false", "false", "constant.language.json"),
        ("  // JS-style line comment", "// JS-style line comment", "comment.line.double-slash.json"),
        ("  \"note\": \"a # b\",", "a # b", "string.quoted.double.json"),
        ("} || POST /things [1, 2]", "||", "keyword.operator.logical.api"),
        ("} || POST /things [1, 2]", "POST", "keyword.control.http.write.api"),
        ("DELETE /people/com.mi6.id=006", "DELETE", "keyword.control.http.delete.api"),
        ("url is https://cos.example.com", "is", "keyword.operator.api"),
        ("  \"token_env\": \"AR_TOKEN\",", "token_env", "meta.property-name.import.api"),
        ("  \"description\": { \"sv-SE\": \"Ett exempel\" },", "description", "meta.property-name.describe.api"),
        ("set { \"stream\": true, \"ndjson\": null }", "ndjson", "meta.property-name.setting.api"),
        ("set { \"stream\": true, \"ndjson\": null }", "null", "constant.language.json"),
        ("sleep 1.5s", "1.5s", "constant.numeric.api"),
        ("HEAD /people", "HEAD", "keyword.control.http.read.api"),
        ("OPTIONS /people", "OPTIONS", "keyword.control.http.read.api"),
        ("  # shell-style line comment", "# shell-style line comment", "comment.line.number-sign.json"),
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

/// The snapshot is of the grammar as it stands. An edit to the grammar that
/// still compiles changes what an editor shows and passes every test that
/// reads the snapshot, until the snapshot is written again: the hash beside
/// it is of the grammar it was written from.
#[test]
fn the_textmate_snapshot_is_of_the_grammar_as_it_stands() {
    use sha2::{Digest, Sha256};
    let grammar = fs::read(repo().join("editors/vscode/syntaxes/api.tmLanguage.json")).unwrap();
    let now: String = Sha256::digest(&grammar).iter().map(|byte| format!("{:02x}", byte)).collect();
    assert_eq!(
        read("editors/sample.api.snap.sha256").trim(),
        now,
        "the TextMate grammar has changed since editors/sample.api.snap was written: write the snapshot again \
         (see the top of this file), read its diff, and put the grammar's SHA-256 in editors/sample.api.snap.sha256"
    );
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

/// Every group the Vim syntax names is one it defines: a group that follows
/// another (`nextgroup=`), one that is contained (`contains=`) and one that
/// is given a colour. A name that is misspelt, or left behind when its rule
/// was taken out, is no error to Vim: the text is simply not coloured.
#[test]
fn every_group_the_vim_syntax_names_is_defined() {
    let syntax = read("editors/vim/syntax/api.vim");
    let rules: Vec<&str> = syntax.lines().map(str::trim).filter(|line| line.starts_with("syn ")).collect();
    let mut defined = BTreeSet::new();
    for rule in &rules {
        let mut words = rule.split_whitespace().skip(1);
        match (words.next(), words.next()) {
            (Some("match" | "region"), Some(name)) => defined.insert(name.to_string()),
            (Some("cluster"), Some(name)) => defined.insert(format!("@{name}")),
            _ => false,
        };
    }
    for rule in &rules {
        for word in rule.split_whitespace() {
            // A pattern may hold the text `contains=`: only a word of names.
            let Some(names) = word.strip_prefix("nextgroup=").or_else(|| word.strip_prefix("contains=")) else { continue };
            if !names.chars().all(|c| c.is_ascii_alphanumeric() || c == ',' || c == '@') {
                continue;
            }
            for name in names.split(',') {
                assert!(defined.contains(name), "`{name}` is named and not defined: {rule}");
            }
        }
    }
    // What `matchgroup=` names is a group too.
    defined.insert("apiBrace".to_string());
    let mut coloured = BTreeSet::new();
    for line in syntax.lines().filter(|line| line.starts_with("hi def link ")) {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(defined.contains(words[3]), "a colour for `{}`, which no rule defines", words[3]);
        assert!(!words[4].starts_with("api") || defined.contains(words[4]), "`{}` is linked to `{}`, which no rule defines", words[3], words[4]);
        coloured.insert(words[3].to_string());
    }
    // A region that only holds others has no colour of its own.
    let plain = ["apiJsonObject", "apiJsonArray", "apiBodyObject", "apiBodyArray", "apiDescribe", "apiUri", "apiImpliedUri"];
    for name in defined.iter().filter(|name| !name.starts_with('@')) {
        assert!(coloured.contains(name) || plain.contains(&name.as_str()), "`{name}` is defined and has no colour");
    }
}

/// The group Vim gives each character of the sample, by line (from 0) and
/// byte column. `None` where there is no `vim` to ask: the test that needs
/// it says so and holds nothing.
#[cfg(unix)]
fn vim_groups() -> Option<Vec<Vec<String>>> {
    let home = tempdir().unwrap();
    let script = home.path().join("dump.vim");
    let dumped = home.path().join("groups.txt");
    // Vim's own fallback syntax is cleared first: the file under test
    // leaves a buffer alone that has a syntax already.
    fs::write(
        &script,
        "syntax on\nsyntax clear\nunlet! b:current_syntax\nexecute 'source ' . fnameescape(g:api_syntax)\n\
         let s:rows = []\n\
         for s:lnum in range(1, line('$'))\n\
         \x20 let s:row = []\n\
         \x20 for s:col in range(1, col([s:lnum, '$']) - 1)\n\
         \x20   call add(s:row, synIDattr(synID(s:lnum, s:col, 1), 'name'))\n\
         \x20 endfor\n\
         \x20 call add(s:rows, join(s:row, ','))\n\
         endfor\n\
         call writefile(s:rows, g:api_dump)\nqa!\n",
    )
    .unwrap();
    let mut vim = std::process::Command::new("vim");
    vim.args(["-e", "-s", "-u", "NONE", "-i", "NONE", "-N"])
        .arg("--cmd")
        .arg(format!("let g:api_syntax='{}'", repo().join("editors/vim/syntax/api.vim").display()))
        .arg("--cmd")
        .arg(format!("let g:api_dump='{}'", dumped.display()))
        .arg("-S")
        .arg(&script)
        .arg(repo().join("editors/sample.api"))
        .env("HOME", home.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = vim.spawn().ok()?;
    let started = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("vim did not end");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let rows = fs::read_to_string(&dumped).expect("vim wrote no groups: the syntax file did not load");
    Some(rows.lines().map(|row| row.split(',').map(str::to_string).collect()).collect())
}

/// The Vim syntax colours each construct of the sample as what it is, in
/// Vim itself: a rule that is taken out, or a pattern Vim can't read, fails
/// here. Holds nothing on a machine without `vim`.
#[cfg(unix)]
#[test]
fn the_vim_syntax_gives_each_construct_of_the_sample_its_group() {
    let Some(groups) = vim_groups() else {
        eprintln!("skipped: no vim on the PATH");
        return;
    };
    let sample = read("editors/sample.api");
    // (the line, a stretch of it, the group its first character has)
    let expected = [
        ("# Sample exercising every construct of the proposed syntax", "# Sample", "apiComment"),
        ("url has localhost:5000   # gate", "url", "apiDirective"),
        ("url has localhost:5000   # gate", "has", "apiUrlOp"),
        ("url has localhost:5000   # gate", "localhost:5000", "apiValue"),
        ("url has localhost:5000   # gate", "# gate", "apiTrailComment"),
        ("url is https://cos.example.com", "is", "apiUrlOp"),
        ("  \"docsLink\": \"https://link-to-docs.com\",", "\"docsLink\"", "apiJsonKey"),
        ("  \"docsLink\": \"https://link-to-docs.com\",", "\"https", "apiJsonString"),
        ("import dir p @parts.json   # from a file", "import", "apiImport"),
        ("import dir p @parts.json   # from a file", "dir", "apiImportKind"),
        ("import dir p @parts.json   # from a file", "p ", "apiAlias"),
        ("import dir p @parts.json   # from a file", "@", "apiInfileOp"),
        ("import archive ar {", "archive", "apiImportKind"),
        ("  \"token_env\": \"AR_TOKEN\",", "\"token_env\"", "apiJsonKey"),
        ("cl/seeds/*.api     # glob include", "cl/", "apiInclude"),
        ("cl/seeds/*.api     # glob include", "*", "apiWildcard"),
        ("/tmp/seed.api", "/tmp", "apiInclude"),
        ("set { \"export\": \"com.heads.seedID\" }", "set", "apiDirective"),
        ("set { \"export\": \"com.heads.seedID\" }", "{", "apiBrace"),
        ("set { \"export\": \"com.heads.seedID\" }", "\"export\"", "apiJsonKey"),
        ("set { \"export\": \"com.heads.seedID\" }", "\"com.heads", "apiJsonString"),
        ("  \"fail-fast\": false,", "\"fail-fast\"", "apiJsonKey"),
        ("  \"fail-fast\": false,", "false", "apiJsonConst"),
        ("  \"timeout\": 30", "30", "apiJsonNumber"),
        ("}   # back off", "# back", "apiTrailComment"),
        ("set @settings.json   # from a file", "@", "apiInfileOp"),
        ("set @settings.json   # from a file", "settings", "apiInfile"),
        ("set @settings.json   # from a file", "# from", "apiTrailComment"),
        ("assert GET /companies/com.heads.seedID=ours", "assert", "apiDirective"),
        ("assert GET /companies/com.heads.seedID=ours", "GET", "apiSegRead"),
        ("assert not /people~where(givenName=Test)~count   # implied GET", "not", "apiNot"),
        ("sleep 500ms", "500ms", "apiDuration"),
        ("sleep 1.5s", "1.5s", "apiDuration"),
        ("sleep while not GET /people~count", "while", "apiWhile"),
        ("sleep while not GET /people~count", "not", "apiNot"),
        ("sleep while not GET /people~count", "GET", "apiSegRead"),
        ("confirm Seed a && b? # all of it is the question", "Seed", "apiMessage"),
        ("confirm Seed a && b? # all of it is the question", "# all", "apiMessage"),
        ("/people~take(5)", "people", "apiImpliedUri"),
        ("HEAD /people", "HEAD", "apiMethodRead"),
        ("get /people#x                    # the #x is no comment", "get", "apiMethodRead"),
        ("get /people#x                    # the #x is no comment", "#x", "apiUriPunct"),
        ("get /people#x                    # the #x is no comment", "# the", "apiTrailComment"),
        ("GET /x~where(name=\"a > b # c\") >> people.json", "\"a > b", "apiUriString"),
        ("GET /x~where(name=\"a > b # c\") >> people.json", ">>", "apiRedirect"),
        ("GET /x~where(name=\"a > b # c\") >> people.json", "people.json", "apiOutfile"),
        ("GET /people > clipboard", "clipboard", "apiClipboard"),
        ("PUT /sync-webhooks @data.csv~map(com.heads.csv-product) > /tmp/r.json", "PUT", "apiMethodWrite"),
        ("PUT /sync-webhooks @data.csv~map(com.heads.csv-product) > /tmp/r.json", "~map", "apiMap"),
        ("PUT /flags/open true", "true", "apiBodyConst"),
        ("PUT /flags/limit 42 > /tmp/limit.json   # a scalar body", "42", "apiBodyNumber"),
        ("PUT /flags/limit 42 > /tmp/limit.json   # a scalar body", "> /tmp", "apiRedirect"),
        ("GET /a && PUT /flags/open null || PUT /flags/limit -1.5e3", "null", "apiBodyConst"),
        ("GET /a && PUT /flags/open null || PUT /flags/limit -1.5e3", "||", "apiChain"),
        ("GET /a && PUT /flags/open null || PUT /flags/limit -1.5e3", "-1.5e3", "apiBodyNumber"),
        ("assert PUT /flags/check false", "false", "apiBodyConst"),
        ("  // JS-style line comment", "// JS", "apiJsonComment"),
        ("  # shell-style line comment", "# shell", "apiJsonComment"),
        ("     spanning lines */", "spanning", "apiJsonComment"),
        ("  \"n\": 1.5, \"ok\": true", "1.5", "apiJsonNumber"),
        ("  \"n\": 1.5, \"ok\": true", "true", "apiJsonConst"),
        ("} || POST /things [1, 2]", "||", "apiChain"),
        ("} || POST /things [1, 2]", "POST", "apiSegWrite"),
        ("DELETE /people/com.mi6.id=006", "DELETE", "apiMethodDelete"),
    ];
    for (line, stretch, group) in expected {
        let number = sample.lines().position(|l| l == line).unwrap_or_else(|| panic!("no line `{}`", line));
        let column = line.find(stretch).unwrap_or_else(|| panic!("no `{}` in `{}`", stretch, line));
        assert_eq!(groups[number][column], group, "`{}` in `{}`: {:?}", stretch, line, groups[number]);
    }
}

// ------------------------------------------------- Sublime Text completions

/// What `editors/sublime/api_completions.py` offers at the `|` of each text:
/// `(typed, names, snippets)`, `Some(None)` in a URI and `None` where it
/// leaves the editor to itself. The second list is what Sublime Text is
/// handed when its own prefix is the second string of the case.
///
/// The half of the plugin that decides this is plain Python, run here by
/// the `python3` of the machine. `None` for the whole where there is none:
/// the tests that need it say so and hold nothing.
#[allow(clippy::type_complexity)]
fn sublime_completions(dir: &Path, cases: &[(&str, &str)]) -> Option<Vec<serde_json::Value>> {
    let driver = r#"
import json, sys
sys.path.insert(0, sys.argv[1])
import api_completions as plugin
root = sys.argv[2]
out = []
for marked, prefix in json.load(sys.stdin):
    offset = marked.rindex('|')  # the last one: a chain has a `||` of its own
    text = marked[:offset] + marked[offset + 1:]
    aliases = plugin.dir_aliases(text, root)
    result = plugin.complete(text, offset, root, plugin.base_dir(text, root), aliases)
    if result is not None and 'items' in result:
        result['sublime'] = plugin.to_sublime(result, prefix)
    out.append(result)
json.dump(out, sys.stdout)
"#;
    let mut python = std::process::Command::new("python3");
    python
        .args(["-I", "-B", "-c", driver])
        .arg(repo().join("editors/sublime"))
        .arg(dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = python.spawn().ok()?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(serde_json::to_string(cases).unwrap().as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "the plugin failed:\n{}", String::from_utf8_lossy(&output.stderr));
    Some(serde_json::from_slice(&output.stdout).expect("the driver prints JSON"))
}

fn names_of(result: &serde_json::Value) -> Vec<String> {
    result["items"].as_array().unwrap().iter().map(|item| item[0].as_str().unwrap().to_string()).collect()
}

fn snippet_of(result: &serde_json::Value, name: &str) -> String {
    let items = result["items"].as_array().unwrap();
    let item = items.iter().find(|item| item[0] == name).unwrap_or_else(|| panic!("no `{}` in {}", name, result));
    item[1].as_str().unwrap().to_string()
}

/// What Sublime Text is handed: `(trigger, contents)`, the trigger without
/// the note behind its tab.
fn handed(result: &serde_json::Value) -> Vec<(String, String)> {
    result["sublime"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            let trigger = pair[0].as_str().unwrap().split('\t').next().unwrap().to_string();
            (trigger, pair[1].as_str().unwrap().to_string())
        })
        .collect()
}

/// A directory with what the path cases complete to.
fn completion_fixture() -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    for file in [
        "seed.api",
        "settings.json",
        "notes.txt",
        ".hidden.api",
        "shared/users.api",
        "shared/data.json",
        "shared/deep/more.api",
        "cloddy/sv.api",
        "cloddy/seeds/one.api",
        "work/body.json",
    ] {
        let path = dir.path().join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "").unwrap();
    }
    dir
}

#[test]
fn the_sublime_plugin_completes_the_members_of_a_set_an_import_and_a_describe_block() {
    let dir = completion_fixture();
    let cases = [
        // the line of the screenshot: a name being typed in its quotes
        ("set {\n  \"in|\"\n}\n", "in"),
        ("set { \"include-nulls\": true, \"|\" }", ""),
        ("set {\n  |\n}", ""),
        ("set { \"include-n|\" }", "n"),
        ("set { \"raw\": | }", ""),
        ("set { \"timeout\": | }", ""),
        ("set { \"raw\": true | }", ""),
        ("set { \"export\": \"com.|\" }", ""),
        ("import git cl {\n  \"|\"\n}", ""),
        ("import dir cl { \"|\" }", ""),
        ("import archive ar { \"url\": \"x\", | }", ""),
        ("{\n  \"|\"\n}\nGET /a", ""),
        ("{\n  \"title\": { \"sv-SE\": \"Katalog\", \"|\" }\n}", ""),
        ("{ \"owner\": { \"|\" } }", ""),
        // a request's body, a comment, a `confirm`: not this plugin's
        ("PUT /people/x { \"na|\" }", "na"),
        ("PUT /things {\n  // a |\n}", ""),
        ("# set { \"|\" }", ""),
        ("confirm Seed { \"|", ""),
        ("GET /a   # then set { \"|", ""),
        // a body that closed is behind the cursor
        ("PUT /a { \"x\": 1 }\nset { \"|\" }", ""),
        ("PUT /a {\n  \"x\": \"a } b\"\n}\nimport git cl { \"|\" }", ""),
    ];
    let Some(got) = sublime_completions(dir.path(), &cases) else {
        eprintln!("skipped: no python3 on the PATH");
        return;
    };
    let settings = ["export", "include-nulls", "fail-fast", "ndjson", "raw", "stream", "timeout"];

    assert_eq!(got[0]["typed"], "in");
    assert_eq!(names_of(&got[0]), settings);
    assert_eq!(snippet_of(&got[0], "include-nulls"), "include-nulls");
    // a setting the object has is not offered again
    assert_eq!(names_of(&got[1]), ["export", "fail-fast", "ndjson", "raw", "stream", "timeout"]);
    // nothing quoted yet: the member whole, with a value to type over
    assert_eq!(names_of(&got[2]), settings);
    assert_eq!(snippet_of(&got[2], "include-nulls"), "\"include-nulls\": ${1:true}");
    assert_eq!(snippet_of(&got[2], "timeout"), "\"timeout\": ${1:30}");
    assert_eq!(snippet_of(&got[2], "export"), "\"export\": \"${1:com.heads.seedID}\"");
    // Sublime Text cuts a word at `-`: what it replaces is `n`, of `include-n`
    assert_eq!(handed(&got[3]), [("nulls".to_string(), "nulls".to_string())]);
    assert_eq!(names_of(&got[4]), ["true", "false", "null"]);
    assert_eq!(names_of(&got[5]), ["0", "null"]);
    assert!(names_of(&got[6]).is_empty(), "{}", got[6]);
    assert!(names_of(&got[7]).is_empty(), "{}", got[7]);
    assert_eq!(names_of(&got[8]), ["url", "ref", "path"]);
    assert_eq!(names_of(&got[9]), ["path"]);
    assert_eq!(names_of(&got[10]), ["sha256", "token_env", "path"]);
    assert_eq!(snippet_of(&got[10], "sha256"), "\"sha256\": \"$1\"");
    assert_eq!(names_of(&got[11]), ["title", "description", "docsLink"]);
    assert_eq!(names_of(&got[12])[..2], ["en-US", "nb-NO"]);
    assert!(names_of(&got[13]).is_empty(), "{}", got[13]);
    for case in 14..19 {
        assert!(got[case].is_null(), "{}: {}", cases[case].0, got[case]);
    }
    assert_eq!(names_of(&got[19]), settings);
    assert_eq!(names_of(&got[20]), ["url", "ref", "path"]);

    // the seven settings are the seven the syntax scopes as settings
    let syntax = read("editors/sublime/API.sublime-syntax");
    assert!(syntax.contains(&format!("(\")({})(\")", settings.join("|"))), "the settings of the syntax have changed");
}

#[test]
fn the_sublime_plugin_completes_the_words_of_a_line() {
    let dir = completion_fixture();
    let cases = [
        ("|", ""),
        ("GET /a\nde|", "de"),
        ("import |", ""),
        ("import git |", ""),
        ("url |", ""),
        ("sleep |", ""),
        ("sleep 20 wh|", "wh"),
        ("sleep 20 while |", ""),
        ("assert |", ""),
        ("assert not |", ""),
        ("GET /a && |", ""),
        ("GET /people~|", ""),
        ("GET /people~wh|", "wh"),
        ("GET /people~where(name=x)~c|", "c"),
        ("GET /people~where(a~|", ""),
        ("GET /people/|", ""),
        ("/peo|", "peo"),
        ("GET /a || PUT /people~|", ""),
        ("PUT /x @data.csv~|", ""),
        ("GET /people > c|", "c"),
        ("GET /people >> c|", "c"),
        ("assert GET /x > c|", "c"),
        ("GET /x~where(name=\"a > c|", "c"),
    ];
    let Some(got) = sublime_completions(dir.path(), &cases) else {
        eprintln!("skipped: no python3 on the PATH");
        return;
    };
    let methods = ["GET", "PUT", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    let with_not: Vec<&str> = ["not"].into_iter().chain(methods).collect();

    // an empty line: the methods, the directives, and what can be included
    let first = names_of(&got[0]);
    assert_eq!(first[..7], methods);
    assert_eq!(first[7..13], ["sleep", "assert", "confirm", "set", "url", "import"]);
    assert_eq!(first[13..], ["cloddy/", "seed.api", "shared/", "work/"]);
    assert_eq!(snippet_of(&got[0], "GET"), "GET ");
    assert_eq!(handed(&got[1]), [("DELETE".to_string(), "DELETE ".to_string())]);
    assert_eq!(names_of(&got[2]), ["git", "dir", "archive"]);
    assert!(got[3].is_null(), "an alias is a name of one's own: {}", got[3]);
    assert_eq!(names_of(&got[4]), ["has", "is"]);
    assert_eq!(names_of(&got[5]), ["while"]);
    assert_eq!(names_of(&got[6]), ["while"]);
    assert_eq!(names_of(&got[7]), with_not);
    assert_eq!(names_of(&got[8]), with_not);
    assert_eq!(names_of(&got[9]), methods);
    assert_eq!(names_of(&got[10]), methods);

    // the operators are the ones the client completes at its prompt
    let source = read("src/main.rs");
    let block = source.split("const API_OPERATORS: &[&str] = &[").nth(1).unwrap().split("];").next().unwrap();
    let operators: Vec<&str> = block.split('"').skip(1).step_by(2).collect();
    assert!(operators.len() > 10, "{:?}", operators);
    assert_eq!(names_of(&got[11]), operators);
    assert_eq!(got[12]["typed"], "wh");
    assert_eq!(snippet_of(&got[12], "where("), "where($1)");
    assert_eq!(snippet_of(&got[13], "count"), "count");
    // inside the parentheses of an operator a `~` is not the next operator
    assert_eq!(got[14]["uri"], true, "{}", got[14]);
    // a URI is left to the editor
    assert_eq!(got[15]["uri"], true);
    assert_eq!(got[16]["uri"], true);
    assert_eq!(names_of(&got[17]), operators);
    assert_eq!(names_of(&got[18]), ["map("]);
    assert_eq!(names_of(&got[19]), ["clipboard", "cloddy/"]);
    // nothing is appended to the clipboard, and a condition has no outfile
    assert_eq!(names_of(&got[20]), ["cloddy/"]);
    assert!(got[21].is_null(), "{}", got[21]);
    assert!(got[22].is_null(), "{}", got[22]);
}

#[test]
fn the_sublime_plugin_completes_paths_from_where_each_is_relative_to() {
    let dir = completion_fixture();
    let cases = [
        // an include: relative to the file, directories and `.api` files
        ("se|", "se"),
        ("shared/|", ""),
        ("shared/us|", "us"),
        (".|", ""),
        // an alias of an `import dir`, read from its line
        ("import dir cl { \"path\": \"cloddy\" }\ncl/|", ""),
        ("import dir cl { \"path\": \"cloddy\" }\nc|", "c"),
        ("import dir cl {\n  \"path\": \"cloddy\"\n}\ncl/seeds/|", ""),
        // the `path` of an `import dir`: directories
        ("import dir cl { \"path\": \"|\" }", ""),
        ("import dir cl { \"path\": \"shared/|\" }", ""),
        ("import git cl { \"path\": \"|\" }", ""),
        // an `@file`: relative to the working directory, any file
        ("PUT /x @|", ""),
        ("PUT /x @shared/|", ""),
        ("# @basedir work\nPUT /x @|", ""),
        // the one JSON file of a `set` and an `import`
        ("set @|", ""),
        ("import git cl @sh|", "sh"),
        ("import git cl @shared/|", ""),
        // an outfile
        ("GET /people > shared/d|", "d"),
    ];
    let Some(got) = sublime_completions(dir.path(), &cases) else {
        eprintln!("skipped: no python3 on the PATH");
        return;
    };
    assert_eq!(names_of(&got[0]), ["set", "seed.api"]);
    assert_eq!(names_of(&got[1]), ["shared/deep/", "shared/users.api"]);
    assert_eq!(names_of(&got[2]), ["shared/users.api"]);
    // Sublime Text replaces `us`: `shared/` stays where it is
    assert_eq!(handed(&got[2]), [("users.api".to_string(), "users.api".to_string())]);
    assert_eq!(names_of(&got[3]), [".hidden.api"]);
    assert_eq!(names_of(&got[4]), ["cl/seeds/", "cl/sv.api"]);
    assert_eq!(handed(&got[4]), [("seeds/".to_string(), "seeds/".to_string()), ("sv.api".to_string(), "sv.api".to_string())]);
    assert_eq!(names_of(&got[5]), ["confirm", "cl/", "cloddy/"]);
    assert_eq!(names_of(&got[6]), ["cl/seeds/one.api"]);
    assert_eq!(names_of(&got[7]), ["cloddy/", "shared/", "work/"]);
    assert_eq!(names_of(&got[8]), ["shared/deep/"]);
    assert!(names_of(&got[9]).is_empty(), "a path in a repository is not one of this machine: {}", got[9]);
    assert_eq!(names_of(&got[10]), ["cloddy/", "notes.txt", "seed.api", "settings.json", "shared/", "work/"]);
    assert_eq!(names_of(&got[11]), ["shared/data.json", "shared/deep/", "shared/users.api"]);
    assert_eq!(names_of(&got[12]), ["body.json"]);
    assert_eq!(names_of(&got[13]), ["cloddy/", "settings.json", "shared/", "work/"]);
    assert_eq!(names_of(&got[14]), ["shared/"]);
    assert_eq!(names_of(&got[15]), ["shared/data.json", "shared/deep/"]);
    assert_eq!(names_of(&got[16]), ["shared/data.json", "shared/deep/"]);
}

/// The client is asked where a git or archive alias is with the file's
/// import lines alone: the file itself can't be read while a line of it is
/// half typed, which is when a completion is asked for.
#[test]
fn the_sublime_plugin_asks_the_client_about_the_import_lines_alone() {
    let text = "# seed\nimport git cl {\n  \"url\": \"https://example.com/r\", // here\n  \"ref\": \"1.0.0\"\n}\n\
                import dir local { \"path\": \"../x\" }\nimport archive ar @ar.json   # from a file\n\
                PUT /x { \"import git\": 1 }\ncl/\nimport archive half { \"url\": \"x";
    let script = "import sys\nsys.path.insert(0, sys.argv[1])\nimport api_completions\n\
                  sys.stdout.write(api_completions.remote_imports(sys.stdin.read()))";
    let mut python = std::process::Command::new("python3");
    python
        .args(["-I", "-B", "-c", script])
        .arg(repo().join("editors/sublime"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let Ok(mut child) = python.spawn() else {
        eprintln!("skipped: no python3 on the PATH");
        return;
    };
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "import git cl {\n  \"url\": \"https://example.com/r\", // here\n  \"ref\": \"1.0.0\"\n}\n\
         import archive ar @ar.json   # from a file"
    );
}

/// Sublime Text runs a plugin of `Packages/User` in Python 3.3. What that
/// version can't read is no error to the `python3` the tests above run, so
/// the syntax tree of the plugin is searched for what came later.
#[test]
fn the_sublime_plugin_is_written_for_python_3_3() {
    let check = r#"
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
later = []
for node in ast.walk(tree):
    kind = type(node).__name__
    if kind in ('JoinedStr', 'TemplateStr', 'NamedExpr', 'AsyncFunctionDef', 'AsyncFor', 'AsyncWith', 'Await',
                'AnnAssign', 'Match', 'MatMult', 'TryStar'):
        later.append('line %d: %s' % (getattr(node, 'lineno', 0), kind))
    if kind == 'Attribute' and node.attr in ('run', 'scandir', 'fspath', 'removeprefix', 'removesuffix'):
        later.append('line %d: .%s' % (node.lineno, node.attr))
    if kind in ('Import', 'ImportFrom'):
        names = [alias.name for alias in node.names] + [getattr(node, 'module', None)]
        if any(name in ('pathlib', 'typing', 'dataclasses', 'enum', 'asyncio') for name in names):
            later.append('line %d: import %s' % (node.lineno, names))
    if kind in ('Dict', 'List', 'Tuple', 'Set', 'Call') and any(
            type(item).__name__ == 'Starred' or item is None
            for item in getattr(node, 'elts', None) or getattr(node, 'keys', None) or []) and kind != 'Call':
        later.append('line %d: unpacking in a display' % node.lineno)
print('\n'.join(later))
"#;
    let output = std::process::Command::new("python3")
        .args(["-I", "-c", check])
        .arg(repo().join("editors/sublime/api_completions.py"))
        .output();
    let Ok(output) = output else {
        eprintln!("skipped: no python3 on the PATH");
        return;
    };
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "", "not Python 3.3");
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
    let plugin = sublime_packages(home.path()).join("User/api_completions.py");
    for _ in 0..2 {
        let output = api(home.path(), bin.path()).args(["--install-syntax", "Sublime"]).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(stdout_lines(&output), [target.display().to_string(), plugin.display().to_string()]);
        assert_eq!(fs::read_to_string(&target).unwrap(), read("editors/sublime/API.sublime-syntax"));
        assert_eq!(fs::read_to_string(&plugin).unwrap(), read("editors/sublime/api_completions.py"));
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
