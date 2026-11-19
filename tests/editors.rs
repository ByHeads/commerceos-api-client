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

// --------------------------------------------------------------- --complete

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

/// What `api --complete` says can stand at the last `|` of `marked`, the
/// text of `main.api` in `dir`, asked in that directory: `null` where it
/// leaves the editor to itself, `{"uri": true}` in a URI.
fn completion(dir: &Path, marked: &str) -> serde_json::Value {
    // the last one: a chain has a `||` of its own
    let offset = marked.rfind('|').unwrap();
    let text = format!("{}{}", &marked[..offset], &marked[offset + 1..]);
    let output = Command::cargo_bin("api")
        .unwrap()
        .current_dir(dir)
        .env("API_IMPORT_CACHE", dir.join(".imports"))
        .args(["-r", "--complete"])
        .arg(dir.join("main.api"))
        .args(["--at", &offset.to_string()])
        .write_stdin(text)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}: {}", marked, stderr(&output));
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{}: {}", marked, e))
}

fn names_of(result: &serde_json::Value) -> Vec<String> {
    let items = result["items"].as_array().unwrap_or_else(|| panic!("no items: {}", result));
    items.iter().map(|item| item["name"].as_str().unwrap().to_string()).collect()
}

fn item_of<'a>(result: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    let items = result["items"].as_array().unwrap();
    items.iter().find(|item| item["name"] == name).unwrap_or_else(|| panic!("no `{}` in {}", name, result))
}

const SETTINGS: [&str; 7] = ["export", "include-nulls", "fail-fast", "ndjson", "raw", "stream", "timeout"];
const METHODS: [&str; 7] = ["GET", "PUT", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"];

#[test]
fn complete_offers_the_members_of_a_set_an_import_and_a_describe_block() {
    let dir = completion_fixture();
    let at = |marked: &str| completion(dir.path(), marked);

    // a name being typed in its quotes
    let quoted = at("set {\n  \"in|\"\n}\n");
    assert_eq!(quoted["typed"], "in");
    assert_eq!(names_of(&quoted), SETTINGS);
    assert_eq!(item_of(&quoted, "include-nulls")["snippet"], "include-nulls");
    // a setting the object has is not offered again
    assert_eq!(
        names_of(&at("set { \"include-nulls\": true, \"|\" }")),
        ["export", "fail-fast", "ndjson", "raw", "stream", "timeout"]
    );
    // nothing quoted yet: the member whole, with a value to type over
    let bare = at("set {\n  |\n}");
    assert_eq!(names_of(&bare), SETTINGS);
    assert_eq!(item_of(&bare, "include-nulls")["snippet"], "\"include-nulls\": ${1:true}");
    assert_eq!(item_of(&bare, "include-nulls")["text"], "\"include-nulls\": true");
    assert_eq!(item_of(&bare, "timeout")["snippet"], "\"timeout\": ${1:30}");
    assert_eq!(item_of(&bare, "export")["snippet"], "\"export\": \"${1:com.heads.seedID}\"");
    assert_eq!(item_of(&bare, "export")["text"], "\"export\": \"com.heads.seedID\"");
    assert_eq!(item_of(&bare, "export")["note"], "setting");
    assert_eq!(at("set { \"include-n|\" }")["typed"], "include-n");

    // the values a setting takes
    assert_eq!(names_of(&at("set { \"raw\": | }")), ["true", "false", "null"]);
    assert_eq!(names_of(&at("set { \"timeout\": | }")), ["0", "null"]);
    assert!(names_of(&at("set { \"raw\": true | }")).is_empty());
    assert!(names_of(&at("set { \"export\": \"com.|\" }")).is_empty());

    // the keys of an import are the keys of its kind
    assert_eq!(names_of(&at("import git cl {\n  \"|\"\n}")), ["url", "ref", "path"]);
    assert_eq!(names_of(&at("import dir cl { \"|\" }")), ["path"]);
    let archive = at("import archive ar { \"url\": \"x\", | }");
    assert_eq!(names_of(&archive), ["sha256", "token_env", "path"]);
    assert_eq!(item_of(&archive, "sha256")["snippet"], "\"sha256\": \"$1\"");
    assert_eq!(item_of(&archive, "sha256")["text"], "\"sha256\": \"\"");

    // a describe block, and the locales of its texts
    let describe = at("{\n  \"|\"\n}\nGET /a");
    assert_eq!(names_of(&describe), ["title", "description", "docsLink"]);
    let whole = at("{\n  |\n}");
    assert_eq!(item_of(&whole, "title")["snippet"], "\"title\": { \"${1:sv-SE}\": \"$2\" }");
    assert_eq!(item_of(&whole, "title")["text"], "\"title\": { \"sv-SE\": \"\" }");
    assert_eq!(names_of(&at("{\n  \"title\": { \"sv-SE\": \"Katalog\", \"|\" }\n}"))[..2], ["en-US", "nb-NO"]);
    assert!(names_of(&at("{ \"owner\": { \"|\" } }")).is_empty());

    // a request's body, a comment, a `confirm`: the editor's own
    for marked in [
        "PUT /people/x { \"na|\" }",
        "PUT /things {\n  // a |\n}",
        "PUT /things {\n  /* a | */\n}",
        "# set { \"|\" }",
        "confirm Seed { \"|",
        "GET /a   # then set { \"|",
    ] {
        assert!(at(marked).is_null(), "{}: {}", marked, at(marked));
    }

    // a body that closed is behind the cursor
    assert_eq!(names_of(&at("PUT /a { \"x\": 1 }\nset { \"|\" }")), SETTINGS);
    assert_eq!(names_of(&at("PUT /a {\n  \"x\": \"a } b\"\n}\nimport git cl { \"|\" }")), ["url", "ref", "path"]);
    // the place is counted in bytes
    assert_eq!(names_of(&at("# é\nset { \"å\": 1, \"|\" }")), SETTINGS);

    // the seven settings are the seven the syntax scopes as settings
    let syntax = read("editors/sublime/API.sublime-syntax");
    assert!(syntax.contains(&format!("(\")({})(\")", SETTINGS.join("|"))), "the settings of the syntax have changed");
}

#[test]
fn complete_offers_the_words_of_a_line() {
    let dir = completion_fixture();
    let at = |marked: &str| completion(dir.path(), marked);
    let with_not: Vec<&str> = ["not"].into_iter().chain(METHODS).collect();
    let operators =
        ["with(", "just(", "without(", "where(", "orderBy(", "take(", "skip(", "first", "last", "count", "flat", "entries", "array", "map("];

    // an empty line: the methods, the directives, and what can be included
    let empty = at("|");
    let names = names_of(&empty);
    assert_eq!(names[..7], METHODS);
    assert_eq!(names[7..13], ["sleep", "assert", "confirm", "set", "url", "import"]);
    assert_eq!(names[13..], ["cloddy/", "shared/", "work/", "seed.api"]);
    assert_eq!(item_of(&empty, "GET")["snippet"], "GET ");
    assert_eq!(item_of(&empty, "GET")["note"], "method");
    assert_eq!(item_of(&empty, "sleep")["note"], "directive");
    assert_eq!(names_of(&at("GET /a\nde|")), ["DELETE"]);

    assert_eq!(names_of(&at("import |")), ["git", "dir", "archive"]);
    assert!(at("import git |").is_null(), "an alias is a name of one's own");
    assert_eq!(names_of(&at("url |")), ["has", "is"]);
    assert!(at("url has |").is_null());
    assert_eq!(names_of(&at("sleep |")), ["while"]);
    assert_eq!(names_of(&at("sleep 20 wh|")), ["while"]);
    assert!(at("sleep 2|").is_null());
    assert_eq!(names_of(&at("sleep 20 while |")), with_not);
    assert_eq!(names_of(&at("sleep while |")), with_not);
    assert_eq!(names_of(&at("assert |")), with_not);
    assert_eq!(names_of(&at("assert not |")), METHODS);
    assert_eq!(names_of(&at("GET /a && |")), METHODS);

    // the operators are the ones the prompt completes
    let all = at("GET /people~|");
    assert_eq!(names_of(&all), operators);
    assert_eq!(item_of(&all, "where(")["snippet"], "where($1)");
    assert_eq!(item_of(&all, "where(")["text"], "where(");
    assert_eq!(item_of(&all, "count")["snippet"], "count");
    assert_eq!(at("GET /people~wh|")["typed"], "wh");
    assert_eq!(names_of(&at("GET /people~where(name=x)~c|")), operators);
    assert_eq!(names_of(&at("GET /a || PUT /people~|")), operators);
    assert_eq!(names_of(&at("/people~|")), operators);
    assert_eq!(names_of(&at("assert /people~|")), operators);
    // inside the parentheses of an operator a `~` is not the next operator
    assert_eq!(at("GET /people~where(a~|")["uri"], true);
    // a URI is the server's
    assert_eq!(at("GET /people/|")["uri"], true);
    assert_eq!(at("/peo|")["uri"], true);
    assert_eq!(at("GET |")["uri"], true);

    assert_eq!(names_of(&at("PUT /x @data.csv~|")), ["map("]);
    assert_eq!(names_of(&at("GET /people > c|")), ["clipboard", "cloddy/"]);
    assert_eq!(names_of(&at("GET /people >c|")), ["clipboard", "cloddy/"]);
    // nothing is appended to the clipboard, and a condition has no outfile
    assert_eq!(names_of(&at("GET /people >> c|")), ["cloddy/"]);
    assert!(at("assert GET /x > c|").is_null());
    // a string of a line is not this client's to complete
    assert!(at("GET /x~where(name=\"a > c|").is_null());
    assert!(at("PUT /x \"a > c|").is_null());
}

#[test]
fn complete_offers_paths_from_where_each_is_relative_to() {
    let dir = completion_fixture();
    let at = |marked: &str| names_of(&completion(dir.path(), marked));

    // an include: relative to the file, directories and `.api` files
    assert_eq!(at("se|"), ["set", "seed.api"]);
    assert_eq!(at("shared/|"), ["shared/deep/", "shared/users.api"]);
    assert_eq!(at("shared/us|"), ["shared/users.api"]);
    assert_eq!(at(".|"), [".hidden.api"]);
    assert_eq!(at("./sh|"), ["./shared/"]);
    // an alias of an `import dir`, read from its line
    let import = "import dir cl { \"path\": \"cloddy\" }";
    assert_eq!(at(&format!("{}\ncl/|", import)), ["cl/seeds/", "cl/sv.api"]);
    assert_eq!(at(&format!("{}\nc|", import)), ["confirm", "cl/", "cloddy/"]);
    assert_eq!(at("import dir cl {\n  // where it is\n  \"path\": \"cloddy\"\n}\ncl/seeds/|"), ["cl/seeds/one.api"]);
    // an import that can't be read has no alias, and stops nothing
    assert_eq!(at(&format!("{}\ncl/|\nimport dir half {{ \"path\": \"clo", import)), ["cl/seeds/", "cl/sv.api"]);
    // the `path` of an `import dir`: directories
    assert_eq!(at("import dir cl { \"path\": \"|\" }"), ["cloddy/", "shared/", "work/"]);
    assert_eq!(at("import dir cl { \"path\": \"shared/|\" }"), ["shared/deep/"]);
    assert!(at("import git cl { \"path\": \"|\" }").is_empty(), "a path in a repository is not one of this machine");
    // an `@file`: relative to the working directory, any file
    assert_eq!(at("PUT /x @|"), ["cloddy/", "shared/", "work/", "notes.txt", "seed.api", "settings.json"]);
    assert_eq!(at("PUT /x @shared/|"), ["shared/deep/", "shared/data.json", "shared/users.api"]);
    assert_eq!(at("PUT /x @ sh|"), ["shared/"]);
    // … which a comment of the file can name, relative to the file
    assert_eq!(at("# @basedir work\nPUT /x @|"), ["body.json"]);
    assert_eq!(at("# @basedir work\nGET /x > |"), ["clipboard", "body.json"]);
    assert_eq!(at("# @basedir work\nsh|"), ["shared/"], "an include is relative to the file");
    // the one JSON file of a `set` and an `import`
    assert_eq!(at("set @|"), ["cloddy/", "shared/", "work/", "settings.json"]);
    assert_eq!(at("import git cl @sh|"), ["shared/"]);
    assert_eq!(at("import git cl @shared/|"), ["shared/deep/", "shared/data.json"]);
    // an outfile, also behind a body of several lines
    assert_eq!(at("GET /people > shared/d|"), ["shared/deep/", "shared/data.json"]);
    assert_eq!(at("PUT /a {\n  \"x\": 1\n} > sh|"), ["shared/"]);

    // the file need not be where the client is asked
    let elsewhere = tempdir().unwrap();
    let output = Command::cargo_bin("api")
        .unwrap()
        .current_dir(elsewhere.path())
        .args(["-r", "--complete"])
        .arg(dir.path().join("shared/users.api"))
        .write_stdin("de")
        .output()
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(names_of(&result), ["DELETE", "deep/"]);
    // a text that is kept nowhere yet has no directory to include from
    let output = Command::cargo_bin("api").unwrap().current_dir(dir.path()).args(["-r", "--complete", "-"]).write_stdin("se").output().unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(names_of(&result), ["set"]);
}

/// A git alias completes from the cache, where a run or `--imports` left
/// its checkout. Nothing is fetched to complete: an editor asks on a
/// keystroke.
#[test]
fn complete_reads_a_git_alias_from_the_cache_and_fetches_nothing() {
    let dir = completion_fixture();
    let repo = tempdir().unwrap();
    fs::create_dir_all(repo.path().join("seeds")).unwrap();
    fs::write(repo.path().join("sv.api"), "GET /about\n").unwrap();
    fs::write(repo.path().join("seeds/one.api"), "GET /about\n").unwrap();
    let git = |args: &[&str]| {
        let done = std::process::Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(["-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .expect("git runs");
        assert!(done.status.success(), "git {:?}: {}", args, String::from_utf8_lossy(&done.stderr));
    };
    git(&["init", "-q"]);
    git(&["add", "."]);
    git(&["commit", "-qm", "seeds"]);
    git(&["tag", "1.0.0"]);
    let import = format!("import git gl {{ \"url\": \"file://{}\", \"ref\": \"1.0.0\" }}\n", repo.path().display());
    let whole = format!("{}import git sub {{ \"url\": \"file://{}\", \"ref\": \"1.0.0\", \"path\": \"seeds\" }}\n", import, repo.path().display());

    // never fetched: the alias stands for nothing yet
    assert!(names_of(&completion(dir.path(), &format!("{}gl/|", whole))).is_empty());
    assert!(!dir.path().join(".imports").exists(), "a completion fetched an import");

    let listed = Command::cargo_bin("api")
        .unwrap()
        .current_dir(dir.path())
        .env("API_IMPORT_CACHE", dir.path().join(".imports"))
        .args(["--imports", "-"])
        .write_stdin(whole.clone())
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));

    assert_eq!(names_of(&completion(dir.path(), &format!("{}gl/|", whole))), ["gl/seeds/", "gl/sv.api"]);
    assert_eq!(names_of(&completion(dir.path(), &format!("{}sub/|", whole))), ["sub/one.api"]);
    assert_eq!(names_of(&completion(dir.path(), &format!("{}g|", whole))), ["GET", "gl/"]);
    // the remote is gone: the checkout it left is still what the alias is
    fs::remove_dir_all(repo.path()).unwrap();
    assert_eq!(names_of(&completion(dir.path(), &format!("{}gl/|", whole))), ["gl/seeds/", "gl/sv.api"]);
}

#[test]
fn complete_prints_a_document_and_stands_alone() {
    let dir = completion_fixture();
    let api = || {
        let mut cmd = Command::cargo_bin("api").unwrap();
        cmd.current_dir(dir.path());
        cmd
    };
    // indented as the other documents are, on one line with `-r`
    let output = api().args(["--complete", "-"]).write_stdin("url ").output().unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("{\n  \"typed\": \"\",\n  \"items\": [\n"), "{:?}", output);
    let output = api().args(["-r", "--complete", "-"]).write_stdin("# a comment").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout), "null\n");
    // without `--at` the place is the end of the text; past the end is the end
    let output = api().args(["-r", "--complete", "-", "--at", "999"]).write_stdin("import ").output().unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(names_of(&result), ["git", "dir", "archive"]);

    let output = api().args(["--complete", "-", "GET", "/people"]).write_stdin("").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stderr(&output), "error: --complete - prints a document and GET /people is a request: give one of the two\n");
    let output = api().args(["--complete", "-", "--describe", "seed.api"]).write_stdin("").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stderr(&output), "error: --describe and --complete each print a document of their own: use one\n");
    let output = api().args(["--at", "3", "GET", "/people"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

// ----------------------------------------------------------------- --format

const UNFORMATTED: &str = "{\n\"title\": { \"sv-SE\": \"Shade\" }\n}\n  PUT   /people   {\"name\":\"Ann\",\n\"tags\":[1,2]}   > out.json   # tail\n";
const FORMATTED: &str = "{\n  \"title\": { \"sv-SE\": \"Shade\" }\n}\nPUT /people {\n  \"name\": \"Ann\",\n  \"tags\": [1, 2]\n} > out.json   # tail\n";
const EXPANDED: &str = "{\n  \"title\": {\n    \"sv-SE\": \"Shade\"\n  }\n}\nPUT /people {\n  \"name\": \"Ann\",\n  \"tags\": [\n    1,\n    2\n  ]\n} > out.json   # tail\n";

#[test]
fn format_prints_a_file_laid_out_and_stands_alone() {
    let dir = tempdir().unwrap();
    let api = || {
        let mut cmd = Command::cargo_bin("api").unwrap();
        cmd.current_dir(dir.path());
        cmd
    };
    // from stdin, as an editor has the text
    let output = api().args(["--format", "-"]).write_stdin(UNFORMATTED).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(String::from_utf8_lossy(&output.stdout), FORMATTED);
    let output = api().args(["--format", "-", "--expand"]).write_stdin(UNFORMATTED).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout), EXPANDED);
    // from a file, which is left as it is
    fs::write(dir.path().join("seed.api"), UNFORMATTED).unwrap();
    let output = api().args(["--format", "seed.api"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout), FORMATTED);
    assert_eq!(fs::read_to_string(dir.path().join("seed.api")).unwrap(), UNFORMATTED);
    // what is laid out is not laid out again
    let output = api().args(["--format", "-"]).write_stdin(FORMATTED).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout), FORMATTED);

    let output = api().args(["--format", "missing.api"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).starts_with("error: could not read missing.api: "), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
    let output = api().args(["--format", "-", "GET", "/people"]).write_stdin("").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stderr(&output), "error: --format - prints a document and GET /people is a request: give one of the two\n");
    let output = api().args(["--expand", "GET", "/people"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

// ------------------------------------------------------ the editors' callers

/// Run `script` with the `python3` of the machine, the Sublime plugin on its
/// path, and return what it printed. `None` where there is no `python3`:
/// the tests that need it say so and hold nothing.
fn with_the_sublime_plugin(script: &str, args: &[&std::ffi::OsStr]) -> Option<String> {
    let output = std::process::Command::new("python3")
        .args(["-I", "-B", "-c", &format!("import sys\nsys.path.insert(0, sys.argv[1])\nimport api_completions as plugin\n{}", script)])
        .arg(repo().join("editors/sublime"))
        .args(args)
        .output()
        .ok()?;
    assert!(output.status.success(), "the plugin failed:\n{}", String::from_utf8_lossy(&output.stderr));
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

/// The Sublime plugin asks the client and hands Sublime Text what is left
/// of each name behind the part of it that stays: Sublime replaces the word
/// in front of the cursor as its word separators cut it.
#[test]
fn the_sublime_plugin_asks_the_client_and_hands_over_what_is_left_of_a_name() {
    let dir = completion_fixture();
    let script = r#"
import json
binary, root = sys.argv[2], sys.argv[3]
out = []
# (the text with a `|` at the cursor, the word Sublime Text replaces)
for marked, prefix in json.loads(sys.argv[4]):
    offset = marked.index('|')
    text = marked[:offset] + marked[offset + 1:]
    result = plugin.ask(binary, text, offset, root + '/main.api', plugin.working_dir(root + '/main.api', [root]))
    out.append(None if result is None or 'items' not in result else plugin.to_sublime(result, prefix))
out.append(plugin.ask(root + '/no-such-client', 'se', 2))
out.append(plugin.ask(binary, 'GET /people/', 12, None, root))
out.append(plugin.working_dir('/a/b/c/x.api', ['/a/other', '/a/b']))
out.append(plugin.working_dir('/a/b/c/x.api', []))
out.append(plugin.working_dir(None, ['/a/other']))
unformatted = sys.argv[5]
out.append(plugin.formatted(binary, unformatted))
out.append(plugin.formatted(binary, unformatted, True))
out.append(plugin.formatted(root + '/no-such-client', unformatted))
print(json.dumps(out))
"#;
    let cases = [
        ("set {\n  \"in|\"\n}\n", "in"),
        // Sublime Text cuts a word at `-`: what it replaces is `n`, of `include-n`
        ("set { \"include-n|\" }", "n"),
        ("# é å ö\nset { \"include-n|\" }", "n"),
        ("GET /a\nde|", "de"),
        ("shared/us|", "us"),
        ("import dir cl { \"path\": \"cloddy\" }\ncl/|", ""),
        ("GET /people~wh|", "wh"),
        ("PUT /x { \"na|\" }", "na"),
    ];
    let binary = assert_cmd::cargo::cargo_bin("api");
    let cases_json = serde_json::to_string(&cases).unwrap();
    let args = [binary.as_os_str(), dir.path().as_os_str(), std::ffi::OsStr::new(&cases_json), std::ffi::OsStr::new(UNFORMATTED)]
        .map(|arg| arg.to_owned());
    let args: Vec<&std::ffi::OsStr> = args.iter().map(|arg| arg.as_os_str()).collect();
    let Some(printed) = with_the_sublime_plugin(script, &args) else {
        eprintln!("skipped: no python3 on the PATH");
        return;
    };
    let got: serde_json::Value = serde_json::from_str(&printed).unwrap();
    let handed = |n: usize| -> Vec<(String, String)> {
        let pairs = got[n].as_array().unwrap_or_else(|| panic!("{}: {}", cases[n].0, got[n]));
        pairs.iter().map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].as_str().unwrap().to_string())).collect()
    };
    let pair = |trigger: &str, contents: &str| (trigger.to_string(), contents.to_string());
    assert_eq!(handed(0)[1], pair("include-nulls\tsetting", "include-nulls"));
    assert_eq!(handed(0).len(), 7);
    assert_eq!(handed(1), [pair("nulls\tinclude-nulls", "nulls")]);
    assert_eq!(handed(2), [pair("nulls\tinclude-nulls", "nulls")], "the place is given in bytes");
    assert_eq!(handed(3), [pair("DELETE\tmethod", "DELETE ")]);
    assert_eq!(handed(4), [pair("users.api\tfile", "users.api")]);
    assert_eq!(handed(5), [pair("seeds/\tdirectory", "seeds/"), pair("sv.api\tfile", "sv.api")]);
    assert_eq!(handed(6)[3], pair("where(\toperator", "where($1)"));
    assert!(got[7].is_null(), "{}", got[7]);
    // a client that is not there, and a URI
    assert!(got[8].is_null(), "{}", got[8]);
    assert_eq!(got[9]["uri"], true);
    assert_eq!(got[10], "/a/b");
    assert_eq!(got[11], "/a/b/c");
    assert_eq!(got[12], "/a/other");
    // the format command: the text as the client lays it out
    assert_eq!(got[13], FORMATTED);
    assert_eq!(got[14], EXPANDED);
    assert!(got[15].is_null(), "{}", got[15]);
}

/// Sublime Text runs a plugin of `Packages/User` in Python 3.3. What that
/// version can't read is no error to the `python3` the test above runs, so
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
    if kind in ('Dict', 'List', 'Tuple', 'Set') and any(
            type(item).__name__ == 'Starred' or item is None
            for item in getattr(node, 'elts', None) or getattr(node, 'keys', None) or []):
        later.append('line %d: unpacking in a display' % node.lineno)
print('\n'.join(later))
"#;
    let output = std::process::Command::new("python3")
        .args(["-I", "-B", "-c", check])
        .arg(repo().join("editors/sublime/api_completions.py"))
        .output();
    let Ok(output) = output else {
        eprintln!("skipped: no python3 on the PATH");
        return;
    };
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "", "not Python 3.3");
}

/// The VS Code extension asks the client and hands the editor an item for
/// each answer, to stand where the text typed so far is. It is run by the
/// `node` of the machine against a `vscode` module of the test's own, which
/// holds what the extension uses of the editor. Holds nothing without `node`.
#[test]
fn the_vscode_extension_asks_the_client_and_hands_over_items_for_the_typed_text() {
    let dir = completion_fixture();
    let modules = tempdir().unwrap();
    fs::create_dir_all(modules.path().join("node_modules/vscode")).unwrap();
    fs::write(
        modules.path().join("node_modules/vscode/index.js"),
        r#"
class Position { constructor(line, character) { this.line = line; this.character = character; }
  translate(lines, characters) { return new Position(this.line + lines, this.character + characters); } }
class Range { constructor(start, end) { this.start = start; this.end = end; } }
class SnippetString { constructor(value) { this.value = value; } }
class CompletionItem { constructor(label, kind) { this.label = label; this.kind = kind; } }
class TextEdit { constructor(range, newText) { this.range = range; this.newText = newText; }
  static replace(range, newText) { return new TextEdit(range, newText); } }
const CompletionItemKind = new Proxy({}, { get: (_, name) => name });
const state = { binary: '', folders: [], providers: [], formatters: [], commands: {}, editor: undefined };
module.exports = {
  Position, Range, SnippetString, CompletionItem, CompletionItemKind, TextEdit, state,
  window: { get activeTextEditor() { return state.editor; } },
  commands: { registerCommand: (name, run) => { state.commands[name] = run; return { dispose() {} }; } },
  workspace: {
    getConfiguration: () => ({ get: () => state.binary }),
    getWorkspaceFolder: () => undefined,
    get workspaceFolders() { return state.folders; },
  },
  languages: {
    registerCompletionItemProvider: (language, provider, ...triggers) => {
      state.providers.push({ language, provider, triggers });
      return { dispose() {} };
    },
    registerDocumentFormattingEditProvider: (language, provider) => {
      state.formatters.push({ language, provider });
      return { dispose() {} };
    },
  },
};
"#,
    )
    .unwrap();
    let driver = r#"
const [extensionPath, binary, root, cases, unformatted] = process.argv.slice(1);
const vscode = require('vscode');
const extension = require(extensionPath);
const subscriptions = [];
extension.activate({ subscriptions });
const { language, provider, triggers } = vscode.state.providers[0];
vscode.state.folders = [{ uri: { scheme: 'file', fsPath: root } }];
// a document, as the extension reads one
const documentOf = (marked) => {
  const offset = marked.lastIndexOf('|');
  const text = marked.slice(0, offset) + marked.slice(offset + 1);
  const lines = text.slice(0, offset).split('\n');
  const position = new vscode.Position(lines.length - 1, lines[lines.length - 1].length);
  const offsetAt = (p) => text.split('\n').slice(0, p.line).reduce((n, line) => n + line.length + 1, 0) + p.character;
  const document = {
    uri: { scheme: 'file', fsPath: root + '/main.api' },
    getText: (range) => (range ? text.slice(offsetAt(range.start), offsetAt(range.end)) : text),
    languageId: language,
  };
  return { document, position };
};
(async () => {
  const out = { language, triggers, subscribed: subscriptions.length, answers: [] };
  for (const client of [binary, root + '/no-such-client']) {
    vscode.state.binary = client;
    for (const marked of JSON.parse(cases)) {
      const { document, position } = documentOf(marked);
      const items = await provider.provideCompletionItems(document, position, undefined);
      out.answers.push(items === undefined ? null : items.map((item) => ({
        label: item.label, kind: item.kind, insert: item.insertText.value, detail: item.detail, sort: item.sortText,
        from: item.range.start.character, to: item.range.end.character, line: item.range.start.line,
        again: Boolean(item.command),
      })));
    }
  }
  // Format Document, and the command for one member a line
  const plain = (edits) => edits.map((edit) => ({ text: edit.newText, start: edit.range.start, end: edit.range.end }));
  const formatter = vscode.state.formatters[0];
  out.formats = formatter.language;
  out.format = [];
  for (const client of [binary, root + '/no-such-client']) {
    vscode.state.binary = client;
    const { document } = documentOf(unformatted + '|');
    out.format.push(plain(await formatter.provider.provideDocumentFormattingEdits(document, {}, undefined)));
  }
  vscode.state.binary = binary;
  const { document } = documentOf(unformatted + '|');
  const replaced = [];
  vscode.state.editor = { document, edit: async (change) => change({ replace: (range, text) => replaced.push(text) }) };
  await vscode.state.commands['commerceosApi.formatExpanded']();
  out.expanded = replaced;
  console.log(JSON.stringify(out));
})();
"#;
    let cases = ["set {\n  \"in|\"\n}\n", "# é å ö\nset {\n  |", "shared/us|", "GET /people~wh|", "PUT /x { \"na|\" }", "GET /people/|", "sh|"];
    let output = std::process::Command::new("node")
        .args(["-e", driver, "--"])
        .arg(repo().join("editors/vscode/extension.js"))
        .arg(assert_cmd::cargo::cargo_bin("api"))
        .arg(dir.path())
        .arg(serde_json::to_string(&cases).unwrap())
        .arg(UNFORMATTED)
        .env("NODE_PATH", modules.path().join("node_modules"))
        .output();
    let Ok(output) = output else {
        eprintln!("skipped: no node on the PATH");
        return;
    };
    assert!(output.status.success(), "the extension failed:\n{}", String::from_utf8_lossy(&output.stderr));
    let got: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    // it answers for the language the extension's package.json names
    let package: serde_json::Value = serde_json::from_str(&read("editors/vscode/package.json")).unwrap();
    assert_eq!(got["language"], package["contributes"]["languages"][0]["id"]);
    assert_eq!(package["main"], "./extension.js");
    assert_eq!(package["activationEvents"][0], format!("onLanguage:{}", got["language"].as_str().unwrap()));
    assert!(package["contributes"]["configuration"]["properties"].get("commerceosApi.binary").is_some());
    assert_eq!(got["triggers"], serde_json::json!(["\"", "/", "~", "@"]));
    assert_eq!(got["subscribed"], 3);
    assert_eq!(package["contributes"]["commands"][0]["command"], "commerceosApi.formatExpanded");

    // Format Document: one edit, the whole text for the text laid out
    assert_eq!(got["formats"], got["language"]);
    assert_eq!(
        got["format"][0],
        serde_json::json!([{ "text": FORMATTED, "start": { "line": 0, "character": 0 }, "end": { "line": 5, "character": 0 } }])
    );
    // a client that is not there: no edit, and no error
    assert_eq!(got["format"][1], serde_json::json!([]));
    assert_eq!(got["expanded"], serde_json::json!([EXPANDED]));

    let answers = got["answers"].as_array().unwrap();
    let labels = |n: usize| -> Vec<&str> { answers[n].as_array().unwrap().iter().map(|item| item["label"].as_str().unwrap()).collect() };
    assert_eq!(labels(0), SETTINGS);
    let nulls = &answers[0][1];
    // `in` is what the item takes the place of: columns 3 to 5 of line 1
    assert_eq!(
        *nulls,
        serde_json::json!({
            "label": "include-nulls", "kind": "Property", "insert": "include-nulls", "detail": "setting",
            "sort": "0001", "from": 3, "to": 5, "line": 1, "again": false
        })
    );
    // the place is given to the client in bytes
    assert_eq!(labels(1), SETTINGS);
    assert_eq!(answers[1][1]["insert"], "\"include-nulls\": ${1:true}");
    assert_eq!(answers[1][1]["from"], 2);
    assert_eq!(labels(2), ["shared/users.api"]);
    assert_eq!((answers[2][0]["from"].as_u64(), answers[2][0]["kind"].as_str()), (Some(0), Some("File")));
    assert_eq!(answers[3][3]["insert"], "where($1)");
    assert_eq!(answers[3][3]["from"], 12);
    // the editor's own: a request's body, and a URI
    assert!(answers[4].is_null() && answers[5].is_null(), "{} {}", answers[4], answers[5]);
    // a directory is gone on into
    assert_eq!(labels(6), ["shared/"]);
    assert_eq!(answers[6][0]["again"], true);
    // a client that is not there: nothing, and no error
    assert!(answers[cases.len()..].iter().all(|answer| answer.is_null()), "{:?}", &answers[cases.len()..]);
}

/// Omni completion in Vim itself (ctrl+x ctrl+o), with the package on the
/// runtime path as an install leaves it: the first thing the client offers
/// is written where the text typed so far stands. Holds nothing on a
/// machine without `vim`.
#[cfg(unix)]
#[test]
fn the_vim_package_completes_with_what_the_client_offers() {
    let dir = completion_fixture();
    let home = tempdir().unwrap();
    let script = home.path().join("complete.vim");
    let written = home.path().join("lines.txt");
    // (the text, as lines; the cursor is behind its last character)
    let cases: [&[&str]; 7] = [
        &["set {", "  \"in"],
        &["# é å ö", "set { \"include-nulls\": true, \"f"],
        &["sleep 20 wh"],
        &["shared/us"],
        &["GET /people~wh"],
        &["import dir cl { \"path\": \"cloddy\" }", "cl/sv"],
        &["PUT /x { \"na"],
    ];
    let mut commands = String::from("set nocompatible encoding=utf-8 completeopt=menu\nlet s:out = []\n");
    for lines in cases {
        commands.push_str("%delete _\n");
        commands.push_str(&format!("call setline(1, {})\n", serde_json::to_string(lines).unwrap()));
        commands.push_str("call cursor(line('$'), 1)\nexecute \"normal! A\\<C-x>\\<C-o>\"\ncall add(s:out, getline('$'))\n");
    }
    commands.push_str("call add(s:out, &omnifunc)\n");
    // :ApiFormat lays the buffer out, :ApiFormat! with a line for each member,
    // and `gq` does what :ApiFormat does to the lines it is given
    let unformatted = serde_json::to_string(&UNFORMATTED.trim_end().split('\n').collect::<Vec<_>>()).unwrap();
    for lay_out in ["ApiFormat", "ApiFormat!", "normal! gggqG"] {
        commands.push_str(&format!("%delete _\ncall setline(1, {})\n{}\n", unformatted, lay_out));
        commands.push_str("call add(s:out, '--')\ncall extend(s:out, getline(1, '$'))\n");
    }
    commands.push_str("call writefile(s:out, g:api_written)\nqa!\n");
    fs::write(&script, commands).unwrap();
    let mut vim = std::process::Command::new("vim");
    vim.args(["-e", "-s", "-u", "NONE", "-i", "NONE", "-N"])
        .arg("--cmd")
        .arg(format!("set runtimepath^={}", repo().join("editors/vim").display()))
        .arg("--cmd")
        .arg("filetype plugin on")
        .arg("--cmd")
        .arg(format!("let g:api_binary='{}'", assert_cmd::cargo::cargo_bin("api").display()))
        .arg("--cmd")
        .arg(format!("let g:api_written='{}'", written.display()))
        .arg(dir.path().join("main.api"))
        .arg("-S")
        .arg(&script)
        .current_dir(dir.path())
        .env("HOME", home.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let Ok(mut child) = vim.spawn() else {
        eprintln!("skipped: no vim on the PATH");
        return;
    };
    let started = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > std::time::Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("vim did not end");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let lines = fs::read_to_string(&written).expect("vim wrote nothing: the package did not load");
    let lines: Vec<&str> = lines.lines().collect();
    assert_eq!(
        lines[..8],
        [
            "  \"include-nulls",
            "set { \"include-nulls\": true, \"fail-fast",
            "sleep 20 while ",
            "shared/users.api",
            "GET /people~where(",
            "cl/sv.api",
            // a request's body is not the client's to complete
            "PUT /x { \"na",
            "ApiComplete",
        ]
    );
    let laid_out: Vec<String> = lines[8..].join("\n").split("--\n").skip(1).map(|text| format!("{}\n", text.trim_end())).collect();
    assert_eq!(laid_out, [FORMATTED, EXPANDED, FORMATTED]);
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
    let commands = sublime_packages(home.path()).join("User/API.sublime-commands");
    for _ in 0..2 {
        let output = api(home.path(), bin.path()).args(["--install-syntax", "Sublime"]).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(stdout_lines(&output), [&target, &plugin, &commands].map(|path| path.display().to_string()));
        assert_eq!(fs::read_to_string(&target).unwrap(), read("editors/sublime/API.sublime-syntax"));
        assert_eq!(fs::read_to_string(&plugin).unwrap(), read("editors/sublime/api_completions.py"));
        assert_eq!(fs::read_to_string(&commands).unwrap(), read("editors/sublime/API.sublime-commands"));
    }
    // the palette names the command the plugin has
    let palette: serde_json::Value = serde_json::from_str(&read("editors/sublime/API.sublime-commands")).unwrap();
    assert_eq!(palette[0]["command"], "api_format");
    assert_eq!(palette[1]["args"]["expanded"], true);
    assert!(read("editors/sublime/api_completions.py").contains("class ApiFormatCommand(sublime_plugin.TextCommand)"));
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
        ["package.json", "extension.js", "language-configuration.json", "syntaxes/api.tmLanguage.json"]
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
                "extension/extension.js",
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
        assert_eq!(files["extension/extension.js"], read("editors/vscode/extension.js"));
        assert!(files["[Content_Types].xml"].contains(r#"Extension=".js""#), "{}", files["[Content_Types].xml"]);

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
