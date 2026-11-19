# -*- coding: utf-8 -*-
"""Completions for `.api` batch files in Sublime Text.

Installed beside `API.sublime-syntax` by `api --install-syntax sublime`.
What is offered follows from where the cursor is: the settings of a `set`
line, the keys of an `import`, the members of a describe block, methods and
directives, URI operators, and the paths of includes, `@file` bodies and
outfiles.

The first half of this file is plain Python and knows nothing of Sublime
Text: `cargo test --test editors` runs it. The second half hands its answers
to the editor. It is written for the Python 3.3 that Sublime Text runs a
plugin of `Packages/User` in, so it does without what came later.
"""

import json
import os
import re
import subprocess
import threading

try:
    import sublime
    import sublime_plugin
except ImportError:  # the tests run this file without an editor
    sublime = None
    sublime_plugin = None


METHODS = ['GET', 'PUT', 'POST', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
DIRECTIVES = ['sleep', 'assert', 'confirm', 'set', 'url', 'import']

# a setting of a `set` line, and its value as a snippet
SETTINGS = [
    ('export', '"${1:com.heads.seedID}"'),
    ('include-nulls', '${1:true}'),
    ('fail-fast', '${1:true}'),
    ('ndjson', '${1:true}'),
    ('raw', '${1:true}'),
    ('stream', '${1:true}'),
    ('timeout', '${1:30}'),
]
SETTING_VALUES = {'export': ['null'], 'timeout': ['0', 'null']}
SWITCH_VALUES = ['true', 'false', 'null']

IMPORT_KINDS = ['git', 'dir', 'archive']
IMPORT_KEYS = {
    'git': ['url', 'ref', 'path'],
    'dir': ['path'],
    'archive': ['url', 'sha256', 'token_env', 'path'],
}

DESCRIBE_MEMBERS = [
    ('title', '{ "${1:sv-SE}": "$2" }'),
    ('description', '{ "${1:sv-SE}": "$2" }'),
    ('docsLink', '"${1:https://}"'),
]
LOCALES = ['sv-SE', 'en-US', 'nb-NO', 'da-DK', 'fi-FI', 'de-DE']

# the operators the client completes at its prompt (`API_OPERATORS`)
OPERATORS = [
    'with(', 'just(', 'without(', 'where(', 'orderBy(',
    'take(', 'skip(', 'first', 'last', 'count',
    'flat', 'entries', 'array', 'map(',
]

JUNK = ('.DS_Store', 'Thumbs.db', 'desktop.ini')

_METHOD = r'(?:GET|PUT|POST|PATCH|DELETE|HEAD|OPTIONS)'

# What matters on a line that is no body: where a body opens, where a
# comment starts, the parentheses of a URI operator (nothing in them ends a
# request), and the `&&` / `||` between the requests of a chain.
_TOP = re.compile(
    r'(?P<nl>\n)'
    r'|(?P<comment>(?:(?<=[ \t])|^)#[^\n]*)'
    r'|(?P<open>(?:(?<=\s)|^)[{\[])'
    r'|(?P<lp>\()'
    r'|(?P<rp>\))'
    r'|(?P<str>"(?:\\.|[^"\\\n])*(?P<strclose>")?)'
    r'|(?P<chain>&&|\|\|)',
    re.M)

# The tokens of a body: strings (a raw newline is allowed in one), the three
# kinds of comment, and the punctuation.
_JTOK = re.compile(
    r'"(?P<body>(?:\\.|[^"\\])*)(?P<close>")?'
    r'|//[^\n]*'
    r'|#[^\n]*'
    r'|/\*.*?(?:\*/|\Z)'
    r'|[{}\[\]:,]',
    re.S)

_CONFIRM = re.compile(r'[ \t]*confirm(?=\s|$)[^\n]*', re.I)
_WORD = re.compile(r'[\w.\-]*$')


def escape(text):
    """`text` as the literal text of a Sublime snippet."""
    return text.replace('\\', '\\\\').replace('$', '\\$')


def _scan_json(text, start, offset):
    """Read the body that opens at `start`. The position behind it when it
    closes before `offset`; else where in it `offset` is, or None in a
    comment."""
    stack = []  # [bracket, keys, current key, what is expected]
    pos = start
    last = ''
    while True:
        m = _JTOK.search(text, pos)
        if not m or m.start() >= offset:
            break
        tok = m.group()
        pos = m.end()
        c = tok[0]
        if c == '"':
            closed = m.group('close') is not None
            top = stack[-1]
            is_key = top[0] == '{' and top[3] == 'key'
            if offset <= (m.end() - 1 if closed else m.end()):
                return {
                    'stack': stack,
                    'string': text[m.start() + 1:offset],
                    'role': 'key' if is_key else ('value' if last == ':' else 'other'),
                }
            if is_key:
                top[2] = m.group('body')
                top[1].append(top[2])
                top[3] = 'colon'
        elif c in '/#':
            if tok.startswith('/*'):
                if offset < m.end() or not tok.endswith('*/'):
                    return None
            elif offset <= m.end():
                return None
            continue
        elif c in '{[':
            stack.append([c, [], None, 'key' if c == '{' else 'value'])
        elif c in '}]':
            stack.pop()
            if not stack:
                return pos
        elif c == ':':
            if stack[-1][0] == '{':
                stack[-1][3] = 'value'
        elif c == ',':
            if stack[-1][0] == '{':
                stack[-1][3] = 'key'
                stack[-1][2] = None
        last = c
    between = text[pos:offset]
    bare = _WORD.search(between).group()
    top = stack[-1]
    role = 'other'
    if between.strip() == bare:
        if top[0] == '{' and top[3] == 'key' and last in '{,':
            role = 'key'
        elif top[0] == '{' and top[3] == 'value' and last == ':':
            role = 'value'
    return {'stack': stack, 'string': None, 'bare': bare, 'role': role}


def _scan(text, offset):
    """Where `offset` is: in a body (with the line that opened it), or on a
    line. None in a comment or in a string of a URI."""
    pos = 0
    line_start = 0
    seg_start = 0
    paren = 0
    while True:
        if pos == line_start:
            confirm = _CONFIRM.match(text, pos)
            if confirm:  # all of a `confirm` line is the question
                if offset <= confirm.end():
                    return None
                pos = confirm.end()
        m = _TOP.search(text, pos)
        if not m or m.start() >= offset:
            break
        kind = m.lastgroup
        pos = m.end()
        if kind == 'nl':
            line_start = seg_start = pos
            paren = 0
        elif kind == 'comment':
            if paren:
                pos = m.start() + 1  # a `#` in `~where(…)` is sent
            elif offset <= m.end():
                return None
        elif kind == 'open':
            if paren == 0:
                found = _scan_json(text, m.start(), offset)
                if found is None:
                    return None
                if isinstance(found, dict):
                    found['owner'] = text[line_start:m.start()]
                    return found
                pos = found
        elif kind == 'lp':
            paren += 1
        elif kind == 'rp':
            paren = max(0, paren - 1)
        elif kind == 'str':
            closed = m.group('strclose') is not None
            if offset <= (m.end() - 1 if closed else m.end()):
                return None
        elif kind == 'chain':
            if paren == 0:
                seg_start = pos
    return {
        'line': text[line_start:offset],
        'seg': text[seg_start:offset],
        'first': seg_start == line_start,
        'paren': paren,
    }


def _result(typed, items):
    return {'typed': typed, 'items': items}


def _words(typed, names, note, tail=' '):
    return _result(typed, [(name, escape(name) + tail, note) for name in names])


def _paths(typed, root, want, aliases=None):
    """The directories and the files `want` takes that `typed` may become."""
    cut = typed.rfind('/') + 1
    dirpart, partial = typed[:cut], typed[cut:]
    if dirpart.startswith('~/'):
        directory = os.path.join(os.path.expanduser('~'), dirpart[2:])
    elif dirpart.startswith('/'):
        directory = dirpart
    else:
        first, slash, rest = dirpart.partition('/')
        if slash and aliases and first in aliases:
            directory = os.path.join(aliases[first], rest)
        elif root is None:
            directory = None
        else:
            directory = os.path.join(root, dirpart)
    items = []
    if not dirpart and aliases:
        for alias in sorted(aliases):
            if alias.lower().startswith(partial.lower()):
                items.append((alias + '/', escape(alias + '/'), 'import'))
    try:
        names = sorted(os.listdir(directory)) if directory is not None else []
    except OSError:
        names = []
    for name in names:
        if name in JUNK or name.startswith('._'):
            continue
        if name.startswith('.') and not partial.startswith('.'):
            continue
        if not name.lower().startswith(partial.lower()):
            continue
        if os.path.isdir(os.path.join(directory, name)):
            items.append((dirpart + name + '/', escape(dirpart + name + '/'), 'directory'))
        elif want(name):
            items.append((dirpart + name, escape(dirpart + name), 'file'))
    return items


def _is_api(name):
    return name.lower().endswith('.api')


def _is_json(name):
    return name.lower().endswith('.json')


def _any_file(name):
    return True


def _no_file(name):
    return False


def _members(found, members, note):
    """The keys of an object: a name in a string that is being typed, the
    whole member where nothing is quoted yet."""
    present = found['stack'][-1][1]
    left = [(name, value) for name, value in members if name not in present]
    if found['string'] is not None:
        return _result(found['string'], [(name, escape(name), note) for name, _ in left])
    items = [(name, '"' + escape(name) + '": ' + value, note) for name, value in left]
    return _result(found['bare'], items)


def _in_block(found, file_dir):
    owner = found['owner']
    stack = found['stack']
    role = found['role']
    top = stack[-1]
    depth = len(stack)
    kind = None
    if re.match(r'\s*set\s*$', owner, re.I):
        kind = 'set'
    elif not owner.strip():
        kind = 'describe'
    else:
        m = re.match(r'\s*import\s+(git|dir|archive)\s+\S+\s*$', owner, re.I)
        if m:
            kind = m.group(1).lower()
    if kind is None or stack[0][0] != '{':
        return None  # a request's body: the editor's own completions

    if kind == 'set':
        if depth == 1 and role == 'key':
            return _members(found, SETTINGS, 'setting')
        if depth == 1 and role == 'value' and found['string'] is None:
            values = SETTING_VALUES.get(top[2], SWITCH_VALUES)
            return _words(found['bare'], values, 'value', '')
    elif kind == 'describe':
        if depth == 1 and role == 'key':
            return _members(found, DESCRIBE_MEMBERS, 'describe')
        if depth == 2 and role == 'key' and stack[0][2] in ('title', 'description'):
            return _members(found, [(locale, '"$1"') for locale in LOCALES], 'locale')
    else:
        if depth == 1 and role == 'key':
            return _members(found, [(key, '"$1"') for key in IMPORT_KEYS[kind]], 'import')
        if depth == 1 and role == 'value' and found['string'] is not None and kind == 'dir' and top[2] == 'path':
            return _result(found['string'], _paths(found['string'], file_dir, _no_file))
    return _result('', [])


_CONDITION = re.compile(
    r'\s*(?:assert|sleep(?:\s+\d*\.?\d+(?:ms|s)?)?\s+while)\s+(?:(not)\s+)?', re.I)


def _request(seg, paren, base_dir, outfile=True, conditions=()):
    """Completions in one request: `seg` is its text up to the cursor."""
    m = re.match(r'\s*(\S*)$', seg)
    if m:  # its first word
        word = m.group(1)
        if word.startswith('/'):
            return _uri(word, paren)
        return _words(word, list(conditions) + METHODS, 'method')
    m = re.match(r'\s*' + _METHOD + r'\s+', seg, re.I)
    if m:
        rest = seg[m.end():]
    elif seg.lstrip().startswith('/'):
        rest = seg.lstrip()
    else:
        return None
    if paren:  # in `~where(…)`: nothing there ends the URI
        return {'uri': True}
    if outfile:
        m = re.search(r'(?:^|\s)(>>?)\s*(\S*)$', rest)
        if m:
            items = _paths(m.group(2), base_dir, _any_file)
            if m.group(1) == '>' and 'clipboard'.startswith(m.group(2).lower()):
                items.insert(0, ('clipboard', 'clipboard', 'system clipboard'))
            return _result(m.group(2), items)
    m = re.search(r'\s@\s*(\S*)$', rest)
    if m:
        path = m.group(1)
        function = re.search(r'~(\w*)$', path)
        if function:
            return _result(function.group(1), [('map(', 'map($1)', 'X-Request-Map')])
        return _result(path, _paths(path, base_dir, _any_file))
    if not re.search(r'\s', rest):
        return _uri(rest, paren)
    return None


def _uri(uri, paren):
    m = re.search(r'~(\w*)$', uri)
    if m and paren == 0:
        items = []
        for operator in OPERATORS:
            snippet = operator[:-1] + '($1)' if operator.endswith('(') else operator
            items.append((operator, snippet, 'operator'))
        return _result(m.group(1), items)
    return {'uri': True}


def _on_line(at, file_dir, base_dir, aliases):
    line = at['line']
    if not at['first']:  # behind a `&&` or `||`
        return _request(at['seg'], at['paren'], base_dir)

    m = re.match(r'\s*import\s+(\S*)$', line, re.I)
    if m:
        return _words(m.group(1), IMPORT_KINDS, 'import')
    m = re.match(r'\s*(?:import\s+\S+\s+\S+|set)\s+@\s*(\S*)$', line, re.I)
    if m:  # one JSON file
        return _result(m.group(1), _paths(m.group(1), base_dir, _is_json))
    if re.match(r'\s*(?:import|set)\s', line, re.I):
        return None
    m = re.match(r'\s*url\s+(\S*)$', line, re.I)
    if m:
        return _words(m.group(1), ['has', 'is'], 'url')
    if re.match(r'\s*url\s', line, re.I):
        return None
    m = re.match(r'\s*sleep\s+(?:\d*\.?\d+(?:ms|s)?\s+)?([A-Za-z]*)$', line, re.I)
    if m:
        return _words(m.group(1), ['while'], 'sleep')
    m = _CONDITION.match(line)
    if m:  # the request of an `assert` or a `sleep while`: no outfile
        conditions = () if m.group(1) else ('not',)
        return _request(line[m.end():], at['paren'], base_dir, False, conditions)

    m = re.match(r'\s*(\S*)$', line)
    if not m:
        return _request(line, at['paren'], base_dir)
    word = m.group(1)
    if word.startswith('/'):
        # `/tmp/seed.api` is an include; a URI is not this file's to complete
        return _uri(word, at['paren'])
    includes = _paths(word, file_dir, _is_api, aliases)
    if '/' in word or word[:1] in ('~', '.'):
        return _result(word, includes)
    items = [(name, escape(name) + ' ', 'method') for name in METHODS]
    items += [(name, escape(name) + ' ', 'directive') for name in DIRECTIVES]
    items = [item for item in items if item[0].lower().startswith(word.lower())]
    return _result(word, items + includes)


def complete(text, offset, file_dir=None, base_dir=None, aliases=None):
    """What can stand at `offset` of the `.api` file `text`.

    `{'typed': …, 'items': [(name, snippet, note), …]}`: `typed` is the text
    in front of the cursor that an item takes the place of. `{'uri': True}`
    in a URI, which is not completed here. None where the editor's own
    completions are as good as any (a request's body, a comment).

    `file_dir` is the directory of the file, which an include is relative
    to; `base_dir` the working directory, which an `@file` and an outfile
    are relative to; `aliases` the directory each import alias stands for.
    """
    at = _scan(text, offset)
    if at is None:
        return None
    if 'stack' in at:
        return _in_block(at, file_dir)
    return _on_line(at, file_dir, base_dir, aliases)


_DIR_IMPORT = re.compile(
    r'^[ \t]*import[ \t]+dir[ \t]+([A-Za-z0-9_-]+)[ \t]*\{[^{}]*?"path"\s*:\s*"([^"\n]*)"',
    re.M | re.I)
_REMOTE_IMPORT = re.compile(
    r'^[ \t]*import[ \t]+(?:git|archive)[ \t]+\S+[ \t]+(?:(@[^\n]*)|(?=\{))', re.M | re.I)
_BASEDIR = re.compile(r'^[ \t]*#[ \t]*@basedir[ \t]+(.+?)[ \t]*$', re.M)


def _resolve(path, relative_to):
    if path.startswith('~/') or path == '~':
        return os.path.expanduser(path)
    if os.path.isabs(path) or relative_to is None:
        return path
    return os.path.normpath(os.path.join(relative_to, path))


def dir_aliases(text, file_dir):
    """The directory of each `import dir` alias, read from its line."""
    return dict((m.group(1), _resolve(m.group(2), file_dir)) for m in _DIR_IMPORT.finditer(text))


def remote_imports(text):
    """The `import git` and `import archive` lines of a file, each whole,
    as a file of their own: what the client is asked about. The file itself
    can't be asked about while it is written: a line that is half typed
    stops it from being read."""
    lines = []
    for m in _REMOTE_IMPORT.finditer(text):
        if m.group(1):
            lines.append(text[m.start():m.end()].strip())
            continue
        end = _scan_json(text, m.end(), len(text))
        if isinstance(end, int):  # an object that is closed
            lines.append(text[m.start():end].strip())
    return '\n'.join(lines)


def base_dir(text, file_dir, folders=()):
    """The directory an `@file` is taken to be relative to. That is the
    working directory of the run, which an editor does not know: a
    `# @basedir <path>` comment of the file says it, else it is the project
    folder the file is in, else the first one, else the file's directory."""
    m = _BASEDIR.search(text)
    if m:
        return _resolve(m.group(1), file_dir)
    if file_dir is not None:
        for folder in folders:
            if (file_dir + os.sep).startswith(folder.rstrip(os.sep) + os.sep):
                return folder
    if folders:
        return folders[0]
    return file_dir


def to_sublime(result, prefix):
    """The items as Sublime Text takes them, `(trigger, contents)`.

    Sublime replaces `prefix`, the word in front of the cursor as its word
    separators cut it, which is the end of what was typed: `nu` of
    `include-nu`, nothing of `cl/`. A trigger is what is left of a name
    behind the part that stays.
    """
    typed = result['typed']
    if prefix and typed.lower().endswith(prefix.lower()):
        head = typed[:len(typed) - len(prefix)]
    elif prefix:
        head = ''
    else:
        head = typed
    out = []
    for name, snippet, note in result['items']:
        if not name.lower().startswith(head.lower()) or len(name) == len(head):
            continue
        trigger = name[len(head):]
        contents = snippet
        if head:
            whole = escape(name)
            tail = snippet[len(whole):] if snippet.startswith(whole) else ''
            contents = escape(trigger) + tail
            if '/' not in head:
                note = name
        out.append((trigger + '\t' + note, contents))
    return out


# ---------------------------------------------------------------- Sublime Text

# The directory of each git and archive alias, as `api --imports` said it
# for the import lines of a file: {(working directory, lines): {alias: directory}}.
_imports = {}
_asking = set()

_BINARIES = ['/opt/homebrew/bin/api', '/usr/local/bin/api', '~/.cargo/bin/api', '~/.local/bin/api']


def _client(settings):
    named = settings.get('api_binary')
    if named:
        return os.path.expanduser(named)
    try:
        from shutil import which
        found = which('api')
    except ImportError:
        found = None
    if found:
        return found
    for path in _BINARIES:
        path = os.path.expanduser(path)
        if os.path.isfile(path):
            return path
    return None


def _ask_imports(binary, lines, cwd):
    """Ask the client where the imports of `lines` are, off the main thread.
    It fetches one that is not in its cache, which may take a while."""
    key = (cwd, lines)

    def run():
        aliases = {}
        try:
            startup = None
            if os.name == 'nt':
                startup = subprocess.STARTUPINFO()
                startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            process = subprocess.Popen(
                [binary, '-r', '--imports', '-'], cwd=cwd, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, startupinfo=startup)
            try:
                out, _ = process.communicate(lines.encode('utf-8'), timeout=120)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                out = b''
            if process.returncode == 0:
                for entry in json.loads(out.decode('utf-8')):
                    aliases[entry['alias']] = entry['directory']
        except Exception:
            aliases = {}
        # An import that can't be resolved has no directory: it is not asked
        # about again until its line changes.
        if len(_imports) > 50:
            _imports.clear()
        _imports[key] = aliases
        _asking.discard(key)

    if key in _asking:
        return
    _asking.add(key)
    threading.Thread(target=run).start()


def _is_api_view(view):
    syntax = view.settings().get('syntax') or ''
    return syntax.endswith('/API.sublime-syntax') or view.match_selector(0, 'source.api')


# characters that open the completions without a letter typed, by scope
_TRIGGERS = [
    {'selector': 'meta.set.api, meta.import.api, meta.describe.api', 'characters': '"'},
    {'selector': 'meta.include.api, meta.path.infile.api, meta.path.outfile.api', 'characters': '/'},
    {'selector': 'meta.url.api - string, meta.path.infile.api', 'characters': '~'},
]


if sublime_plugin is not None:

    class ApiCompletions(sublime_plugin.EventListener):

        def _prepare(self, view):
            settings = view.settings()
            if settings.get('api_completions') or not _is_api_view(view):
                return
            triggers = list(settings.get('auto_complete_triggers') or [])
            settings.set('auto_complete_triggers', triggers + _TRIGGERS)
            settings.set('api_completions', True)

        def on_load(self, view):
            self._prepare(view)

        def on_activated(self, view):
            self._prepare(view)

        def _folders(self, view):
            window = view.window()
            return window.folders() if window else []

        def _aliases(self, view, text):
            path = view.file_name()
            file_dir = os.path.dirname(path) if path else None
            aliases = {}
            lines = remote_imports(text)
            if lines:
                cwd = base_dir(text, file_dir, self._folders(view))
                if cwd is None or not os.path.isdir(cwd):
                    cwd = None
                if (cwd, lines) not in _imports:
                    binary = _client(view.settings())
                    if binary:
                        _ask_imports(binary, lines, cwd)
                aliases.update(_imports.get((cwd, lines), {}))
            aliases.update(dir_aliases(text, file_dir))
            return aliases

        def on_query_completions(self, view, prefix, locations):
            point = locations[0]
            if not view.match_selector(point, 'source.api'):
                return None
            text = view.substr(sublime.Region(0, view.size()))
            path = view.file_name()
            file_dir = os.path.dirname(path) if path else None
            result = complete(
                text, point, file_dir, base_dir(text, file_dir, self._folders(view)),
                self._aliases(view, text))
            if result is None:
                return None
            quiet = sublime.INHIBIT_WORD_COMPLETIONS | sublime.INHIBIT_EXPLICIT_COMPLETIONS
            if result.get('uri'):
                # a `/` typed in a URI opens nothing; a word of it completes
                # from the words of the file, as before
                return None if prefix else ([], quiet)
            return (to_sublime(result, prefix), quiet)
