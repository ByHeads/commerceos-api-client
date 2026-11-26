# -*- coding: utf-8 -*-
"""Completions and formatting for `.api` batch files in Sublime Text.

Installed beside `API.sublime-syntax` by `api --install-editor sublime`.
What can stand where the cursor is, is the client's to say: this plugin asks
it (`api --complete`) and hands the answer to the editor. So what is offered
is what the client that is installed reads. The command `api_format` lays
the file out the same way: by asking the client (`api --format`).

It is written for the Python 3.3 that Sublime Text runs a plugin of
`Packages/User` in, so it does without what came later.
"""

import json
import os
import subprocess

try:
    import sublime
    import sublime_plugin
except ImportError:  # the tests run this file without an editor
    sublime = None
    sublime_plugin = None


# Where the client is looked for when Sublime Text was not started from a
# shell and has no `PATH` to speak of.
_BINARIES = ['/opt/homebrew/bin/api', '/usr/local/bin/api', '~/.cargo/bin/api', '~/.local/bin/api']


def installed_client():
    """The client that installed this plugin, which wrote its path to
    `api_client.json` beside it. None when that file or the client is gone."""
    try:
        beside = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'api_client.json')
        with open(beside, encoding='utf-8') as named:
            path = json.load(named).get('client')
    except (OSError, ValueError, AttributeError, NameError):
        return None
    return path if path and os.path.isfile(path) else None


def client(named=None):
    """The client to ask: the one the setting `api_binary` names, else the
    one that installed this plugin, else the `api` on the `PATH`, else one
    where a client is usually installed. The installing client goes before
    the `PATH`: what is there may be an older client, without what is asked."""
    if named:
        return os.path.expanduser(named)
    installed = installed_client()
    if installed:
        return installed
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


def ask(binary, text, offset, path=None, cwd=None):
    """What the client says can stand at character `offset` of `text`, the
    text of the file `path`. None when it says nothing, or can't be asked
    (a client from before `--complete`)."""
    at = len(text[:offset].encode('utf-8'))
    try:
        startup = None
        if os.name == 'nt':
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        process = subprocess.Popen(
            [binary, '-r', '--complete', path or '-', '--at', str(at)], cwd=cwd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, startupinfo=startup)
        try:
            out, _ = process.communicate(text.encode('utf-8'), timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            return None
        if process.returncode != 0:
            return None
        return json.loads(out.decode('utf-8'))
    except (OSError, ValueError):
        return None


def formatted(binary, text, expanded=False):
    """`text` as the client lays a `.api` file out. None when it can't be
    asked (a client from before `--format`)."""
    args = [binary, '--format', '-']
    if expanded:
        args.append('--expand')
    try:
        startup = None
        if os.name == 'nt':
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        process = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, startupinfo=startup)
        try:
            out, _ = process.communicate(text.encode('utf-8'), timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            return None
        if process.returncode != 0:
            return None
        return out.decode('utf-8')
    except (OSError, ValueError):
        return None


def working_dir(path, folders=()):
    """The directory the client is asked in, which is what it takes an
    `@file` and an outfile to be relative to: the project folder the file is
    in, else the first one, else the directory of the file."""
    file_dir = os.path.dirname(path) if path else None
    if file_dir:
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
    for item in result['items']:
        name, snippet, note = item['name'], item['snippet'], item['note']
        if not name.lower().startswith(head.lower()) or len(name) == len(head):
            continue
        trigger = name[len(head):]
        if head:
            # the snippet starts with the name, and so with what stays
            escaped = len(head.replace('\\', '\\\\').replace('$', '\\$'))
            snippet = snippet[escaped:]
            if '/' not in head:
                note = name
        out.append((trigger + '\t' + note, snippet))
    return out


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

        def on_query_completions(self, view, prefix, locations):
            point = locations[0]
            if not view.match_selector(point, 'source.api'):
                return None
            binary = client(view.settings().get('api_binary'))
            if not binary:
                return None
            window = view.window()
            path = view.file_name()
            cwd = working_dir(path, window.folders() if window else [])
            text = view.substr(sublime.Region(0, view.size()))
            result = ask(binary, text, point, path, cwd if cwd and os.path.isdir(cwd) else None)
            if result is None:
                return None
            quiet = sublime.INHIBIT_WORD_COMPLETIONS | sublime.INHIBIT_EXPLICIT_COMPLETIONS
            if result.get('uri'):
                # a `/` typed in a URI opens nothing; a word of it completes
                # from the words of the file, as before
                return None if prefix else ([], quiet)
            return (to_sublime(result, prefix), quiet)

    class ApiFormatCommand(sublime_plugin.TextCommand):
        """`api_format`: lay the file out as the client does. With
        `expanded`, a line for each member of every object and array."""

        def is_enabled(self):
            return _is_api_view(self.view)

        def run(self, edit, expanded=False):
            view = self.view
            binary = client(view.settings().get('api_binary'))
            whole = sublime.Region(0, view.size())
            text = view.substr(whole)
            laid_out = formatted(binary, text, expanded) if binary else None
            if laid_out is None:
                sublime.status_message(
                    'API: %s could not format this file: it needs a client with --format' % (binary or 'api'))
            elif laid_out != text:
                view.replace(edit, whole, laid_out)
