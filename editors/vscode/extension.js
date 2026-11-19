// Completions for `.api` batch files in VS Code and Cursor.
//
// What can stand where the cursor is, is the client's to say: this extension
// asks it (`api --complete`) and hands the answer to the editor. So what is
// offered is what the client that is installed reads. It needs nothing but
// what the editor has: no module is installed for it.

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vscode = require('vscode');

const LANGUAGE = 'commerceos-api';

// Where the client is looked for when the editor was not started from a
// shell and has no `PATH` to speak of.
const BINARIES = ['/opt/homebrew/bin/api', '/usr/local/bin/api', '~/.cargo/bin/api', '~/.local/bin/api'];

function expanded(file) {
  return file.startsWith('~/') ? path.join(os.homedir(), file.slice(2)) : file;
}

// The client to ask: the one the setting `commerceosApi.binary` names, else
// one where a client is usually installed, else the `api` on the `PATH`.
function client() {
  const named = vscode.workspace.getConfiguration('commerceosApi').get('binary');
  if (named) {
    return expanded(named);
  }
  const onPath = (process.env.PATH || '').split(path.delimiter).some((dir) => {
    return dir && ['api', 'api.exe'].some((name) => fs.existsSync(path.join(dir, name)));
  });
  if (!onPath) {
    const found = BINARIES.map(expanded).find((file) => fs.existsSync(file));
    if (found) {
      return found;
    }
  }
  return 'api';
}

// The directory the client is asked in, which is what it takes an `@file`
// and an outfile to be relative to: the workspace folder the file is in,
// else the first one, else the directory of the file.
function workingDir(document) {
  const folder = vscode.workspace.getWorkspaceFolder(document.uri) || (vscode.workspace.workspaceFolders || [])[0];
  if (folder && folder.uri.scheme === 'file') {
    return folder.uri.fsPath;
  }
  return document.uri.scheme === 'file' ? path.dirname(document.uri.fsPath) : undefined;
}

// What the client says can stand at `position`. Undefined when it says
// nothing, or can't be asked (a client from before `--complete`).
function ask(document, position, token) {
  const text = document.getText();
  const before = document.getText(new vscode.Range(new vscode.Position(0, 0), position));
  const file = document.uri.scheme === 'file' ? document.uri.fsPath : '-';
  const args = ['-r', '--complete', file, '--at', String(Buffer.byteLength(before, 'utf8'))];
  return new Promise((resolve) => {
    let child;
    try {
      child = childProcess.execFile(client(), args, { cwd: workingDir(document), timeout: 3000 }, (error, stdout) => {
        if (error) {
          return resolve(undefined);
        }
        try {
          resolve(JSON.parse(stdout) || undefined);
        } catch (e) {
          resolve(undefined);
        }
      });
    } catch (e) {
      return resolve(undefined);
    }
    child.on('error', () => resolve(undefined));
    child.stdin.on('error', () => {});
    child.stdin.end(text);
    if (token) {
      token.onCancellationRequested(() => child.kill());
    }
  });
}

const KINDS = {
  setting: 'Property',
  describe: 'Property',
  import: 'Module',
  locale: 'Constant',
  value: 'Value',
  method: 'Keyword',
  directive: 'Keyword',
  url: 'Keyword',
  sleep: 'Keyword',
  operator: 'Function',
  'X-Request-Map': 'Function',
  directory: 'Folder',
  file: 'File',
};

async function provideCompletionItems(document, position, token) {
  const result = await ask(document, position, token);
  if (!result || !result.items) {
    return undefined;
  }
  // what an item takes the place of: the text typed so far, on this line
  const range = new vscode.Range(position.translate(0, -result.typed.length), position);
  return result.items.map((item, index) => {
    const completion = new vscode.CompletionItem(item.name, vscode.CompletionItemKind[KINDS[item.note] || 'Text']);
    completion.insertText = new vscode.SnippetString(item.snippet);
    completion.range = range;
    completion.detail = item.note;
    completion.filterText = item.name;
    // in the order the client gave them
    completion.sortText = String(index).padStart(4, '0');
    if (item.name.endsWith('/')) {
      // a directory: go on into it
      completion.command = { command: 'editor.action.triggerSuggest', title: '' };
    }
    return completion;
  });
}

function activate(context) {
  context.subscriptions.push(
    vscode.languages.registerCompletionItemProvider(LANGUAGE, { provideCompletionItems }, '"', '/', '~', '@')
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
