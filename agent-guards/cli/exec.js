// Running the real command after the check passes.
//
// Windows is the whole reason this file exists. `npm` there is `npm.cmd`, a batch file, and Windows
// cannot execute a batch file without a shell — so the command has to go through cmd.exe. Handing
// cmd.exe a command line means its metacharacters apply, and `^` is one of them, which matters
// because `npm install lodash@^4.17.21` is an ordinary thing to type and cmd would silently eat the
// caret. Inside double quotes cmd leaves `^` alone, so every argument is quoted and the line is
// passed verbatim.
//
// POSIX needs none of this: spawn the binary with an argument array and no shell is involved.

const { spawnSync } = require('child_process');

function quoteForCmd(arg) {
  const s = String(arg);
  // A double quote inside an argument has to be escaped for cmd, and any trailing backslashes have
  // to be doubled or they escape the closing quote.
  const escaped = s.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1');
  return `"${escaped}"`;
}

// Returns the exit code of the command that ran, or null if it could not be started.
function passthrough(command, args, opts = {}) {
  const stdio = opts.stdio || 'inherit';
  if (process.platform === 'win32') {
    const comspec = process.env.ComSpec || process.env.COMSPEC || 'cmd.exe';
    // The outer pair of quotes is load-bearing. `/s` tells cmd to strip the first and last character
    // of the argument when both are quotes and run what is left verbatim; without the extra pair it
    // strips the quotes around the executable instead, and any path with a space in it — which on
    // Windows means most of them, starting with C:\Program Files — becomes two arguments.
    const line = '"' + [command, ...args].map(quoteForCmd).join(' ') + '"';
    const r = spawnSync(comspec, ['/d', '/s', '/c', line], {
      stdio,
      windowsVerbatimArguments: true,
      cwd: opts.cwd,
      env: opts.env,
    });
    if (r.error) return { code: null, error: r.error.message };
    return { code: r.status === null ? 1 : r.status, stdout: r.stdout && String(r.stdout), stderr: r.stderr && String(r.stderr) };
  }
  const r = spawnSync(command, args, { stdio, cwd: opts.cwd, env: opts.env });
  if (r.error) return { code: null, error: r.error.message };
  return { code: r.status === null ? 1 : r.status, stdout: r.stdout && String(r.stdout), stderr: r.stderr && String(r.stderr) };
}

// git, for `guard diff`. Captured rather than inherited, and a missing git is reported as a missing
// git instead of an empty diff — an empty diff would read as "nothing to review".
function git(args, cwd) {
  const r = passthrough('git', args, { stdio: 'pipe', cwd });
  if (r.error) return { ok: false, error: `git could not be run: ${r.error}` };
  if (r.code !== 0) return { ok: false, error: (r.stderr || '').trim() || `git exited ${r.code}` };
  return { ok: true, out: r.stdout || '' };
}

module.exports = { passthrough, git, quoteForCmd };
