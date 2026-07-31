// The thread that actually runs untrusted patterns. See lib/redos.js for why this exists.
//
// It compiles one pattern at a time and runs it against the pump strings the parent sent, posting
// a `start` message before each pattern so the parent knows which one to blame if the clock runs
// out. Nothing here is allowed to be clever: if this thread hangs, that is the expected outcome for
// a catastrophic pattern and the parent kills it.

const { parentPort } = require('worker_threads');

parentPort.on('message', (job) => {
  const results = [];
  for (let i = 0; i < job.patterns.length; i++) {
    const p = job.patterns[i];
    // Tell the parent which pattern is in flight before touching it. If the next line never
    // returns, this message is the only record of what was running.
    parentPort.postMessage({ start: i });

    let re;
    try {
      re = new RegExp(p.source, p.flags || '');
    } catch (e) {
      results.push({ index: i, ok: false, reason: `does not compile: ${String((e && e.message) || e)}` });
      continue;
    }

    const started = Date.now();
    for (const input of job.inputs[i]) {
      // lastIndex matters for /g patterns: without the reset a second call starts mid-string and
      // the expensive prefix never gets exercised.
      re.lastIndex = 0;
      try { re.test(input); } catch { /* a pattern that throws at match time is caught by the parent's compile check */ }
    }
    results.push({ index: i, ok: true, ms: Date.now() - started });
  }
  parentPort.postMessage({ done: true, results });
});

parentPort.postMessage({ ready: true });
