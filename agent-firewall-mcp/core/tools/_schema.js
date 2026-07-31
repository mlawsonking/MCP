// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/tools/_schema.js
// Regenerate: node scripts/sync-shared.js
// Tool definitions are declared as plain data so the core stays dependency-light: the MCP layer
// converts them to zod at registration time, and nothing in engines/ has to know MCP exists.
//
// A declaration looks like:
//   { name, product, description, needs: [...], input: { field: {type, description, optional, enum} }, run }
//
// `needs` lists the external services the tool calls. An empty array means the tool is fully local
// and works offline. Anything listed there is a service that can be unreachable, and the handler is
// responsible for saying so rather than returning a reassuring answer.

// A cloud tool that cannot reach its service must return this shape rather than a verdict. The
// wording matters: "could not check" is not "nothing found". Four endpoints once said "not
// sanctioned", "no known vulnerabilities", "not a honeypot" and "safe" when the lookup behind each
// had failed, and that is the bug class this project exists to not have.
function unavailable(tool, needs, reason) {
  return {
    ok: false,
    tool,
    verdict: 'unknown',
    checked: false,
    error: reason,
    needs,
    advice: `This check needs ${needs.join(', ')} and could not reach ${needs.length === 1 ? 'it' : 'them'}. Treat the result as unknown, not as clear.`,
  };
}

// Describe what a tool costs in offline mode, for the tool description shown to an agent.
function offlineNote(needs) {
  if (!needs || !needs.length) return 'Runs fully locally. No network, no data leaves the machine.';
  return `Needs the network (${needs.join(', ')}). With --offline this reports that it could not check rather than returning a verdict.`;
}

module.exports = { unavailable, offlineNote };
