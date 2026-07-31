// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/mcp/server.mjs
// Regenerate: node scripts/sync-shared.js
// The MCP layer shared by the unified server and by all six facade packages.
//
// Everything about a tool (name, schema, description, behaviour) comes from the core registry. This
// file only turns those declarations into MCP registrations, which is why a facade is about ten
// lines and cannot drift from the unified server.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

// Plain declarations -> a zod raw shape. Kept deliberately small: the core stays free of zod, and
// the only shapes we use are strings, numbers, enums and string arrays.
function zodShape(input) {
  const shape = {};
  for (const [key, spec] of Object.entries(input || {})) {
    let f;
    if (spec.enum) f = z.enum(spec.enum);
    else if (spec.type === 'number') f = z.number();
    else if (spec.type === 'boolean') f = z.boolean();
    else if (spec.type === 'array') f = z.array(z.string());
    else if (spec.type === 'record') f = z.record(z.string());
    else f = z.string();
    if (spec.description) f = f.describe(spec.description);
    if (spec.optional) f = f.optional();
    shape[key] = f;
  }
  return shape;
}

// What an agent reads before deciding to call a tool. The offline/cloud status belongs here: a tool
// that cannot reach its data source should say so up front, not only in its error.
function describe(tool, ctx) {
  let d = tool.description;
  if (tool.needs && tool.needs.length) {
    d += ` Network: needs ${tool.needs.join(', ')}.`;
    // Not every cloud tool refuses offline. Some are mostly local with a remote enrichment on top
    // (an inbound email still gets parsed and injection-scanned without DNS), and telling an agent
    // those return nothing offline is its own small lie. A tool says so with `cloudWhen`.
    if (ctx.offline) {
      d += tool.cloudWhen
        ? ` OFFLINE MODE IS ON. The network is only used when ${tool.cloudWhen}; offline the local part still runs and anything skipped is listed in checks_skipped.`
        : ' OFFLINE MODE IS ON, so this tool will report that it could not check rather than returning a verdict.';
    } else if (tool.cloudWhen) {
      d += ` The network is only used when ${tool.cloudWhen}.`;
    }
  } else {
    d += ' Runs fully locally: the input never leaves this machine.';
  }
  if (tool.needsPackages && tool.needsPackages.length) {
    d += ` Optional packages: ${tool.needsPackages.join(', ')}. Without them this tool reports what is missing instead of guessing.`;
  }
  return d;
}

const ok = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });
const errored = (msg) => ({ content: [{ type: 'text', text: 'Error: ' + msg }], isError: true });

// Build a server from a list of tool declarations.
//
//   tools     the declarations to register
//   name      MCP server name
//   version   MCP server version (keep this equal to the package version)
//   ctx       { offline, disabled: Set<string> } passed to every handler
export function createServer({ tools, name, version, ctx }) {
  const server = new McpServer({ name, version });
  const registered = [];

  for (const tool of tools) {
    if (ctx.disabled && ctx.disabled.has(tool.name)) continue;
    registered.push(tool.name);
    server.tool(tool.name, describe(tool, ctx), zodShape(tool.input), async (args) => {
      try {
        const result = await tool.run(args || {}, ctx);
        // A handler that reports ok:false is a failed check, not a crashed tool. Surface it as an
        // error so an agent does not read the payload as a verdict.
        if (result && result.ok === false && result.error) return errored(result.error + (result.advice ? ' ' + result.advice : ''));
        return ok(result);
      } catch (e) {
        return errored(String((e && e.message) || e));
      }
    });
  }

  return { server, registered };
}

export async function serveStdio({ tools, name, version, ctx }) {
  const { server, registered } = createServer({ tools, name, version, ctx });
  await server.connect(new StdioServerTransport());
  return registered;
}

export { zodShape, describe };
