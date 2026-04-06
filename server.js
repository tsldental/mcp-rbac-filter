/**
 * mcp-rbac-filter
 *
 * An Express proxy that sits in front of an Azure Functions MCP server and
 * filters the tools returned by `tools/list` based on the caller's Microsoft
 * Entra ID roles (or delegated scopes) embedded in their Bearer JWT.
 *
 * Environment variables (see .env.example):
 *   TARGET_URL  – upstream MCP server base URL (required)
 *   PORT        – port this proxy listens on (default: 3000)
 */

import express from 'express';
import axios from 'axios';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import dotenv from 'dotenv';

dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT ?? 3000;
const TARGET_URL = process.env.TARGET_URL;

// ---------------------------------------------------------------------------
// RBAC config
// ---------------------------------------------------------------------------

const rbacConfig = JSON.parse(
  readFileSync(join(__dirname, 'rbac-config.json'), 'utf-8'),
);

// Remove the comment key if present
delete rbacConfig['_comment'];

// ---------------------------------------------------------------------------
// JWT helpers (decode only — no signature verification)
// ---------------------------------------------------------------------------

function decodeJwtPayload(token) {
  try {
    const [, payloadB64] = token.split('.');
    if (!payloadB64) return null;
    return JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
  } catch {
    return null;
  }
}

/**
 * Extract role/scope strings from a decoded Entra ID JWT payload.
 * Prefers the `roles` app-role claim; falls back to the `scp` delegated-scope
 * claim (space-separated string).
 */
function getUserRoles(payload) {
  if (!payload) return [];
  if (Array.isArray(payload.roles) && payload.roles.length > 0) return payload.roles;
  if (typeof payload.scp === 'string' && payload.scp.length > 0) return payload.scp.split(' ');
  return [];
}

/**
 * Resolve the set of tool names the caller is allowed to see.
 * Returns `null` to mean "allow everything" (wildcard admin).
 * Returns an empty Set when the caller has no matching roles at all.
 */
function resolveAllowedTools(roles) {
  const allowed = new Set();
  for (const role of roles) {
    const perms = rbacConfig[role];
    if (!perms) continue;
    if (perms.includes('*')) return null; // wildcard — skip further checks
    perms.forEach((t) => allowed.add(t));
  }
  return allowed;
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

/**
 * Remove tools the caller is not permitted to see from a JSON-RPC response
 * body that contains a `result.tools` array.
 *
 * @param {object} body         - Parsed JSON-RPC response
 * @param {Set|null} allowed    - Set of allowed tool names, or null for all
 * @returns {object}            - (Mutated) body
 */
function filterToolsListBody(body, allowed) {
  if (allowed === null) return body; // admin wildcard
  if (!body?.result?.tools) return body;

  body.result.tools = body.result.tools.filter((tool) => allowed.has(tool.name));
  return body;
}

// ---------------------------------------------------------------------------
// SSE helpers
// ---------------------------------------------------------------------------

/**
 * Process one SSE "block" — the text between two `\n\n` delimiters.
 * Parses every `data:` line as JSON, applies the tools filter, and
 * re-serialises it. Non-JSON data lines (heartbeats, etc.) are passed through.
 *
 * @param {string}   block   - Raw SSE block text (no trailing \n\n)
 * @param {Set|null} allowed - Allowed tool set from resolveAllowedTools()
 * @returns {string}         - Processed block (no trailing \n\n)
 */
function processSSEBlock(block, allowed) {
  const outLines = [];

  for (const line of block.split('\n')) {
    if (!line.startsWith('data: ')) {
      outLines.push(line); // comment, event, id, retry — pass through
      continue;
    }

    const raw = line.slice(6).trim();

    // SSE heartbeats like `data: ` (empty) or non-JSON pings
    if (!raw || raw === '[DONE]') {
      outLines.push(line);
      continue;
    }

    try {
      const parsed = JSON.parse(raw);
      const filtered = filterToolsListBody(parsed, allowed);
      outLines.push('data: ' + JSON.stringify(filtered));
    } catch {
      outLines.push(line); // not JSON — pass through verbatim
    }
  }

  return outLines.join('\n');
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

app.use(async (req, res) => {
  if (!TARGET_URL) {
    return res
      .status(500)
      .json({ error: 'TARGET_URL environment variable is not configured.' });
  }

  // --- Auth & role resolution ---
  const authHeader = req.headers['authorization'] ?? '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    console.warn('[mcp-rbac-filter] Request received without a Bearer token — no tools will be visible.');
  }

  const jwtPayload = token ? decodeJwtPayload(token) : null;
  const roles = getUserRoles(jwtPayload);
  const allowedTools = resolveAllowedTools(roles);

  console.log(
    `[mcp-rbac-filter] ${req.method} ${req.path} | roles: [${roles.join(', ') || 'none'}] | method: ${req.body?.method ?? 'n/a'}`,
  );

  const isToolsListReq = req.body?.method === 'tools/list';

  // --- Build forwarded headers ---
  const forwardHeaders = { ...req.headers };
  delete forwardHeaders['host'];
  // Let axios set the correct Content-Length for the re-serialised body
  delete forwardHeaders['content-length'];

  const upstreamUrl = TARGET_URL.replace(/\/$/, '') + (req.path || '/');

  // --- Proxy the request ---
  let upstream;
  try {
    upstream = await axios({
      method: req.method,
      url: upstreamUrl,
      headers: forwardHeaders,
      // Only attach a body for methods that carry one
      data: ['POST', 'PUT', 'PATCH'].includes(req.method) ? req.body : undefined,
      responseType: 'stream',
      // Pass all upstream status codes through — do not throw on 4xx/5xx
      validateStatus: () => true,
    });
  } catch (err) {
    console.error('[mcp-rbac-filter] Failed to reach upstream:', err.message);
    if (!res.headersSent) {
      res.status(502).json({ error: 'Bad gateway — could not reach upstream MCP server.', details: err.message });
    }
    return;
  }

  // --- Relay upstream status & headers ---
  res.status(upstream.status);
  for (const [key, value] of Object.entries(upstream.headers)) {
    // Express handles Transfer-Encoding itself; skip to avoid conflicts
    if (key.toLowerCase() === 'transfer-encoding') continue;
    res.setHeader(key, value);
  }

  const contentType = upstream.headers['content-type'] ?? '';
  const isSSE = contentType.includes('text/event-stream');

  // --- Non-SSE passthrough (or SSE that isn't a tools/list response) ---
  if (!isSSE || !isToolsListReq) {
    if (isSSE) {
      // Ensure SSE headers are set for passthrough streams
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders();
    }
    upstream.data.pipe(res);

    req.on('close', () => upstream.data.destroy());
    return;
  }

  // --- SSE tools/list: intercept, filter, relay ---
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  let buffer = '';

  upstream.data.on('data', (chunk) => {
    buffer += chunk.toString('utf-8');

    // SSE messages are delimited by a blank line (\n\n).
    // Process every complete message that has arrived so far.
    let boundary;
    while ((boundary = buffer.indexOf('\n\n')) !== -1) {
      const block = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);

      if (!block.trim()) continue; // skip blank separators

      const processed = processSSEBlock(block, allowedTools);
      res.write(processed + '\n\n');
    }
  });

  upstream.data.on('end', () => {
    // Flush any partial block remaining in the buffer
    if (buffer.trim()) {
      const processed = processSSEBlock(buffer, allowedTools);
      res.write(processed + '\n');
    }
    res.end();
  });

  upstream.data.on('error', (err) => {
    console.error('[mcp-rbac-filter] Upstream stream error:', err.message);
    res.end();
  });

  // If the client disconnects, stop draining the upstream
  req.on('close', () => upstream.data.destroy());
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`[mcp-rbac-filter] Listening on http://localhost:${PORT}`);
  console.log(`[mcp-rbac-filter] Upstream MCP server: ${TARGET_URL ?? '⚠️  TARGET_URL not set'}`);
  console.log(`[mcp-rbac-filter] Loaded ${Object.keys(rbacConfig).length} role(s) from rbac-config.json`);
});
