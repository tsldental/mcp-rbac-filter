/**
 * mcp-rbac-filter
 *
 * An Express proxy that sits in front of an Azure Functions MCP server and:
 *  1. Verifies the caller's Entra ID Bearer JWT (signature + expiry).
 *  2. Filters tools/list responses so the AI only sees permitted tools.
 *  3. Blocks tools/call requests for tools the caller cannot access.
 *  4. Handles both application/json and text/event-stream (SSE) responses.
 *  5. Handles batch JSON-RPC requests.
 *
 * Required environment variables (see .env.example):
 *   TARGET_URL  – upstream MCP server base URL
 *   TENANT_ID   – Entra ID tenant ID (enables JWT signature verification)
 *   AUDIENCE    – App registration client ID / audience claim
 *
 * Optional:
 *   PORT        – port this proxy listens on (default: 3000)
 *
 * When TENANT_ID is not set the proxy falls back to decode-only mode and
 * emits a startup warning — safe for local development, not for production.
 */

import express from 'express';
import axios from 'axios';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import dotenv from 'dotenv';

dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT      = process.env.PORT       ?? 3000;
const TARGET_URL = process.env.TARGET_URL;
const TENANT_ID  = process.env.TENANT_ID;
const AUDIENCE   = process.env.AUDIENCE;

// ---------------------------------------------------------------------------
// RBAC config
// ---------------------------------------------------------------------------

const rbacConfig = JSON.parse(
  readFileSync(join(__dirname, 'rbac-config.json'), 'utf-8'),
);
delete rbacConfig['_comment'];

// ---------------------------------------------------------------------------
// JWT verification
// ---------------------------------------------------------------------------

// createRemoteJWKSet caches the key set and auto-rotates — safe to create once.
const jwks = TENANT_ID
  ? createRemoteJWKSet(
      new URL(`https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`),
    )
  : null;

/**
 * Verify a Bearer token and return its decoded payload.
 * When TENANT_ID is absent (dev mode) the signature is NOT checked.
 *
 * @throws if the token is expired, malformed, or has a bad signature.
 */
async function verifyToken(token) {
  if (!jwks) {
    // Dev / demo mode — decode only
    try {
      const [, b64] = token.split('.');
      return JSON.parse(Buffer.from(b64, 'base64url').toString('utf-8'));
    } catch {
      return null;
    }
  }

  const { payload } = await jwtVerify(token, jwks, {
    issuer:   `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
    ...(AUDIENCE ? { audience: AUDIENCE } : {}),
  });
  return payload;
}

// ---------------------------------------------------------------------------
// Role / permission helpers
// ---------------------------------------------------------------------------

function getUserRoles(payload) {
  if (!payload) return [];
  if (Array.isArray(payload.roles) && payload.roles.length > 0) return payload.roles;
  if (typeof payload.scp === 'string' && payload.scp.length > 0) return payload.scp.split(' ');
  return [];
}

/**
 * Returns null  → caller has full access (wildcard role).
 * Returns Set   → set of permitted tool names (may be empty).
 */
function resolveAllowedTools(roles) {
  const allowed = new Set();
  for (const role of roles) {
    const perms = rbacConfig[role];
    if (!perms) continue;
    if (perms.includes('*')) return null;
    perms.forEach((t) => allowed.add(t));
  }
  return allowed;
}

function isToolPermitted(toolName, allowed) {
  if (allowed === null) return true;   // wildcard
  return allowed.has(toolName);
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

function jsonRpcError(id, code, message) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

// -32001 = custom server error: permission denied
const PERMISSION_DENIED = -32001;

// ---------------------------------------------------------------------------
// tools/list response filtering
// ---------------------------------------------------------------------------

function filterToolsListBody(body, allowed) {
  if (allowed === null) return body;
  if (!body?.result?.tools) return body;
  body.result.tools = body.result.tools.filter((t) => allowed.has(t.name));
  return body;
}

// ---------------------------------------------------------------------------
// SSE helpers
// ---------------------------------------------------------------------------

function processSSEBlock(block, allowed) {
  return block
    .split('\n')
    .map((line) => {
      if (!line.startsWith('data: ')) return line;
      const raw = line.slice(6).trim();
      if (!raw || raw === '[DONE]') return line;
      try {
        const parsed = JSON.parse(raw);
        return 'data: ' + JSON.stringify(filterToolsListBody(parsed, allowed));
      } catch {
        return line;
      }
    })
    .join('\n');
}

// ---------------------------------------------------------------------------
// Batch JSON-RPC helpers
// ---------------------------------------------------------------------------

/**
 * For a batch request, check every tools/call item against the allowed set
 * and return an array of { index, errorResponse } for each denied call.
 */
function auditBatchToolCalls(requests, allowed) {
  const denied = [];
  requests.forEach((req, index) => {
    if (req?.method !== 'tools/call') return;
    const toolName = req?.params?.name;
    if (!isToolPermitted(toolName, allowed)) {
      denied.push({
        index,
        errorResponse: jsonRpcError(
          req.id,
          PERMISSION_DENIED,
          `Access denied: you do not have permission to call tool '${toolName}'.`,
        ),
      });
    }
  });
  return denied;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

app.use(async (req, res) => {
  if (!TARGET_URL) {
    return res.status(500).json({ error: 'TARGET_URL environment variable is not configured.' });
  }

  // ------------------------------------------------------------------
  // 1. Authenticate & resolve permissions
  // ------------------------------------------------------------------
  const authHeader = req.headers['authorization'] ?? '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  let jwtPayload = null;
  if (token) {
    try {
      jwtPayload = await verifyToken(token);
    } catch (err) {
      console.warn(`[mcp-rbac-filter] JWT rejected: ${err.message}`);
      return res.status(401).json(
        jsonRpcError(req.body?.id ?? null, -32600, `Unauthorized: ${err.message}`),
      );
    }
  } else {
    console.warn('[mcp-rbac-filter] No Bearer token — treating as anonymous (no tools allowed).');
  }

  const roles = getUserRoles(jwtPayload);
  const allowedTools = resolveAllowedTools(roles);

  // ------------------------------------------------------------------
  // 2. Inspect the request body (single or batch JSON-RPC)
  // ------------------------------------------------------------------
  const isBatch = Array.isArray(req.body);
  const requests = isBatch ? req.body : [req.body];

  const hasToolsList = requests.some((r) => r?.method === 'tools/list');
  const hasToolsCall = requests.some((r) => r?.method === 'tools/call');

  console.log(
    `[mcp-rbac-filter] ${req.method} ${req.path} | batch:${isBatch} | roles:[${roles.join(',') || 'none'}] | ` +
    `methods:[${[...new Set(requests.map((r) => r?.method).filter(Boolean))].join(',')}]`,
  );

  // ------------------------------------------------------------------
  // 3. Enforce tools/call authorization before forwarding
  // ------------------------------------------------------------------
  if (hasToolsCall) {
    if (isBatch) {
      const denied = auditBatchToolCalls(requests, allowedTools);
      if (denied.length > 0) {
        // Build a batch error response for every denied call.
        // Permitted calls are still forwarded; denied ones are answered inline.
        const deniedIndices = new Set(denied.map((d) => d.index));
        const permitted = requests.filter((_, i) => !deniedIndices.has(i));
        const errorResponses = denied.map((d) => d.errorResponse);

        if (permitted.length === 0) {
          return res.status(403).json(isBatch ? errorResponses : errorResponses[0]);
        }
        // Forward only the permitted subset; merge error responses after.
        req.body = permitted; // mutate for forwarding
      }
    } else {
      // Single tools/call
      const toolName = req.body?.params?.name;
      if (!isToolPermitted(toolName, allowedTools)) {
        console.warn(`[mcp-rbac-filter] Blocked tools/call for '${toolName}' — role(s): [${roles.join(', ')}]`);
        return res.status(403).json(
          jsonRpcError(req.body?.id, PERMISSION_DENIED,
            `Access denied: you do not have permission to call tool '${toolName}'.`),
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // 4. Forward the request upstream
  // ------------------------------------------------------------------
  const forwardHeaders = { ...req.headers };
  delete forwardHeaders['host'];
  delete forwardHeaders['content-length']; // recalculated by axios

  const upstreamUrl = TARGET_URL.replace(/\/$/, '') + (req.path || '/');

  let upstream;
  try {
    upstream = await axios({
      method: req.method,
      url: upstreamUrl,
      headers: forwardHeaders,
      data: ['POST', 'PUT', 'PATCH'].includes(req.method) ? req.body : undefined,
      responseType: 'stream',
      validateStatus: () => true,
    });
  } catch (err) {
    console.error('[mcp-rbac-filter] Failed to reach upstream:', err.message);
    if (!res.headersSent) {
      res.status(502).json({ error: 'Bad gateway', details: err.message });
    }
    return;
  }

  // ------------------------------------------------------------------
  // 5. Relay upstream status & headers
  // ------------------------------------------------------------------
  res.status(upstream.status);
  for (const [key, value] of Object.entries(upstream.headers)) {
    if (key.toLowerCase() === 'transfer-encoding') continue;
    res.setHeader(key, value);
  }

  const contentType = upstream.headers['content-type'] ?? '';
  const isSSE = contentType.includes('text/event-stream');

  // ------------------------------------------------------------------
  // 6. Pass through if no filtering is needed
  // ------------------------------------------------------------------
  if (!hasToolsList) {
    if (isSSE) {
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders();
    }
    upstream.data.pipe(res);
    req.on('close', () => upstream.data.destroy());
    return;
  }

  // ------------------------------------------------------------------
  // 7a. SSE tools/list — intercept, filter, relay
  // ------------------------------------------------------------------
  if (isSSE) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    let buffer = '';

    upstream.data.on('data', (chunk) => {
      buffer += chunk.toString('utf-8');
      let boundary;
      while ((boundary = buffer.indexOf('\n\n')) !== -1) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        if (!block.trim()) continue;
        res.write(processSSEBlock(block, allowedTools) + '\n\n');
      }
    });

    upstream.data.on('end', () => {
      if (buffer.trim()) res.write(processSSEBlock(buffer, allowedTools) + '\n');
      res.end();
    });

    upstream.data.on('error', (err) => {
      console.error('[mcp-rbac-filter] Upstream stream error:', err.message);
      res.end();
    });

    req.on('close', () => upstream.data.destroy());
    return;
  }

  // ------------------------------------------------------------------
  // 7b. Plain JSON tools/list — buffer, filter, send
  // ------------------------------------------------------------------
  let raw = '';
  upstream.data.on('data', (chunk) => { raw += chunk.toString('utf-8'); });
  upstream.data.on('end', () => {
    try {
      const parsed = JSON.parse(raw);
      if (isBatch) {
        const filtered = Array.isArray(parsed)
          ? parsed.map((item) => filterToolsListBody(item, allowedTools))
          : filterToolsListBody(parsed, allowedTools);
        res.json(filtered);
      } else {
        res.json(filterToolsListBody(parsed, allowedTools));
      }
    } catch {
      res.send(raw);
    }
  });
  upstream.data.on('error', (err) => {
    console.error('[mcp-rbac-filter] Upstream read error:', err.message);
    if (!res.headersSent) res.status(502).end();
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

if (!TENANT_ID) {
  console.warn('[mcp-rbac-filter] ⚠️  TENANT_ID is not set — JWT signatures will NOT be verified (dev mode).');
  console.warn('[mcp-rbac-filter] ⚠️  Set TENANT_ID and AUDIENCE in .env before deploying to production.');
}

app.listen(PORT, () => {
  console.log(`[mcp-rbac-filter] Listening on http://localhost:${PORT}`);
  console.log(`[mcp-rbac-filter] Upstream:  ${TARGET_URL ?? '⚠️  TARGET_URL not set'}`);
  console.log(`[mcp-rbac-filter] Tenant ID: ${TENANT_ID ?? '(decode-only / dev mode)'}`);
  console.log(`[mcp-rbac-filter] Roles loaded: ${Object.keys(rbacConfig).join(', ')}`);
});
