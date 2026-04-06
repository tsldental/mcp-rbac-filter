/**
 * demo.js — End-to-end demo of mcp-rbac-filter
 *
 * No Azure, no Entra ID, no setup required.
 *
 * What it does:
 *  1. Spins up a mock MCP upstream (mimicking paulyuk/node-mcp-sdk-functions-hosting
 *     + paulyuk/hackathon-mcp-functions combined) on port 3001.
 *  2. Starts the mcp-rbac-filter proxy on port 3002 targeting it.
 *  3. Fires tools/list as five different roles and shows what each one sees.
 *  4. Shows tools/call being blocked for a forbidden tool.
 *  5. Cleans up and exits.
 *
 * Usage:
 *   node demo.js
 */

import http from 'http';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const UPSTREAM_PORT = 3001;
const PROXY_PORT    = 3002;
const UPSTREAM_URL  = `http://localhost:${UPSTREAM_PORT}`;
const PROXY_URL     = `http://localhost:${PROXY_PORT}`;

// ---------------------------------------------------------------------------
// All tools that the "real" upstream would expose
// (get-alerts + get-forecast from node-mcp-sdk-functions-hosting,
//  the rest from hackathon-mcp-functions)
// ---------------------------------------------------------------------------
const ALL_TOOLS = [
  { name: 'get-alerts',           description: 'Get weather alerts for a US state' },
  { name: 'get-forecast',         description: 'Get weather forecast for a location' },
  { name: 'list_users',           description: 'List all registered users [admin]' },
  { name: 'get_user_sessions',    description: 'Get game sessions for a user [admin]' },
  { name: 'create_user',          description: 'Create a new user [admin]' },
  { name: 'save_submission',      description: 'Persist a hackathon submission' },
  { name: 'list_submissions',     description: 'List submissions for a session' },
  { name: 'list_all_submissions', description: 'List ALL submissions across sessions [admin]' },
  { name: 'save_vote',            description: 'Save or update a vote' },
  { name: 'list_votes',           description: 'List votes for a session' },
];

// ---------------------------------------------------------------------------
// Colours
// ---------------------------------------------------------------------------
const C = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
  green:  '\x1b[32m',
  red:    '\x1b[31m',
  yellow: '\x1b[33m',
  cyan:   '\x1b[36m',
  blue:   '\x1b[34m',
  magenta:'\x1b[35m',
};
const bold   = (s) => `${C.bold}${s}${C.reset}`;
const green  = (s) => `${C.green}${s}${C.reset}`;
const red    = (s) => `${C.red}${s}${C.reset}`;
const yellow = (s) => `${C.yellow}${s}${C.reset}`;
const cyan   = (s) => `${C.cyan}${s}${C.reset}`;
const dim    = (s) => `${C.dim}${s}${C.reset}`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFakeJwt(roles) {
  const payload = Buffer.from(JSON.stringify({ roles, name: 'Demo User', exp: 9999999999 }))
    .toString('base64url');
  return `eyJhbGciOiJub25lIn0.${payload}.fakesig`;
}

function post(url, body, token) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const opts = {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    };
    const req = http.request(url, opts, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        // Handle SSE: extract the first data: line
        if ((res.headers['content-type'] ?? '').includes('text/event-stream')) {
          const match = raw.match(/^data: (.+)$/m);
          if (match) {
            try { return resolve({ status: res.statusCode, body: JSON.parse(match[1]) }); }
            catch { /* fall through */ }
          }
        }
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, body: raw }); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ---------------------------------------------------------------------------
// 1. Mock upstream server
// ---------------------------------------------------------------------------

function startMockUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(body); } catch { parsed = {}; }

        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        });

        if (parsed.method === 'tools/list') {
          const response = {
            jsonrpc: '2.0', id: parsed.id,
            result: { tools: ALL_TOOLS },
          };
          res.write(`data: ${JSON.stringify(response)}\n\n`);
        } else if (parsed.method === 'tools/call') {
          const response = {
            jsonrpc: '2.0', id: parsed.id,
            result: { content: [{ type: 'text', text: `✔ upstream executed ${parsed.params?.name}` }] },
          };
          res.write(`data: ${JSON.stringify(response)}\n\n`);
        } else {
          res.write(`data: ${JSON.stringify({ jsonrpc:'2.0', id: parsed.id, result: {} })}\n\n`);
        }
        res.end();
      });
    });

    server.listen(UPSTREAM_PORT, () => {
      console.log(dim(`  [mock upstream] listening on ${UPSTREAM_URL}`));
      resolve(server);
    });
  });
}

// ---------------------------------------------------------------------------
// 2. Proxy process
// ---------------------------------------------------------------------------

function startProxy() {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, ['server.js'], {
      cwd: __dirname,
      env: {
        ...process.env,
        TARGET_URL: UPSTREAM_URL,
        PORT: String(PROXY_PORT),
        // No TENANT_ID — runs in dev/decode-only mode (perfect for demo)
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let ready = false;
    const onData = (chunk) => {
      const line = chunk.toString();
      process.stdout.write(dim('  ' + line.replace(/\n/g, '\n  ')));
      if (!ready && line.includes('Listening on')) {
        ready = true;
        proc.stdout.off('data', onData);
        resolve(proc);
      }
    };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', (c) => process.stderr.write(dim(c.toString())));
    proc.on('error', reject);
    setTimeout(() => { if (!ready) reject(new Error('Proxy did not start in time')); }, 5000);
  });
}

// ---------------------------------------------------------------------------
// 3. Demo scenarios
// ---------------------------------------------------------------------------

const SCENARIOS = [
  {
    label:  'admin',
    roles:  ['admin'],
    colour: C.magenta,
    note:   'wildcard — should see ALL tools',
  },
  {
    label:  'HackathonAdmin',
    roles:  ['HackathonAdmin'],
    colour: C.magenta,
    note:   'wildcard — should see ALL tools',
  },
  {
    label:  'HackathonJudge',
    roles:  ['HackathonJudge'],
    colour: C.cyan,
    note:   'should see submissions + votes (no user-admin tools)',
  },
  {
    label:  'HackathonParticipant',
    roles:  ['HackathonParticipant'],
    colour: C.blue,
    note:   'should see only own-submission tools',
  },
  {
    label:  'intern',
    roles:  ['intern'],
    colour: C.yellow,
    note:   'weather only — should see only get-alerts',
  },
  {
    label:  '(no token)',
    roles:  null,
    colour: C.red,
    note:   'anonymous — should see zero tools',
  },
];

async function runToolsListDemo() {
  console.log(`\n${'═'.repeat(60)}`);
  console.log(bold('  tools/list  —  what each role sees through the proxy'));
  console.log(`${'═'.repeat(60)}\n`);

  console.log(
    `  ${bold('Upstream exposes')} ${ALL_TOOLS.length} tools: ` +
    dim(ALL_TOOLS.map((t) => t.name).join(', ')) + '\n',
  );

  for (const s of SCENARIOS) {
    const token = s.roles ? makeFakeJwt(s.roles) : null;
    const { status, body } = await post(
      `${PROXY_URL}/mcp`,
      { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
      token,
    );

    const tools = body?.result?.tools ?? [];
    const roleStr = `${s.colour}${bold(s.label)}${C.reset}`;
    const toolList = tools.length
      ? tools.map((t) => green(t.name)).join(', ')
      : red('(none)');

    console.log(`  ${roleStr}`);
    console.log(`  ${dim(s.note)}`);
    console.log(`  → ${bold(String(tools.length))} tool(s): ${toolList}`);
    console.log();
  }
}

async function runToolsCallDemo() {
  console.log(`${'═'.repeat(60)}`);
  console.log(bold('  tools/call  —  enforcement (intern trying forbidden tools)'));
  console.log(`${'═'.repeat(60)}\n`);

  const token = makeFakeJwt(['intern']);

  const calls = [
    { name: 'get-alerts',           expectAllow: true },
    { name: 'get-forecast',         expectAllow: false },  // intern only has get-alerts
    { name: 'list_all_submissions', expectAllow: false },
    { name: 'create_user',          expectAllow: false },
  ];

  for (const call of calls) {
    const { status, body } = await post(
      `${PROXY_URL}/mcp`,
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: call.name, arguments: {} } },
      token,
    );

    const allowed = status === 200 && !body?.error;
    const icon  = allowed ? green('✔ allowed ') : red('✘ blocked ');
    const label = `${C.yellow}intern${C.reset} → ${bold(call.name)}`;

    if (allowed) {
      console.log(`  ${icon}  ${label}`);
      console.log(`          ${dim(body?.result?.content?.[0]?.text ?? JSON.stringify(body?.result))}`);
    } else {
      console.log(`  ${icon}  ${label}`);
      console.log(`          ${dim(body?.error?.message ?? `HTTP ${status}`)}`);
    }
    console.log();
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log(`\n${bold(cyan('  mcp-rbac-filter  —  live end-to-end demo'))}`);
  console.log(dim('  Using paulyuk/node-mcp-sdk-functions-hosting + hackathon-mcp-functions tools\n'));

  console.log(dim('  Starting servers…'));
  const upstream = await startMockUpstream();
  const proxy    = await startProxy();
  await sleep(200); // let proxy settle

  try {
    await runToolsListDemo();
    await runToolsCallDemo();
  } finally {
    proxy.kill();
    upstream.close();
    console.log(dim('\n  Servers stopped. Demo complete.\n'));
  }
}

main().catch((err) => {
  console.error(red(`\n  Demo failed: ${err.message}`));
  process.exit(1);
});
