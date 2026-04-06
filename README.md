# mcp-rbac-filter

> A security middleware proxy that enforces Microsoft Entra ID role-based access control (RBAC) in front of an Azure Functions MCP server. It filters the tools an AI agent can **see** and **call** based on the user's JWT roles — before the AI ever knows the restricted tools exist.

Designed to complement: [node-mcp-sdk-functions-hosting](https://github.com/paulyuk/node-mcp-sdk-functions-hosting)

---

## Architecture

```
AI Agent / MCP Client
        │
        │  POST  (Bearer JWT)
        ▼
┌──────────────────────┐
│   mcp-rbac-filter    │  ← This proxy
│                      │
│  1. Verify JWT       │
│  2. Extract roles    │
│  3. Enforce tools/   │
│     call authz       │
│  4. Forward request  │
│  5. Filter tools/    │
│     list response    │
└──────────────────────┘
        │
        │  proxied request
        ▼
┌──────────────────────┐
│  Azure Functions     │
│  MCP Server          │
│  (all tools)         │
└──────────────────────┘
```

The AI only ever sees and can invoke the tools its role permits. Restricted tools are invisible.

---

## Features

- ✅ **JWT signature verification** via Microsoft's JWKS endpoint (`jose`)
- ✅ **tools/list filtering** — removes hidden tools from the response
- ✅ **tools/call enforcement** — blocks direct calls to forbidden tools (JSON-RPC `-32001` error)
- ✅ **SSE (Server-Sent Events)** support — intercepts and filters streaming responses
- ✅ **Batch JSON-RPC** handling
- ✅ **Wildcard role** (`"*"`) for unrestricted admin access
- ✅ **Dev mode** — when `TENANT_ID` is unset, signatures are skipped (local testing only)

---

## Quick Start

```bash
git clone https://github.com/tsldental/mcp-rbac-filter
cd mcp-rbac-filter
npm install

cp .env.example .env
# Edit .env — set TARGET_URL, TENANT_ID, AUDIENCE

npm start
```

Point your MCP client at `http://localhost:3000` instead of the Azure Function URL.

---

## Environment Variables

| Variable     | Required        | Description |
|-------------|-----------------|-------------|
| `TARGET_URL` | ✅ Yes          | Base URL of the upstream Azure Functions MCP server |
| `TENANT_ID`  | ⚠️ Production   | Entra ID tenant ID — enables JWT signature verification |
| `AUDIENCE`   | ⚠️ Production   | Expected `aud` claim (app client ID or Application ID URI) |
| `PORT`       | No (default 3000) | Port this proxy listens on |

> **Warning:** If `TENANT_ID` is not set the proxy skips signature verification and trusts the `roles`/`scp` claim as-is. This is intentional for local development but **must not be used in production**.

---

## RBAC Configuration (`rbac-config.json`)

Map Entra ID app role names (or delegated scope names) to arrays of permitted MCP tool names.

```json
{
  "admin":     ["*"],
  "developer": ["get-alerts", "get-forecast", "create-ticket", "deploy-service"],
  "analyst":   ["get-forecast", "list-tickets", "get-report"],
  "intern":    ["get-alerts", "get-forecast"]
}
```

- **`"*"`** — wildcard, grants access to all tools (admin bypass)
- A user with **multiple roles** gets the union of all permitted tools
- A user with **no matching roles** gets an empty tool list

### Setting up app roles in Entra ID

1. Go to **App registrations** → your MCP app → **App roles**
2. Create roles matching the keys in `rbac-config.json` (e.g. `intern`, `developer`)
3. In **Enterprise applications** → **Users and groups**, assign roles to users/groups
4. The roles will appear in the `roles` claim of the user's access token automatically

---

## How It Works

### `tools/list` (what the AI sees)

```
Client → POST /  { "method": "tools/list" }
Proxy  → verifies JWT, resolves role → Set{"get-alerts","get-forecast"}
Proxy  → forwards to upstream
Upstream → { result: { tools: [ all 20 tools... ] } }
Proxy  → filters to only permitted tools
Client ← { result: { tools: [ get-alerts, get-forecast ] } }
```

### `tools/call` (what the AI can invoke)

If the AI attempts to call a tool outside its allowed set (e.g. by guessing the name):

```
Client → POST /  { "method": "tools/call", "params": { "name": "deploy-service" } }
Proxy  → role=intern, deploy-service not in Set → blocked immediately
Client ← 403  { "error": { "code": -32001, "message": "Access denied..." } }
                                         ↑ never reaches upstream
```

### SSE Streaming

When the upstream responds with `Content-Type: text/event-stream`, the proxy:
1. Buffers incoming chunks until a complete SSE message (`\n\n` boundary) arrives
2. Parses the `data:` JSON payload
3. Applies the tools filter
4. Re-emits the modified message — keeping the connection alive throughout

---

## Deployment

### As a standalone Node.js service

```bash
node server.js
```

### As an Azure Function (coming soon)

The proxy itself can be hosted as an Azure Function in front of another Function App, keeping everything serverless.

### Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

---

## Security Notes

| Concern | Mitigation |
|---------|-----------|
| Forged JWTs | `TENANT_ID` + `AUDIENCE` enforce signature, expiry, issuer, and audience validation via Microsoft's JWKS |
| Role escalation | Roles are read from the verified JWT payload — not from the request |
| Hidden tool invocation | `tools/call` is checked independently of `tools/list` |
| Token replay | `jose` validates the `exp` claim on every request |

---

## License

MIT
