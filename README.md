# airlock

Expose a stdio MCP server over [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http),
behind Cloudflare Tunnel and Cloudflare Access OAuth.

Cloudflare Tunnel can only forward HTTP, so a stdio MCP server needs a bridge
in front of it. Airlock is that bridge:

- **OAuth via Cloudflare Access.** Access [Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)
  acts as the MCP authorization server (metadata, client registration, IdP
  sign-in). Airlock verifies the `Cf-Access-Jwt-Assertion` JWT on every request.
- **One process per session, per user.** Each `initialize` spawns a fresh child
  process. Sessions are bound to the Access identity that created them, and the
  child receives that identity in `AIRLOCK_USER`.
- **Transparent.** JSON-RPC messages are piped through unmodified, so every
  capability the server offers works as-is.

```
MCP client ──▶ Cloudflare edge (Access OAuth) ──▶ Tunnel ──▶ airlock ──▶ stdio MCP server
```

## Setup

1. Create a named tunnel whose public hostname (e.g. `mcp.example.com`)
   routes to `http://127.0.0.1:8080`. Quick tunnels (`trycloudflare.com`)
   cannot be protected by Access.
2. In Zero Trust, add a self-hosted Access application for that hostname and
   a policy that allows the intended users. Copy its **Application Audience
   (AUD) tag**.
3. In the application's **Advanced settings**, turn on **Managed OAuth**.
   Allow the redirect URIs your clients use, e.g. **Allow localhost clients**
   for Claude Code and `https://claude.ai/api/mcp/auth_callback` for claude.ai.
4. Run airlock:

   ```sh
   cargo install --git https://github.com/mkusaka/airlock

   airlock --team-domain <team>.cloudflareaccess.com --aud <AUD tag> \
     -- npx -y @modelcontextprotocol/server-everything
   ```

5. Add `https://mcp.example.com/mcp` to a client, e.g.
   `claude mcp add --transport http my-server https://mcp.example.com/mcp`.
   The client discovers Access's OAuth endpoints and opens a sign-in page.

| Option | Default | Description |
| --- | --- | --- |
| `--team-domain` | required | Access team domain; JWT issuer and JWKS source |
| `--aud` | required | AUD tag of the Access application |
| `--listen` | `127.0.0.1:8080` | Address to listen on |
| `--idle-timeout-secs` | `3600` | Kill sessions with no requests for this long |

Identity is the JWT's `email`, falling back to `common_name` (service tokens)
and then `sub`.

## Behavior

- Requests without a valid Access JWT get `403`. Requests for another user's
  session get `404`.
- Request POSTs are answered with `text/event-stream` and periodic keep-alives,
  so long tool calls survive Cloudflare's ~100 second response timeout.
- Server-initiated requests and notifications are delivered on the session's
  GET stream and buffered until the client opens it.
- Child stderr is passed through to Airlock's stderr.

## Limitations

- Only session-based Streamable HTTP (protocol versions up to `2025-11-25`) is
  supported. Sessionless requests such as `2026-07-28` `server/discover` are
  rejected with `400`; clients must fall back to `initialize`.
- JSON-RPC batches and SSE resumption (`Last-Event-ID`) are not supported.

## License

MIT
