# airlock

Expose a stdio MCP server over authenticated [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http).

Tunnels such as Cloudflare Tunnel can only forward HTTP, so a stdio MCP server
needs a bridge in front of it. Airlock is that bridge:

- **Bearer token auth.** Every request must carry `Authorization: Bearer <token>`.
- **One process per session.** Each `initialize` spawns a fresh child process,
  so concurrent callers never share server state. Sessions end on `DELETE`,
  when the child exits, or after an idle timeout.
- **Transparent.** JSON-RPC messages are piped through unmodified, so every
  capability the server offers (tools, resources, prompts, sampling, ...)
  works as-is.

## Usage

```sh
cargo install --git https://github.com/mkusaka/airlock

export AIRLOCK_TOKEN="$(openssl rand -hex 32)"
airlock --listen 127.0.0.1:8080 -- npx -y @modelcontextprotocol/server-everything
```

The endpoint is `http://127.0.0.1:8080/mcp`. Put it behind a tunnel to reach
it from elsewhere, for example:

```sh
cloudflared tunnel --url http://127.0.0.1:8080
```

Then register it with a client, e.g. Claude Code:

```sh
claude mcp add --transport http my-server https://<host>/mcp \
  --header "Authorization: Bearer $AIRLOCK_TOKEN"
```

| Option | Default | Description |
| --- | --- | --- |
| `--listen` | `127.0.0.1:8080` | Address to listen on |
| `--idle-timeout-secs` | `3600` | Kill sessions with no requests for this long |
| `AIRLOCK_TOKEN` (env) | required | Bearer token; removed from the child's environment |

## Behavior

- Request POSTs are answered with `text/event-stream` and periodic keep-alives,
  so long tool calls survive proxies that drop silent responses (Cloudflare
  times out after about 100 seconds).
- Server-initiated requests and notifications are delivered on the session's
  GET stream and buffered until the client opens it.
- Child stderr is passed through to Airlock's stderr.

## Limitations

- Only session-based Streamable HTTP (protocol versions up to `2025-11-25`) is
  supported. Sessionless requests such as `2026-07-28` `server/discover` are
  rejected with `400`; clients must fall back to `initialize`.
- A single shared token: sessions are isolated, but callers are not told apart.
- JSON-RPC batches and SSE resumption (`Last-Event-ID`) are not supported.

## License

MIT
