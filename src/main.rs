//! Airlock: expose a stdio MCP server over authenticated Streamable HTTP.
//!
//! Every MCP session (`Mcp-Session-Id`) gets its own child process, so callers
//! never share server state. JSON-RPC messages are piped through unmodified.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use clap::Parser;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{OwnedMutexGuard, mpsc, oneshot};

const TOKEN_ENV: &str = "AIRLOCK_TOKEN";
const SESSION_HEADER: &str = "mcp-session-id";
/// Server-initiated messages buffered per session while no GET stream is open.
const OUTBOUND_BUFFER: usize = 256;

#[derive(Parser)]
#[command(
    version,
    about = "Expose a stdio MCP server over authenticated Streamable HTTP",
    after_help = "The bearer token is read from the AIRLOCK_TOKEN environment variable."
)]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Kill sessions that receive no requests for this many seconds.
    #[arg(long, default_value_t = 3600)]
    idle_timeout_secs: u64,
    /// The stdio MCP server command, spawned once per session.
    #[arg(required = true, last = true)]
    command: Vec<String>,
}

struct App {
    token: String,
    command: Vec<String>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
}

struct Session {
    child: Mutex<Child>,
    stdin: tokio::sync::Mutex<ChildStdin>,
    /// Waiting POST requests keyed by their serialized JSON-RPC id.
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    outbound_tx: mpsc::Sender<Value>,
    outbound_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Value>>>,
    last_seen: Mutex<Instant>,
}

impl Session {
    async fn send(&self, message: &Value) -> std::io::Result<()> {
        let mut line = message.to_string();
        line.push('\n');
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(line.as_bytes()).await?;
        stdin.flush().await
    }

    fn kill(&self) {
        let _ = self.child.lock().unwrap().start_kill();
    }
}

/// Removes a pending entry if the HTTP request goes away before the response.
struct PendingGuard {
    session: Arc<Session>,
    key: String,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.session.pending.lock().unwrap().remove(&self.key);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let token = std::env::var(TOKEN_ENV).unwrap_or_default();
    if token.is_empty() {
        bail!("{TOKEN_ENV} must be set to a non-empty bearer token");
    }
    let app = Arc::new(App {
        token,
        command: args.command,
        sessions: Mutex::default(),
    });

    tokio::spawn(reap_idle(
        app.clone(),
        Duration::from_secs(args.idle_timeout_secs),
    ));

    let router = Router::new()
        .route(
            "/mcp",
            post(handle_post).get(handle_get).delete(handle_delete),
        )
        .layer(middleware::from_fn_with_state(app.clone(), require_token))
        .with_state(app.clone());

    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;
    eprintln!("airlock listening on http://{}/mcp", listener.local_addr()?);
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;

    for session in app.sessions.lock().unwrap().drain().map(|(_, s)| s) {
        session.kill();
    }
    Ok(())
}

async fn require_token(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), app.token.as_bytes()) => {
            next.run(request).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response(),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn handle_post(State(app): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        return jsonrpc_error(StatusCode::BAD_REQUEST, Value::Null, -32700, "parse error");
    };
    if !message.is_object() {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "batch requests are not supported",
        );
    }
    let id = message.get("id").cloned();
    let is_request = id.is_some() && message.get("method").is_some();

    let (session_id, session) = match session_id(&headers) {
        Some(sid) => match app.get_session(sid) {
            Some(session) => (sid.to_owned(), session),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
        None if message.get("method").and_then(Value::as_str) == Some("initialize") => {
            match app.spawn_session() {
                Ok(created) => created,
                Err(err) => {
                    eprintln!("airlock: failed to spawn MCP server: {err:#}");
                    return jsonrpc_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        id.unwrap_or(Value::Null),
                        -32603,
                        "failed to start MCP server",
                    );
                }
            }
        }
        // Includes sessionless `server/discover`: clients fall back to `initialize`.
        None => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id.unwrap_or(Value::Null),
                -32600,
                "missing Mcp-Session-Id; send initialize first",
            );
        }
    };
    *session.last_seen.lock().unwrap() = Instant::now();

    let Some(id) = id.filter(|_| is_request) else {
        if session.send(&message).await.is_err() {
            return StatusCode::NOT_FOUND.into_response();
        }
        return StatusCode::ACCEPTED.into_response();
    };

    let key = id.to_string();
    let (tx, rx) = oneshot::channel();
    session.pending.lock().unwrap().insert(key.clone(), tx);
    let guard = PendingGuard {
        session: session.clone(),
        key,
    };
    if session.send(&message).await.is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Always answer requests over SSE so keep-alives flow during long calls;
    // proxies such as Cloudflare drop responses that stay silent for ~100s.
    let stream = futures_util::stream::once(async move {
        let _guard = guard;
        let reply = rx.await.unwrap_or_else(|_| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32603, "message": "MCP server exited"},
            })
        });
        Ok::<_, Infallible>(Event::default().data(reply.to_string()))
    });
    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&session_id) {
        response.headers_mut().insert(SESSION_HEADER, value);
    }
    response
}

/// Standalone SSE stream for server-initiated requests and notifications.
async fn handle_get(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some(session) = session_id(&headers).and_then(|sid| app.get_session(sid)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(rx) = session.outbound_rx.clone().try_lock_owned() else {
        return (StatusCode::CONFLICT, "a GET stream is already open").into_response();
    };
    let stream = futures_util::stream::unfold(rx, |mut rx: OwnedMutexGuard<_>| async move {
        let message = rx.recv().await?;
        Some((Event::default().data(message.to_string()), rx))
    })
    .map(Ok::<_, Infallible>);
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn handle_delete(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let removed = session_id(&headers).and_then(|sid| app.sessions.lock().unwrap().remove(sid));
    match removed {
        Some(session) => {
            session.kill();
            StatusCode::NO_CONTENT.into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn session_id(headers: &HeaderMap) -> Option<&str> {
    headers.get(SESSION_HEADER).and_then(|v| v.to_str().ok())
}

fn jsonrpc_error(status: StatusCode, id: Value, code: i64, message: &str) -> Response {
    let body = json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}});
    (status, axum::Json(body)).into_response()
}

impl App {
    fn get_session(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    fn spawn_session(self: &Arc<Self>) -> anyhow::Result<(String, Arc<Session>)> {
        let mut child = Command::new(&self.command[0])
            .args(&self.command[1..])
            .env_remove(TOKEN_ENV)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to spawn {:?}", self.command[0]))?;
        let stdin = child.stdin.take().context("child stdin missing")?;
        let stdout = child.stdout.take().context("child stdout missing")?;
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        let session = Arc::new(Session {
            child: Mutex::new(child),
            stdin: tokio::sync::Mutex::new(stdin),
            pending: Mutex::default(),
            outbound_tx,
            outbound_rx: Arc::new(tokio::sync::Mutex::new(outbound_rx)),
            last_seen: Mutex::new(Instant::now()),
        });
        let id = uuid::Uuid::new_v4().to_string();
        self.sessions
            .lock()
            .unwrap()
            .insert(id.clone(), session.clone());
        eprintln!("airlock: session {id} started");

        let app = self.clone();
        let reader_session = session.clone();
        let reader_id = id.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(message) = serde_json::from_str::<Value>(&line) else {
                    eprintln!("airlock: session {reader_id}: ignoring non-JSON stdout line");
                    continue;
                };
                route_from_server(&reader_session, message);
            }
            app.sessions.lock().unwrap().remove(&reader_id);
            reader_session.pending.lock().unwrap().clear();
            eprintln!("airlock: session {reader_id} ended");
        });
        Ok((id, session))
    }
}

fn route_from_server(session: &Session, message: Value) {
    let is_response = message.get("method").is_none();
    if is_response && let Some(id) = message.get("id") {
        let waiter = session.pending.lock().unwrap().remove(&id.to_string());
        if let Some(waiter) = waiter {
            let _ = waiter.send(message);
            return;
        }
    }
    if session.outbound_tx.try_send(message).is_err() {
        eprintln!("airlock: dropping server message; no GET stream is draining the buffer");
    }
}

async fn reap_idle(app: Arc<App>, timeout: Duration) {
    let mut tick =
        tokio::time::interval(timeout.clamp(Duration::from_secs(1), Duration::from_secs(60)));
    loop {
        tick.tick().await;
        let mut sessions = app.sessions.lock().unwrap();
        sessions.retain(|id, session| {
            let alive = session.last_seen.lock().unwrap().elapsed() < timeout;
            if !alive {
                eprintln!("airlock: session {id} idle; killing");
                session.kill();
            }
            alive
        });
    }
}
