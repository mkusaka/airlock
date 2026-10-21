use std::collections::HashMap;
use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const AUD: &str = "test-aud";
const KID: &str = "test-kid";
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;
const TOOLS_LIST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;

/// A fake Cloudflare Access team: an RSA key and a JWKS endpoint serving it.
struct Team {
    issuer: String,
    key: EncodingKey,
}

impl Team {
    async fn start() -> Self {
        let pem = openssl(&["genpkey", "-algorithm", "RSA"], b"");
        let modulus = openssl(&["rsa", "-noout", "-modulus"], &pem);
        let hex = String::from_utf8(modulus).unwrap();
        let hex = hex.trim().trim_start_matches("Modulus=");
        let n: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let jwks = json!({"keys": [{
            "kty": "RSA", "alg": "RS256", "use": "sig", "kid": KID,
            "n": URL_SAFE_NO_PAD.encode(n), "e": "AQAB",
        }]});
        let router = axum::Router::new().route(
            "/cdn-cgi/access/certs",
            axum::routing::get(move || async move { axum::Json(jwks) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            issuer,
            key: EncodingKey::from_rsa_pem(&pem).unwrap(),
        }
    }

    /// Valid claims for `email`; tests override fields to break them.
    fn claims(&self, email: &str) -> Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        json!({"iss": self.issuer, "aud": [AUD], "exp": now + 300, "email": email, "sub": email})
    }

    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.into());
        jsonwebtoken::encode(&header, claims, &self.key).unwrap()
    }

    fn jwt(&self, email: &str) -> String {
        self.sign(&self.claims(email))
    }
}

fn openssl(args: &[&str], stdin: &[u8]) -> Vec<u8> {
    let mut child = std::process::Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    output.stdout
}

/// Starts airlock on an ephemeral port and returns it with its MCP URL.
async fn start_airlock(team: &Team, extra_args: &[&str]) -> (Child, String) {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pid_server.py");
    let mut child = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args([
            "--listen",
            "127.0.0.1:0",
            "--team-domain",
            &team.issuer,
            "--aud",
            AUD,
        ])
        .args(extra_args)
        .args(["--", "python3", fixture])
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let first = lines.next_line().await.unwrap().unwrap();
    let url = first.rsplit(' ').next().unwrap().to_owned();
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    (child, url)
}

/// A hand-rolled Streamable HTTP client for exercising protocol edges.
struct Raw {
    url: String,
    jwt: String,
    session: Option<String>,
}

impl Raw {
    async fn connect(url: &str, jwt: String) -> Self {
        let mut raw = Self {
            url: url.to_owned(),
            jwt,
            session: None,
        };
        let response = raw.post(INITIALIZE).await;
        assert_eq!(response.status(), 200);
        raw.session = Some(
            response.headers()["mcp-session-id"]
                .to_str()
                .unwrap()
                .into(),
        );
        let initialized = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert_eq!(raw.post(initialized).await.status(), 202);
        raw
    }

    fn request(&self, method: reqwest::Method) -> reqwest::RequestBuilder {
        let mut request = reqwest::Client::new()
            .request(method, &self.url)
            .header("accept", "application/json, text/event-stream")
            .header("cf-access-jwt-assertion", &self.jwt);
        if let Some(session) = &self.session {
            request = request.header("mcp-session-id", session);
        }
        request
    }

    async fn post(&self, body: &str) -> reqwest::Response {
        self.request(reqwest::Method::POST)
            .header("content-type", "application/json")
            .body(body.to_owned())
            .send()
            .await
            .unwrap()
    }

    async fn call(&self, id: u64, tool: &str) -> Value {
        let body =
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool}});
        let mut response = self.post(&body.to_string()).await;
        assert_eq!(response.status(), 200);
        next_event(&mut response).await
    }

    async fn whoami_pid(&self) -> u32 {
        let reply = self.call(10, "whoami").await;
        let text = reply["result"]["content"][0]["text"].as_str().unwrap();
        text.split(' ').next().unwrap().parse().unwrap()
    }
}

/// Reads the next SSE `data:` event as JSON, skipping keep-alive comments.
async fn next_event(response: &mut reqwest::Response) -> Value {
    let mut buffer = String::new();
    loop {
        if let Some(line) = buffer.lines().find_map(|l| l.strip_prefix("data: "))
            && buffer.contains("\n\n")
        {
            return serde_json::from_str(line).unwrap();
        }
        let chunk = tokio::time::timeout(Duration::from_secs(10), response.chunk())
            .await
            .expect("timed out waiting for an SSE event")
            .unwrap()
            .expect("SSE stream ended");
        buffer.push_str(std::str::from_utf8(&chunk).unwrap());
    }
}

fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

async fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..50 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn whoami(url: &str, jwt: String) -> String {
    let headers = HashMap::from([(
        "cf-access-jwt-assertion".parse().unwrap(),
        jwt.parse().unwrap(),
    )]);
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(url).custom_headers(headers),
    );
    let client = ().serve(transport).await.unwrap();
    let tools = client.list_all_tools().await.unwrap();
    assert_eq!(tools[0].name, "whoami");
    let result = client
        .call_tool(CallToolRequestParams::new("whoami"))
        .await
        .unwrap();
    let text = result.content[0].as_text().unwrap().text.clone();
    client.cancel().await.unwrap();
    text
}

#[tokio::test]
async fn sessions_get_their_own_process_and_user() {
    let team = Team::start().await;
    let (_airlock, url) = start_airlock(&team, &[]).await;
    let alice = whoami(&url, team.jwt("alice@example.com")).await;
    let bob = whoami(&url, team.jwt("bob@example.com")).await;
    let (alice_pid, alice_user) = alice.split_once(' ').unwrap();
    let (bob_pid, bob_user) = bob.split_once(' ').unwrap();
    assert_ne!(
        alice_pid, bob_pid,
        "each session must get its own child process"
    );
    assert_eq!(alice_user, "alice@example.com");
    assert_eq!(bob_user, "bob@example.com");
}

#[tokio::test]
async fn rejects_invalid_access_jwts() {
    let team = Team::start().await;
    let other_team = Team::start().await;
    let (_airlock, url) = start_airlock(&team, &[]).await;
    let mut broken = Vec::new();
    for (field, value) in [
        ("aud", json!(["other-aud"])),
        ("iss", json!("https://evil.cloudflareaccess.com")),
        ("exp", json!(1)),
    ] {
        let mut claims = team.claims("alice@example.com");
        claims[field] = value;
        broken.push(team.sign(&claims));
    }
    broken.push(other_team.jwt("alice@example.com"));
    broken.push("garbage".into());
    broken.push(String::new());

    for jwt in broken {
        let raw = Raw {
            url: url.clone(),
            jwt,
            session: None,
        };
        assert_eq!(raw.post(INITIALIZE).await.status(), 403);
    }
    let missing = reqwest::Client::new().post(&url).body(INITIALIZE).send();
    assert_eq!(missing.await.unwrap().status(), 403);
}

#[tokio::test]
async fn sessions_are_bound_to_their_owner() {
    let team = Team::start().await;
    let (_airlock, url) = start_airlock(&team, &[]).await;
    let alice = Raw::connect(&url, team.jwt("alice@example.com")).await;
    let bob = Raw {
        jwt: team.jwt("bob@example.com"),
        session: alice.session.clone(),
        url: url.clone(),
    };
    assert_eq!(bob.post(TOOLS_LIST).await.status(), 404);
    assert_eq!(
        bob.request(reqwest::Method::GET)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        bob.request(reqwest::Method::DELETE)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(alice.post(TOOLS_LIST).await.status(), 200);
}

#[tokio::test]
async fn rejects_malformed_and_sessionless_messages() {
    let team = Team::start().await;
    let (_airlock, url) = start_airlock(&team, &[]).await;
    let raw = Raw {
        url: url.clone(),
        jwt: team.jwt("alice@example.com"),
        session: None,
    };
    let discover = raw
        .post(r#"{"jsonrpc":"2.0","id":7,"method":"server/discover"}"#)
        .await;
    assert_eq!(discover.status(), 400);
    let error: Value = discover.json().await.unwrap();
    assert_eq!(error["id"], 7);
    assert_eq!(error["error"]["code"], -32600);

    assert_eq!(raw.post("not json").await.status(), 400);
    assert_eq!(raw.post(&format!("[{INITIALIZE}]")).await.status(), 400);

    let unknown = Raw {
        session: Some("no-such-session".into()),
        ..raw
    };
    assert_eq!(unknown.post(TOOLS_LIST).await.status(), 404);
}

#[tokio::test]
async fn relays_server_requests_over_get_stream() {
    let team = Team::start().await;
    let (_airlock, url) = start_airlock(&team, &[]).await;
    let raw = Raw::connect(&url, team.jwt("alice@example.com")).await;

    let mut stream = raw.request(reqwest::Method::GET).send().await.unwrap();
    assert_eq!(stream.status(), 200);
    let second = raw.request(reqwest::Method::GET).send().await.unwrap();
    assert_eq!(second.status(), 409, "only one GET stream per session");

    let body =
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "ask"}});
    let mut call = raw.post(&body.to_string()).await;
    let server_request = next_event(&mut stream).await;
    assert_eq!(server_request["method"], "roots/list", "{server_request}");

    let answer = json!({"jsonrpc": "2.0", "id": server_request["id"], "result": {"roots": []}});
    assert_eq!(raw.post(&answer.to_string()).await.status(), 202);
    let reply = next_event(&mut call).await;
    assert_eq!(reply["id"], 3);
    assert_eq!(reply["result"]["content"][0]["text"], r#"{"roots": []}"#);
}

#[tokio::test]
async fn delete_kills_the_session_process() {
    let team = Team::start().await;
    let (_airlock, url) = start_airlock(&team, &[]).await;
    let raw = Raw::connect(&url, team.jwt("alice@example.com")).await;
    let pid = raw.whoami_pid().await;

    let deleted = raw.request(reqwest::Method::DELETE).send().await.unwrap();
    assert_eq!(deleted.status(), 204);
    assert!(eventually(|| !process_alive(pid)).await);
    assert_eq!(raw.post(TOOLS_LIST).await.status(), 404);
}

#[tokio::test]
async fn child_exit_fails_pending_request_and_ends_session() {
    let team = Team::start().await;
    let (_airlock, url) = start_airlock(&team, &[]).await;
    let raw = Raw::connect(&url, team.jwt("alice@example.com")).await;

    let reply = raw.call(4, "exit").await;
    assert_eq!(reply["id"], 4);
    assert_eq!(reply["error"]["code"], -32603);
    assert_eq!(raw.post(TOOLS_LIST).await.status(), 404);
}

#[tokio::test]
async fn idle_sessions_are_reaped() {
    let team = Team::start().await;
    let (_airlock, url) = start_airlock(&team, &["--idle-timeout-secs", "1"]).await;
    let raw = Raw::connect(&url, team.jwt("alice@example.com")).await;
    let pid = raw.whoami_pid().await;

    assert!(eventually(|| !process_alive(pid)).await);
    assert_eq!(raw.post(TOOLS_LIST).await.status(), 404);
}

#[tokio::test]
async fn ctrl_c_exits_despite_open_streams() {
    let team = Team::start().await;
    let (mut airlock, url) = start_airlock(&team, &[]).await;
    let raw = Raw::connect(&url, team.jwt("alice@example.com")).await;
    let pid = raw.whoami_pid().await;
    let _stream = raw.request(reqwest::Method::GET).send().await.unwrap();

    let airlock_pid = airlock.id().unwrap().to_string();
    let signal = std::process::Command::new("kill")
        .args(["-INT", &airlock_pid])
        .status();
    assert!(signal.unwrap().success());
    let status = tokio::time::timeout(Duration::from_secs(5), airlock.wait()).await;
    assert!(status.expect("airlock hung on Ctrl-C").unwrap().success());
    assert!(eventually(|| !process_alive(pid)).await);
}
