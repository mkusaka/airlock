use std::collections::HashMap;
use std::io::Write;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const AUD: &str = "test-aud";
const KID: &str = "test-kid";
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;

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

    fn jwt(&self, email: &str, aud: &str) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.into());
        let claims =
            json!({"iss": self.issuer, "aud": [aud], "exp": exp, "email": email, "sub": email});
        jsonwebtoken::encode(&header, &claims, &self.key).unwrap()
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
async fn start_airlock(team: &Team) -> (Child, String) {
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

async fn post(
    url: &str,
    jwt: Option<&str>,
    session: Option<&str>,
    body: &str,
) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(body.to_owned());
    if let Some(jwt) = jwt {
        request = request.header("cf-access-jwt-assertion", jwt);
    }
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    request.send().await.unwrap()
}

#[tokio::test]
async fn sessions_get_their_own_process_and_user() {
    let team = Team::start().await;
    let (_airlock, url) = start_airlock(&team).await;
    let alice = whoami(&url, team.jwt("alice@example.com", AUD)).await;
    let bob = whoami(&url, team.jwt("bob@example.com", AUD)).await;
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
    let (_airlock, url) = start_airlock(&team).await;
    let wrong_aud = team.jwt("alice@example.com", "other-aud");
    let wrong_key = other_team.jwt("alice@example.com", AUD);
    for jwt in [None, Some("garbage"), Some(&wrong_aud), Some(&wrong_key)] {
        assert_eq!(post(&url, jwt, None, INITIALIZE).await.status(), 403);
    }
}

#[tokio::test]
async fn sessions_are_bound_to_their_owner() {
    let team = Team::start().await;
    let (_airlock, url) = start_airlock(&team).await;
    let alice = team.jwt("alice@example.com", AUD);
    let response = post(&url, Some(&alice), None, INITIALIZE).await;
    assert_eq!(response.status(), 200);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();

    let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    let bob = team.jwt("bob@example.com", AUD);
    assert_eq!(
        post(&url, Some(&bob), Some(&session), list).await.status(),
        404
    );
    assert_eq!(
        post(&url, Some(&alice), Some(&session), list)
            .await
            .status(),
        200
    );
}
