use std::process::Stdio;

use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const TOKEN: &str = "test-token";

/// Starts airlock on an ephemeral port and returns it with its MCP URL.
async fn start_airlock() -> (Child, String) {
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pid_server.py");
    let mut child = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["--listen", "127.0.0.1:0", "--", "python3", fixture])
        .env("AIRLOCK_TOKEN", TOKEN)
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

async fn tool_pid(url: &str) -> String {
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(url).auth_header(TOKEN),
    );
    let client = ().serve(transport).await.unwrap();
    let tools = client.list_all_tools().await.unwrap();
    assert_eq!(tools[0].name, "pid");
    let result = client
        .call_tool(CallToolRequestParams::new("pid"))
        .await
        .unwrap();
    let pid = result.content[0].as_text().unwrap().text.clone();
    client.cancel().await.unwrap();
    pid
}

#[tokio::test]
async fn sessions_are_isolated_per_client() {
    let (_airlock, url) = start_airlock().await;
    let first = tool_pid(&url).await;
    let second = tool_pid(&url).await;
    assert_ne!(first, second, "each session must get its own child process");
}

#[tokio::test]
async fn rejects_missing_or_wrong_token() {
    let (_airlock, url) = start_airlock().await;
    let http = reqwest::Client::new();
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    for auth in [None, Some("Bearer wrong")] {
        let mut request = http
            .post(&url)
            .header("content-type", "application/json")
            .body(body);
        if let Some(auth) = auth {
            request = request.header("authorization", auth);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 401);
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
    }
}
