//! 真正监听临时端口验证 HTTP 契约，不加载 ~/.muse-bridge。
use muse_connector_lib::core::{
    api::{self, ApiOptions, ApiState, BridgePaths},
    config::BridgeConfig,
    token,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        if let Ok(target) = std::fs::canonicalize(&self.0) {
            assert!(target.starts_with(base));
            let _ = std::fs::remove_dir_all(target);
        }
    }
}
async fn request(port: u16, method: &str, uri: &str, auth: bool, body: &str) -> (u16, Value) {
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let auth = if auth {
        "Authorization: Bearer disposable-integration-token\r\n"
    } else {
        ""
    };
    let data = format!(
        "{method} {uri} HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tcp.write_all(data.as_bytes()).await.unwrap();
    let mut output = Vec::new();
    tcp.read_to_end(&mut output).await.unwrap();
    let response = String::from_utf8(output).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    let code = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, serde_json::from_str(body).unwrap())
}
#[tokio::test]
async fn real_http_preserves_encoding_and_audits_wrong_methods() {
    let fixture = Fixture(std::env::temp_dir().join(format!("muse-tcp-{}", token::generate())));
    let root = fixture.0.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let cfg = BridgeConfig {
        port: 0,
        read_only: false,
        roots: [("r".into(), root.clone())].into(),
    };
    let paths = BridgePaths {
        config: fixture.0.join("config.json"),
        token: fixture.0.join("token"),
        audit: fixture.0.join("audit.log"),
    };
    let (state, _) = ApiState::new(
        cfg,
        "disposable-integration-token".into(),
        paths,
        ApiOptions::default(),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let api = state.clone();
    let task = tokio::spawn(async move { api::serve_listener(api, listener, rx).await });
    let write =
        json!({"root":"r","path":"中文 a.txt","content":"你好，Muse\nsecond line"}).to_string();
    assert_eq!(
        request(port, "POST", "/api/write", true, &write).await.0,
        200
    );
    let (code, read) = request(
        port,
        "GET",
        "/api/read?root=&root=r&path=%E4%B8%AD%E6%96%87+a.txt",
        true,
        "",
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(read["content"], "你好，Muse\nsecond line");
    assert_eq!(request(port, "POST", "/api/health", false, "").await.0, 401);
    assert_eq!(request(port, "POST", "/api/health", true, "").await.0, 404);
    assert_eq!(state.audit().recent(None, 20).entries.len(), 4);
    shutdown.send(true).unwrap();
    task.await.unwrap().unwrap();
}
