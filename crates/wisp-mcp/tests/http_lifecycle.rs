use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Notify;
use wisp_mcp::{
    connection::{ClientFactory, ManagedConnection},
    McpClient,
};

#[derive(Default)]
struct Fixture {
    entered: Notify,
    release: Notify,
    stale: AtomicBool,
    writes: AtomicUsize,
    initializations: AtomicUsize,
    cancellations: AtomicUsize,
}
async fn rpc(State(state): State<Arc<Fixture>>, Json(rpc): Json<Value>) -> Response {
    let id = rpc["id"].clone();
    let result = match rpc["method"].as_str().unwrap_or("") {
        "initialize" => {
            state.initializations.fetch_add(1, Ordering::SeqCst);
            json!({"capabilities":{"tools":{}}})
        }
        "notifications/initialized" => return StatusCode::ACCEPTED.into_response(),
        "notifications/cancelled" => {
            state.cancellations.fetch_add(1, Ordering::SeqCst);
            return StatusCode::ACCEPTED.into_response();
        }
        "tools/list" => {
            json!({"tools":[{"name":"echo","description":"test","inputSchema":{"type":"object"}}]})
        }
        "tools/call" => {
            match rpc["params"]["arguments"]["mode"].as_str().unwrap_or("") {
                "hold" => { state.entered.notify_one(); state.release.notified().await; }
                "stale_write" => { state.writes.fetch_add(1, Ordering::SeqCst); state.stale.store(true, Ordering::SeqCst); return StatusCode::NOT_FOUND.into_response(); }
                "sse" => {
                    // Match arrives but the server never closes the stream.
                    let frame = format!("data: {}\r\n\r\n", json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"流式"}]}}));
                    use futures_util::StreamExt;
                    let stream = futures_util::stream::iter(vec![Ok::<_,std::io::Error>(frame)]).chain(futures_util::stream::pending());
                    return ([("content-type","text/event-stream")], axum::body::Body::from_stream(stream)).into_response();
                }
                "rpc_error" => return Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"invalid args"}})).into_response(),
                _ => {}
            }
            json!({"content":[{"type":"text","text":"ok"}]})
        }
        _ => json!({}),
    };
    (
        [("mcp-session-id", "fixture-session")],
        Json(json!({"jsonrpc":"2.0","id":id,"result":result})),
    )
        .into_response()
}
async fn fixture() -> (Arc<Fixture>, String, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Fixture::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/", post(rpc))
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (state, url, server)
}

#[tokio::test]
async fn http_tool_has_no_120_second_deadline_and_cancellation_is_isolated() {
    let (state, url, server) = fixture().await;
    let client = Arc::new(
        McpClient::connect_http_with_proxy(&url, &[], "none")
            .await
            .unwrap(),
    );
    let task = {
        let client = client.clone();
        tokio::spawn(async move { client.tool_call("echo", &json!({"mode":"hold"})).await })
    };
    state.entered.notified().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(121)).await;
    tokio::task::yield_now().await;
    assert!(
        !task.is_finished(),
        "the former client-wide timeout must not fire"
    );
    tokio::time::resume();
    task.abort();
    let _ = task.await;
    for _ in 0..100 {
        if state.cancellations.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(state.cancellations.load(Ordering::SeqCst), 1);
    assert!(client.is_connected());
    assert_eq!(client.tool_call("echo", &json!({})).await.unwrap(), "ok");
    state.release.notify_one();
    client.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn sse_returns_matching_result_before_eof_and_rpc_error_keeps_connection() {
    let (_, url, server) = fixture().await;
    let client = McpClient::connect_http_with_proxy(&url, &[], "none")
        .await
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        client.tool_call("echo", &json!({"mode":"sse"})),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result, "流式");
    assert!(client
        .tool_call("echo", &json!({"mode":"rpc_error"}))
        .await
        .is_err());
    assert!(client.is_connected());
    client.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn reconnect_coalesces_and_never_replays_ambiguous_write() {
    let (state, url, server) = fixture().await;
    let factory: ClientFactory = Arc::new(move || {
        let url = url.clone();
        Box::pin(async move { McpClient::connect_http_with_proxy(&url, &[], "none").await })
    });
    let client = Arc::new(McpClient::managed(ManagedConnection::new(factory)));
    client.tools_list().await.unwrap();
    let old_generation = client.generation();
    let error = client
        .tool_call("echo", &json!({"mode":"stale_write"}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no automatic replay"));
    assert_eq!(state.writes.load(Ordering::SeqCst), 1);
    assert!(!client.is_connected());
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let client = client.clone();
        calls.spawn(async move { client.tool_call("echo", &json!({})).await });
    }
    while let Some(result) = calls.join_next().await {
        assert_eq!(result.unwrap().unwrap(), "ok");
    }
    assert_eq!(state.initializations.load(Ordering::SeqCst), 2);
    assert_eq!(state.writes.load(Ordering::SeqCst), 1);
    assert_eq!(client.generation(), old_generation + 1);
    let expected = client.tools_list().await.unwrap().remove(0);
    assert!(client
        .tool_call_checked_generation(&expected, &json!({}), Some(old_generation))
        .await
        .unwrap_err()
        .to_string()
        .contains("stale-instance"));
    client.shutdown().await.unwrap();
    assert!(client.tool_call("echo", &json!({})).await.is_err());
    assert_eq!(state.initializations.load(Ordering::SeqCst), 2);
    server.abort();
}
