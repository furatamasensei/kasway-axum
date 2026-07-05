//! Connectivity smoke check for a Kaspa node's wRPC JSON endpoint.
//!
//! Verifies reachability, network, sync state, and the utxoindex flag the
//! chain observer depends on.
//!
//! Usage: KASPA_NODE_URL=ws://<ip>:18210 cargo run -p kasway-api --example check_node

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

async fn call(url: &str, id: u64, method: &str) -> anyhow::Result<Value> {
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await?;
    ws.send(Message::Text(json!({ "id": id, "method": method, "params": {} }).to_string()))
        .await?;
    let result = loop {
        let msg = ws.next().await.ok_or_else(|| anyhow::anyhow!("connection closed"))??;
        let text = match msg {
            Message::Text(t) => t,
            Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
            Message::Close(_) => anyhow::bail!("closed before response"),
            _ => continue,
        };
        let value: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if value.get("id").and_then(Value::as_u64) != Some(id) {
            continue
        }
        if let Some(err) = value.get("error").filter(|e| !e.is_null()) {
            anyhow::bail!("{method} failed: {err}");
        }
        break value.get("params").cloned().unwrap_or(Value::Null);
    };
    let _ = ws.close(None).await;
    Ok(result)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("KASPA_NODE_URL")
        .map_err(|_| anyhow::anyhow!("set KASPA_NODE_URL, e.g. ws://<ip>:18210"))?;

    let info = call(&url, 1, "getInfo").await?;
    let dag = call(&url, 2, "getBlockDagInfo").await?;

    println!("serverVersion  : {}", info.get("serverVersion").and_then(Value::as_str).unwrap_or("?"));
    println!("isSynced       : {}", info.get("isSynced").and_then(Value::as_bool).unwrap_or(false));
    println!("isUtxoIndexed  : {}", info.get("isUtxoIndexed").and_then(Value::as_bool).unwrap_or(false));
    let network = dag
        .get("networkName")
        .or_else(|| dag.get("network"))
        .and_then(Value::as_str)
        .unwrap_or("?");
    println!("network        : {network}");
    println!("virtualDaaScore: {}", dag.get("virtualDaaScore").map(|v| v.to_string()).unwrap_or_default());
    if network == "?" {
        println!("getBlockDagInfo raw: {dag}");
    }
    Ok(())
}
