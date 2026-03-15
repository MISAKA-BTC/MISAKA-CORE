//! Faucet — request testnet tokens from a MISAKA node.

use anyhow::Result;

pub async fn run(address: &str, rpc_url: &str) -> Result<()> {
    println!("🚰 Requesting testnet tokens...");
    println!("   Address: {}", address);
    println!("   Node:    {}", rpc_url);

    let url = format!("{}/api/faucet", rpc_url);
    let body = serde_json::json!({ "address": address });
    let result = post_json(&url, &body).await?;

    let success = result["success"].as_bool().unwrap_or(false);
    if success {
        let amount = result["amount"].as_u64().unwrap_or(0);
        let tx_hash = result["txHash"].as_str().unwrap_or("?");
        println!();
        println!("✅ Faucet drip successful!");
        println!("   Amount:  {} MISAKA", amount);
        println!("   TX Hash: {}", tx_hash);
        println!("   Status:  pending (will be included in next block)");
    } else {
        let error = result["error"].as_str().unwrap_or("unknown error");
        println!();
        println!("❌ Faucet request failed: {}", error);
    }

    Ok(())
}

async fn post_json(url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{}", path);
    let (host, port) = authority.split_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(3001)))
        .unwrap_or((authority.to_string(), 3001));

    let body_str = serde_json::to_string(body)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, port, body_str.len(), body_str,
    );

    let mut stream = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await?;

    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response).await?;

    let response_str = String::from_utf8_lossy(&response);
    let body_start = response_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body_text = &response_str[body_start..];

    serde_json::from_str(body_text)
        .map_err(|e| anyhow::anyhow!("JSON parse error: {}", e))
}
