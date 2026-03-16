//! Simple HTTP client for querying the MISAKA node RPC.

use anyhow::Result;
use serde_json::Value;

async fn post_json(url: &str, body: Value) -> Result<Value> {
    // Use a basic TCP approach since we don't want reqwest dependency.
    // Build a minimal HTTP/1.1 POST request manually.
    let url_parsed: url::Url = url.parse().map_err(|_| anyhow::anyhow!("invalid URL"))?;
    let host = url_parsed.host_str().unwrap_or("127.0.0.1");
    let port = url_parsed.port().unwrap_or(3001);
    let path = url_parsed.path();

    let body_str = serde_json::to_string(&body)?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, port, body_str.len(), body_str,
    );

    let mut stream = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await?;

    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response).await?;

    let response_str = String::from_utf8_lossy(&response);
    // Find the body after \r\n\r\n
    let body_start = response_str.find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let body_text = &response_str[body_start..];

    // Handle chunked transfer encoding
    let json_text = if body_text.starts_with(|c: char| c.is_ascii_hexdigit()) {
        // Simple chunked decode: skip first line (chunk size), take until "0\r\n"
        body_text.lines()
            .skip(1)
            .take_while(|l| *l != "0")
            .collect::<Vec<_>>()
            .join("")
    } else {
        body_text.to_string()
    };

    serde_json::from_str(&json_text)
        .map_err(|e| anyhow::anyhow!("JSON parse error: {} | body: {}", e, &json_text[..json_text.len().min(200)]))
}

pub async fn get_status(rpc_url: &str) -> Result<()> {
    let url = format!("{}/api/get_chain_info", rpc_url);
    let resp = post_json(&url, serde_json::json!({})).await?;

    println!("╔═══════════════════════════════════════════════╗");
    println!("║  MISAKA Node Status                          ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!();
    println!("  Network:     {}", resp["networkName"].as_str().unwrap_or("?"));
    println!("  Version:     {}", resp["networkVersion"].as_str().unwrap_or("?"));
    println!("  Chain ID:    {}", resp["chainId"]);
    println!("  Height:      {}", resp["latestBlockHeight"]);
    println!("  Total TXs:   {}", resp["totalTransactions"]);
    println!("  Validators:  {}", resp["activeValidators"]);
    println!("  Avg Block:   {:.1}s", resp["avgBlockTime"].as_f64().unwrap_or(0.0));
    println!("  TPS:         {:.1}", resp["tpsEstimate"].as_f64().unwrap_or(0.0));
    println!("  Health:      {}", resp["chainHealth"].as_str().unwrap_or("?"));
    println!("  Finality:    {}", resp["finalityStatus"].as_str().unwrap_or("?"));

    Ok(())
}

pub async fn get_balance(rpc_url: &str, address: &str) -> Result<()> {
    let url = format!("{}/api/get_address_outputs", rpc_url);
    let resp = post_json(&url, serde_json::json!({ "address": address })).await?;

    println!("Address: {}", address);
    println!();

    if let Some(note) = resp["privacyNote"].as_str() {
        println!("⚠  {}", note);
        println!();
    }

    match resp["balance"].as_u64() {
        Some(bal) => println!("  Balance: {} MISAKA", bal),
        None => println!("  Balance: [privacy-protected]"),
    }
    println!("  TX Count: {}", resp["txCount"]);

    if let Some(outputs) = resp["outputs"].as_array() {
        if !outputs.is_empty() {
            println!();
            println!("  Outputs ({}):", outputs.len());
            for o in outputs {
                let tx = o["txHash"].as_str().unwrap_or("?");
                let idx = o["outputIndex"];
                print!("    {}..:{}", &tx[..tx.len().min(12)], idx);
                match o["amount"].as_u64() {
                    Some(a) => print!("  amount={}", a),
                    None => print!("  amount=[hidden]"),
                }
                println!();
            }
        }
    }

    Ok(())
}

/// Minimal URL parser (avoid external dep).
mod url {
    pub struct Url {
        pub scheme: String,
        pub host: String,
        pub port: Option<u16>,
        pub path: String,
    }

    impl std::str::FromStr for Url {
        type Err = ();
        fn from_str(s: &str) -> Result<Self, ()> {
            let s = s.trim();
            let (scheme, rest) = s.split_once("://").unwrap_or(("http", s));
            let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
            let path = format!("/{}", path);
            let (host, port) = if let Some((h, p)) = authority.split_once(':') {
                (h.to_string(), p.parse().ok())
            } else {
                (authority.to_string(), None)
            };
            Ok(Url { scheme: scheme.to_string(), host, port, path })
        }
    }

    impl Url {
        pub fn host_str(&self) -> Option<&str> { Some(&self.host) }
        pub fn port(&self) -> Option<u16> { self.port }
        pub fn path(&self) -> &str { &self.path }
    }
}
