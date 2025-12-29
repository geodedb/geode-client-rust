use geode_client::Client;

#[tokio::main]
async fn main() {
    println!("[TEST] Starting Rust client connection test...");
    println!("[TEST] Connecting to localhost:8443");

    // Try with skip_verify first
    let client = Client::new("localhost", 8443).skip_verify(true);

    println!("[TEST] Client configured with skip_verify=true");

    match client.connect().await {
        Ok(mut conn) => {
            println!("[TEST] ✓ Successfully connected!");
            println!("[TEST] Connection established with Quinn QUIC library");

            // Try a simple query
            match conn.query("RETURN 1 AS x").await {
                Ok((page, _)) => {
                    println!("[TEST] ✓ Query successful!");
                    println!("[TEST] Columns: {:?}", page.columns);
                    println!("[TEST] Rows: {:?}", page.rows);
                }
                Err(e) => {
                    eprintln!("[TEST] ✗ Query failed: {}", e);
                }
            }

            println!("[TEST] Connection successful - test complete");
        }
        Err(e) => {
            eprintln!("[TEST] ✗ Connection failed: {}", e);
            eprintln!("[TEST] Error details: {:?}", e);
            std::process::exit(1);
        }
    }
}
