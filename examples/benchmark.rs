//! Native Rust client benchmark for Geode
//!
//! Usage: cargo run --example benchmark -- --host localhost --port 3142 --workers 10 --queries 1000

use geode_client::{Client, Result};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Serialize)]
struct BenchmarkResult {
    timestamp: String,
    duration_seconds: f64,
    total_queries: i64,
    successful_queries: i64,
    failed_queries: i64,
    throughput_qps: f64,
    latency_p50_ms: f64,
    latency_p95_ms: f64,
    latency_p99_ms: f64,
    latency_avg_ms: f64,
    workers: usize,
    queries_per_worker: usize,
    status: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut host = "localhost".to_string();
    let mut port: u16 = 3141;
    let mut workers: usize = 10;
    let mut queries: usize = 1000;
    let mut json_output = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                host = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--port" => {
                port = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(3142);
                i += 2;
            }
            "--workers" => {
                workers = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(10);
                i += 2;
            }
            "--queries" => {
                queries = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(1000);
                i += 2;
            }
            "--json" => {
                json_output = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    let all_latencies: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    let successful = Arc::new(AtomicI64::new(0));
    let failed = Arc::new(AtomicI64::new(0));

    let start = Instant::now();

    let mut handles = Vec::new();

    for _ in 0..workers {
        let host = host.clone();
        let latencies = Arc::clone(&all_latencies);
        let succ = Arc::clone(&successful);
        let fail = Arc::clone(&failed);

        handles.push(tokio::spawn(async move {
            let client = Client::new(&host, port).skip_verify(true);

            let mut conn = match client.connect().await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                    fail.fetch_add(queries as i64, Ordering::Relaxed);
                    return;
                }
            };

            let mut worker_latencies = Vec::with_capacity(queries);

            for _ in 0..queries {
                let qstart = Instant::now();
                match conn.query("RETURN 1").await {
                    Ok(_) => {
                        let latency = qstart.elapsed().as_secs_f64() * 1000.0;
                        worker_latencies.push(latency);
                        succ.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        // Only print first few errors to avoid spam
                        if fail.load(Ordering::Relaxed) < 3 {
                            eprintln!("Query failed: {}", e);
                        }
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            let _ = conn.close();

            let mut lat = latencies.lock().await;
            lat.extend(worker_latencies);
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }

    let duration = start.elapsed().as_secs_f64();
    let succ_count = successful.load(Ordering::Relaxed);
    let fail_count = failed.load(Ordering::Relaxed);

    let mut latencies = all_latencies.lock().await;
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let (p50, p95, p99, avg) = if !latencies.is_empty() {
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[(latencies.len() as f64 * 0.95) as usize];
        let p99 = latencies[(latencies.len() as f64 * 0.99) as usize];
        let avg: f64 = latencies.iter().sum::<f64>() / latencies.len() as f64;
        (p50, p95, p99, avg)
    } else {
        (0.0, 0.0, 0.0, 0.0)
    };

    let throughput = succ_count as f64 / duration;

    let status = if throughput >= 10000.0 {
        "EXCELLENT"
    } else if throughput >= 1000.0 {
        "GOOD"
    } else if throughput >= 100.0 {
        "ACCEPTABLE"
    } else {
        "LIMITED"
    };

    let result = BenchmarkResult {
        timestamp: chrono::Utc::now().to_rfc3339(),
        duration_seconds: duration,
        total_queries: succ_count + fail_count,
        successful_queries: succ_count,
        failed_queries: fail_count,
        throughput_qps: throughput,
        latency_p50_ms: p50,
        latency_p95_ms: p95,
        latency_p99_ms: p99,
        latency_avg_ms: avg,
        workers,
        queries_per_worker: queries,
        status: status.to_string(),
    };

    if json_output {
        println!("{}", serde_json::to_string(&result).unwrap());
    } else {
        println!("======================================================================");
        println!("RUST CLIENT BENCHMARK RESULTS");
        println!("======================================================================");
        println!("Duration: {:.2}s", result.duration_seconds);
        println!("Workers: {}", result.workers);
        println!("Queries/worker: {}", result.queries_per_worker);
        println!();
        println!("RESULTS:");
        println!("  Total queries:    {}", result.total_queries);
        println!("  Successful:       {}", result.successful_queries);
        println!("  Failed:           {}", result.failed_queries);
        println!("  Throughput:       {:.0} qps", result.throughput_qps);
        println!();
        println!("LATENCY:");
        println!("  p50:  {:.2}ms", result.latency_p50_ms);
        println!("  p95:  {:.2}ms", result.latency_p95_ms);
        println!("  p99:  {:.2}ms", result.latency_p99_ms);
        println!("  avg:  {:.2}ms", result.latency_avg_ms);
        println!();
        println!("STATUS: {}", result.status);
        println!("======================================================================");
    }

    Ok(())
}
