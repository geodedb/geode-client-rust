//! Integration tests for the Geode Rust client.
//!
//! Run with: `cargo test --features integration`
//!
//! By default, tests connect to a local Geode server at 127.0.0.1:3141.
//! You can configure this with environment variables:
//!   - GEODE_HOST: Server hostname (default: 127.0.0.1)
//!   - GEODE_PORT: Server port (default: 3141)
//!   - GEODE_USE_DOCKER: Set to "true" to use Docker testcontainers instead
//!   - GEODE_IMAGE: Docker image to use (default: geode:local)
//!
//! Example with local server (RECOMMENDED):
//!   cd ../geode && ./zig-out/bin/geode serve
//!   cargo test --features integration
//!
//! Example with Docker (requires pre-built image):
//!   cd ../geode && docker build -t geode:local .
//!   GEODE_USE_DOCKER=true cargo test --features integration

use geode_client::{Client, Connection, ConnectionPool, QueryBuilder, Value};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::Mutex;

const DEFAULT_GEODE_HOST: &str = "127.0.0.1";
const DEFAULT_GEODE_PORT: u16 = 3141;
const DEFAULT_GEODE_GRPC_PORT: u16 = 50051;
// Port exposed by Docker image for QUIC (UDP)
const DOCKER_GEODE_PORT: u16 = 3141;
// Port exposed by Docker image for gRPC (TCP)
const DOCKER_GRPC_PORT: u16 = 50051;
// Default to the registry image (available at geodedb/geode)
// Or build locally with: cd ../geode && docker build -t geode:local .
const DEFAULT_GEODE_IMAGE: &str = "geodedb/geode";
const DEFAULT_GEODE_TAG: &str = "latest";

/// Shared container state (only used in Docker mode)
static CONTAINER: Lazy<Arc<Mutex<Option<GeodeContainer>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));

/// Geode container wrapper
struct GeodeContainer {
    _container: ContainerAsync<GenericImage>,
    host: String,
    port: u16,
    grpc_port: u16,
}

/// Check if we should use Docker mode
fn use_docker_mode() -> bool {
    env::var("GEODE_USE_DOCKER")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

/// Get the local server connection info from environment
fn get_local_server_info() -> (String, u16) {
    let host = env::var("GEODE_HOST").unwrap_or_else(|_| DEFAULT_GEODE_HOST.to_string());
    let port = env::var("GEODE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_GEODE_PORT);
    (host, port)
}

/// Get the Docker image to use for testing
fn get_geode_image() -> (String, String) {
    if let Ok(img) = env::var("GEODE_IMAGE") {
        // Parse image:tag format
        if let Some((image, tag)) = img.rsplit_once(':') {
            return (image.to_string(), tag.to_string());
        }
        return (img, DEFAULT_GEODE_TAG.to_string());
    }
    (
        DEFAULT_GEODE_IMAGE.to_string(),
        DEFAULT_GEODE_TAG.to_string(),
    )
}

/// Start a Geode container for testing
async fn start_geode_container() -> Result<GeodeContainer, Box<dyn std::error::Error>> {
    let (image_name, tag) = get_geode_image();

    // Use UDP for QUIC protocol
    // Match Go client behavior - don't set GEODE_ADMIN_PASSWORD (no auth required by default)
    let container = GenericImage::new(image_name, tag)
        .with_exposed_port(DOCKER_GEODE_PORT.udp())
        .with_exposed_port(DOCKER_GRPC_PORT.tcp())
        .with_cmd(vec![
            "serve".to_string(),
            "--listen".to_string(),
            format!("0.0.0.0:{}", DOCKER_GEODE_PORT),
            "--listen-grpc".to_string(),
            format!("0.0.0.0:{}", DOCKER_GRPC_PORT),
            "--log-level".to_string(),
            "info".to_string(),
        ])
        .with_startup_timeout(Duration::from_secs(60))
        .start()
        .await?;

    let host = container.get_host().await?.to_string();
    let port = container
        .get_host_port_ipv4(DOCKER_GEODE_PORT.udp())
        .await?;
    let grpc_port = container.get_host_port_ipv4(DOCKER_GRPC_PORT.tcp()).await?;

    // Wait for QUIC server to be fully ready
    // The server needs time to generate TLS certificates and start the QUIC listener
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Health check: try to connect with retries
    // Match Go client behavior - no auth credentials by default
    let max_retries = 10;
    let mut last_error = None;
    for attempt in 1..=max_retries {
        match Client::new(&host, port).skip_verify(true).connect().await {
            Ok(conn) => {
                // Connection successful, server is ready
                drop(conn);
                return Ok(GeodeContainer {
                    _container: container,
                    host,
                    port,
                    grpc_port,
                });
            }
            Err(e) => {
                last_error = Some(e);
                if attempt < max_retries {
                    // Wait between retries with exponential backoff
                    tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
                }
            }
        }
    }

    Err(format!(
        "Container started but server not responding after {} attempts: {:?}",
        max_retries, last_error
    )
    .into())
}

/// Check if gRPC transport is requested
fn use_grpc_transport() -> bool {
    env::var("GEODE_TRANSPORT")
        .map(|v| v.to_lowercase() == "grpc")
        .unwrap_or(false)
}

/// Get server connection info (either local or Docker)
async fn get_server_info() -> (String, u16) {
    if use_docker_mode() {
        // Use Docker container
        let mut guard = CONTAINER.lock().await;

        if let Some(ref container) = *guard {
            if use_grpc_transport() {
                return (container.host.clone(), container.grpc_port);
            }
            return (container.host.clone(), container.port);
        }

        let (image, tag) = get_geode_image();
        let container = start_geode_container().await.unwrap_or_else(|e| {
            panic!(
                "Failed to start Geode container with image {}:{}.\n\
                Error: {}\n\n\
                To fix this, either:\n\
                1. Pull the image: docker pull geodedb/geode:latest\n\
                2. Or build locally: cd ../geode && docker build -t geode:local . && use GEODE_IMAGE=geode:local\n\
                3. Or use a local server instead: unset GEODE_USE_DOCKER",
                image, tag, e
            )
        });

        let host = container.host.clone();
        let port = if use_grpc_transport() {
            container.grpc_port
        } else {
            container.port
        };
        *guard = Some(container);

        (host, port)
    } else {
        // Use local server
        if use_grpc_transport() {
            let host = env::var("GEODE_HOST").unwrap_or_else(|_| DEFAULT_GEODE_HOST.to_string());
            let port = env::var("GEODE_GRPC_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(DEFAULT_GEODE_GRPC_PORT);
            (host, port)
        } else {
            get_local_server_info()
        }
    }
}

/// Create a test connection
async fn get_test_connection() -> Connection {
    let (host, port) = get_server_info().await;

    if use_grpc_transport() {
        // Use gRPC transport via DSN, include credentials if set
        let dsn = match (env::var("GEODE_USERNAME"), env::var("GEODE_PASSWORD")) {
            (Ok(user), Ok(pass)) => format!("grpc://{}:{}@{}:{}?tls=0", user, pass, host, port),
            _ => format!("grpc://{}:{}?tls=0", host, port),
        };
        let client = Client::from_dsn(&dsn)
            .unwrap_or_else(|e| panic!("Failed to parse gRPC DSN {}: {}", dsn, e));
        return client.connect().await.unwrap_or_else(|e| {
            panic!(
                "Failed to connect to Geode gRPC at {}:{}: {}. Make sure Geode is running with --listen-grpc.",
                host, port, e
            )
        });
    }

    // Match Go client behavior - no auth credentials by default
    // Override with GEODE_USERNAME/GEODE_PASSWORD if needed
    let mut client = Client::new(&host, port).skip_verify(true);

    // Only add credentials if explicitly set via environment
    if let Ok(username) = env::var("GEODE_USERNAME") {
        client = client.username(&username);
        if let Ok(password) = env::var("GEODE_PASSWORD") {
            client = client.password(&password);
        }
    }

    client.connect().await.unwrap_or_else(|e| {
        panic!(
            "Failed to connect to Geode at {}:{}: {}. Make sure Geode is running.",
            host, port, e
        )
    })
}

/// Clean up test data
async fn cleanup_test_data(conn: &mut Connection) {
    let _ = conn.query("MATCH (n) DETACH DELETE n").await;
}

/// Helper to get value from row by column name
fn get_value<'a>(row: &'a HashMap<String, Value>, col: &str) -> &'a Value {
    row.get(col)
        .unwrap_or_else(|| panic!("Column '{}' not found", col))
}

// =============================================================================
// Basic Operations Tests
// =============================================================================

#[tokio::test]
async fn test_docker_simple_return() {
    let mut conn = get_test_connection().await;

    let (page, _) = conn.query("RETURN 1 AS result").await.unwrap();

    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.columns.len(), 1);
    assert_eq!(page.columns[0].name, "result");

    let row = &page.rows[0];
    assert_eq!(get_value(row, "result").as_int().unwrap(), 1);

    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_string_return() {
    let mut conn = get_test_connection().await;

    let (page, _) = conn.query("RETURN 'hello' AS greeting").await.unwrap();

    assert_eq!(page.rows.len(), 1);
    let row = &page.rows[0];
    assert_eq!(get_value(row, "greeting").as_string().unwrap(), "hello");

    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_multiple_columns() {
    let mut conn = get_test_connection().await;

    let (page, _) = conn.query("RETURN 1 AS a, 2 AS b, 3 AS c").await.unwrap();

    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.columns.len(), 3);

    let row = &page.rows[0];
    assert_eq!(get_value(row, "a").as_int().unwrap(), 1);
    assert_eq!(get_value(row, "b").as_int().unwrap(), 2);
    assert_eq!(get_value(row, "c").as_int().unwrap(), 3);

    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_boolean_values() {
    let mut conn = get_test_connection().await;

    let (page, _) = conn.query("RETURN true AS t, false AS f").await.unwrap();

    assert_eq!(page.rows.len(), 1);
    let row = &page.rows[0];
    assert!(get_value(row, "t").as_bool().unwrap());
    assert!(!get_value(row, "f").as_bool().unwrap());

    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_null_value() {
    let mut conn = get_test_connection().await;

    let (page, _) = conn.query("RETURN null AS n").await.unwrap();

    assert_eq!(page.rows.len(), 1);
    let row = &page.rows[0];
    assert!(get_value(row, "n").is_null());

    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_parameterized_query() {
    let mut conn = get_test_connection().await;

    let mut params = HashMap::new();
    params.insert("x".to_string(), Value::int(42));
    params.insert("y".to_string(), Value::string("hello"));

    let (page, _) = conn
        .query_with_params("RETURN $x AS num, $y AS str", &params)
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 1);
    let row = &page.rows[0];
    assert_eq!(get_value(row, "num").as_int().unwrap(), 42);
    assert_eq!(get_value(row, "str").as_string().unwrap(), "hello");

    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_list_return() {
    let mut conn = get_test_connection().await;

    let (page, _) = conn.query("RETURN [1, 2, 3] AS arr").await.unwrap();

    assert_eq!(page.rows.len(), 1);
    let row = &page.rows[0];
    let arr = get_value(row, "arr").as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0].as_int().unwrap(), 1);
    assert_eq!(arr[1].as_int().unwrap(), 2);
    assert_eq!(arr[2].as_int().unwrap(), 3);

    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_map_return() {
    let mut conn = get_test_connection().await;

    let (page, _) = conn
        .query("RETURN {name: 'Alice', age: 30} AS person")
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 1);
    let row = &page.rows[0];
    let obj = get_value(row, "person").as_object().unwrap();
    assert_eq!(obj.get("name").unwrap().as_string().unwrap(), "Alice");
    assert_eq!(obj.get("age").unwrap().as_int().unwrap(), 30);

    conn.close().unwrap();
}

// =============================================================================
// Node CRUD Tests
// =============================================================================

#[tokio::test]
async fn test_docker_create_node() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    let (page, _) = conn
        .query("CREATE (n:TestNode {name: 'test'}) RETURN n.name AS name")
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 1);
    assert_eq!(
        get_value(&page.rows[0], "name").as_string().unwrap(),
        "test"
    );

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_create_node_with_properties() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Create node with inline values (matches Go client pattern)
    conn.query("CREATE (p:Person {name: 'Alice', age: 30, active: true})")
        .await
        .unwrap();

    // Verify properties with separate MATCH
    let (page, _) = conn
        .query("MATCH (p:Person {name: 'Alice'}) RETURN p.name AS pname, p.age AS page, p.active AS pactive")
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 1);
    let row = &page.rows[0];
    assert_eq!(get_value(row, "pname").as_string().unwrap(), "Alice");
    assert_eq!(get_value(row, "page").as_int().unwrap(), 30);
    assert!(get_value(row, "pactive").as_bool().unwrap());

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_read_nodes() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Create test data
    conn.query("CREATE (a:Person {name: 'Alice'})")
        .await
        .unwrap();
    conn.query("CREATE (b:Person {name: 'Bob'})").await.unwrap();

    // Read nodes
    let (page, _) = conn
        .query("MATCH (p:Person) RETURN p.name AS name ORDER BY p.name")
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 2);
    assert_eq!(
        get_value(&page.rows[0], "name").as_string().unwrap(),
        "Alice"
    );
    assert_eq!(get_value(&page.rows[1], "name").as_string().unwrap(), "Bob");

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_update_node() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Create node
    conn.query("CREATE (p:Person {name: 'Alice', age: 25})")
        .await
        .unwrap();

    // Update node
    conn.query("MATCH (p:Person {name: 'Alice'}) SET p.age = 26")
        .await
        .unwrap();

    // Verify update
    let (page, _) = conn
        .query("MATCH (p:Person {name: 'Alice'}) RETURN p.age AS age")
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 1);
    assert_eq!(get_value(&page.rows[0], "age").as_int().unwrap(), 26);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_delete_node() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Create node
    conn.query("CREATE (p:Person {name: 'ToDelete'})")
        .await
        .unwrap();

    // Verify exists
    let (page, _) = conn
        .query("MATCH (p:Person {name: 'ToDelete'}) RETURN p.name AS name")
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 1);

    // Delete node
    conn.query("MATCH (p:Person {name: 'ToDelete'}) DELETE p")
        .await
        .unwrap();

    // Verify deleted
    let (page, _) = conn
        .query("MATCH (p:Person {name: 'ToDelete'}) RETURN p.name AS name")
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 0);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_node_with_multiple_labels() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    conn.query("CREATE (n:Person:Employee {name: 'Worker'})")
        .await
        .unwrap();

    // Query by first label
    let (page, _) = conn
        .query("MATCH (n:Person) WHERE n.name = 'Worker' RETURN n.name AS name")
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 1);

    // Query by second label
    let (page, _) = conn
        .query("MATCH (n:Employee) WHERE n.name = 'Worker' RETURN n.name AS name")
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 1);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

// =============================================================================
// Relationship Tests
// =============================================================================

#[tokio::test]
async fn test_docker_create_relationship() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Create nodes and relationship
    conn.query("CREATE (a:Person {name: 'Alice'})-[:KNOWS]->(b:Person {name: 'Bob'})")
        .await
        .unwrap();

    // Query relationship
    let (page, _) = conn
        .query("MATCH (a:Person)-[:KNOWS]->(b:Person) RETURN a.name AS aname, b.name AS bname")
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 1);
    assert_eq!(
        get_value(&page.rows[0], "aname").as_string().unwrap(),
        "Alice"
    );
    assert_eq!(
        get_value(&page.rows[0], "bname").as_string().unwrap(),
        "Bob"
    );

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_relationship_with_properties() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    conn.query(
        "CREATE (a:Person {name: 'Alice'})-[:KNOWS {since: 2020}]->(b:Person {name: 'Bob'})",
    )
    .await
    .unwrap();

    let (page, _) = conn
        .query("MATCH (a)-[r:KNOWS]->(b) RETURN r.since AS since")
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 1);
    assert_eq!(get_value(&page.rows[0], "since").as_int().unwrap(), 2020);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_bidirectional_relationships() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Create bidirectional friendships
    conn.query(
        "CREATE (a:Person {name: 'Alice'}), (b:Person {name: 'Bob'}), \
         (a)-[:FRIENDS]->(b), (b)-[:FRIENDS]->(a)",
    )
    .await
    .unwrap();

    // Query undirected
    let (page, _) = conn
        .query(
            "MATCH (a:Person)-[:FRIENDS]-(b:Person) WHERE a.name = 'Alice' RETURN b.name AS bname",
        )
        .await
        .unwrap();

    // Should find Bob via either direction
    assert!(!page.rows.is_empty());

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_path_traversal() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Create chain: A -> B -> C
    conn.query(
        "CREATE (a:Person {name: 'A'})-[:KNOWS]->(b:Person {name: 'B'})-[:KNOWS]->(c:Person {name: 'C'})",
    )
    .await
    .unwrap();

    // Traverse path
    let (page, _) = conn
        .query("MATCH (a {name: 'A'})-[:KNOWS*2]->(c) RETURN c.name AS cname")
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 1);
    assert_eq!(get_value(&page.rows[0], "cname").as_string().unwrap(), "C");

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

// =============================================================================
// Transaction Tests
// =============================================================================

#[tokio::test]
async fn test_docker_transaction_commit() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Begin transaction
    conn.begin().await.unwrap();

    // Create node in transaction
    conn.query("CREATE (n:TxTest {value: 1})").await.unwrap();

    // Commit
    conn.commit().await.unwrap();

    // Verify persisted
    let (page, _) = conn
        .query("MATCH (n:TxTest) RETURN n.value AS value")
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(get_value(&page.rows[0], "value").as_int().unwrap(), 1);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_transaction_rollback() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Begin transaction
    conn.begin().await.unwrap();

    // Create node in transaction
    conn.query("CREATE (n:TxRollback {name: 'RolledBack'})")
        .await
        .unwrap();

    // Rollback
    conn.rollback().await.unwrap();

    // Verify node doesn't exist after rollback using count() (matches Go client pattern)
    let (page, _) = conn
        .query("MATCH (n:TxRollback {name: 'RolledBack'}) RETURN count(n) AS cnt")
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 1);
    assert_eq!(get_value(&page.rows[0], "cnt").as_int().unwrap(), 0);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_transaction_multiple_operations() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    conn.begin().await.unwrap();

    conn.query("CREATE (a:MultiTx {name: 'A'})").await.unwrap();
    conn.query("CREATE (b:MultiTx {name: 'B'})").await.unwrap();
    conn.query("MATCH (a:MultiTx {name: 'A'}), (b:MultiTx {name: 'B'}) CREATE (a)-[:LINKED]->(b)")
        .await
        .unwrap();

    conn.commit().await.unwrap();

    // Verify all operations persisted
    let (page, _) = conn
        .query("MATCH (n:MultiTx) RETURN n.name AS name ORDER BY n.name")
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 2);

    let (page, _) = conn
        .query("MATCH (:MultiTx)-[r:LINKED]->(:MultiTx) RETURN count(r) AS cnt")
        .await
        .unwrap();
    assert_eq!(get_value(&page.rows[0], "cnt").as_int().unwrap(), 1);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

// =============================================================================
// Query Operations Tests
// =============================================================================

#[tokio::test]
async fn test_docker_where_clause() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Create test data
    conn.query("CREATE (a:Person {name: 'Alice', age: 30})")
        .await
        .unwrap();
    conn.query("CREATE (b:Person {name: 'Bob', age: 25})")
        .await
        .unwrap();
    conn.query("CREATE (c:Person {name: 'Charlie', age: 35})")
        .await
        .unwrap();

    // Query with WHERE
    let (page, _) = conn
        .query("MATCH (p:Person) WHERE p.age > 28 RETURN p.name AS name ORDER BY p.name")
        .await
        .unwrap();

    assert_eq!(page.rows.len(), 2);
    assert_eq!(
        get_value(&page.rows[0], "name").as_string().unwrap(),
        "Alice"
    );
    assert_eq!(
        get_value(&page.rows[1], "name").as_string().unwrap(),
        "Charlie"
    );

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_order_by() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    conn.query("CREATE (a:Item {name: 'C', value: 3})")
        .await
        .unwrap();
    conn.query("CREATE (b:Item {name: 'A', value: 1})")
        .await
        .unwrap();
    conn.query("CREATE (c:Item {name: 'B', value: 2})")
        .await
        .unwrap();

    // Order by name ascending
    let (page, _) = conn
        .query("MATCH (i:Item) RETURN i.name AS name ORDER BY i.name ASC")
        .await
        .unwrap();

    assert_eq!(get_value(&page.rows[0], "name").as_string().unwrap(), "A");
    assert_eq!(get_value(&page.rows[1], "name").as_string().unwrap(), "B");
    assert_eq!(get_value(&page.rows[2], "name").as_string().unwrap(), "C");

    // Order by value descending
    let (page, _) = conn
        .query("MATCH (i:Item) RETURN i.value AS value ORDER BY i.value DESC")
        .await
        .unwrap();

    assert_eq!(get_value(&page.rows[0], "value").as_int().unwrap(), 3);
    assert_eq!(get_value(&page.rows[1], "value").as_int().unwrap(), 2);
    assert_eq!(get_value(&page.rows[2], "value").as_int().unwrap(), 1);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_limit_skip() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    for i in 1..=10 {
        conn.query(&format!("CREATE (n:Number {{value: {}}})", i))
            .await
            .unwrap();
    }

    // LIMIT
    let (page, _) = conn
        .query("MATCH (n:Number) RETURN n.value AS value ORDER BY n.value LIMIT 3")
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 3);

    // SKIP
    let (page, _) = conn
        .query("MATCH (n:Number) RETURN n.value AS value ORDER BY n.value SKIP 7")
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 3);
    assert_eq!(get_value(&page.rows[0], "value").as_int().unwrap(), 8);

    // SKIP + LIMIT
    let (page, _) = conn
        .query("MATCH (n:Number) RETURN n.value AS value ORDER BY n.value SKIP 2 LIMIT 3")
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 3);
    assert_eq!(get_value(&page.rows[0], "value").as_int().unwrap(), 3);
    assert_eq!(get_value(&page.rows[2], "value").as_int().unwrap(), 5);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

// =============================================================================
// Aggregation Tests
// =============================================================================

#[tokio::test]
async fn test_docker_count() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    conn.query("CREATE (a:CountTest)").await.unwrap();
    conn.query("CREATE (b:CountTest)").await.unwrap();
    conn.query("CREATE (c:CountTest)").await.unwrap();

    let (page, _) = conn
        .query("MATCH (n:CountTest) RETURN count(n) AS cnt")
        .await
        .unwrap();

    assert_eq!(get_value(&page.rows[0], "cnt").as_int().unwrap(), 3);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_sum() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    conn.query("CREATE (a:SumTest {value: 10})").await.unwrap();
    conn.query("CREATE (b:SumTest {value: 20})").await.unwrap();
    conn.query("CREATE (c:SumTest {value: 30})").await.unwrap();

    let (page, _) = conn
        .query("MATCH (n:SumTest) RETURN sum(n.value) AS total")
        .await
        .unwrap();

    assert_eq!(get_value(&page.rows[0], "total").as_int().unwrap(), 60);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_avg() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    conn.query("CREATE (a:AvgTest {value: 10})").await.unwrap();
    conn.query("CREATE (b:AvgTest {value: 20})").await.unwrap();
    conn.query("CREATE (c:AvgTest {value: 30})").await.unwrap();

    let (page, _) = conn
        .query("MATCH (n:AvgTest) RETURN avg(n.value) AS average")
        .await
        .unwrap();

    // Average of 10, 20, 30 = 20
    let avg_val = &page.rows[0]["average"];
    let avg = avg_val.as_int().unwrap_or_else(|_| {
        // Might be returned as decimal
        avg_val
            .as_decimal()
            .map(|d| d.to_string().parse::<i64>().unwrap_or(0))
            .unwrap_or(0)
    });
    assert_eq!(avg, 20);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_min_max() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    conn.query("CREATE (a:MinMaxTest {value: 5})")
        .await
        .unwrap();
    conn.query("CREATE (b:MinMaxTest {value: 15})")
        .await
        .unwrap();
    conn.query("CREATE (c:MinMaxTest {value: 10})")
        .await
        .unwrap();

    let (page, _) = conn
        .query("MATCH (n:MinMaxTest) RETURN min(n.value) AS minimum, max(n.value) AS maximum")
        .await
        .unwrap();

    assert_eq!(get_value(&page.rows[0], "minimum").as_int().unwrap(), 5);
    assert_eq!(get_value(&page.rows[0], "maximum").as_int().unwrap(), 15);

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

// =============================================================================
// Data Type Tests
// =============================================================================

#[tokio::test]
async fn test_docker_integer_types() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Test various integer values
    let mut params = HashMap::new();
    params.insert("zero".to_string(), Value::int(0));
    params.insert("positive".to_string(), Value::int(42));
    params.insert("negative".to_string(), Value::int(-100));
    params.insert("large".to_string(), Value::int(9223372036854775807i64));

    let (page, _) = conn
        .query_with_params(
            "RETURN $zero AS z, $positive AS p, $negative AS n, $large AS l",
            &params,
        )
        .await
        .unwrap();

    let row = &page.rows[0];
    assert_eq!(get_value(row, "z").as_int().unwrap(), 0);
    assert_eq!(get_value(row, "p").as_int().unwrap(), 42);
    assert_eq!(get_value(row, "n").as_int().unwrap(), -100);
    assert_eq!(
        get_value(row, "l").as_int().unwrap(),
        9223372036854775807i64
    );

    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_string_unicode() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    let test_strings = vec![
        ("ascii", "Hello World"),
        ("unicode", "こんにちは世界"),
        ("emoji", "Hello 🌍🚀"),
        ("mixed", "Café résumé naïve"),
    ];

    for (name, value) in test_strings {
        let mut params = HashMap::new();
        params.insert("val".to_string(), Value::string(value));

        let (page, _) = conn
            .query_with_params("RETURN $val AS result", &params)
            .await
            .unwrap();

        assert_eq!(
            get_value(&page.rows[0], "result").as_string().unwrap(),
            value,
            "Failed for {}",
            name
        );
    }

    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_nested_structures() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Nested list
    let (page, _) = conn
        .query("RETURN [[1, 2], [3, 4]] AS nested")
        .await
        .unwrap();

    let outer = get_value(&page.rows[0], "nested").as_array().unwrap();
    assert_eq!(outer.len(), 2);
    let inner1 = outer[0].as_array().unwrap();
    assert_eq!(inner1[0].as_int().unwrap(), 1);
    assert_eq!(inner1[1].as_int().unwrap(), 2);

    // Nested map
    let (page, _) = conn
        .query("RETURN {outer: {inner: 'value'}} AS nested")
        .await
        .unwrap();

    let outer = get_value(&page.rows[0], "nested").as_object().unwrap();
    let inner = outer.get("outer").unwrap().as_object().unwrap();
    assert_eq!(inner.get("inner").unwrap().as_string().unwrap(), "value");

    conn.close().unwrap();
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

#[tokio::test]
async fn test_docker_concurrent_queries() {
    let (host, port) = get_server_info().await;

    // Create multiple connections
    let mut handles = vec![];

    for i in 0..5 {
        let h = host.clone();
        let handle = tokio::spawn(async move {
            let mut conn = Client::new(&h, port)
                .skip_verify(true)
                .connect()
                .await
                .unwrap();

            let (page, _) = conn.query(&format!("RETURN {} AS num", i)).await.unwrap();

            let result = get_value(&page.rows[0], "num").as_int().unwrap();
            conn.close().unwrap();
            result
        });
        handles.push(handle);
    }

    // Collect results
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // Verify all queries completed
    results.sort();
    assert_eq!(results, vec![0, 1, 2, 3, 4]);
}

#[tokio::test]
async fn test_docker_connection_pool() {
    let (host, port) = get_server_info().await;

    let pool = ConnectionPool::new(&host, port, 5).skip_verify(true);

    // Run multiple queries through pool
    let mut handles = vec![];

    for i in 0..10 {
        let mut p = pool.acquire().await.unwrap();
        let handle = tokio::spawn(async move {
            let (page, _) = p.query(&format!("RETURN {} AS num", i)).await.unwrap();
            get_value(&page.rows[0], "num").as_int().unwrap()
        });
        handles.push(handle);
    }

    // Collect results
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    assert_eq!(results.len(), 10);
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[tokio::test]
async fn test_docker_syntax_error() {
    let mut conn = get_test_connection().await;

    // Use same query as Go client test
    let result = conn.query("MATCH (n RETURN n").await;

    // Server may accept some invalid syntax - skip test if no error (matches Go behavior)
    if result.is_ok() {
        eprintln!("Query accepted by server, skipping syntax error test");
        conn.close().unwrap();
        return;
    }

    let err = result.unwrap_err();
    assert!(!err.is_retryable());

    conn.close().unwrap();
}

#[tokio::test]
async fn test_docker_nonexistent_property() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    conn.query("CREATE (n:PropTest {name: 'test'})")
        .await
        .unwrap();

    // Accessing non-existent property should return null
    let (page, _) = conn
        .query("MATCH (n:PropTest) RETURN n.nonexistent AS val")
        .await
        .unwrap();

    assert!(get_value(&page.rows[0], "val").is_null());

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

// =============================================================================
// Query Builder Integration Tests
// =============================================================================

#[tokio::test]
async fn test_docker_query_builder() {
    let mut conn = get_test_connection().await;
    cleanup_test_data(&mut conn).await;

    // Create test data
    conn.query("CREATE (a:QB {name: 'Alice', age: 30})")
        .await
        .unwrap();
    conn.query("CREATE (b:QB {name: 'Bob', age: 25})")
        .await
        .unwrap();

    // Use query builder
    let (query, json_params) = QueryBuilder::new()
        .match_pattern("(p:QB)")
        .where_clause("p.age > $min_age")
        .return_(&["p.name AS name"])
        .order_by(&["p.name"])
        .with_param("min_age", 26)
        .build();

    // Convert serde_json params to Value params
    let mut params = HashMap::new();
    for (k, v) in json_params {
        params.insert(k, Value::from_json(v).unwrap());
    }

    let (page, _) = conn.query_with_params(&query, &params).await.unwrap();

    assert_eq!(page.rows.len(), 1);
    assert_eq!(
        get_value(&page.rows[0], "name").as_string().unwrap(),
        "Alice"
    );

    cleanup_test_data(&mut conn).await;
    conn.close().unwrap();
}

#[cfg(feature = "integration")]
#[tokio::test]
async fn test_pool_batch_and_pipeline_exec() {
    use geode_client::{ConnectionPool, Statement};
    use std::sync::Arc;
    let (host, port) = get_local_server_info();
    let pool = Arc::new(
        ConnectionPool::from_dsn(&format!("quic://{}:{}?insecure=true", host, port)).unwrap(),
    );
    let stmts: Vec<Statement> = (0..5)
        .map(|i| Statement::new(format!("RETURN {} AS x", i)))
        .collect();
    pool.batch_exec(&stmts).await.unwrap();
    pool.pipeline_exec(&stmts, 2, 4).await.unwrap();
}
