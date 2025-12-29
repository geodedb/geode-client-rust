//! Authentication and authorization client.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// User in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub roles: Vec<String>,
}

/// Role in the RBAC system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
}

/// Permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: i64,
    pub name: String,
    pub resource: String,
    pub action: String,
}

/// RLS Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RLSPolicy {
    pub id: i64,
    pub name: String,
    pub table: String,
    pub operation: String,
    pub enabled: bool,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub token: String,
    pub user_id: i64,
    pub username: String,
    pub expires_at: DateTime<Utc>,
    pub roles: Vec<String>,
}

/// Authentication client
pub struct AuthClient {
    // Connection reference would go here
}

impl AuthClient {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for AuthClient {
    fn default() -> Self {
        Self::new()
    }
}
