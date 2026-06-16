use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct LogEvent {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub source_ip: String,
    pub event_type: String,
    pub username: Option<String>,
    pub message: String,
    pub severity: String,
    pub raw: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct IngestLogRequest {
    pub source_ip: String,
    pub event_type: String,
    pub username: Option<String>,
    pub message: String,
    pub severity: String,
    pub raw: Option<serde_json::Value>,
}
