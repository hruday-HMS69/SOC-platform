use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Alert {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub rule_name: String,
    pub severity: String,
    pub source_ip: String,
    pub description: String,
    pub log_event_id: Uuid,
}
#[derive(Debug)]
pub struct NewAlert {
    pub rule_name: String,
    pub severity: String,
    pub source_ip: String,
    pub description: String,
    pub log_event_id: Uuid,
}
