use anyhow::Result;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{
    alert::{Alert, NewAlert},
    log_event::{IngestLogRequest, LogEvent},
};

pub async fn insert_log_event(pool: &PgPool, req: &IngestLogRequest) -> Result<LogEvent> {
    let log = sqlx::query_as::<_, LogEvent>(
        r#"
        INSERT INTO log_events (id, created_at, source_ip, event_type, username, message, severity, raw)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        "#,
    )
        .bind(Uuid::new_v4())
        .bind(Utc::now())
        .bind(&req.source_ip)
        .bind(&req.event_type)
        .bind(&req.username)
        .bind(&req.message)
        .bind(&req.severity)
        .bind(&req.raw)
        .fetch_one(pool)
        .await?;

    Ok(log)
}

pub async fn count_recent_failed_logins(
    pool: &PgPool,
    source_ip: &str,
    within_minutes: i64,
) -> Result<i64> {
    let row = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM log_events
        WHERE source_ip = $1
          AND event_type = 'failed_login'
          AND created_at > NOW() - ($2 * INTERVAL '1 minute')
        "#,
    )
        .bind(source_ip)
        .bind(within_minutes)
        .fetch_one(pool)
        .await?;

    Ok(row)
}

pub async fn insert_alert(pool: &PgPool, alert: &NewAlert) -> Result<Alert> {
    let saved = sqlx::query_as::<_, Alert>(
        r#"
        INSERT INTO alerts (id, created_at, rule_name, severity, source_ip, description, log_event_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
        .bind(Uuid::new_v4())
        .bind(Utc::now())
        .bind(&alert.rule_name)
        .bind(&alert.severity)
        .bind(&alert.source_ip)
        .bind(&alert.description)
        .bind(alert.log_event_id)
        .fetch_one(pool)
        .await?;

    Ok(saved)
}

pub async fn list_log_events(pool: &PgPool, limit: i64) -> Result<Vec<LogEvent>> {
    let logs = sqlx::query_as::<_, LogEvent>(
        "SELECT * FROM log_events ORDER BY created_at DESC LIMIT $1",
    )
        .bind(limit)
        .fetch_all(pool)
        .await?;

    Ok(logs)
}

pub async fn list_alerts(pool: &PgPool, limit: i64) -> Result<Vec<Alert>> {
    let alerts = sqlx::query_as::<_, Alert>(
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT $1",
    )
        .bind(limit)
        .fetch_all(pool)
        .await?;

    Ok(alerts)
}