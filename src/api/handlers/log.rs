use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::{db::queries, detection::rules, models::log_event::IngestLogRequest, AppState};

#[derive(Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
}

pub async fn ingest_log(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<IngestLogRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let log = queries::insert_log_event(&state.db, &payload)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let triggered = rules::run_all_rules(&state.db, &log)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut saved_alerts = Vec::new();
    for alert in &triggered {
        let saved = queries::insert_alert(&state.db, alert)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        saved_alerts.push(saved);
    }

    tracing::info!(
        source_ip = %log.source_ip,
        event_type = %log.event_type,
        alerts = saved_alerts.len(),
        "Log ingested"
    );

    Ok(Json(serde_json::json!({
        "log": log,
        "alerts_triggered": saved_alerts.len(),
        "alerts": saved_alerts,
    })))
}

pub async fn list_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(50).min(500);

    let logs = queries::list_log_events(&state.db, limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "logs": logs,
        "count": logs.len()
    })))
}