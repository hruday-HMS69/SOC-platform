use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::{db::queries, AppState};

#[derive(Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
}
pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(50).min(500);

    let alerts = queries::list_alerts(&state.db, limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "alerts": alerts,
        "count": alerts.len()
    })))
}
