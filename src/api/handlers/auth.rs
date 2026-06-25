use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

use crate::{
    auth::jwt::create_token,
    db::queries,
    models::user::{LoginRequest, RegisterRequest},
    AppState,
};

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let existing = queries::find_user_by_username(&state.db, &payload.username)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            "Username already taken".to_string(),
        ));
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    let user = queries::insert_user(&state.db, &payload.username, &password_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!(username = %user.username, "New user registered");

    Ok(Json(serde_json::json!({
        "message": "User registered successfully",
        "user_id": user.id,
        "username": user.username,
    })))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user = queries::find_user_by_username(&state.db, &payload.username)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Invalid username or password".to_string(),
        ))?;

    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid username or password".to_string(),
            )
        })?;

    let token = create_token(
        &user.id.to_string(),
        &user.username,
        &user.role,
        &state.jwt_secret,
    )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!(username = %user.username, "User logged in");

    Ok(Json(serde_json::json!({
        "token": token,
        "token_type": "Bearer",
        "expires_in": "24h",
        "username": user.username,
        "role": user.role,
    })))
}