use anyhow::Result;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub exp: usize,
}

pub fn create_token(
    user_id: &str,
    username: &str,
    role: &str,
    secret: &str,
) -> Result<String> {
    let expiry = Utc::now() + Duration::hours(24);

    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        exp: expiry.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    Ok(token)
}

pub fn verify_token(token: &str, secret: &str) -> Result<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}
#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test_secret_only";

    #[test]
    fn token_roundtrip_works() {
        let token = create_token("u1", "alice", "analyst", SECRET).unwrap();
        let claims = verify_token(&token, SECRET).unwrap();
        assert_eq!(claims.username, "alice");
        assert_eq!(claims.role, "analyst");
    }

    #[test]
    fn wrong_secret_fails_verification() {
        let token = create_token("u1", "alice", "analyst", SECRET).unwrap();
        assert!(verify_token(&token, "wrong").is_err());
    }

    #[test]
    fn garbage_token_fails() {
        assert!(verify_token("not.a.token", SECRET).is_err());
    }
}