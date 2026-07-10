use anyhow::Result;
use sqlx::PgPool;

use crate::{
    db::queries,
    models::{alert::NewAlert, log_event::LogEvent},
};

pub async fn check_brute_force(pool: &PgPool, log: &LogEvent) -> Result<Option<NewAlert>> {
    if log.event_type != "failed_login" {
        return Ok(None);
    }

    let count = queries::count_recent_failed_logins(pool, &log.source_ip, 10).await?;

    if count >= 5 {
        return Ok(Some(NewAlert {
            rule_name: "BRUTE_FORCE_DETECTED".to_string(),
            severity: "high".to_string(),
            source_ip: log.source_ip.clone(),
            description: format!(
                "IP {} made {} failed login attempts in the last 10 minutes",
                log.source_ip, count
            ),
            log_event_id: log.id,
        }));
    }

    Ok(None)
}

pub fn check_critical_event_type(log: &LogEvent) -> Option<NewAlert> {
    const CRITICAL_TYPES: &[&str] = &[
        "sql_injection",
        "xss_attempt",
        "rce_attempt",
        "privilege_escalation",
        "malware_detected",
    ];

    if CRITICAL_TYPES.contains(&log.event_type.as_str()) {
        return Some(NewAlert {
            rule_name: "CRITICAL_EVENT_TYPE".to_string(),
            severity: "critical".to_string(),
            source_ip: log.source_ip.clone(),
            description: format!(
                "Critical security event '{}' detected from IP {}",
                log.event_type, log.source_ip
            ),
            log_event_id: log.id,
        });
    }

    None
}

pub async fn run_all_rules(pool: &PgPool, log: &LogEvent) -> Result<Vec<NewAlert>> {
    let mut alerts = Vec::new();

    if let Some(alert) = check_brute_force(pool, log).await? {
        alerts.push(alert);
    }

    if let Some(alert) = check_critical_event_type(log) {
        alerts.push(alert);
    }

    Ok(alerts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use crate::models::log_event::LogEvent;

    fn make_log(event_type: &str, source_ip: &str) -> LogEvent {
        LogEvent {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            source_ip: source_ip.to_string(),
            event_type: event_type.to_string(),
            username: None,
            message: "test".to_string(),
            severity: "medium".to_string(),
            raw: None,
        }
    }

    #[test]
    fn critical_rule_fires_on_sql_injection() {
        let log = make_log("sql_injection", "10.0.0.1");
        let alert = check_critical_event_type(&log);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, "critical");
    }

    #[test]
    fn critical_rule_does_not_fire_on_normal_event() {
        let log = make_log("failed_login", "10.0.0.1");
        let alert = check_critical_event_type(&log);
        assert!(alert.is_none());
    }

    #[test]
    fn critical_rule_fires_on_rce_attempt() {
        let log = make_log("rce_attempt", "10.0.0.1");
        assert!(check_critical_event_type(&log).is_some());
    }
}