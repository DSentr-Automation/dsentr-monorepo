use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

use crate::engine::actions::registry::{
    ActionExecutionResult, ActionExecutionSemantics, ActionExecutor, ActionManifest,
    ActionRuntimeContext, ActionValidator,
};
use crate::engine::graph::Node;
use crate::engine::actions::validate_required_fields;

pub(crate) const MANIFEST: ActionManifest = ActionManifest {
    action_type: "delay",
    required_fields: &["config"],
    execution_semantics: ActionExecutionSemantics::Resumable,
};

pub(crate) struct DelayValidator;

impl ActionValidator for DelayValidator {
    fn validate(&self, node: &Node) -> Result<(), String> {
        validate_required_fields(node, MANIFEST.required_fields)?;
        let config_value = node.data.get("config").cloned().unwrap_or(Value::Null);
        parse_delay_config(&config_value).map(|_| ())
    }
}

pub(crate) struct DelayExecutor;

#[async_trait]
impl ActionExecutor for DelayExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let config_value = ctx.node.data.get("config").cloned().unwrap_or(Value::Null);
        let config = parse_delay_config(&config_value)
            .map_err(|err| format!("Invalid delay config: {err}"))?;
        let mut rng = rand::rng();
        let plan = compute_delay_plan(&config, Utc::now(), &mut rng)
            .map_err(|err| format!("Delay planning failed: {err}"))?;

        let outputs = match &plan {
            DelayOutcome::NoWait { base_delay } => json!({
                "resumeAt": Value::Null,
                "delaySeconds": base_delay.as_secs(),
                "jitterAppliedSeconds": 0,
                "mode": "duration"
            }),
            DelayOutcome::Wait(comp) => json!({
                "resumeAt": comp.resume_at.to_rfc3339(),
                "delaySeconds": comp.total_delay.as_secs(),
                "baseDelaySeconds": comp.base_delay.as_secs(),
                "jitterAppliedSeconds": comp.jitter_applied.as_secs(),
                "mode": "duration_or_absolute"
            }),
        };

        match plan {
            DelayOutcome::Wait(comp) => Ok(ActionExecutionResult::Pause {
                outputs,
                resume_at: comp.resume_at,
            }),
            DelayOutcome::NoWait { .. } => Ok(ActionExecutionResult::Immediate {
                outputs,
                selected_next: None,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub struct DurationConfig {
    pub minutes: Option<u64>,
    pub hours: Option<u64>,
    pub days: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub struct DelayConfig {
    #[serde(default)]
    pub mode: Option<String>,
    pub wait_for: Option<DurationConfig>,
    #[serde(default)]
    pub wait_until: Option<DateTime<Utc>>,
    pub jitter_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayComputation {
    pub base_delay: Duration,
    pub jitter_applied: Duration,
    pub total_delay: Duration,
    pub resume_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelayOutcome {
    NoWait { base_delay: Duration },
    Wait(DelayComputation),
}

pub fn parse_delay_config(value: &Value) -> Result<DelayConfig, String> {
    serde_json::from_value::<DelayConfig>(value.clone())
        .map_err(|_| "Invalid delay configuration".to_string())
}

pub fn compute_delay_plan(
    config: &DelayConfig,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<DelayOutcome, String> {
    let duration_delay = config
        .wait_for
        .as_ref()
        .and_then(duration_from_config)
        .unwrap_or(Duration::ZERO);

    let wait_until_delay = match config.wait_until {
        Some(target) => {
            if target <= now {
                Duration::ZERO
            } else {
                (target - now).to_std().unwrap_or(Duration::ZERO)
            }
        }
        None => Duration::ZERO,
    };

    let mode = config.mode.as_deref().unwrap_or("auto");
    let has_wait = config.wait_for.is_some() || config.wait_until.is_some();

    match mode {
        "duration" => {
            if duration_delay.is_zero() {
                return Err("Configure a duration before continuing".to_string());
            }
        }
        "datetime" => {
            if config.wait_until.is_none() {
                return Err("Configure a valid target datetime before continuing".to_string());
            }
        }
        _ => {
            if !has_wait {
                return Err("Configure either a wait duration or an absolute datetime".to_string());
            }
        }
    };

    let base_delay = match mode {
        "duration" => duration_delay,
        "datetime" => wait_until_delay,
        _ => duration_delay.max(wait_until_delay),
    };
    let jitter_range = config.jitter_seconds.unwrap_or(0);
    let jitter_applied = if jitter_range == 0 || base_delay.is_zero() {
        Duration::ZERO
    } else {
        Duration::from_secs(rng.random_range(0..=jitter_range))
    };

    let total_delay = base_delay
        .checked_add(jitter_applied)
        .ok_or_else(|| "Delay duration is too large".to_string())?;

    if total_delay.is_zero() {
        return Ok(DelayOutcome::NoWait { base_delay });
    }

    let resume_at = now
        .checked_add_signed(chrono_duration_from_std(total_delay)?)
        .unwrap_or(now);

    Ok(DelayOutcome::Wait(DelayComputation {
        base_delay,
        jitter_applied,
        total_delay,
        resume_at,
    }))
}

fn duration_from_config(config: &DurationConfig) -> Option<Duration> {
    let mut total: u64 = 0;
    if let Some(minutes) = config.minutes {
        total = total.checked_add(minutes.checked_mul(60)?)?;
    }
    if let Some(hours) = config.hours {
        total = total.checked_add(hours.checked_mul(3600)?)?;
    }
    if let Some(days) = config.days {
        total = total.checked_add(days.checked_mul(86_400)?)?;
    }
    Some(Duration::from_secs(total))
}

fn chrono_duration_from_std(duration: Duration) -> Result<ChronoDuration, String> {
    ChronoDuration::from_std(duration)
        .map_err(|_| "Delay duration is too large for chrono conversion".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn duration_config_sums_components() {
        let config = DelayConfig {
            mode: Some("duration".into()),
            wait_for: Some(DurationConfig {
                minutes: Some(30),
                hours: Some(2),
                days: Some(1),
            }),
            wait_until: None,
            jitter_seconds: None,
        };

        let mut rng = StdRng::seed_from_u64(1);
        let result =
            compute_delay_plan(&config, Utc::now(), &mut rng).expect("delay plan should compute");
        match result {
            DelayOutcome::Wait(plan) => {
                assert_eq!(plan.base_delay.as_secs(), 86_400 + 2 * 3600 + 1800);
                assert_eq!(plan.jitter_applied.as_secs(), 0);
                assert_eq!(plan.total_delay.as_secs(), plan.base_delay.as_secs());
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn absolute_timestamp_in_past_is_immediate() {
        let now = Utc::now();
        let past = now - ChronoDuration::minutes(5);
        let config = DelayConfig {
            mode: Some("datetime".into()),
            wait_for: None,
            wait_until: Some(past),
            jitter_seconds: None,
        };

        let mut rng = StdRng::seed_from_u64(2);
        let result =
            compute_delay_plan(&config, now, &mut rng).expect("plan should compute even when past");

        match result {
            DelayOutcome::NoWait { base_delay } => {
                assert_eq!(base_delay, Duration::ZERO);
            }
            other => panic!("expected immediate continuation, got {other:?}"),
        }
    }

    #[test]
    fn jitter_applies_when_delay_present() {
        let now = Utc::now();
        let config = DelayConfig {
            mode: Some("duration".into()),
            wait_for: Some(DurationConfig {
                minutes: Some(1),
                hours: None,
                days: None,
            }),
            wait_until: None,
            jitter_seconds: Some(5),
        };
        let mut rng = StdRng::seed_from_u64(123);

        let result =
            compute_delay_plan(&config, now, &mut rng).expect("plan with jitter should compute");

        match result {
            DelayOutcome::Wait(plan) => {
                assert_eq!(plan.base_delay.as_secs(), 60);
                assert!(plan.jitter_applied.as_secs() <= 5);
                assert_eq!(
                    plan.total_delay.as_secs(),
                    plan.base_delay.as_secs() + plan.jitter_applied.as_secs()
                );
            }
            other => panic!("expected wait outcome, got {other:?}"),
        }
    }

    #[test]
    fn wait_until_datetime_calculates_delay() {
        let now = Utc::now();
        let future = now + ChronoDuration::minutes(10);
        let config = DelayConfig {
            mode: Some("datetime".into()),
            wait_for: None,
            wait_until: Some(future),
            jitter_seconds: None,
        };
        let mut rng = StdRng::seed_from_u64(9);

        let result = compute_delay_plan(&config, now, &mut rng).expect("plan should compute");

        match result {
            DelayOutcome::Wait(plan) => {
                let diff_secs = (future - now).num_seconds() as u64;
                assert_eq!(plan.base_delay.as_secs(), diff_secs);
                assert_eq!(plan.total_delay.as_secs(), diff_secs);
            }
            other => panic!("expected wait outcome, got {other:?}"),
        }
    }

    #[test]
    fn zero_wait_modes_error() {
        let config = DelayConfig {
            mode: Some("duration".into()),
            wait_for: None,
            wait_until: None,
            jitter_seconds: None,
        };
        let mut rng = StdRng::seed_from_u64(5);

        let err = compute_delay_plan(&config, Utc::now(), &mut rng)
            .expect_err("missing modes should error");
        assert!(err.contains("duration"), "Unexpected error: {err}");
    }
}
