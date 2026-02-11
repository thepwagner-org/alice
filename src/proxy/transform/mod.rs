//! Transform pipeline for LLM API request/response modification.
//!
//! Provides a transport-agnostic middleware layer that operates on parsed JSON
//! request bodies. Each transform implements [`RequestTransform`] and can modify
//! the request body or block the request entirely.
//!
//! Transforms are configured via `[[transforms]]` in the TOML config file and
//! run in declaration order (first match on `Block` short-circuits).

mod injection_scan;
mod message_swap;
mod system_prompt;
mod tool_filter;

use serde::Deserialize;
use tracing::{info, warn};

pub use injection_scan::InjectionScanTransform;
pub use message_swap::{MessageSwapTransform, SwapRule};
pub use system_prompt::SystemPromptTransform;
pub use tool_filter::ToolFilterTransform;

/// Normalized view of an LLM API request, independent of H1/H2 transport.
pub struct LlmRequestContext {
    pub host: String,
    pub path: String,
    /// Pre-parsed JSON body. Transforms operate on this directly.
    /// Serialized back to bytes after all transforms run.
    pub body: serde_json::Value,
}

/// Result of a transform: continue processing or block the request.
pub enum TransformResult {
    /// Continue to the next transform (body may have been modified in place).
    Continue,
    /// Block the request with the given HTTP status and message.
    Block { status: u16, message: String },
}

/// A request transform that can modify or block LLM API requests.
pub trait RequestTransform: Send + Sync {
    /// Short name for logging (e.g., "system_prompt", "tool_filter").
    fn name(&self) -> &str;

    /// Transform the request. Modify `ctx.body` in place, or return `Block` to reject.
    fn transform(&self, ctx: &mut LlmRequestContext) -> TransformResult;
}

/// Ordered pipeline of request transforms.
pub struct TransformPipeline {
    transforms: Vec<Box<dyn RequestTransform>>,
}

impl TransformPipeline {
    /// Run all transforms in order. Returns `Block` on first rejection.
    pub fn process(&self, ctx: &mut LlmRequestContext) -> TransformResult {
        for transform in &self.transforms {
            match transform.transform(ctx) {
                TransformResult::Continue => {}
                block @ TransformResult::Block { .. } => {
                    warn!(
                        transform = transform.name(),
                        host = %ctx.host,
                        path = %ctx.path,
                        "request blocked by transform"
                    );
                    return block;
                }
            }
        }
        TransformResult::Continue
    }

    /// Returns true if the pipeline has any transforms configured.
    pub fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for a single transform, deserialized from `[[transforms]]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransformConfig {
    /// Append text to the system prompt in /v1/messages requests.
    SystemPrompt {
        /// Text to append (separated by `\n\n`).
        suffix: String,
    },
    /// Filter which tools the model is allowed to use.
    ToolFilter {
        /// `"allow"` to keep only listed tools, `"deny"` to remove listed tools.
        mode: ToolFilterMode,
        /// Tool names to allow or deny (e.g., `["Bash", "Write"]`).
        tools: Vec<String>,
    },
    /// Scan for prompt injection patterns in user/tool_result messages.
    InjectionScan {
        /// What to do when a pattern is detected.
        #[serde(default)]
        action: InjectionAction,
        /// Regex patterns to scan for.
        #[serde(default)]
        patterns: Vec<String>,
    },
    /// Find-and-replace text in messages and system prompts before sending to the model.
    MessageSwap {
        /// List of find/replace pairs.
        swaps: Vec<SwapRule>,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ToolFilterMode {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum InjectionAction {
    /// Log a warning but allow the request.
    #[default]
    Warn,
    /// Block the request with 403.
    Block,
}

/// Build a transform pipeline from config entries.
pub fn build_pipeline(configs: &[TransformConfig]) -> TransformPipeline {
    let mut transforms: Vec<Box<dyn RequestTransform>> = Vec::new();

    for config in configs {
        match config {
            TransformConfig::SystemPrompt { suffix } => {
                info!(len = suffix.len(), "transform: system_prompt enabled");
                transforms.push(Box::new(SystemPromptTransform::new(suffix.clone())));
            }
            TransformConfig::ToolFilter { mode, tools } => {
                info!(
                    mode = ?mode,
                    tools = ?tools,
                    "transform: tool_filter enabled"
                );
                transforms.push(Box::new(ToolFilterTransform::new(
                    mode.clone(),
                    tools.clone(),
                )));
            }
            TransformConfig::InjectionScan { action, patterns } => {
                match InjectionScanTransform::new(action.clone(), patterns.clone()) {
                    Ok(t) => {
                        info!(
                            action = ?action,
                            patterns = patterns.len(),
                            "transform: injection_scan enabled"
                        );
                        transforms.push(Box::new(t));
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to compile injection_scan patterns, skipping");
                    }
                }
            }
            TransformConfig::MessageSwap { swaps } => {
                info!(rules = swaps.len(), "transform: message_swap enabled");
                transforms.push(Box::new(MessageSwapTransform::new(swaps.clone())));
            }
        }
    }

    TransformPipeline { transforms }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_pipeline() {
        let pipeline = build_pipeline(&[]);
        assert!(pipeline.is_empty());

        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({"model": "claude-opus-4-6"}),
        };
        assert!(matches!(
            pipeline.process(&mut ctx),
            TransformResult::Continue
        ));
    }

    #[test]
    fn test_pipeline_runs_in_order() {
        // Two system_prompt transforms should both append
        let configs = vec![
            TransformConfig::SystemPrompt {
                suffix: "First.".to_string(),
            },
            TransformConfig::SystemPrompt {
                suffix: "Second.".to_string(),
            },
        ];
        let pipeline = build_pipeline(&configs);

        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({
                "model": "claude-opus-4-6",
                "system": "Base.",
                "messages": [{"role": "user", "content": "Hello"}]
            }),
        };

        assert!(matches!(
            pipeline.process(&mut ctx),
            TransformResult::Continue
        ));
        assert_eq!(ctx.body["system"], "Base.\n\nFirst.\n\nSecond.");
    }

    #[test]
    fn test_pipeline_short_circuits_on_block() {
        // injection_scan that blocks should prevent system_prompt from running
        let configs = vec![
            TransformConfig::InjectionScan {
                action: InjectionAction::Block,
                patterns: vec!["EVIL".to_string()],
            },
            TransformConfig::SystemPrompt {
                suffix: "Should not run.".to_string(),
            },
        ];
        let pipeline = build_pipeline(&configs);

        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({
                "model": "claude-opus-4-6",
                "messages": [{"role": "user", "content": "EVIL instructions"}]
            }),
        };

        match pipeline.process(&mut ctx) {
            TransformResult::Block { status, .. } => assert_eq!(status, 403),
            TransformResult::Continue => panic!("expected block"),
        }
        // system_prompt should NOT have run
        assert!(ctx.body.get("system").is_none());
    }

    #[test]
    fn test_config_deserialization() {
        let toml = r#"
[[transforms]]
type = "system_prompt"
suffix = "Be concise."

[[transforms]]
type = "tool_filter"
mode = "allow"
tools = ["Read", "Grep"]

[[transforms]]
type = "injection_scan"
action = "warn"
patterns = ["ignore previous"]

[[transforms]]
type = "message_swap"
swaps = [
    { find = "peter", replace = "peter (a cool dude)" },
]
"#;

        #[derive(Deserialize)]
        struct Wrapper {
            transforms: Vec<TransformConfig>,
        }

        let w: Wrapper = toml::from_str(toml).expect("parse TOML");
        assert_eq!(w.transforms.len(), 4);
    }
}
