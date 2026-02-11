//! Replaces text patterns in message content before sending to the model.
//!
//! Operates on all string content in the `messages` array and the `system`
//! field. Useful for expanding shorthand, injecting context about people
//! or projects, or normalizing terminology.
//!
//! Example config:
//! ```toml
//! [[transforms]]
//! type = "message_swap"
//! swaps = [
//!     { find = "peter", replace = "peter (a cool dude)" },
//!     { find = "the app", replace = "the app (codename: Alice)" },
//! ]
//! ```

use super::{LlmRequestContext, RequestTransform, TransformResult};
use tracing::debug;

/// A single find/replace pair.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SwapRule {
    /// Text to find (case-sensitive substring match).
    pub find: String,
    /// Replacement text.
    pub replace: String,
}

pub struct MessageSwapTransform {
    swaps: Vec<SwapRule>,
}

impl MessageSwapTransform {
    pub fn new(swaps: Vec<SwapRule>) -> Self {
        Self { swaps }
    }

    /// Apply all swap rules to a single string, returning the new string.
    fn apply_swaps(&self, input: &str) -> String {
        let mut result = input.to_string();
        for swap in &self.swaps {
            if result.contains(&swap.find) {
                debug!(find = %swap.find, "message_swap: applying replacement");
                result = result.replace(&swap.find, &swap.replace);
            }
        }
        result
    }

    /// Recursively walk a JSON value, applying swaps to all strings in
    /// message content and system prompts.
    fn swap_in_value(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => {
                let swapped = self.apply_swaps(s);
                if swapped != *s {
                    *s = swapped;
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.swap_in_value(item);
                }
            }
            serde_json::Value::Object(map) => {
                for (_, v) in map.iter_mut() {
                    self.swap_in_value(v);
                }
            }
            _ => {}
        }
    }
}

impl RequestTransform for MessageSwapTransform {
    fn name(&self) -> &str {
        "message_swap"
    }

    fn transform(&self, ctx: &mut LlmRequestContext) -> TransformResult {
        if self.swaps.is_empty() {
            return TransformResult::Continue;
        }

        // Apply swaps to the system prompt
        if let Some(system) = ctx.body.get_mut("system") {
            self.swap_in_value(system);
        }

        // Apply swaps to all message content
        if let Some(messages) = ctx.body.get_mut("messages") {
            self.swap_in_value(messages);
        }

        TransformResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn swap_transform(swaps: &[(&str, &str)]) -> MessageSwapTransform {
        MessageSwapTransform::new(
            swaps
                .iter()
                .map(|(f, r)| SwapRule {
                    find: f.to_string(),
                    replace: r.to_string(),
                })
                .collect(),
        )
    }

    #[test]
    fn test_swap_in_user_message() {
        let t = swap_transform(&[("peter", "peter (who is a cool dude)")]);
        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({
                "messages": [
                    {"role": "user", "content": "Ask peter about the project"}
                ]
            }),
        };
        t.transform(&mut ctx);
        assert_eq!(
            ctx.body["messages"][0]["content"],
            "Ask peter (who is a cool dude) about the project"
        );
    }

    #[test]
    fn test_swap_in_system_prompt_string() {
        let t = swap_transform(&[("the app", "the app (codename: Alice)")]);
        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({
                "system": "You are helping build the app.",
                "messages": []
            }),
        };
        t.transform(&mut ctx);
        assert_eq!(
            ctx.body["system"],
            "You are helping build the app (codename: Alice)."
        );
    }

    #[test]
    fn test_swap_in_content_blocks() {
        let t = swap_transform(&[("TODO", "TODO (high priority)")]);
        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Fix the TODO items"},
                        {"type": "text", "text": "Another TODO here"}
                    ]
                }]
            }),
        };
        t.transform(&mut ctx);
        assert_eq!(
            ctx.body["messages"][0]["content"][0]["text"],
            "Fix the TODO (high priority) items"
        );
        assert_eq!(
            ctx.body["messages"][0]["content"][1]["text"],
            "Another TODO (high priority) here"
        );
    }

    #[test]
    fn test_multiple_swaps() {
        let t = swap_transform(&[("alice", "alice (the proxy)"), ("bob", "bob (the client)")]);
        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({
                "messages": [
                    {"role": "user", "content": "alice proxies for bob"}
                ]
            }),
        };
        t.transform(&mut ctx);
        assert_eq!(
            ctx.body["messages"][0]["content"],
            "alice (the proxy) proxies for bob (the client)"
        );
    }

    #[test]
    fn test_no_match_unchanged() {
        let t = swap_transform(&[("nonexistent", "replacement")]);
        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({
                "messages": [{"role": "user", "content": "nothing to replace"}]
            }),
        };
        t.transform(&mut ctx);
        assert_eq!(ctx.body["messages"][0]["content"], "nothing to replace");
    }

    #[test]
    fn test_empty_swaps() {
        let t = swap_transform(&[]);
        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({"messages": []}),
        };
        assert!(matches!(t.transform(&mut ctx), TransformResult::Continue));
    }
}
