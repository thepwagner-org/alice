//! Filters the `tools` array in Anthropic Messages API requests.
//!
//! In `allow` mode, only tools whose `name` is in the list are kept.
//! In `deny` mode, tools whose `name` is in the list are removed.

use super::{LlmRequestContext, RequestTransform, ToolFilterMode, TransformResult};
use std::collections::HashSet;
use tracing::info;

pub struct ToolFilterTransform {
    mode: ToolFilterMode,
    tools: HashSet<String>,
}

impl ToolFilterTransform {
    pub fn new(mode: ToolFilterMode, tools: Vec<String>) -> Self {
        Self {
            mode,
            tools: tools.into_iter().collect(),
        }
    }
}

impl RequestTransform for ToolFilterTransform {
    fn name(&self) -> &str {
        "tool_filter"
    }

    fn transform(&self, ctx: &mut LlmRequestContext) -> TransformResult {
        let tools = match ctx.body.get_mut("tools").and_then(|v| v.as_array_mut()) {
            Some(arr) => arr,
            None => return TransformResult::Continue, // no tools array, nothing to filter
        };

        let before = tools.len();
        tools.retain(|tool| {
            let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("");
            match self.mode {
                ToolFilterMode::Allow => self.tools.contains(name),
                ToolFilterMode::Deny => !self.tools.contains(name),
            }
        });
        let after = tools.len();

        if before != after {
            info!(
                before = before,
                after = after,
                removed = before - after,
                "tool_filter: filtered tools"
            );
        }

        TransformResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(tools: &[&str]) -> LlmRequestContext {
        let tools_json: Vec<serde_json::Value> = tools
            .iter()
            .map(|name| {
                serde_json::json!({
                    "name": name,
                    "description": format!("{} tool", name),
                    "input_schema": {"type": "object"}
                })
            })
            .collect();

        LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({
                "model": "claude-opus-4-6",
                "tools": tools_json,
                "messages": [{"role": "user", "content": "Hello"}]
            }),
        }
    }

    fn tool_names(ctx: &LlmRequestContext) -> Vec<String> {
        ctx.body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn test_allow_mode() {
        let t = ToolFilterTransform::new(
            ToolFilterMode::Allow,
            vec!["Read".to_string(), "Grep".to_string()],
        );
        let mut ctx = make_ctx(&["Read", "Bash", "Grep", "Write"]);
        t.transform(&mut ctx);
        assert_eq!(tool_names(&ctx), vec!["Read", "Grep"]);
    }

    #[test]
    fn test_deny_mode() {
        let t = ToolFilterTransform::new(
            ToolFilterMode::Deny,
            vec!["Bash".to_string(), "Write".to_string()],
        );
        let mut ctx = make_ctx(&["Read", "Bash", "Grep", "Write"]);
        t.transform(&mut ctx);
        assert_eq!(tool_names(&ctx), vec!["Read", "Grep"]);
    }

    #[test]
    fn test_no_tools_array() {
        let t = ToolFilterTransform::new(ToolFilterMode::Allow, vec!["Read".to_string()]);
        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({"messages": []}),
        };
        // Should not panic or modify anything
        assert!(matches!(t.transform(&mut ctx), TransformResult::Continue));
    }
}
