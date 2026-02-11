//! Appends a suffix to the system prompt in Anthropic Messages API requests.

use super::{LlmRequestContext, RequestTransform, TransformResult};

pub struct SystemPromptTransform {
    suffix: String,
}

impl SystemPromptTransform {
    pub fn new(suffix: String) -> Self {
        Self { suffix }
    }
}

impl RequestTransform for SystemPromptTransform {
    fn name(&self) -> &str {
        "system_prompt"
    }

    fn transform(&self, ctx: &mut LlmRequestContext) -> TransformResult {
        let obj = match ctx.body.as_object_mut() {
            Some(obj) => obj,
            None => return TransformResult::Continue,
        };

        match obj.get_mut("system") {
            Some(serde_json::Value::String(s)) => {
                s.push_str("\n\n");
                s.push_str(&self.suffix);
            }
            Some(serde_json::Value::Array(arr)) => {
                arr.push(serde_json::json!({
                    "type": "text",
                    "text": format!("\n\n{}", self.suffix),
                }));
            }
            None => {
                obj.insert(
                    "system".to_string(),
                    serde_json::Value::String(self.suffix.clone()),
                );
            }
            _ => {} // unexpected type, skip
        }

        TransformResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_system() {
        let t = SystemPromptTransform::new("Be concise.".to_string());
        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({
                "model": "claude-opus-4-6",
                "system": "You are helpful.",
                "messages": []
            }),
        };
        t.transform(&mut ctx);
        assert_eq!(ctx.body["system"], "You are helpful.\n\nBe concise.");
    }

    #[test]
    fn test_array_system() {
        let t = SystemPromptTransform::new("Be concise.".to_string());
        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({
                "system": [{"type": "text", "text": "Base."}],
                "messages": []
            }),
        };
        t.transform(&mut ctx);
        let arr = ctx.body["system"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[1]["text"], "\n\nBe concise.");
    }

    #[test]
    fn test_absent_system() {
        let t = SystemPromptTransform::new("Be concise.".to_string());
        let mut ctx = LlmRequestContext {
            host: "api.anthropic.com".to_string(),
            path: "/v1/messages".to_string(),

            body: serde_json::json!({"messages": []}),
        };
        t.transform(&mut ctx);
        assert_eq!(ctx.body["system"], "Be concise.");
    }
}
