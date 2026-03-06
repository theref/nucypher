use extism_pdk::*;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct Context {
    #[serde(flatten)]
    values: HashMap<String, serde_json::Value>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<String> {
    let context: Context = serde_json::from_str(&input)?;
    if context.values.contains_key(":testKey") {
        Ok("true".to_string())
    } else {
        Ok("false".to_string())
    }
}

fn main() {}
