use extism_pdk::*;

#[plugin_fn]
pub fn evaluate(_input: String) -> FnResult<String> {
    Ok("true".to_string())
}

fn main() {}
