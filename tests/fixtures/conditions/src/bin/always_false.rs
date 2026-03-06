use extism_pdk::*;

#[plugin_fn]
pub fn evaluate(_input: String) -> FnResult<String> {
    Ok("false".to_string())
}

fn main() {}
