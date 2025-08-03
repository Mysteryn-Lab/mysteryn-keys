mod classic;
pub mod default_key_factory;
mod post_quantum;

pub use classic::*;
pub use default_key_factory::*;
pub use post_quantum::*;

#[cfg(all(test, target_family = "wasm", target_os = "unknown"))]
mod tests {
    use wasm_bindgen_test;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
}
