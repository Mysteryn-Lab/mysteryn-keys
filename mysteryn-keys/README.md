# Mysteryn-keys

This crate provides a collection of digital signature keys for the `mysteryn-crypto` crate.

See the [`mysteryn-crypto` Readme](https://github.com/Mysteryn-Lab/mysteryn-crypto/blob/master/README.md) for the full description.

## Tests

Run tests:

```bash
cargo test --all-features
```

Testing with the `WasmEdge` or `wasmtime` (see `.cargo/config.toml runner`):

```bash
cargo test --all-features --target wasm32-wasip2 -- --nocapture
```

Testing in a browser with the `wasm-pack`:

```bash
wasm-pack test --chrome --all-features
```

> Install`wasm-pack` version which does not require your "Cargo.toml" to have `crate-type = ["cdylib", "rlib"]`.
>
> ```bash
> cargo install --git https://github.com/druide/wasm-pack.git
> ```

Testing in a browser with the `wasm-bindgen-test-runner`:

```bash
NO_HEADLESS=1 cargo test --all-features --target wasm32-unknown-unknown -- --nocapture

# Windows version
set NO_HEADLESS=1 && cargo test --all-features --target wasm32-unknown-unknown -- --nocapture
```

## Benchmarks

```bash
cargo bench --all-features -- --test --test-threads=1 -q bench
```

or

```bash
cargo b
```

## License

Licensed under the [Ethical Use License v1.0](./LICENSE.md).
