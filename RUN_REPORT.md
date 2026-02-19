# Validation Report

## Commands Executed

- `cargo test --all-features`
  - Result: **failed** (`145 passed, 1 failed`)
  - Failure: `client::http::future::test::error_has_url` expected an error for `http://does.not.exist.local/ever` but received an HTTP 503 response.
- `cargo run --example <name> --all-features` for every file in `examples/`
  - Result: **partial pass**
  - Passing examples: `emulation`, `form`, `keylog`.
  - Failing examples: `cert_store`, `connect_via_lower_priority_tokio_runtime`, `http1_websocket`, `http2_websocket`, `json_dynamic`, `json_typed`, `request_with_emulation`, `request_with_interface`, `request_with_local_address`, `request_with_proxy`, `request_with_redirect`, `request_with_version`, `tor_socks`, `unix_socket`.
  - Primary failure causes: TLS certificate verification failures in this environment, missing local services/proxies, and unavailable local interfaces/UNIX sockets.
- `cargo bench --all-features`
  - Result: **started and ran**, but full benchmark sweep is very long in this environment; run was interrupted after collecting substantial `http1` measurements.

## Notes

- This report captures what was fully executed in the current environment and why some runs fail or were interrupted.
