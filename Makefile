.PHONY: clippy test-integration

clippy:
	cargo clippy -- -D warnings

test-integration:
	cargo test --test integration_tests