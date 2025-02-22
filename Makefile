.PHONY: clippy audit audit-fix test-unit test-integration

audit:
	cargo audit

audit-fix:
	cargo audit fix

clippy:
	cargo clippy -- -D warnings

test-unit:
	cargo test --lib

test-integration:
	cargo test --test integration_tests