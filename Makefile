.PHONY: clippy audit audit-fix test-integration

audit:
	cargo audit

audit-fix:
	cargo audit fix

clippy:
	cargo clippy -- -D warnings

test-integration:
	cargo test --test integration_tests