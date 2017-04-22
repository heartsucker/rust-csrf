.PHONY: help travis
.DEFAULT_GOAL := help

help: ## Print this message and exit
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

travis: ## Run the TravisCI tests
	@{ cargo build --verbose && \
		cargo test --verbose || \
		{ cat Cargo.lock; exit 1; }; \
		} && \
		if rustc --version | grep -q nightly; then cargo bench; fi
