.PHONY: fuzz help travis
.DEFAULT_GOAL := help

fuzz: ## Run all fuzzers
	@find fuzz/fuzzers/ -name '*.rs' -type f | \
		sed -e 's:fuzz/fuzzers/\(.*\).rs:\1:g'| \
		xargs -n 1 cargo +nightly fuzz run

help: ## Print this message and exit
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

travis: ## Run the TravisCI tests
	@cargo test && \
		cd fuzz && \
		if rustc --version | grep -q nightly; then cargo check; fi
