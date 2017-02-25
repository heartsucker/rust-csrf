.PHONY: help build
.DEFAULT_GOAL := build

help: ## Print this help message and exit
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%8s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Compile the proto files and run cargo
	# requires `apt-get install protobuf-compiler` and `cargo install protobuf`
	@protoc proto/serial.proto --rust_out src/ && \
		cargo build && \
		cargo doc --no-deps
