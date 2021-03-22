.PHONY: build-js
build-js:
	npx tsc

.PHONY: build-node-%
build-node-%: export PAIR = $(subst +, ,$(subst build-node-,,$@))
build-node-%:
	cargo build --package secp256k1-node --target $(firstword $(PAIR)) -Z build-std=panic_abort,std --release
	mkdir -p lib && cp -f target/$(firstword $(PAIR))/release/libsecp256k1_node.so lib/secp256k1-$(lastword $(PAIR)).so
	strip lib/secp256k1-$(lastword $(PAIR)).so

.PHONY: build-node-debug
build-node-debug:
	cargo build --package secp256k1-node

.PHONY: build-node-debug-%
build-node-debug-%: export PAIR = $(subst +, ,$(subst build-node-debug-,,$@))
build-node-debug-%:
	cargo build --package secp256k1-node --target $(firstword $(PAIR))
	mkdir -p lib && cp -f target/$(firstword $(PAIR))/debug/libsecp256k1_node.so lib/secp256k1-$(lastword $(PAIR)).so

.PHONY: build-wasm
build-wasm:
	RUSTFLAGS="-C link-args=-zstack-size=655360" cargo build --package secp256k1-wasm --target wasm32-unknown-unknown --release
	mkdir -p lib && cp -f target/wasm32-unknown-unknown/release/secp256k1_wasm.wasm lib/secp256k1.wasm
	wasm-opt --strip-debug --strip-producers --output lib/secp256k1.wasm lib/secp256k1.wasm
	node util/wasm-strip.js lib/secp256k1.wasm
	wasm-opt -O4 --output lib/secp256k1.wasm lib/secp256k1.wasm

.PHONY: build-wasm-debug
build-wasm-debug:
	RUSTFLAGS="-C link-args=-zstack-size=655360" cargo build --package secp256k1-wasm --target wasm32-unknown-unknown
	mkdir -p lib && cp -f target/wasm32-unknown-unknown/debug/secp256k1_wasm.wasm lib/secp256k1.wasm

.PHONY: clean
clean:
	rm -rf benches/node_modules lib node_modules target tests/browser types

.PHONY: format
format:
	cargo-fmt
	npx eslint benches/*.{js,json} src_ts/*.ts tests/*.js util/*.js *.json *.cjs --fix
	npx sort-package-json package.json benches/package.json

.PHONY: lint
lint:
	cargo fmt -- --check
	cargo clippy --package secp256k1-node
	cargo clippy --package secp256k1-wasm --target wasm32-unknown-unknown
	npx eslint benches/*.{js,json} src_ts/*.ts tests/*.js util/*.js *.json *.cjs

.PHONY: test
test: test-browser test-node

.PHONY: test-browser-build
test-browser-build: build-js build-wasm-debug
	npx webpack build -c tests/browser.webpack.js

.PHONY: test-browser
test-browser: test-browser-build
	cat tests/browser/index.js | npx browser-run --static tests/browser | npx tap-difflet -p

.PHONY: test-node
test-node: build-js build-node-debug build-wasm-debug
	node --experimental-json-modules tests/index.js | npx tap-difflet -p
