.PHONY: build-js
build-js:
	npx tsc

.PHONY: build-wasm
build-wasm:
	RUSTFLAGS="-C link-args=-zstack-size=655360" cargo build --target wasm32-unknown-unknown --release
	mkdir -p lib && cp -f target/wasm32-unknown-unknown/release/secp256k1_wasm.wasm lib/secp256k1.wasm
	wasm-opt -O4 --strip-debug --strip-producers --output lib/secp256k1.wasm lib/secp256k1.wasm

.PHONY: build-wasm-debug
build-wasm-debug:
	RUSTFLAGS="-C link-args=-zstack-size=655360" cargo build --target wasm32-unknown-unknown
	mkdir -p lib && cp -f target/wasm32-unknown-unknown/debug/secp256k1_wasm.wasm lib/secp256k1.wasm

.PHONY: clean
clean:
	rm -rf \
		.nyc_output \
		benches/node_modules \
		coverage \
		examples/random-in-node/node_modules \
		examples/react-app/dist/*.js \
		examples/react-app/dist/*.txt \
		examples/react-app/dist/*.wasm \
		examples/react-app/node_modules \
		lib \
		node_modules \
		target \
		tests/browser \
		types

eslint_files = benches/*.{js,json} examples/**/*.{js,json} src_ts/*.ts tests/*.js *.json *.cjs

.PHONY: format
format:
	cargo-fmt
	npx eslint $(eslint_files) --fix
	npx sort-package-json \
		package.json \
		benches/package.json \
		examples/*/package.json

.PHONY: lint
lint:
	cargo fmt -- --check
	cargo clippy --target wasm32-unknown-unknown
	npx eslint $(eslint_files)

.PHONY: test
test: test-browser test-node

.PHONY: test-browser-build-raw
test-browser-build-raw:
	npx webpack build -c tests/browser.webpack.js

.PHONY: test-browser-build
test-browser-build: build-js build-wasm-debug test-browser-build-raw

test_browser_raw = node tests/browser-run.js | npx tap-summary

.PHONY: test-browser-raw
test-browser-raw:
	$(test_browser_raw)

.PHONY: test-browser-raw-ci
test-browser-raw-ci:
	$(test_browser_raw) --no-ansi --no-progress

.PHONY: test-browser
test-browser: test-browser-build test-browser-raw

test_node_raw = npx nyc --silent node --experimental-json-modules tests/index.js | npx tap-summary

.PHONY: test-node-raw
test-node-raw:
	$(test_node_raw)

.PHONY: test-node-raw-ci
test-node-raw-ci:
	$(test_node_raw) --no-ansi --no-progress

.PHONY: test-node
test-node: build-js build-wasm-debug test-node-raw

.PHONY: test-node-coverage-raw
test-node-coverage-raw:
	npx nyc report --reporter=html --reporter=text

.PHONY: test-node-coverage
test-node-coverage: test-node test-node-coverage-raw
