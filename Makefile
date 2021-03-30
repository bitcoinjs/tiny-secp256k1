.PHONY: build-js
build-js:
	npx tsc

.PHONY: build-addon-%
build-addon-%: export PAIR = $(subst +, ,$(subst build-addon-,,$@))
build-addon-%:
	$(if $(findstring musl,$(firstword $(PAIR))),RUSTFLAGS="-C target-feature=-crt-static",) cargo build \
		--package secp256k1-node \
		--target $(firstword $(PAIR)) \
		$(if $(findstring musl,$(firstword $(PAIR))),,-Z build-std=panic_abort,std) \
		--release
	mkdir -p lib && cp -f target/$(firstword $(PAIR))/release/`node util/addon-target-name.js` lib/secp256k1-$(lastword $(PAIR))
	strip $(if $(findstring Darwin,$(shell uname -s)),-Sx,--strip-all) lib/secp256k1-$(lastword $(PAIR))

.PHONY: build-addon-debug
build-addon-debug:
	cargo build --package secp256k1-node

.PHONY: build-addon-debug-%
build-addon-debug-%: export PAIR = $(subst +, ,$(subst build-addon-debug-,,$@))
build-addon-debug-%:
	cargo build --package secp256k1-node --target $(firstword $(PAIR))
	mkdir -p lib && cp -f target/$(firstword $(PAIR))/debug/`node util/addon-target-name.js` lib/secp256k1-$(lastword $(PAIR))

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
	rm -rf \
		.nyc_output \
		benches/node_modules \
		coverage \
		examples/random-in-node/node_modules \
		examples/react-app/dist/*.js \
		examples/react-app/dist/*.wasm \
		examples/react-app/node_modules \
		lib \
		node_modules \
		target \
		tests/browser \
		types

eslint_files = benches/*.{js,json} examples/**/*.{js,json} src_ts/*.ts tests/*.js util/*.js *.json *.cjs

.PHONY: format
format:
	cargo-fmt
	npx eslint $(eslint_files) --fix
	npx sort-package-json \
		package.json \
		benches/package.json \
		examples/random-in-node/package.json \
		examples/react-app/package.json

.PHONY: lint
lint:
	cargo fmt -- --check
	cargo clippy --package secp256k1-node
	cargo clippy --package secp256k1-wasm --target wasm32-unknown-unknown
	npx eslint $(eslint_files)

.PHONY: test
test: test-browser test-node

.PHONY: test-browser-build-raw
test-browser-build-raw:
	npx webpack build -c tests/browser.webpack.js

.PHONY: test-browser-build
test-browser-build: build-js build-wasm-debug test-browser-build-raw

test_browser_raw = cat tests/browser/index.js | npx browser-run --static tests/browser | npx tap-summary

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
test-node: build-js build-addon-debug build-wasm-debug test-node-raw

.PHONY: test-node-coverage-raw
test-node-coverage-raw:
	npx nyc report --reporter=html --reporter=text

.PHONY: test-node-coverage
test-node-coverage: test-node test-node-coverage-raw
