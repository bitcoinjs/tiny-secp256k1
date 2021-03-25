.PHONY: build-js
build-js: build-js-browser build-js-node

.PHONY: build-js-browser
build-js-browser:
	npx tsc --project tsconfig.browser.json && \
		rm lib.browser/addon.js && \
		rm lib.browser/index.js && mv lib.browser/index.browser.js lib.browser/index.js && \
		rm lib.browser/rand.js && mv lib.browser/rand.browser.js lib.browser/rand.js && \
		rm lib.browser/wasm_loader.js && mv lib.browser/wasm_loader.browser.js lib.browser/wasm_loader.js

.PHONY: build-js-node
build-js-node:
	npx tsc --project tsconfig.node.json && rm lib.node/*.browser.js

.PHONY: build-node-%
build-node-%: export PAIR = $(subst +, ,$(subst build-node-,,$@))
build-node-%:
	cargo build --package secp256k1-node --target $(firstword $(PAIR)) -Z build-std=panic_abort,std --release
	mkdir -p lib.node && cp -f target/$(firstword $(PAIR))/release/libsecp256k1_node.so lib.node/secp256k1-$(lastword $(PAIR)).so
	strip lib.node/secp256k1-$(lastword $(PAIR)).so

.PHONY: build-node-debug
build-node-debug:
	cargo build --package secp256k1-node

.PHONY: build-node-debug-%
build-node-debug-%: export PAIR = $(subst +, ,$(subst build-node-debug-,,$@))
build-node-debug-%:
	cargo build --package secp256k1-node --target $(firstword $(PAIR))
	mkdir -p lib.node && cp -f target/$(firstword $(PAIR))/debug/libsecp256k1_node.so lib.node/secp256k1-$(lastword $(PAIR)).so

.PHONY: build-wasm
build-wasm:
	RUSTFLAGS="-C link-args=-zstack-size=655360" cargo build --package secp256k1-wasm --target wasm32-unknown-unknown --release
	mkdir -p lib.browser && cp -f target/wasm32-unknown-unknown/release/secp256k1_wasm.wasm lib.browser/secp256k1.wasm
	wasm-opt --strip-debug --strip-producers --output lib.browser/secp256k1.wasm lib.browser/secp256k1.wasm
	node util/wasm-strip.js lib.browser/secp256k1.wasm
	wasm-opt -O4 --output lib.browser/secp256k1.wasm lib.browser/secp256k1.wasm
	mkdir -p lib.node && cp -f lib.browser/secp256k1.wasm lib.node/secp256k1.wasm

.PHONY: build-wasm-debug
build-wasm-debug:
	RUSTFLAGS="-C link-args=-zstack-size=655360" cargo build --package secp256k1-wasm --target wasm32-unknown-unknown
	mkdir -p lib.browser && cp -f target/wasm32-unknown-unknown/debug/secp256k1_wasm.wasm lib.browser/secp256k1.wasm
	mkdir -p lib.node && cp -f target/wasm32-unknown-unknown/debug/secp256k1_wasm.wasm lib.node/secp256k1.wasm

.PHONY: clean
clean:
	rm -rf \
		benches/node_modules \
		examples/random-in-node/node_modules \
		examples/react-app/dist/*.js \
		examples/react-app/dist/*.wasm \
		examples/react-app/node_modules \
		lib.browser \
		lib.node \
		node_modules \
		target \
		tests/browser \
		types

.PHONY: format
format:
	cargo-fmt
	npx eslint benches/*.{js,json} examples/**/*.{js,json} src_ts/*.ts tests/*.js util/*.js *.json *.cjs --fix
	npx sort-package-json package.json benches/package.json

.PHONY: lint
lint:
	cargo fmt -- --check
	cargo clippy --package secp256k1-node
	cargo clippy --package secp256k1-wasm --target wasm32-unknown-unknown
	npx eslint benches/*.{js,json} examples/**/*.{js,json} src_ts/*.ts tests/*.js util/*.js *.json *.cjs

.PHONY: test
test: test-browser test-node

.PHONY: test-browser-build
test-browser-build: build-js-browser build-wasm-debug
	npx webpack build -c tests/browser.webpack.js

.PHONY: test-browser
test-browser: test-browser-build
	cat tests/browser/index.js | npx browser-run --static tests/browser | npx tap-difflet -p

.PHONY: test-node
test-node: build-js-node build-node-debug build-wasm-debug
	npx babel-node -b @babel/preset-env tests/index.js | npx tap-difflet -p

.PHONY: test-node-coverage
test-node-coverage: build-js-node build-node-debug build-wasm-debug
	npx nyc npx babel-node -b @babel/preset-env tests/index.js >/dev/null
	npx nyc report --reporter=html --reporter=text
