build-wasm-location = lib/secp256k1.wasm
build-wasm-cp = mkdir -p lib && cp -f target/wasm32-unknown-unknown/$(1)/secp256k1_wasm.wasm $(build-wasm-location)

build-wasm:
	cargo build --target wasm32-unknown-unknown --release
	$(call build-wasm-cp,release)
	wasm-opt --strip-debug --strip-producers --output $(build-wasm-location) $(build-wasm-location)
	node ./util/wasm-strip.js $(build-wasm-location)
	wasm-opt -O4 --output $(build-wasm-location) $(build-wasm-location)

build-wasm-debug:
	cargo build --target wasm32-unknown-unknown
	$(call build-wasm-cp,debug)

clean:
	rm -rf target node_modules tests/browser

format:
	cargo-fmt
	npx prettier -w . 

lint:
	cargo fmt -- --check
	cargo clippy --target wasm32-unknown-unknown
	npx prettier -c .

test: test-browser test-node

test-browser-build:
	npx webpack build -c tests/browser.webpack.js

test-browser: build-wasm-debug test-browser-build
	cat tests/browser/index.js | npx browser-run --static tests/browser | npx tap-difflet -p

test-node: build-wasm-debug
	node --experimental-json-modules tests/index.js | npx tap-difflet -p
