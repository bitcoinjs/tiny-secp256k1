build-wasm-cp = cp -f target/wasm32-unknown-unknown/$(1)/tiny_secp256k1_wasm.wasm lib/secp256k1.wasm

build-wasm:
	cargo build --target wasm32-unknown-unknown --release
	$(call build-wasm-cp,release)
	wasm-opt -O4 --output lib/secp256k1.wasm lib/secp256k1.wasm

build-wasm-debug:
	cargo build --target wasm32-unknown-unknown
	$(call build-wasm-cp,debug)

format:
	cargo-fmt
	npx prettier -w . 

lint:
	cargo fmt -- --check
	cargo clippy
	npx prettier -c .

test:
	npx tape tests/index.js | npx tap-difflet -p
