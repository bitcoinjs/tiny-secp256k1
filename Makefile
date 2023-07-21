.PHONY: build
build: install-js-deps build-all-clean

.PHONY: build-all
build-all: build-js build-wasm

.PHONY: build-all-clean
build-all-clean: clean-built build-all

.PHONY: build-js
build-js:
	npx tsc && \
	sed -i -e 's/\.\/wasm_path\.js/.\/wasm_path_cjs.js/g' ./src_ts/wasm_loader.ts && \
	npx tsc -p tsconfig-cjs.json && \
	sed -i -e 's/\.\/wasm_path_cjs\.js/.\/wasm_path.js/g' ./src_ts/wasm_loader.ts && \
	for f in ./lib/cjs/*.js; do mv -- "$$f" "$${f%.js}.cjs"; done && \
	for f in ./lib/cjs/*.cjs; do sed -i -e 's/\(require(".*\)\.js");/\1.cjs");/g' -- "$$f"; done

.PHONY: build-wasm
build-wasm:
	RUSTFLAGS="-C link-args=-zstack-size=655360" cargo build --target wasm32-unknown-unknown --release
	mkdir -p lib && cp -f target/wasm32-unknown-unknown/release/secp256k1_wasm.wasm lib/secp256k1.wasm
	wasm-opt -O4 --strip-debug --strip-producers --output lib/secp256k1.wasm lib/secp256k1.wasm

.PHONY: build-asmjs
build-asmjs: asmjs-build asmjs-fixes

.PHONY: build-asmjs-dev
build-asmjs-dev: asmjs-build-dev asmjs-fixes

.PHONY: asmjs-build
asmjs-build:
	mkdir -p tiny-secp256k1-asmjs/lib
	cp -R lib/ tiny-secp256k1-asmjs/
	wasm2js -O4 --disable-gc -n tiny-secp256k1-asmjs/lib/secp256k1.wasm --output tiny-secp256k1-asmjs/lib/secp256k1.asm.js

.PHONY: asmjs-build-dev
asmjs-build-dev:
	mkdir -p tiny-secp256k1-asmjs/lib
	cp -R lib/ tiny-secp256k1-asmjs/
	wasm2js tiny-secp256k1-asmjs/lib/secp256k1.wasm --output tiny-secp256k1-asmjs/lib/secp256k1.asm.js

.PHONY: asmjs-fixes
asmjs-fixes:
	### Remove the copied wasm file and replace all imports
	rm tiny-secp256k1-asmjs/lib/secp256k1.wasm
	for FILE in $$(grep -lR secp256k1.wasm ./tiny-secp256k1-asmjs/lib); do \
		sed -i 's/\.wasm/.asm.js/g' "$$FILE"; \
	done

	### Copy over package.json, README, LICENSE
	cp package.json tiny-secp256k1-asmjs/
	cp LICENSE tiny-secp256k1-asmjs/
	cp README.md tiny-secp256k1-asmjs/
	sed -i 's/"tiny-secp256k1"/"@bitcoin-js\/tiny-secp256k1-asmjs"/g' tiny-secp256k1-asmjs/package.json
	grep -v wasm_loader tiny-secp256k1-asmjs/package.json > tiny-secp256k1-asmjs/package.json.new
	mv tiny-secp256k1-asmjs/package.json.new tiny-secp256k1-asmjs/package.json

	### 4 places where we want to replace the name tiny-secp256k1 in the README
	sed -i 's/\(# \|install \|add \|v\/\|package\/\)tiny-secp256k1/\1@bitcoin-js\/tiny-secp256k1-asmjs/g' tiny-secp256k1-asmjs/README.md

	### Copy the asm JS to cjs folder (needs modification)
	cp tiny-secp256k1-asmjs/lib/secp256k1.asm.js tiny-secp256k1-asmjs/lib/cjs/secp256k1.asm.js
	sed -i -e 's/import \* as \(.*\) from .\.\/\(.*\)\.js.;/const \1 = require('"'"'.\/\2.cjs'"'"');/g' tiny-secp256k1-asmjs/lib/cjs/secp256k1.asm.js
	sed -i -e 's/export var /module.exports./g' tiny-secp256k1-asmjs/lib/cjs/secp256k1.asm.js
	mv tiny-secp256k1-asmjs/lib/cjs/secp256k1.asm.js tiny-secp256k1-asmjs/lib/cjs/secp256k1.asm.cjs

	### Modify imports for cjs only
	for FILE in $$(grep -lR secp256k1.asm.js ./tiny-secp256k1-asmjs/lib/cjs); do \
		sed -i 's/\.asm.js/.asm.cjs/g' "$$FILE"; \
	done

	### The NodeJS loader is not needed with ASM JS
	mv tiny-secp256k1-asmjs/lib/cjs/wasm_loader.browser.cjs tiny-secp256k1-asmjs/lib/cjs/wasm_loader.cjs
	mv tiny-secp256k1-asmjs/lib/wasm_loader.browser.js tiny-secp256k1-asmjs/lib/wasm_loader.js
	rm tiny-secp256k1-asmjs/lib/wasm_loader.browser.d.ts

.PHONY: build-wasm-debug
build-wasm-debug:
	RUSTFLAGS="-C link-args=-zstack-size=655360" cargo build --target wasm32-unknown-unknown
	mkdir -p lib && cp -f target/wasm32-unknown-unknown/debug/secp256k1_wasm.wasm lib/secp256k1.wasm

.PHONY: clean
clean: clean-deps clean-built

.PHONY: clean-deps
clean-deps:
	rm -rf \
		benches/node_modules \
		examples/random-in-node/node_modules \
		examples/react-app/node_modules \
		node_modules \
		target

.PHONY: clean-built
clean-built:
	rm -rf \
		.nyc_output \
		coverage \
		examples/react-app/dist/*.js \
		examples/react-app/dist/*.txt \
		examples/react-app/dist/*.wasm \
		lib \
		tiny-secp256k1-asmjs \
		*.tgz \
		tests/browser

eslint_files = benches/*.{js,json} examples/**/*.{js,json} src_ts/*.ts tests/*.js *.json *.cjs

.PHONY: format
format:
	cargo-fmt
	npx eslint $(eslint_files) --fix
	npx sort-package-json \
		package.json \
		benches/package.json \
		examples/*/package.json

.PHONY: install-js-deps
install-js-deps:
	npm ci

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
test-browser-build: build-js build-wasm-debug build-asmjs test-browser-build-raw

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
test-node: build-js build-wasm-debug build-asmjs test-node-raw

.PHONY: test-node-coverage-raw
test-node-coverage-raw:
	npx nyc report --reporter=html --reporter=text

.PHONY: test-node-coverage
test-node-coverage: test-node test-node-coverage-raw
