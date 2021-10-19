all: json-privates json-points json-ecdsa

.PHONY: secp256k1
secp256k1:
	cd secp256k1 && \
	./autogen.sh && \
	./configure \
	--enable-experimental \
	--enable-module-extrakeys \
	--enable-module-schnorrsig \
	&& make

privates: secp256k1
privates: privates.cpp shared.hpp
	g++ $< -Lsecp256k1/.libs/ -lgmp -l:libsecp256k1.a -o $@

points: secp256k1
points: points.cpp shared.hpp
	g++ $< -Lsecp256k1/.libs/ -lgmp -l:libsecp256k1.a -o $@

ecdsa: secp256k1
ecdsa: ecdsa.cpp shared.hpp
	g++ $< -Lsecp256k1/.libs/ -lgmp -lcrypto -lssl -l:libsecp256k1.a -o $@

clean:
	rm -f privates points ecdsa && cd secp256k1 && make clean

json-points: points
	./points | jq . > ../../tests/fixtures/points.json

json-privates: privates
	./privates | jq . > ../../tests/fixtures/privates.json

json-ecdsa: ecdsa
	./ecdsa | jq . > ../../tests/fixtures/ecdsa.json
