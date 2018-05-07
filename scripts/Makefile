all: privates points ecdsa

privates: privates.cpp shared.hpp
	g++ $< -L../native/secp256k1/.libs/ -lgmp -lsecp256k1 -o $@

points: points.cpp shared.hpp
	g++ $< -L../native/secp256k1/.libs/ -lgmp -lsecp256k1 -o $@

ecdsa: ecdsa.cpp shared.hpp
	g++ $< -L../native/secp256k1/.libs/ -lgmp -lcrypto -lssl -lsecp256k1 -o $@

clean:
	rm privates points ecdsa

json: all
	./privates | jq . > ../tests/fixtures/privates.json
	./points | jq . > ../tests/fixtures/points.json
	./ecdsa | jq . > ../tests/fixtures/ecdsa.json
