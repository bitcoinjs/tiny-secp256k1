all: json-privates json-points json-ecdsa

hexxer.hpp:
	curl https://raw.githubusercontent.com/dcousens/hexxer/master/hexxer.hpp > hexxer.hpp

privates: privates.cpp shared.hpp hexxer.hpp json.hpp
	g++ $< -L../native/secp256k1/.libs/ -lgmp -lsecp256k1 -o $@

points: points.cpp shared.hpp hexxer.hpp json.hpp
	g++ $< -L../native/secp256k1/.libs/ -lgmp -lsecp256k1 -o $@

ecdsa: ecdsa.cpp shared.hpp hexxer.hpp json.hpp
	g++ $< -L../native/secp256k1/.libs/ -lgmp -lcrypto -lssl -lsecp256k1 -o $@

clean:
	rm privates points ecdsa

json-points: points
	./points | jq . > ../tests/fixtures/points.json

json-privates: privates
	./privates | jq . > ../tests/fixtures/privates.json

json-ecdsa: ecdsa
	./ecdsa | jq . > ../tests/fixtures/ecdsa.json
