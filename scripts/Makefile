all: privates points

privates: privates.cpp utils.hpp
	g++ $< -L../native/secp256k1/.libs/ -lbsd -lgmp -lsecp256k1 -o $@

points: points.cpp utils.hpp
	g++ $< -L../native/secp256k1/.libs/ -lbsd -lgmp -lsecp256k1 -o $@
