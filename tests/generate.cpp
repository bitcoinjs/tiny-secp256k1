// g++ % -L../native/secp256k1/.libs/ -lbsd -lgmp -lsecp256k1 -o tmp

#include "../native/secp256k1/include/secp256k1.h"

#include <array>
#include <bsd/stdlib.h>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <fstream>

typedef std::array<uint8_t, 32> uint8_t_32;
secp256k1_context* ctx;

template <typename R>
auto hexify (const R& range) {
	std::stringstream ss;

	ss << std::hex;
	for (size_t i = 0; i < range.size(); ++i) {
		ss << std::setw(2) << std::setfill('0') << (uint32_t) range.at(i);
	}

	return ss.str();
}

auto randomScalar () {
	uint8_t_32 s;
	arc4random_buf(s.data(), sizeof(s));
	return s;
}

auto randomScalarHigh () {
	uint8_t_32 s;
	s.fill(0xff);
	arc4random_buf(s.data(), 16);
	return s;
}

auto randomScalarLow () {
	uint8_t_32 s;
	s.fill(0);
	arc4random_buf(s.data() + 16, 16);
	return s;
}

auto scalarFromUInt32 (const uint32_t i) {
	uint8_t_32 s;
	s.fill(0);
	s[28] = i >> 24;
	s[29] = i >> 16;
	s[30] = i >> 8;
	s[31] = i & 0xff;
	return s;
}

auto randomPrivate () {
	while (true) {
		const auto key = randomScalar();
		if (secp256k1_ec_seckey_verify(ctx, key.data())) return key;
	}
}

auto randomPrivateHigh () {
	while (true) {
		const auto key = randomScalarHigh();
		if (secp256k1_ec_seckey_verify(ctx, key.data())) return key;
	}
}

auto randomPrivateLow () {
	while (true) {
		const auto key = randomScalarLow();
		if (secp256k1_ec_seckey_verify(ctx, key.data())) return key;
	}
}

auto privadd (uint8_t_32 key, const uint8_t_32 tweak) {
	assert(secp256k1_ec_privkey_tweak_add(ctx, key.data(), tweak.data()));
	return hexify(key);
}

auto privsub (uint8_t_32 key, uint8_t_32 tweak) {
	assert(secp256k1_ec_privkey_negate(ctx, tweak.data()));
	assert(secp256k1_ec_privkey_tweak_add(ctx, key.data(), tweak.data()));
	return hexify(key);
}

void dumpKey (std::ostream& o, const std::string k, const bool ok) {
	o << '{';
	o << "\"key\": \"" << k << "\"," << std::endl;
	o << "\"ok\": " << (ok ? "true" : "false") << std::endl;
	o << "},";
}

void dumpKTR (std::ostream& o, const std::string k, const std::string tweak, const std::string result = "") {
	o << '{';
	o << "\"key\": \"" << k << "\"," << std::endl;
	o << "\"tweak\": \"" << tweak << "\"" << std::endl;
	if (!result.empty()) {
		o << ", \"result\": \"" << result << "\"" << std::endl;
	}
	o << "},";
}

void generatePrivates (std::ostream& o) {
	o << "{";

	// edge cases (verify)
	//   from https://github.com/bitcoin-core/secp256k1/blob/6ad5cdb42a1a8257289a0423d644dcbdeab0f83c/src/tests.c
	o << "\"verify\": [";
	dumpKey(o, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0); // #L3115, fail, == group order
	dumpKey(o, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0); // #L3131, fail, > group order
	dumpKey(o, "0000000000000000000000000000000000000000000000000000000000000000", 0); // #L3145, fail, == 0
	dumpKey(o, "0000000000000000000000000000000000000000000000000000000000000001", 1); // #L3153, OK
	dumpKey(o, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142", 0); // #L3162, fail, >= group order
	dumpKey(o, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", 1); // #L3171, OK (-1)

	// fuzz
	for (size_t i = 0; i < 1000; ++i) {
		const auto key = randomPrivate();
		dumpKey(o, hexify(key), true);
	}

	// fuzz (high key)
	for (size_t i = 0; i < 10000; ++i) {
		const auto key = randomScalarHigh();
		const auto ok = secp256k1_ec_seckey_verify(ctx, key.data());

		dumpKey(o, hexify(key), ok);
	}

	o << " null],";
	o << "\"tweakAdd\": [";

	// visual range
	for (size_t i = 0; i < 10; ++i) {
		const auto key = scalarFromUInt32(i + 1);
		const auto tweak = scalarFromUInt32(1);
		dumpKTR(o, hexify(key), hexify(tweak), privadd(key, tweak));
	}

	// edge cases (tweak add)
	//   from https://github.com/bitcoin-core/secp256k1/blob/6ad5cdb42a1a8257289a0423d644dcbdeab0f83c/src/tests.c
	dumpKTR(o, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139", "0000000000000000000000000000000000000000000000000000000000000001",
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"); // custom, OK

	dumpKTR(o, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "0000000000000000000000000000000000000000000000000000000000000001"); // custom, fail == group order
	dumpKTR(o, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0000000000000000000000000000000000000000000000000000000000000001"); // custom, fail, > group order
	dumpKTR(o, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "0000000000000000000000000000000000000000000000000000000000000000",
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"); // #L3180, OK, unchanged

	dumpKTR(o, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"); // #L3193, fail, ?
	dumpKTR(o, "0000000000000000000000000000000000000000000000000000000000000000", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"); // custom, fail, == group order
	dumpKTR(o, "0000000000000000000000000000000000000000000000000000000000000001", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"); // #L3212, fail, == 0
	dumpKTR(o, "0000000000000000000000000000000000000000000000000000000000000002", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
			"0000000000000000000000000000000000000000000000000000000000000001"); // #L3220, OK

	// fuzz
	for (size_t i = 0; i < 10000; ++i) {
		// random random
		{
			const auto key = randomPrivate();
			const auto tweak = randomPrivate();
			dumpKTR(o, hexify(key), hexify(tweak), privadd(key, tweak));
		}

		// high low
		{
			const auto key = randomPrivateHigh();
			const auto tweak = randomPrivateLow();
			dumpKTR(o, hexify(key), hexify(tweak), privadd(key, tweak));
		}

		// low high
		{
			const auto key = randomPrivateLow();
			const auto tweak = randomPrivateHigh();
			dumpKTR(o, hexify(key), hexify(tweak), privadd(key, tweak));
		}
	}

	o << " null],";
	o << "\"tweakSub\": [";

	// visual range
	for (size_t i = 0; i < 10; ++i) {
		const auto key = scalarFromUInt32(i + 2);
		const auto tweak = scalarFromUInt32(1);
		dumpKTR(o, hexify(key), hexify(tweak), privsub(key, tweak));
	}

	// edge cases (tweak sub)
	dumpKTR(o, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "0000000000000000000000000000000000000000000000000000000000000001",
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139"); // custom, OK
	dumpKTR(o, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139",
			"0000000000000000000000000000000000000000000000000000000000000001"); // custom, OK
	dumpKTR(o, "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"); // custom, fail, == 0
	dumpKTR(o, "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000001"); // custom, fail, == group order
	dumpKTR(o, "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000002",
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"); // custom, OK
	dumpKTR(o, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"); // custom, fail, == 0

	// fuzz
	for (size_t i = 0; i < 10000; ++i) {
		// random random
		{
			const auto key = randomPrivate();
			const auto tweak = randomPrivate();
			dumpKTR(o, hexify(key), hexify(tweak), privsub(key, tweak));
		}

		// high low
		{
			const auto key = randomPrivateHigh();
			const auto tweak = randomPrivateLow();
			dumpKTR(o, hexify(key), hexify(tweak), privsub(key, tweak));
		}

		// low high
		{
			const auto key = randomPrivateLow();
			const auto tweak = randomPrivateHigh();
			dumpKTR(o, hexify(key), hexify(tweak), privsub(key, tweak));
		}
	}

	o << " null]";
	o << "}";
}

void generatePoints () {}
void generateSignatures () {}

int main () {
// 	std::ofstream points ("fixtures/points.txt");
// 	std::ofstream keys ("fixtures/privates.txt");
// 	std::ofstream sigs ("fixtures/signatures.txt");

// 	generatePoints();
	generatePrivates(std::cout);
// 	generateSignatures();

	return 0;
}
