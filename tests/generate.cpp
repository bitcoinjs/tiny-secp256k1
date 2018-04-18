// g++ % -L../native/secp256k1/.libs/ -lbsd -lgmp -lsecp256k1 -o tmp

#include "../native/secp256k1/include/secp256k1.h"
#include "hexxer.hpp"

#include <array>
#include <cassert>
#include <bsd/stdlib.h>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <vector>

typedef std::array<uint8_t, 32> uint8_t_32;

auto enforce (const bool e, const std::string& message) {
	if (e) return;
	std::cerr << message << std::endl;
	assert(false);
}

template <typename R>
auto hexify (const R& range) {
	std::stringstream ss;
	for (auto& x : range) {
		ss << hexxer::encodeFirst(x) << hexxer::encodeSecond(x);
	}
	return ss.str();
}

auto randomScalar () {
	uint8_t_32 x;
	arc4random_buf(x.data(), 32);
	return x;
}

auto randomScalarHigh () {
	uint8_t_32 x;
	x.fill(0xff);
	arc4random_buf(x.data(), 16);
	return x;
}

auto randomScalarLow () {
	uint8_t_32 x;
	x.fill(0);
	arc4random_buf(x.data() + 16, 16);
	return x;
}

auto scalarFromUInt32 (const uint32_t i) {
	uint8_t_32 x;
	x.fill(0);
	x[28] = i >> 24;
	x[29] = i >> 16;
	x[30] = i >> 8;
	x[31] = i & 0xff;
	return x;
}

auto scalarFromHex (const std::string& s) {
	uint8_t_32 x;
	auto i = 0;
	for (auto& y : x) {
		const auto a = s.at(i++);
		const auto b = s.at(i++);
		y = hexxer::decode(a, b);
	}
	return x;
}

secp256k1_context* ctx;

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

auto _privadd (uint8_t_32 key, const uint8_t_32 tweak, bool& ok) {
	ok = true;
	ok &= secp256k1_ec_privkey_tweak_add(ctx, key.data(), tweak.data());
	return key;
}
auto _privadd (uint8_t_32 key, const uint8_t_32 tweak) {
	bool ok;
	return _privadd(key, tweak, ok);
}

auto _privsub (uint8_t_32 key, uint8_t_32 tweak, bool& ok) {
	ok = true;
	ok &= secp256k1_ec_privkey_negate(ctx, tweak.data());
	ok &= secp256k1_ec_privkey_tweak_add(ctx, key.data(), tweak.data());
	return key;
}
auto _privsub (uint8_t_32 key, const uint8_t_32 tweak) {
	bool ok;
	return _privsub(key, tweak, ok);
}

auto _privok (const uint8_t_32& key) {
	return secp256k1_ec_seckey_verify(ctx, key.data());
}

const auto ZERO = scalarFromHex("0000000000000000000000000000000000000000000000000000000000000000");
const auto ONE = scalarFromHex("0000000000000000000000000000000000000000000000000000000000000001");
const auto TWO = scalarFromHex("0000000000000000000000000000000000000000000000000000000000000002");
const auto GROUP_ORDER_LESS_2 = scalarFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f");
const auto GROUP_ORDER_LESS_1 = scalarFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
const auto GROUP_ORDER = scalarFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const auto GROUP_ORDER_OVER_1 = scalarFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142");
const auto UINT256_MAX = scalarFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
const auto THROWS = scalarFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");

struct AE { uint8_t_32 a = {}; bool e = false; };
struct ABE { uint8_t_32 a; uint8_t_32 b; uint8_t_32 e = THROWS; };

void generatePrivates (std::ostream& o) {
	///////////////////////////////// isPrivate
	std::vector<AE> p;

	// edge cases (verify)
	//   from https://github.com/bitcoin-core/secp256k1/blob/6ad5cdb42a1a8257289a0423d644dcbdeab0f83c/src/tests.c
	p.push_back({ ZERO, false }); // #L3145, fail, == 0
	p.push_back({ ONE, true }); // #L3153, OK, > 0
	p.push_back({ GROUP_ORDER_LESS_1, true }); // #L3171, OK == G - 1
	p.push_back({ GROUP_ORDER, false }); // #L3115, fail, == G
	p.push_back({ GROUP_ORDER_OVER_1, false }); // #L3162, fail, >= G
	p.push_back({ UINT256_MAX, false }); // #L3131, fail, > G

	// fuzz
	for (size_t i = 0; i < 1000; ++i) {
		p.push_back({ randomPrivate(), true });
	}
	// fuzz (high key)
	for (size_t i = 0; i < 10000; ++i) {
		const auto key = randomScalarHigh();
		const auto verified = secp256k1_ec_seckey_verify(ctx, key.data());

		p.push_back({ key, verified });
	}

	///////////////////////////////// privateAdd
	std::vector<ABE> pa;

	// visually inspected
	for (size_t i = 0; i < 10; ++i) {
		const auto key = scalarFromUInt32(i + 1);
		const auto tweak = scalarFromUInt32(1);
		pa.push_back({ key, tweak, _privadd(key, tweak) });
	}
	for (size_t i = 0; i < 5; ++i) {
		const auto key = ONE;
		const auto tweak = scalarFromUInt32(i);
		pa.push_back({ key, tweak, _privadd(key, tweak) });
	}

	// edge cases (tweak add)
	//   from https://github.com/bitcoin-core/secp256k1/blob/6ad5cdb42a1a8257289a0423d644dcbdeab0f83c/src/tests.c
	pa.push_back({ UINT256_MAX, ZERO }); // fail, bad private
	pa.push_back({ ZERO, GROUP_ORDER }); // fail, bad private
	pa.push_back({ ZERO, GROUP_ORDER_LESS_2 }); // fail, bad private
	pa.push_back({ ONE, GROUP_ORDER_LESS_2, GROUP_ORDER_LESS_1 }); // OK, == G - 1
	pa.push_back({ ONE, GROUP_ORDER }); // #L3212, fail, == 0
	pa.push_back({ TWO, GROUP_ORDER_LESS_1 }); // fail, == 0
	pa.push_back({ TWO, GROUP_ORDER, ONE }); // #L3220, OK, > 0
	pa.push_back({ GROUP_ORDER_LESS_2, GROUP_ORDER, GROUP_ORDER_LESS_1 }); // OK, == G - 1
	pa.push_back({ GROUP_ORDER_LESS_1, GROUP_ORDER }); // #L3193, fail, == 0

	// above, but flipped parameters
	pa.push_back({ UINT256_MAX, ZERO }); // fail, bad private
	pa.push_back({ GROUP_ORDER_LESS_1, TWO }); // fail, == 0
	pa.push_back({ GROUP_ORDER_LESS_2, ZERO }); // fail, bad private
	pa.push_back({ GROUP_ORDER_LESS_2, ONE, GROUP_ORDER_LESS_1 }); // OK, == G - 1
	pa.push_back({ GROUP_ORDER, ZERO }); // fail, bad private
	pa.push_back({ GROUP_ORDER, ONE }); // #L3212, fail, == 0
	pa.push_back({ GROUP_ORDER, TWO, ONE }); // #L3220, OK, > 0
	pa.push_back({ GROUP_ORDER, GROUP_ORDER_LESS_2, GROUP_ORDER_LESS_1 }); // OK, == G - 1
	pa.push_back({ GROUP_ORDER, GROUP_ORDER_LESS_1 }); // #L3193, fail, == 0

	// fuzz
	for (size_t i = 0; i < 10000; ++i) {
		// random random
		{
			const auto key = randomPrivate();
			const auto tweak = randomPrivate();
			pa.push_back({ key, tweak, _privadd(key, tweak) });
		}

		// high low
		{
			const auto key = randomPrivateHigh();
			const auto tweak = randomPrivateLow();
			pa.push_back({ key, tweak, _privadd(key, tweak) });
		}

		// low high
		{
			const auto key = randomPrivateLow();
			const auto tweak = randomPrivateHigh();
			pa.push_back({ key, tweak, _privadd(key, tweak) });
		}
	}

	///////////////////////////////// privateAdd
	std::vector<ABE> ps;

	// visually inspected
	for (size_t i = 0; i < 10; ++i) {
		const auto key = scalarFromUInt32(i + 2);
		const auto tweak = scalarFromUInt32(1);
		ps.push_back({ key, tweak, _privsub(key, tweak) });
	}
	for (size_t i = 0; i < 5; ++i) {
		const auto key = scalarFromUInt32(10);
		const auto tweak = scalarFromUInt32(i);
		ps.push_back({ key, tweak, _privsub(key, tweak) });
	}

	// edge cases (tweak sub)
	ps.push_back({ GROUP_ORDER_LESS_1, ONE, GROUP_ORDER_LESS_2 }); // OK
	ps.push_back({ GROUP_ORDER_LESS_1, GROUP_ORDER_LESS_2, ONE }); // OK
	ps.push_back({ ZERO, ZERO }); // fail, == 0
	ps.push_back({ ZERO, ONE }); // fail, == group order
	ps.push_back({ ZERO, TWO, GROUP_ORDER_LESS_1 }); // OK
	ps.push_back({ GROUP_ORDER_LESS_1, GROUP_ORDER_LESS_1 }); // fail, == 0

	// fuzz
	for (size_t i = 0; i < 10000; ++i) {
		// random random
		{
			const auto key = randomPrivate();
			const auto tweak = randomPrivate();
			ps.push_back({ key, tweak, _privsub(key, tweak) });
		}

		// high low
		{
			const auto key = randomPrivateHigh();
			const auto tweak = randomPrivateLow();
			ps.push_back({ key, tweak, _privsub(key, tweak) });
		}

		// low high
		{
			const auto key = randomPrivateLow();
			const auto tweak = randomPrivateHigh();
			ps.push_back({ key, tweak, _privsub(key, tweak) });
		}
	}

	// (re)verify
	for (auto& x : p) enforce(_privok(x.a) == x.e, hexify(x.a) + (x.e ? " true" : " false"));
	for (auto& x : pa) {
		bool ok;
		const auto actual = _privadd(x.a, x.b, ok);
		if (x.e == THROWS) {
			enforce(!ok, hexify(x.a) + " - " + hexify(x.b) + " should throw");
			continue;
		}
		enforce(ok, hexify(x.a) + " + " + hexify(x.b) + " should pass");
		enforce(actual == x.e, hexify(x.a) + " + " + hexify(x.b) + " = " + hexify(x.e) + " ... " + hexify(actual));
	}
// 	for (auto& x : ps) {
// 		bool ok;
// 		const auto actual = _privsub(x.a, x.b, ok);
// 		if (x.e == THROWS) {
// 			enforce(!ok, hexify(x.a) + " - " + hexify(x.b) + " should throw");
// 			continue;
// 		}
// 		enforce(ok, hexify(x.a) + " - " + hexify(x.b) + " should pass");
// 		enforce(actual == x.e, hexify(x.a) + " - " + hexify(x.b) + " = " + hexify(x.e) + " ... " + hexify(actual));
// 	}

	// dump JSON
	o << "{";
	o << "\"isPrivate\": [";
	auto i = 0;
	for (auto& x : p) {
		if (i++ > 0) o << ',';
		o << '{';
		o << "\"priv\": \"" << hexify(x.a) << "\",";
		o << "\"expected\": " << (x.e ? "true" : "false");
		o << '}';
	}
	o << "], \"privateAdd\": [";
	i = 0;
	for (auto& x : pa) {
		if (i > 0) o << ',';
		o << '{';
		o << "\"priv\": \"" << hexify(x.a) << "\",";
		o << "\"tweak\": \"" << hexify(x.b) << "\",";
		o << "\"expected\": \"" << hexify(x.e) << "\",";
		o << '}';
	}
	o << "], \"privateSub\": [";
	i = 0;
	for (auto& x : ps) {
		if (i > 0) o << ',';
		o << '{';
		o << "\"priv\": \"" << hexify(x.a) << "\",";
		o << "\"tweak\": \"" << hexify(x.b) << "\",";
		o << "\"expected\": \"" << hexify(x.e) << "\",";
		o << '}';
	}
	o << "]}";
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
