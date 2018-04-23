#include <iostream>
#include <vector>
#include "utils.hpp"

struct AE { uint8_t_32 a = {}; bool e = false; };
struct ABE { uint8_t_32 a; uint8_t_32 b; uint8_t_32 e = THROWS; };

template <typename F>
void fverify (const char sign, const ABE& x, const F f) {
	bool ok = true;
	const auto actual = f(x.a, x.b, ok);
	if (x.e == THROWS) {
		enforce(!ok, hexify(x.a) + ' ' + sign + ' ' + hexify(x.b) + " should throw");
		return;
	}
	enforce(ok, hexify(x.a) + ' ' + sign + ' ' + hexify(x.b) + " should pass");
	enforce(actual == x.e, hexify(x.a) + ' ' + sign + ' ' + hexify(x.b) + " should equal " + hexify(x.e) + " ... " + hexify(actual));
};

void generate (std::ostream& o) {
	///////////////////////////////// isPrivate
	std::vector<AE> ip;

	// edge cases (verify)
	//   from https://github.com/bitcoin-core/secp256k1/blob/6ad5cdb42a1a8257289a0423d644dcbdeab0f83c/src/tests.c
	ip.push_back({ ZERO, false }); // #L3145, fail, == 0
	ip.push_back({ ONE, true }); // #L3153, OK, > 0
	ip.push_back({ GROUP_ORDER_LESS_1, true }); // #L3171, OK == G - 1
	ip.push_back({ GROUP_ORDER, false }); // #L3115, fail, == G
	ip.push_back({ GROUP_ORDER_OVER_1, false }); // #L3162, fail, >= G
	ip.push_back({ UINT256_MAX, false }); // #L3131, fail, > G

	// fuzz
	for (size_t i = 0; i < 1000; ++i) {
		ip.push_back({ randomPrivate(), true });
	}
	// fuzz (high key)
	for (size_t i = 0; i < 10000; ++i) {
		const auto key = randomScalarHigh();
		const auto verified = secp256k1_ec_seckey_verify(ctx, key.data());

		ip.push_back({ key, verified });
	}

	///////////////////////////////// privateAdd
	std::vector<ABE> pa;
	const auto paPush = [&](const auto k, const auto t) {
		bool ok = true;
		const auto expected = _privAdd(k, t, ok);
		if (ok) pa.push_back({ k, t, expected });
		else pa.push_back({ k, t, THROWS });
	};

	pa.push_back({ ONE, GROUP_ORDER, THROWS }); // bad tweak

	// visually inspected
	//   covers https://github.com/bitcoin-core/secp256k1/blob/6ad5cdb42a1a8257289a0423d644dcbdeab0f83c/src/tests.c
	for (size_t i = 0; i < 5; ++i) pa.push_back({ ONE, scalarFromUInt32(i), scalarFromUInt32(1 + i) });
	for (size_t i = 0; i < 5; ++i) paPush(GROUP_ORDER_LESS_3, scalarFromUInt32(i));
	for (size_t i = 0; i < 5; ++i) pa.push_back({ scalarFromUInt32(i), TWO, scalarFromUInt32(i + 2) });
	for (size_t i = 1; i < 5; ++i) paPush(scalarFromUInt32(i), GROUP_ORDER_LESS_2);
	pa.push_back({ GROUP_ORDER_LESS_1, GROUP_ORDER_LESS_1, GROUP_ORDER_LESS_2 });
	pa.push_back({ GROUP_ORDER_LESS_2, GROUP_ORDER_LESS_1, GROUP_ORDER_LESS_3 });

	// fuzz
	for (size_t i = 0; i < 10000; ++i) {
		paPush(randomPrivate(), randomPrivate());
		paPush(randomPrivateHigh(), randomPrivateLow());
		paPush(randomPrivateLow(), randomPrivateHigh());
	}

	///////////////////////////////// privateSub
	std::vector<ABE> ps;
	const auto psPush = [&](const auto k, const auto t) {
		bool ok = true;
		const auto expected = _privSub(k, t, ok);
		if (ok) ps.push_back({ k, t, expected });
		else ps.push_back({ k, t, THROWS });
	};

	// visually inspected
	for (size_t i = 0; i < 5; ++i) psPush(ONE, scalarFromUInt32(i));
	for (size_t i = 0; i < 5; ++i) psPush(GROUP_ORDER_LESS_3, scalarFromUInt32(i));
	for (size_t i = 0; i < 3; ++i) psPush(scalarFromUInt32(i), ONE);
	for (size_t i = 2; i < 5; ++i) ps.push_back({ scalarFromUInt32(i), ONE, scalarFromUInt32(i - 1) });
	for (size_t i = 1; i < 5; ++i) psPush(scalarFromUInt32(i), GROUP_ORDER_LESS_2);
	// fuzz
	for (size_t i = 0; i < 10000; ++i) {
		psPush(randomPrivate(), randomPrivate());
		psPush(randomPrivateHigh(), randomPrivateLow());
		psPush(randomPrivateLow(), randomPrivateHigh());
	}

	// (re)verify
	for (auto& x : ip) enforce(_isPriv(x.a) == x.e, hexify(x.a) + (x.e ? " true" : " false"));
	for (auto& x : pa) fverify('+', x, _privAdd);
	for (auto& x : ps) fverify('-', x, _privSub);

	// dump JSON
	o << "{";
	o << "\"isPrivate\": [";
	auto i = 0;
	for (auto& x : ip) {
		if (i++ > 0) o << ',';
		o << '{';
		o << "\"priv\": \"" << hexify(x.a) << "\",";
		o << "\"expected\": " << (x.e ? "true" : "false");
		o << '}';
	}
	o << "], \"privateAdd\": [";
	i = 0;
	for (auto& x : pa) {
		if (i++ > 0) o << ',';
		o << '{';
		o << "\"priv\": \"" << hexify(x.a) << "\",";
		o << "\"tweak\": \"" << hexify(x.b) << "\",";
		o << "\"expected\": ";
		if (x.e == THROWS) o << "null";
		else o << "\"" << hexify(x.e) << "\"";
		o << '}';
	}
	o << "], \"privateSub\": [";
	i = 0;
	for (auto& x : ps) {
		if (i++ > 0) o << ',';
		o << '{';
		o << "\"priv\": \"" << hexify(x.a) << "\",";
		o << "\"tweak\": \"" << hexify(x.b) << "\",";
		o << "\"expected\": ";
		if (x.e == THROWS) o << "null";
		else o << "\"" << hexify(x.e) << "\"";
		o << '}';
	}
	o << "]}";
}

int main () {
	_ec_init();
	generate(std::cout);
	return 0;
}
