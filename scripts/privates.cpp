#include <iostream>
#include <vector>
#include "utils.hpp"

struct IP { uint8_t_32 a = {}; bool e = false; };
struct PA { uint8_t_32 a; uint8_t_32 b; uint8_t_32 e = THROWS; };

void generate (std::ostream& o) {
	///////////////////////////////// isPrivate
	std::vector<IP> ip;

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
	std::vector<PA> pa;
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

	// dump JSON
	o << jsonifyO({
		jsonp("isPrivate", jsonifyA(ip, [](auto x) {
			return jsonifyO({
				jsonp("priv", jsonify(x.a)),
				jsonp("expected", jsonify(x.e))
			});
		})),
		jsonp("privateAdd", jsonifyA(pa, [](auto x) {
			return jsonifyO({
				jsonp("priv", jsonify(x.a)),
				jsonp("tweak", jsonify(x.b)),
				jsonp("expected", x.e == THROWS ? "null" : jsonify(x.e))
			});
		}))
	});
}

int main () {
	_ec_init();
	generate(std::cout);

	return 0;
}
