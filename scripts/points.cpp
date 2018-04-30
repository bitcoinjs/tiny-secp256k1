#include <iostream>
#include <tuple>
#include <vector>

#include "utils.hpp"

template <typename A> struct IP { A a; bool e; std::string desc = ""; };
template <typename A> struct PFS { uint8_t_32 a; A e; };
template <typename A> struct PA { A a; A b; A e; };
template <typename A> struct PAS { A a; uint8_t_32 b; A e; };
struct PC { uint8_t_vec a; bool b; uint8_t_vec e; };

// ref https://github.com/bitcoin-core/secp256k1/blob/6ad5cdb42a1a8257289a0423d644dcbdeab0f83c/src/tests.c#L2160
//   iteratively verifies that (d + ...)G == (dG + ...G)
template <typename A>
void test_ec_combine (std::vector<PA<A>>& pa, std::vector<PAS<A>>& pas, std::vector<PFS<A>>& pfs) {
	bool ok = true;
	auto sum = ONE;
	auto sumQ = _pointFromScalar<A>(sum, ok);
	assert(ok);

	for (int i = 1; i <= 10; i++) {
		const auto d = randomPrivate();
		const auto Q = _pointFromScalar<A>(d, ok);
		assert(ok);

		// dG + ...G
		const auto P = _pointAdd<A>(sumQ, Q, ok);
		assert(ok);

		// (d + ...)G
		const auto U = _pointAddScalar<A>(sumQ, d, ok);
		assert(ok);
		assert(P == U);

		// (d + ...)G
		sum = _privAdd(sum, d, ok);
		assert(ok);

		const auto R = _pointFromScalar<A>(sum, ok);
		assert(ok);
		assert(P == R);

		pa.push_back({ sumQ, Q, P });
		pas.push_back({ sumQ, d, P });
		pfs.push_back({ sum, P });

		sumQ = P;
	}
}

auto generatePC () {
	std::vector<PC> pc;
	pc.push_back({ vectorify(GENERATOR), true, vectorify(GENERATORC) });
	pc.push_back({ vectorify(GENERATOR), false, vectorify(GENERATOR) });
	pc.push_back({ vectorify(GENERATORC), true, vectorify(GENERATORC) });
	pc.push_back({ vectorify(GENERATORC), false, vectorify(GENERATOR) });
	pc.push_back({ uint8_t_vec(33, 0), false, {} });
	pc.push_back({ uint8_t_vec(33, 0), true, {} });
	pc.push_back({ uint8_t_vec(65, 0), false, {} });
	pc.push_back({ uint8_t_vec(65, 0), true, {} });

	bool ok = true;
	for (auto i = 1; i < 10; ++i) {
		const auto iic = vectorify(_pointFromUInt32<uint8_t_33>(i, ok));
		const auto ii = vectorify(_pointFromUInt32<uint8_t_65>(i, ok));
		assert(ok);

		pc.push_back({ iic, true, iic });
		pc.push_back({ iic, false, ii });
		pc.push_back({ ii, true, iic });
		pc.push_back({ ii, false, ii });
	}

	return pc;
}

template <typename A>
auto generate (const A G) {
	bool ok = true;
	const auto G_LESS_1 = _pointFromScalar<A>(GROUP_ORDER_LESS_1, ok);
	const auto G_LESS_2 = _pointFromScalar<A>(GROUP_ORDER_LESS_2, ok);
	const auto G_LESS_3 = _pointFromScalar<A>(GROUP_ORDER_LESS_3, ok);
	const auto G_ONE = _pointFromUInt32<A>(1, ok);
	const auto G_TWO = _pointFromUInt32<A>(2, ok);
	const auto G_THREE = _pointFromUInt32<A>(3, ok);
	auto THROWSQ = A();
	THROWSQ.fill(0xff);
	assert(ok);

	///////////////////////////////// isPoint
	std::vector<IP<A>> ip;
	ip.push_back({ G, true });
	ip.push_back({ A{0x2}, false });
	ip.push_back({ A{0x3}, false });
	ip.push_back({ A{0x4}, false });
	ip.push_back({ G_ONE, true });
	ip.push_back({ G_TWO, true });
	ip.push_back({ G_THREE, true });

	// from https://github.com/cryptocoinjs/ecurve/blob/14d72f5f468d53ff33dc13c1c7af350a41d52aab/test/fixtures/point.json#L84
	if (sizeof(A) == 65) {
		ip.push_back({ fromHex<A>("0579be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10ab2e"), false, "Bad sequence prefix" });
	} else {
		ip.push_back({ fromHex<A>("0179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), false, "Bad sequence prefix" });
	}

	for (size_t i = 0; i < 100; ++i) {
		ip.push_back({ _pointFromScalar<A>(randomPrivate(), ok), true });
		assert(ok);
	}

	///////////////////////////////// pointAdd
	std::vector<PA<A>> pa;
	pa.push_back({ G_LESS_1, G_LESS_1, G_LESS_2 });
	pa.push_back({ G_LESS_1, G_LESS_2, G_LESS_3 });
	pa.push_back({ G_LESS_1, G_LESS_2, G_LESS_3 });

	// https://github.com/bitcoin-core/secp256k1/blob/452d8e4d2a2f9f1b5be6b02e18f1ba102e5ca0b4/src/tests.c#L3857
	pa.push_back({ G_ONE, G_LESS_1, THROWSQ }); // == 0/infinity
	pa.push_back({ G_ONE, G_LESS_2, G_LESS_1 }); // == -1
	pa.push_back({ G_TWO, G_LESS_1, G_ONE }); // == 1
	pa.push_back({ G_ONE, G, THROWSQ });

	for (size_t i = 0; i < 100; ++i) {
		const auto a = _pointFromScalar<A>(randomPrivate(), ok);
		const auto b = _pointFromScalar<A>(randomPrivate(), ok);
		const auto e = _pointAdd(a, b, ok);
		assert(ok);
		pa.push_back({ a, b, e });
	}

	///////////////////////////////// pointAddScalar
	std::vector<PAS<A>> pas;

	// #L3719, -1 + 0 == -1
	pas.push_back({ G_LESS_1, ZERO, G_LESS_1 });
	pas.push_back({ G_LESS_1, GROUP_ORDER_LESS_1, G_LESS_2 });
	pas.push_back({ G_LESS_1, GROUP_ORDER_LESS_2, G_LESS_3 });
	pas.push_back({ G_LESS_1, GROUP_ORDER_LESS_2, G_LESS_3 });

	pas.push_back({ G_ONE, GROUP_ORDER_LESS_1, THROWSQ }); // == 0/infinity
	pas.push_back({ G_ONE, GROUP_ORDER_LESS_2, G_LESS_1 }); // == -1
	pas.push_back({ G_TWO, GROUP_ORDER_LESS_1, G_ONE }); // == 1
	pas.push_back({ G_ONE, GROUP_ORDER, THROWSQ });
	pas.push_back({ G_ONE, GROUP_ORDER_OVER_1, THROWSQ });

	for (uint32_t i = 1; i < 5; ++i) {
		bool ok;
		const auto G_i = _pointFromUInt32<A>(i, ok); assert(ok);
		const auto G_i_p1 = _pointFromUInt32<A>(i + 1, ok); assert(ok);

		pas.push_back({ G_i, ONE, G_i_p1 });
	}

	///////////////////////////////// pointFromScalar
	std::vector<PFS<A>> pfs;
	const auto pfsPush = [&](const auto s, const auto expected) {
		bool ok = true;
		const auto actual = _pointFromScalar<A>(s, ok);
		assert(ok == expected);
		if (ok) pfs.push_back({ s, actual });
		else pfs.push_back({ s, THROWSQ });
	};

	pfsPush(ZERO, false); // #L3145, #L3684, fail, == 0
	pfsPush(ONE, true); // #L3153, #L3692, OK, > 0
	pfsPush(GROUP_ORDER_LESS_1, true); // #L3171, #L3710, OK == G - 1
	pfsPush(GROUP_ORDER, false); // #L3115, #L3670, fail, == G
	pfsPush(GROUP_ORDER_OVER_1, false); // #L3162, #L3701, fail, >= G
	pfsPush(UINT256_MAX, false); // #L3131, #L3676, fail, > G

	// ref https://github.com/bitcoin-core/secp256k1/blob/6ad5cdb42a1a8257289a0423d644dcbdeab0f83c/src/tests.c#L2160
	test_ec_combine<A>(pa, pas, pfs);

	return std::make_tuple(ip, pa, pas, pfs, THROWSQ);
}

template <typename T>
auto jdE (const T& throws) {
	return [=](auto x) {
		return jsonifyO({
			jsonp("d", jsonify(x.a)),
			jsonp("expected", x.e == throws ? "null" : jsonify(x.e))
		});
	};
}

template <typename T>
auto jPDE (const T& throws) {
	return [=](auto x) {
		return jsonifyO({
			jsonp("P", jsonify(x.a)),
			jsonp("d", jsonify(x.b)),
			jsonp("expected", x.e == throws ? "null" : jsonify(x.e))
		});
	};
}

template <typename A, typename B>
void dumpJSON (
	std::ostream& o,
	const A& compressed,
	const B& uncompressed,
	const std::vector<PC>& pc
) {
	const auto jPE = [](auto x) {
		std::vector<std::string> kvs = {
			jsonp("point", jsonify(x.a)),
			jsonp("expected", jsonify(x.e))
		};
		if (!x.desc.empty()) kvs.push_back(jsonp("description", jsonify(x.desc)));
		return jsonifyO(kvs);
	};
	const auto cthrows = std::get<4>(compressed);
	const auto uthrows = std::get<4>(uncompressed);

	o << jsonifyO({
		jsonp("isPoint", jsonifyA({
			jsonify_csv(std::get<0>(compressed), jPE),
			jsonify_csv(std::get<0>(uncompressed), jPE)
		})),
		jsonp("pointAdd", jsonifyA({
			jsonify_csv(std::get<1>(compressed), jPDE(cthrows)),
			jsonify_csv(std::get<1>(uncompressed), jPDE(uthrows))
		})),
		jsonp("pointAddScalar", jsonifyA({
			jsonify_csv(std::get<2>(compressed), jPDE(cthrows)),
			jsonify_csv(std::get<2>(uncompressed), jPDE(uthrows))
		})),
		jsonp("pointFromScalar", jsonifyA({
			jsonify_csv(std::get<3>(compressed), jdE(cthrows)),
			jsonify_csv(std::get<3>(uncompressed), jdE(uthrows))
		})),
		jsonp("pointCompress", jsonifyA(pc, [](auto x) {
			return jsonifyO({
				jsonp("P", jsonify(x.a)),
				jsonp("compress", jsonify(x.b)),
				jsonp("expected", x.e.empty() ? "null" : jsonify(x.e))
			});
		}))
	});
}

int main () {
	_ec_init();

	const auto c = generate<uint8_t_33>(GENERATORC);
	const auto u = generate<uint8_t_65>(GENERATOR);
	const auto t = generatePC();
	dumpJSON(std::cout, c, u, t);

	return 0;
}
