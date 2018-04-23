#include <iostream>
#include <vector>
#include "utils.hpp"

template <typename A> struct IP { A a; bool e; std::string description = ""; };
template <typename A> struct PFS { uint8_t_32 a; A e; };
template <typename A> struct PA { A a; A b; A e; };
template <typename A> struct PAS { A a; uint8_t_32 b; A e; };
template <typename A> struct PC { A a; bool b; A e; };

template <typename U, typename A, typename F>
void fverify1 (const std::string& prefix, const U& x, const F f, const A& THROWSQ) {
	bool ok = true;
	const auto actual = f(x.a, ok);
	if (x.e == THROWSQ) {
		enforce(!ok, prefix + ' ' + hexify(x.a) + " should throw");
		return;
	}
	enforce(ok, prefix + ' ' + hexify(x.a) + ' ' + " should pass");
	enforce(actual == x.e, prefix + ' ' + hexify(x.a) + " should equal " + hexify(x.e) + " ... " + hexify(actual));
};

template <typename U, typename A, typename F>
void fverify2 (const std::string& prefix, const U& x, const F f, const A& THROWSQ) {
	bool ok = true;
	const auto actual = f(x.a, x.b, ok);
	if (x.e == THROWSQ) {
		enforce(!ok, prefix + ' ' + hexify(x.a) + ' ' + hexify(x.b) + " should throw");
		return;
	}
	enforce(ok, prefix + ' ' + hexify(x.a) + ' ' + hexify(x.b) + " should pass");
	enforce(actual == x.e, prefix + ' ' + hexify(x.a) + ' ' + hexify(x.b) + " should equal " + hexify(x.e) + " ... " + hexify(actual));
};

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

template <typename A>
void generate (std::ostream& o, const A G) {
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
		ip.push_back({ fromHex<A>("0179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), true, "Bad sequence prefix" });
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

	pa.push_back({ G_ONE, G_LESS_1, THROWSQ }); // == 0
	pa.push_back({ G_ONE, G_LESS_2, G_LESS_1 }); // == -1
	pa.push_back({ G_TWO, G_LESS_1, G_ONE }); // == 1
	pa.push_back({ G_ONE, G, THROWSQ });

	///////////////////////////////// pointAddScalar
	std::vector<PAS<A>> pas;

	// #L3719, -1 + 0 == -1
	pas.push_back({ G_LESS_1, ZERO, G_LESS_1 });
	pas.push_back({ G_LESS_1, GROUP_ORDER_LESS_1, G_LESS_2 });
	pas.push_back({ G_LESS_1, GROUP_ORDER_LESS_2, G_LESS_3 });
	pas.push_back({ G_LESS_1, GROUP_ORDER_LESS_2, G_LESS_3 });

	pas.push_back({ G_ONE, GROUP_ORDER_LESS_1, THROWSQ }); // == 0
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

	///////////////////////////////// pointCompress
	std::vector<PC<A>> pc;

// 	pc.push_back({ P, compress, expected });

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

	for (auto& x : ip) enforce(_isPoint(x.a) == x.e, "expected " + hexify(x.a) + " as " + (x.e ? "valid" : "invalid"));
	for (auto& x : pas) fverify2("pas", x, _pointAddScalar<A>, THROWSQ);
	for (auto& x : pfs) fverify1("pfs", x, _pointFromScalar<A>, THROWSQ);

	// dump JSON
	o << "{";
	o << "\"isPoint\": [";
	auto i = 0;
	for (auto& x : ip) {
		if (i++ > 0) o << ',';
		o << '{';
		if (!x.description.empty()) o << "\"description\": \"" << x.description << "\",";
		o << "\"point\": \"" << hexify(x.a) << "\",";
		o << "\"expected\": " << (x.e ? "true" : "false");
		o << '}';
	}
	o << "], \"pointFromScalar\": [";
	i = 0;
	for (auto& x : pfs) {
		if (i++ > 0) o << ',';
		o << '{';
		o << "\"d\": \"" << hexify(x.a) << "\",";
		o << "\"expected\": ";
		if (x.e == THROWSQ) o << "null";
		else o << "\"" << hexify(x.e) << "\"";
		o << '}';
	}
	o << "], \"pointAddScalar\": [";
	i = 0;
	for (auto& x : pas) {
		if (i++ > 0) o << ',';
		o << '{';
		o << "\"P\": \"" << hexify(x.a) << "\",";
		o << "\"d\": \"" << hexify(x.b) << "\",";
		o << "\"expected\": ";
		if (x.e == THROWSQ) o << "null";
		else o << "\"" << hexify(x.e) << "\"";
		o << '}';
	}
	o << "]}";
}

int main () {
	_ec_init();
	generate<uint8_t_33>(std::cout, GENERATORC);
// 	generate<uint8_t_65>(std::cout, GENERATOR);
	return 0;
}
