#include <iostream>
#include <vector>
#include "utils.hpp"

template <typename X, typename F, typename A = decltype(X::a)>
void fverify2 (const std::string& prefix, const X& x, const F f, const A& THROWSQ) {
	bool ok = true;
	const auto actual = f(x.a, x.b, ok);
	if (x.e == THROWSQ) {
		enforce(!ok, prefix + ' ' + hexify(x.a) + ' ' + hexify(x.b) + " should throw");
		return;
	}
	enforce(ok, prefix + ' ' + hexify(x.a) + ' ' + hexify(x.b) + " should pass");
	enforce(actual == x.e, prefix + ' ' + hexify(x.a) + ' ' + hexify(x.b) + " should equal " + hexify(x.e) + " ... " + hexify(actual));
};

struct dmE { uint8_t_32 d; uint8_t_32 m; uint8_t_64 rs; };

// keys and messages from bitcoinjs-lib/ecdsa test fixtures
// https://github.com/bitcoinjs/bitcoinjs-lib/blob/6b3c41a06c6e38ec79dc2f3389fa2362559b4a46/test/fixtures/ecdsa.json
const auto fkeys = std::vector<std::string>({
	"0000000000000000000000000000000000000000000000000000000000000001",
	"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
	"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
	"0000000000000000000000000000000000000000000000000000000000000001",
	"69ec59eaa1f4f2e36b639716b7c30ca86d9a5375c7b38d8918bd9c0ebc80ba64",
	"00000000000000000000000000007246174ab1e92e9149c6e446fe194d072637",
	"000000000000000000000000000000000000000000056916d0f9b31dc9b637f3",
});

const auto messages = std::vector<std::string>({
	"Everything should be made as simple as possible, but not simpler.",
	"Equations are more important to me, because politics is for the present, but an equation is something for eternity.",
	"Not only is the Universe stranger than we think, it is stranger than we can think.",
	"How wonderful that we have met with a paradox. Now we have some hope of making progress.",
	"Computer science is no more about computers than astronomy is about telescopes.",
	"...if you aren't, at any given time, scandalized by code you wrote five or even three years ago, you're not learning anywhere near enough",
	"The question of whether computers can think is like the question of whether submarines can swim.",
});

auto generateSignatures () {
	std::vector<dmE> signs;
	const auto signPush = [&](const auto d, const auto m, const auto expected) {
		bool ok = true;
		const auto signature = _eccSign(d, m, ok);
		assert(ok == expected);
		if (ok) signs.push_back({ d, m, signature });
		else signs.push_back({ d, m, THROWS64 });
	};

	size_t i = 0;
	for (const auto& message : messages) {
		const auto fkey = scalarFromHex(fkeys[i++]);
		const auto hash = sha256(message);
		signPush(fkey, hash, true);
	}

	for (const auto& message : messages) {
		signPush(randomPrivate(), sha256(message), true);
	}

	signPush(ZERO, ZERO, false);
	signPush(ZERO, UINT256_MAX, false);
	signPush(ONE, ZERO, true);
	signPush(ONE, UINT256_MAX, true);
	signPush(GROUP_ORDER_LESS_1, ZERO, true);
	signPush(GROUP_ORDER_LESS_1, UINT256_MAX, true);
	signPush(GROUP_ORDER, ZERO, false);
	signPush(GROUP_ORDER, UINT256_MAX, false);
	signPush(GROUP_ORDER_OVER_1, ZERO, false);
	signPush(GROUP_ORDER_OVER_1, UINT256_MAX, false);

	// fuzz
	for (int i = 0; i < 10000; i++) {
		signPush(randomPrivate(), randomScalar(), true);
	}

	return signs;
}

void dumpJSON (std::ostream& o, const std::vector<dmE>& signs) {
	o << jsonifyO({
		jsonp("sign", jsonifyA(signs, [](auto x) {
			return jsonifyO({
				jsonp("d", jsonify(x.d)),
				jsonp("m", jsonify(x.m)),
				jsonp("signature", jsonify(x.rs))
			});
		}))
	});
}

int main () {
	_ec_init();
	const auto signs = generateSignatures();
	dumpJSON(std::cout, signs);

	return 0;
}
