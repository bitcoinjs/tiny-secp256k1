#include <iostream>
#include <vector>
#include "utils.hpp"

#include <tuple>

struct S { uint8_t_32 d; uint8_t_32 m; uint8_t_64 e; std::string desc; };
struct BS { uint8_t_32 d; uint8_t_32 m; std::string except; std::string desc; };
struct BV { uint8_t_33 Q; uint8_t_32 m; uint8_t_64 s; std::string except; std::string desc; };

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
	bool ok = true;
	std::vector<S> s;

	size_t i = 0;
	for (const auto& message : messages) {
		const auto fkey = scalarFromHex(fkeys[i++]);
		const auto hash = sha256(message);
		const auto sig = _eccSign(fkey, hash, ok);
		s.push_back({ fkey, hash, sig, message });
	}

	for (const auto& message : messages) {
		const auto rkey = randomPrivate();
		const auto hash = sha256(message);
		const auto sig = _eccSign(rkey, hash, ok);
		s.push_back({ rkey, hash, sig, message });
	}

	s.push_back({ ONE, ZERO, _eccSign(ONE, ZERO, ok), "Strange hash" });
	s.push_back({ ONE, UINT256_MAX, _eccSign(ONE, UINT256_MAX, ok), "Strange hash" });
	s.push_back({ GROUP_ORDER_LESS_1, ZERO, _eccSign(GROUP_ORDER_LESS_1, ZERO, ok), "Stange hash" });
	s.push_back({ GROUP_ORDER_LESS_1, UINT256_MAX, _eccSign(GROUP_ORDER_LESS_1, UINT256_MAX, ok), "Strange hash" });

	// fuzz
	for (int i = 0; i < 10000; i++) {
		const auto rkey = randomPrivate();
		const auto hash = randomScalar();
		const auto sig = _eccSign(rkey, hash, ok);
		s.push_back({ rkey, hash, sig, "" });
	}

	assert(ok);
	return s;
}

auto generateBadSignatures () {
	std::vector<BS> bs;
	bs.push_back({ ZERO, ZERO, "Expected Private", "Private key == 0" });
	bs.push_back({ ZERO, UINT256_MAX, "Expected Private", "Private key == 0" });
	bs.push_back({ GROUP_ORDER, ZERO, "Expected Private", "Private key >= G" });
	bs.push_back({ GROUP_ORDER, UINT256_MAX, "Expected Private", "Private key >= G" });
	bs.push_back({ GROUP_ORDER_OVER_1, ZERO, "Expected Private", "Private key >= G" });
	bs.push_back({ GROUP_ORDER_OVER_1, UINT256_MAX, "Expected Private", "Private key >= G" });
	bs.push_back({ UINT256_MAX, ZERO, "Expected Private", "Private key >= G" });
	bs.push_back({ UINT256_MAX, UINT256_MAX, "Expected Private", "Private key >= G" });
	return bs;
}

template <typename A>
auto generateBadVerify () {
	bool ok = true;
	const auto G_ONE = _pointFromUInt32<A>(1, ok);
	assert(ok);

	std::vector<BV> bv;
	bv.push_back({ fromUInt32<A>(0), THREE, _signatureFromRS(ZERO, ZERO), "Expected Point", "Invalid Point" });
	bv.push_back({ G_ONE, THREE, _signatureFromRS(ZERO, ZERO), "Expected Signature", "Invalid r, s values (== 0)" });
	bv.push_back({ G_ONE, THREE, _signatureFromRS(ZERO, ONE), "Expected Signature", "Invalid r value (== 0)" });
	bv.push_back({ G_ONE, THREE, _signatureFromRS(ONE, ZERO), "Expected Signature", "Invalid s value (== 0)" });
	bv.push_back({ G_ONE, THREE, _signatureFromRS(GROUP_ORDER, ONE), "Expected Signature", "Invalid r value (>= n)" });
	bv.push_back({ G_ONE, THREE, _signatureFromRS(ONE, GROUP_ORDER), "Expected Signature", "Invalid s value (>= n)" });
	return bv;
}

template <typename T>
void dumpJSON (std::ostream& o, const T& t) {
	o << jsonifyO({
		jsonp("valid", jsonifyA(std::get<0>(t), [&](auto x) {
			std::vector<std::string> kvs = {
				jsonp("d", jsonify(x.d)),
				jsonp("m", jsonify(x.m)),
				jsonp("signature", jsonify(x.e))
			};
			if (!x.desc.empty()) kvs.push_back(jsonp("description", jsonify(x.desc)));
			return jsonifyO(kvs);
		})),
		jsonp("invalid", jsonifyO({
			jsonp("sign", jsonifyA(std::get<1>(t), [&](auto x) {
				std::vector<std::string> kvs = {
					jsonp("exception", jsonify(x.except)),
					jsonp("d", jsonify(x.d)),
					jsonp("m", jsonify(x.m))
				};
				if (!x.desc.empty()) kvs.push_back(jsonp("description", jsonify(x.desc)));
				return jsonifyO(kvs);
			})),
			jsonp("verify", jsonifyA(std::get<2>(t), [&](auto x) {
				std::vector<std::string> kvs = {
					jsonp("exception", jsonify(x.except)),
					jsonp("Q", jsonify(x.Q)),
					jsonp("m", jsonify(x.m)),
					jsonp("signature", jsonify(x.s))
				};
				if (!x.desc.empty()) kvs.push_back(jsonp("description", jsonify(x.desc)));
				return jsonifyO(kvs);
			}))
		}))
	});
}

int main () {
	_ec_init();
	const auto s = generateSignatures();
	const auto bs = generateBadSignatures();
	const auto bv = generateBadVerify<uint8_t_33>();

	dumpJSON(std::cout, std::make_tuple(s, bs, bv));

	return 0;
}
