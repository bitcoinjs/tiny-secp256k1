#include <array>
#include <cstdlib>

#define NAPI_VERSION 3
#include <napi.h>
#include <uv.h>
#include <secp256k1.h>

#define THROW_BAD_ARGUMENTS napi_throw_type_error(env, "1", "Not enough arguments")
#define THROW_BAD_PRIVATE napi_throw_type_error(env, "1", "Expected Private")
#define THROW_BAD_POINT napi_throw_type_error(env, "1", "Expected Point")
#define THROW_BAD_TWEAK napi_throw_type_error(env, "1", "Expected Tweak")
#define THROW_BAD_HASH napi_throw_type_error(env, "1", "Expected Hash")
#define THROW_BAD_SIGNATURE napi_throw_type_error(env, "1", "Expected Signature")
#define THROW_BAD_EXTRA_DATA napi_throw_type_error(env, "1", "Expected Extra Data (32 bytes)")
#define EXPECT_ARGS(N) if (info.Length() < N) THROW_BAD_ARGUMENTS

#define RETURNV(X) info.GetReturnValue().Set(X)

secp256k1_context* context;

namespace {
	napi_env env;
	
	const std::array<uint8_t, 32> ZERO = {};
	const std::array<uint8_t, 32> GROUP_ORDER = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
	};

	napi_value asBuffer (void* data, const size_t length) {
		napi_value result;
		napi_create_buffer(env, length, &data, &result);
		return result;
	}

	template <typename T>
	const unsigned char* asDataPointer (const T& x) {
		return reinterpret_cast<const unsigned char*>(x.As<Napi::Buffer<const unsigned char>>().Data());
	}

	template <typename T>
	bool isScalar (const T& x) {
		return x.IsBuffer() && x.As<Napi::Buffer<const unsigned char>>().Length() == 32;
	}

	template <typename T>
	bool isOrderScalar (const T& x) {
		if (!isScalar<T>(x)) return false;
		return memcmp(asDataPointer(x), GROUP_ORDER.data(), 32) < 0;
	}

	template <typename T>
	bool isPrivate (const T& x) {
		if (!isScalar<T>(x)) return false;
		return secp256k1_ec_seckey_verify(context, asDataPointer(x)) != 0;
	}

	template <typename T>
	bool isPoint (const T& x, secp256k1_pubkey& pubkey) {
		if (!x.IsBuffer()) return false;
		return secp256k1_ec_pubkey_parse(context, &pubkey, asDataPointer(x), x.As<Napi::Buffer<char>>().Length()) != 0;
	}

	template <typename A>
	bool __isPointCompressed (const A& x) {
		return x.As<Napi::Buffer<char>>().Length() == 33;
	}

	template <typename T>
	bool isSignature (const T& x, secp256k1_ecdsa_signature& signature) {
		if (!x.IsBuffer()) return false;
		if (x.As<Napi::Buffer<char>>().Length() != 64) return false;
		return secp256k1_ecdsa_signature_parse_compact(context, &signature, asDataPointer(x)) != 0;
	}

	napi_value pointAsBuffer (const secp256k1_pubkey& public_key, const uint32_t flags) {
		unsigned char output[65];
		size_t output_length = 65;
		secp256k1_ec_pubkey_serialize(context, output, &output_length, &public_key, flags);
		return asBuffer(output, output_length);
	}

	template <size_t index, typename I, typename A>
	unsigned int assumeCompression (const I& info, const A& p) {
		if (info.Length() <= index || info[index].IsUndefined()) {
			return __isPointCompressed(p) ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
		}
		return info[index].As<bool>() ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
	}

	template <size_t index, typename I>
	unsigned int assumeCompression (const I& info) {
		if (info.Length() <= index) return SECP256K1_EC_COMPRESSED;
		if (info[index].IsUndefined()) return SECP256K1_EC_COMPRESSED;
		return info[index].As<bool>() ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
	}
}

// returns Bool
Napi::Value eccIsPoint(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(1);

	const auto p = info[0].As<Napi::Object>();

	secp256k1_pubkey public_key;
	return RETURNV(isPoint(p, public_key));
}

// returns Bool
Napi::Value eccIsPointCompressed(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(1);

	const auto p = info[0].As<Napi::Object>();

	secp256k1_pubkey public_key;
	if (!isPoint(p, public_key)) THROW_BAD_POINT;

	return RETURNV(__isPointCompressed(p));
}

// returns Bool
Napi::Value eccIsPrivate(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(1);

	const auto d = info[0].As<Napi::Object>();
	return RETURNV(isPrivate(d));
}

// returns ?Point
Napi::Value eccPointAdd(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(2);

	const auto pA = info[0].As<Napi::Object>();
	const auto pB = info[1].As<Napi::Object>();

	secp256k1_pubkey a, b;
	if (!isPoint(pA, a)) THROW_BAD_POINT;
	if (!isPoint(pB, b)) THROW_BAD_POINT;

	const secp256k1_pubkey* points[] = { &a, &b };
	secp256k1_pubkey p;
	if (secp256k1_ec_pubkey_combine(context, &p, points, 2) == 0) return RETURNV(env.Null());

	const auto flags = assumeCompression<2>(info, pA);
	return RETURNV(pointAsBuffer(p, flags));
}

// returns ?Point
Napi::Value eccPointAddScalar(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(2);

	const auto p = info[0].As<Napi::Object>();
	const auto tweak = info[1].As<Napi::Object>();

	secp256k1_pubkey public_key;
	if (!isPoint(p, public_key)) THROW_BAD_POINT;
	if (!isOrderScalar(tweak)) THROW_BAD_TWEAK;

	if (secp256k1_ec_pubkey_tweak_add(context, &public_key, asDataPointer(tweak)) == 0) return RETURNV(env.Null());

	const auto flags = assumeCompression<2>(info, p);
	return RETURNV(pointAsBuffer(public_key, flags));
}

// returns Point
Napi::Value eccPointCompress(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(1);

	const auto p = info[0].As<Napi::Object>();

	secp256k1_pubkey public_key;
	if (!isPoint(p, public_key)) THROW_BAD_POINT;

	const auto flags = assumeCompression<1>(info, p);
	return RETURNV(pointAsBuffer(public_key, flags));
}

// returns ?Point
Napi::Value eccPointFromScalar(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(1);

	const auto d = info[0].As<Napi::Object>();
	if (!isPrivate(d)) THROW_BAD_PRIVATE;

	secp256k1_pubkey public_key;
	if (secp256k1_ec_pubkey_create(context, &public_key, asDataPointer(d)) == 0) return RETURNV(env.Null());

	const auto flags = assumeCompression<1>(info);
	return RETURNV(pointAsBuffer(public_key, flags));
}

// returns ?Point
Napi::Value eccPointMultiply(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(2);

	const auto p = info[0].As<Napi::Object>();
	const auto tweak = info[1].As<Napi::Object>();

	secp256k1_pubkey public_key;
	if (!isPoint(p, public_key)) THROW_BAD_POINT;
	if (!isOrderScalar(tweak)) THROW_BAD_TWEAK;

	if (secp256k1_ec_pubkey_tweak_mul(context, &public_key, asDataPointer(tweak)) == 0) return RETURNV(env.Null());

	const auto flags = assumeCompression<2>(info, p);
	return RETURNV(pointAsBuffer(public_key, flags));
}

// returns ?Secret
Napi::Value eccPrivateAdd(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(2);

	const auto d = info[0].As<Napi::Object>();
	const auto tweak = info[1].As<Napi::Object>();
	if (!isPrivate(d)) THROW_BAD_PRIVATE;
	if (!isOrderScalar(tweak)) THROW_BAD_TWEAK;

	unsigned char output[32];
	memcpy(output, asDataPointer(d), 32);
	if (secp256k1_ec_privkey_tweak_add(context, output, asDataPointer(tweak)) == 0) return RETURNV(env.Null());

	return RETURNV(asBuffer(output, 32));
}

// returns ?Secret
Napi::Value eccPrivateSub(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(2);

	const auto d = info[0].As<Napi::Object>();
	const auto tweak = info[1].As<Napi::Object>();
	if (!isPrivate(d)) THROW_BAD_PRIVATE;
	if (!isOrderScalar(tweak)) THROW_BAD_TWEAK;

	unsigned char tweak_negated[32];
	memcpy(tweak_negated, asDataPointer(tweak), 32);
	secp256k1_ec_privkey_negate(context, tweak_negated); // returns 1 always

	unsigned char output[32];
	memcpy(output, asDataPointer(d), 32);
	if (secp256k1_ec_privkey_tweak_add(context, output, tweak_negated) == 0) return RETURNV(env.Null());

	return RETURNV(asBuffer(output, 32));
}

// returns Signature
Napi::Value ecdsaSign(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(2);

	const auto hash = info[0].As<Napi::Object>();
	const auto d = info[1].As<Napi::Object>();
	if (!isScalar(hash)) THROW_BAD_HASH;
	if (!isPrivate(d)) THROW_BAD_PRIVATE;

	secp256k1_ecdsa_signature signature;
	if (secp256k1_ecdsa_sign(
		context,
		&signature,
		asDataPointer(hash),
		asDataPointer(d),
		secp256k1_nonce_function_rfc6979,
		nullptr
	) == 0) THROW_BAD_SIGNATURE;

	unsigned char output[64];
	secp256k1_ecdsa_signature_serialize_compact(context, output, &signature);

	return RETURNV(asBuffer(output, 64));
}

// returns Signature
Napi::Value ecdsaSignWithEntropy(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(2);

	const auto hash = info[0].As<Napi::Object>();
	const auto d = info[1].As<Napi::Object>();
	const auto addData = info[2].As<Napi::Object>();
	if (!isScalar(hash)) THROW_BAD_HASH;
	if (!isPrivate(d)) THROW_BAD_PRIVATE;
	if (!addData->IsUndefined() && !isScalar(addData)) THROW_BAD_EXTRA_DATA;

	const unsigned char* extraData;
	if (addData->IsUndefined()) {
		extraData = nullptr;
	} else {
		extraData = asDataPointer(addData);
	}

	secp256k1_ecdsa_signature signature;
	if (secp256k1_ecdsa_sign(
		context,
		&signature,
		asDataPointer(hash),
		asDataPointer(d),
		secp256k1_nonce_function_rfc6979,
		extraData
	) == 0) THROW_BAD_SIGNATURE;

	unsigned char output[64];
	secp256k1_ecdsa_signature_serialize_compact(context, output, &signature);

	return RETURNV(asBuffer(output, 64));
}

// returns Bool
Napi::Value ecdsaVerify(const Napi::CallbackInfo& info) {
	Napi::HandleScope scope(env);
	EXPECT_ARGS(3);

	const auto hash = info[0].As<Napi::Object>();
	const auto p = info[1].As<Napi::Object>();
	const auto sig = info[2].As<Napi::Object>();
	auto strict = false;
	if (info.Length() > 3 && !info[3].IsUndefined()) {
		strict = info[3].As<bool>();
	}

	secp256k1_pubkey public_key;
	secp256k1_ecdsa_signature signature;

	if (!isScalar(hash)) THROW_BAD_HASH;
	if (!isPoint(p, public_key)) THROW_BAD_POINT;
	if (!isSignature(sig, signature)) THROW_BAD_SIGNATURE;
	if (!strict) {
		const auto copy = signature;
		secp256k1_ecdsa_signature_normalize(context, &signature, &copy);
	}

	const auto result = secp256k1_ecdsa_verify(context, &signature, asDataPointer(hash), &public_key) == 1;
	return RETURNV(result);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  // ecc
  Napi::Export(target, "isPoint", eccIsPoint);
  Napi::Export(target, "isPointCompressed", eccIsPointCompressed);
  Napi::Export(target, "isPrivate", eccIsPrivate);
  Napi::Export(target, "pointAdd", eccPointAdd);
  Napi::Export(target, "pointAddScalar", eccPointAddScalar);
  Napi::Export(target, "pointCompress", eccPointCompress);
  Napi::Export(target, "pointFromScalar", eccPointFromScalar);
  Napi::Export(target, "pointMultiply", eccPointMultiply);
  Napi::Export(target, "privateAdd", eccPrivateAdd);
  Napi::Export(target, "privateSub", eccPrivateSub);

  // ecdsa
  Napi::Export(target, "sign", ecdsaSign);
  Napi::Export(target, "signWithEntropy", ecdsaSignWithEntropy);
  Napi::Export(target, "verify", ecdsaVerify);
}

NODE_API_MODULE(secp256k1, Init)
