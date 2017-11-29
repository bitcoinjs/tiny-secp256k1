#include <memory>
#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <vector>

#define EXPECT_ARGS(N) if (info.Length() != N) return Nan::ThrowTypeError("Wrong number of arguments")
#define THROW_BAD_PRIVATE Nan::ThrowTypeError("Expected Private")
#define THROW_BAD_POINT Nan::ThrowTypeError("Expected Point")
#define THROW_BAD_TWEAK Nan::ThrowTypeError("Expected Tweak")
#define THROW_BAD_HASH Nan::ThrowTypeError("Expected Hash")
#define THROW_BAD_SIGNATURE Nan::ThrowTypeError("Expected Signature")
#define RETURNV(X) info.GetReturnValue().Set(X)

secp256k1_context* secp256k1ctx;

namespace {
	v8::Local<v8::Object> asBuffer (const unsigned char* data, const size_t length) {
		return Nan::CopyBuffer(reinterpret_cast<const char*>(data), static_cast<uint32_t>(length)).ToLocalChecked();
	}

	template <typename T>
	const unsigned char* asDataPointer (const T& x) {
		return reinterpret_cast<const unsigned char*>(node::Buffer::Data(x));
	}

	template <typename T>
	bool isUInt256 (const T& x) {
		return node::Buffer::HasInstance(x) && node::Buffer::Length(x) == 32;
	}

	template <typename T>
	bool isPrivate (const T& x) {
		if (!isUInt256<T>(x)) return false;
		return secp256k1_ec_seckey_verify(secp256k1ctx, asDataPointer(x)) != 0;
	}

	template <typename T>
	bool isPoint (const T& x, secp256k1_pubkey& pubkey) {
		if (!node::Buffer::HasInstance(x)) return false;
		return secp256k1_ec_pubkey_parse(secp256k1ctx, &pubkey, asDataPointer(x), node::Buffer::Length(x)) != 0;
	}

	template <typename T>
	bool isSignature (const T& x, secp256k1_ecdsa_signature& sig) {
		if (!node::Buffer::HasInstance(x)) return false;
		if (node::Buffer::Length(x) != 64) return false;
		return secp256k1_ecdsa_signature_parse_compact(secp256k1ctx, &sig, asDataPointer(x)) != 0;
	}
}

// returns Bool
NAN_METHOD(eccIsPoint) {
	Nan::HandleScope scope;
	EXPECT_ARGS(1);

	const auto q = info[0].As<v8::Object>();

	secp256k1_pubkey result;
	return RETURNV(isPoint(q, result));
}

// returns Bool
NAN_METHOD(eccIsPrivate) {
	Nan::HandleScope scope;
	EXPECT_ARGS(1);

	const auto d = info[0].As<v8::Object>();
	return RETURNV(isPrivate(d));
}

// returns ?Point
NAN_METHOD(eccPointAdd) {
	Nan::HandleScope scope;
	EXPECT_ARGS(3);

	const auto pA = info[0].As<v8::Object>();
	const auto pB = info[0].As<v8::Object>();
	const auto flags = info[2]->BooleanValue() ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

	secp256k1_pubkey a, b;
	if (!isPoint(pA, a)) return THROW_BAD_POINT;
	if (!isPoint(pB, b)) return THROW_BAD_POINT;

	const secp256k1_pubkey* points[] = { &a, &b };
	secp256k1_pubkey p;
	if (secp256k1_ec_pubkey_combine(secp256k1ctx, &p, points, 2) == 0) return RETURNV(Nan::Null());

	unsigned char output[65];
	size_t output_length = 65;
	secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &output_length, &p, flags);

	return RETURNV(asBuffer(output, output_length));
}

// returns ?Point
NAN_METHOD(eccPointDerive) {
	Nan::HandleScope scope;
	EXPECT_ARGS(2);

	const auto d = info[0].As<v8::Object>();
	const auto flags = info[1]->BooleanValue() ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
	if (!isPrivate(d)) return THROW_BAD_PRIVATE;

	secp256k1_pubkey public_key;
	if (secp256k1_ec_pubkey_create(secp256k1ctx, &public_key, asDataPointer(d)) == 0) return RETURNV(Nan::Null());

	unsigned char output[65];
	size_t output_length = 65;
	secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &output_length, &public_key, flags);

	return RETURNV(asBuffer(output, output_length));
}

// returns ?Point
NAN_METHOD(eccPointAddScalar) {
	Nan::HandleScope scope;
	EXPECT_ARGS(3);

	const auto p = info[0].As<v8::Object>();
	const auto tweak = info[1].As<v8::Object>();
	const auto flags = info[2]->BooleanValue() ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

	secp256k1_pubkey public_key;
	if (!isPoint(p, public_key)) return THROW_BAD_POINT;
	if (!isUInt256(tweak)) return THROW_BAD_TWEAK;

	if (secp256k1_ec_pubkey_tweak_add(secp256k1ctx, &public_key, asDataPointer(tweak)) == 0) return RETURNV(Nan::Null());

	unsigned char output[65];
	size_t output_length = 65;
	secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &output_length, &public_key, flags);

	return RETURNV(asBuffer(output, output_length));
}

// returns Point
NAN_METHOD(eccPointCompress) {
	Nan::HandleScope scope;
	EXPECT_ARGS(2);

	const auto p = info[0].As<v8::Object>();
	const auto flags = info[1]->BooleanValue() ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

	secp256k1_pubkey public_key;
	if (!isPoint(p, public_key)) return THROW_BAD_POINT;

	unsigned char output[65];
	size_t output_length = 65;
	secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &output_length, &public_key, flags);

	return RETURNV(asBuffer(output, output_length));
}

// returns ?Secret
NAN_METHOD(eccPrivateAdd) {
	Nan::HandleScope scope;
	EXPECT_ARGS(2);

	const auto d = info[0].As<v8::Object>();
	const auto tweak = info[1].As<v8::Object>();
	if (!isPrivate(d)) return THROW_BAD_PRIVATE;
	if (!isUInt256(tweak)) return THROW_BAD_TWEAK;

	unsigned char output[32];
	memcpy(output, asDataPointer(d), 32);
	if (secp256k1_ec_privkey_tweak_add(secp256k1ctx, output, asDataPointer(tweak)) == 0) return RETURNV(Nan::Null());

	return RETURNV(asBuffer(output, 32));
}

// returns ?Secret
NAN_METHOD(eccPrivateSub) {
	Nan::HandleScope scope;
	EXPECT_ARGS(2);

	const auto d = info[0].As<v8::Object>();
	const auto tweak = info[1].As<v8::Object>();
	if (!isPrivate(d)) return THROW_BAD_PRIVATE;
	if (!isUInt256(tweak)) return THROW_BAD_TWEAK;

	unsigned char tweak_negated[32];
	memcpy(tweak_negated, asDataPointer(tweak), 32);
	secp256k1_ec_privkey_negate(secp256k1ctx, tweak_negated);

	unsigned char output[32];
	memcpy(output, asDataPointer(d), 32);
	if (secp256k1_ec_privkey_tweak_add(secp256k1ctx, output, tweak_negated) == 0) return RETURNV(Nan::Null());

	return RETURNV(asBuffer(output, 32));
}

// returns Signature
NAN_METHOD(ecdsaSign) {
	Nan::HandleScope scope;
	EXPECT_ARGS(2);

	const auto hash = info[0].As<v8::Object>();
	const auto d = info[1].As<v8::Object>();
	if (!isUInt256(hash)) return THROW_BAD_HASH;
	if (!isPrivate(d)) return THROW_BAD_PRIVATE;

	secp256k1_ecdsa_signature signature;
	if (secp256k1_ecdsa_sign(
		secp256k1ctx,
		&signature,
		asDataPointer(hash),
		asDataPointer(d),
		secp256k1_nonce_function_rfc6979,
		NULL
	) == 0) return THROW_BAD_SIGNATURE;

	unsigned char output[64];
	secp256k1_ecdsa_signature_serialize_compact(secp256k1ctx, output, &signature);

	return RETURNV(asBuffer(output, 64));
}

// returns Bool
NAN_METHOD(ecdsaVerify) {
	Nan::HandleScope scope;
	EXPECT_ARGS(3);

	const auto hash = info[0].As<v8::Object>();
	const auto p = info[1].As<v8::Object>();
	const auto sig = info[2].As<v8::Object>();

	secp256k1_pubkey public_key;
	secp256k1_ecdsa_signature signature;

	if (!isUInt256(hash)) return THROW_BAD_HASH;
	if (!isPoint(p, public_key)) return THROW_BAD_POINT;
	if (!isSignature(sig, signature)) return THROW_BAD_SIGNATURE;

	const auto result = secp256k1_ecdsa_verify(secp256k1ctx, &signature, asDataPointer(hash), &public_key) == 1;
	return RETURNV(result);
}

NAN_MODULE_INIT(Init) {
  secp256k1ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  // ecc
  Nan::Export(target, "isPoint", eccIsPoint);
  Nan::Export(target, "isPrivate", eccIsPrivate);
  Nan::Export(target, "pointAdd", eccPointAdd);
  Nan::Export(target, "pointAddScalar", eccPointAddScalar);
  Nan::Export(target, "pointCompress", eccPointCompress);
  Nan::Export(target, "pointDerive", eccPointDerive);
  Nan::Export(target, "privateAdd", eccPrivateAdd);
  Nan::Export(target, "privateSub", eccPrivateSub);

  // ecdsa
  Nan::Export(target, "sign", ecdsaSign);
  Nan::Export(target, "verify", ecdsaVerify);
}

NODE_MODULE(secp256k1, Init)
