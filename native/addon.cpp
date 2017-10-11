#include <memory>
#include <node.h>
#include <nan.h>
#include <secp256k1.h>

#define EXPECT_ARGS(N) if (info.Length() != N) return Nan::ThrowTypeError("Wrong number of arguments")
#define THROW_PRIVATE_KEY Nan::ThrowTypeError("Expected Private Key")
#define THROW_PUBLIC_KEY Nan::ThrowTypeError("Expected Public Key")
#define THROW_BAD_TWEAK Nan::ThrowTypeError("Expected Tweak")
#define RETURNV(X) info.GetReturnValue().Set(X)

extern secp256k1_context* secp256k1ctx;

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
	bool isPrivateKey (const T& x) {
		if (!isUInt256<T>(x)) return false;
		return secp256k1_ec_seckey_verify(secp256k1ctx, asDataPointer(x)) == 1;
	}

	template <typename T>
	bool isPublicKey (const T& x, secp256k1_pubkey& pubkey) {
		if (!node::Buffer::HasInstance(x)) return false;
		return secp256k1_ec_pubkey_parse(secp256k1ctx, &pubkey, asDataPointer(x), node::Buffer::Length(x)) != 0;
	}
}

NAN_METHOD(privateKeyTweakAdd) {
	Nan::HandleScope scope;
	EXPECT_ARGS(2);

	const auto priv = info[0].As<v8::Object>();
	const auto tweak = info[1].As<v8::Object>();
	if (!isPrivateKey(priv)) return THROW_PRIVATE_KEY;
	if (!isUInt256(tweak)) return THROW_BAD_TWEAK;

	unsigned char output[32];
	memcpy(output, asDataPointer(priv), 32);
	if (secp256k1_ec_privkey_tweak_add(secp256k1ctx, output, asDataPointer(tweak)) == 0) return RETURNV(Nan::Null());

	return RETURNV(asBuffer(output, 32));
}

NAN_METHOD(privateKeyValidate) {
	Nan::HandleScope scope;
	EXPECT_ARGS(1);

	const auto priv = info[0].As<v8::Object>();
	return RETURNV(isPrivateKey(priv));
}

NAN_METHOD(publicKeyDerive) {
	Nan::HandleScope scope;
	EXPECT_ARGS(2);

	const auto priv = info[0].As<v8::Object>();
	const auto flags = info[1]->BooleanValue() ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
	if (!isPrivateKey(priv)) return THROW_PRIVATE_KEY;

	secp256k1_pubkey public_key;
	if (secp256k1_ec_pubkey_create(secp256k1ctx, &public_key, asDataPointer(priv)) == 0) return RETURNV(Nan::Null());

	unsigned char output[65];
	size_t output_length = 65;
	secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &output_length, &public_key, flags);

	return RETURNV(asBuffer(output, output_length));
}

NAN_METHOD(publicKeyReform) {
	Nan::HandleScope scope;
	EXPECT_ARGS(2);

	const auto pub = info[0].As<v8::Object>();
	const auto flags = info[1]->BooleanValue() ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

	secp256k1_pubkey public_key;
	if (!isPublicKey(pub, public_key)) return THROW_PUBLIC_KEY;

	unsigned char output[65];
	size_t output_length = 65;
	secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &output_length, &public_key, flags);

	return RETURNV(asBuffer(output, output_length));
}

NAN_METHOD(publicKeyTweakAdd) {
	Nan::HandleScope scope;
	EXPECT_ARGS(3);

	const auto pub = info[0].As<v8::Object>();
	const auto tweak = info[1].As<v8::Object>();
	const auto flags = info[2]->BooleanValue() ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

	secp256k1_pubkey public_key;
	if (!isPublicKey(pub, public_key)) return THROW_PUBLIC_KEY;
	if (!isUInt256(tweak)) return THROW_BAD_TWEAK;

	if (secp256k1_ec_pubkey_tweak_add(secp256k1ctx, &public_key, asDataPointer(tweak)) == 0) return RETURNV(Nan::Null());

	unsigned char output[65];
	size_t output_length = 65;
	secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &output_length, &public_key, flags);

	return RETURNV(asBuffer(output, output_length));
}

NAN_METHOD(publicKeyValidate) {
	Nan::HandleScope scope;
	EXPECT_ARGS(1);

	const auto pub = info[0].As<v8::Object>();

	secp256k1_pubkey public_key;
	return RETURNV(isPublicKey(pub, public_key));
}
