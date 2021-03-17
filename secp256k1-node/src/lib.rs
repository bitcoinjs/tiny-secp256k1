#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate napi_derive;

use napi::{
    CallContext, ContextlessResult, Env, Error as NapiError, JsArrayBufferValue, JsBoolean,
    JsFunction, JsNumber, JsObject, JsTypedArray, JsTypedArrayValue, JsUnknown, Ref,
    Result as NapiResult, Status, TypedArrayType,
};
use secp256k1::{
    c_void, pubkey_parse, pubkey_serialize, secp256k1_context_no_precomp,
    secp256k1_context_preallocated_create, secp256k1_context_preallocated_size,
    secp256k1_context_randomize, secp256k1_ec_pubkey_combine, secp256k1_ec_pubkey_create,
    secp256k1_ec_pubkey_tweak_add, secp256k1_ec_pubkey_tweak_mul, secp256k1_ec_seckey_negate,
    secp256k1_ec_seckey_tweak_add, secp256k1_ecdsa_sign, secp256k1_ecdsa_signature_normalize,
    secp256k1_ecdsa_signature_parse_compact, secp256k1_ecdsa_signature_serialize_compact,
    secp256k1_ecdsa_verify, secp256k1_nonce_function_rfc6979, Context, PublicKey, Signature,
    ERROR_BAD_SIGNATURE, SECP256K1_START_SIGN, SECP256K1_START_VERIFY, SIGNATURE_SIZE,
};
use std::{
    alloc,
    convert::TryFrom,
    sync::{Mutex, Once},
};

lazy_static! {
    static ref THROW_ERROR_FUNC: Mutex<Option<Ref<()>>> = Mutex::new(None);
    static ref GENERATE_SEED_FUNC: Mutex<Option<Ref<()>>> = Mutex::new(None);
}

macro_rules! throw_error {
    ($ctx:expr, $code:expr) => {{
        let env = $ctx.env;
        let throw_error_locked = THROW_ERROR_FUNC.lock().unwrap();
        let throw_error_ref = throw_error_locked.as_ref().expect("should be defined");
        let throw_error = env.get_reference_value::<JsFunction>(throw_error_ref)?;
        let code = env.create_uint32($code as u32)?.into_unknown();
        return match throw_error.call(None, &[code]) {
            Ok(result) => {
                let value_type = result.get_type()?;
                let reason = format!("Invalid function result: {}", value_type);
                Err(NapiError::from_reason(reason))
            }
            Err(error) if error.status == Status::PendingException => {
                Ok(env.get_undefined().unwrap().into_unknown())
            }
            Err(error) => {
                let reason = format!("Invalid function status: {}", error.status);
                Err(NapiError::from_reason(reason))
            }
        };
    }};
}

macro_rules! get_pubkey {
    ($ctx:expr, $index:expr) => {{
        let p = get_typed_array(&$ctx, $index)?;
        match unsafe { pubkey_parse(p.as_ptr(), p.len()) } {
            Ok(value) => value,
            Err(code) => {
                throw_error!($ctx, code)
            }
        }
    }};
}

fn get_typed_array(ctx: &CallContext, index: usize) -> NapiResult<JsTypedArrayValue> {
    ctx.get::<JsTypedArray>(index)?.into_value()
}

fn get_number(ctx: &CallContext, index: usize) -> NapiResult<usize> {
    Ok(ctx.get::<JsNumber>(index)?.get_uint32()? as usize)
}

fn get_output_buffer(ctx: &CallContext, index: usize) -> NapiResult<JsArrayBufferValue> {
    let outputlen = get_number(ctx, index)?;
    ctx.env.create_arraybuffer_with_data(vec![0; outputlen])
}

fn buffer2unknown(buffer: JsArrayBufferValue) -> NapiResult<JsUnknown> {
    let length = buffer.len();
    let buffer = buffer.into_raw();
    let typedarray = buffer.into_typedarray(TypedArrayType::Uint8, length, 0)?;
    Ok(typedarray.into_unknown())
}

fn get_context(env: &Env) -> *const Context {
    static mut CONTEXT: Option<*const Context> = None;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        // Create
        let flags = SECP256K1_START_SIGN | SECP256K1_START_VERIFY;
        let size = secp256k1_context_preallocated_size(flags);
        let layout = alloc::Layout::from_size_align(size, 16).unwrap();
        let ptr = alloc::alloc(layout);
        let ctx = secp256k1_context_preallocated_create(ptr as *mut c_void, flags);
        // Randomize
        let generate_seed_locked = GENERATE_SEED_FUNC.lock().unwrap();
        let generate_seed_ref = generate_seed_locked.as_ref().expect("should be defined");
        let generated_seed = env
            .get_reference_value::<JsFunction>(generate_seed_ref)
            .expect("wrong type")
            .call(None, &[])
            .expect("failed to generate seed");
        let seed = JsTypedArray::try_from(generated_seed)
            .expect("generated seed is not a TypedArray")
            .into_value()
            .expect("failed to get seed bytes");
        assert_eq!(secp256k1_context_randomize(ctx, seed.as_ptr()), 1);
        // Save
        CONTEXT = Some(ctx);
    });
    unsafe { *CONTEXT.as_ref().expect("should be initialized") }
}

#[module_exports]
fn init(mut exports: JsObject, env: Env) -> NapiResult<()> {
    let prop = exports.get_named_property::<JsFunction>("throwError")?;
    let prop_ref = env.create_reference(prop)?;
    THROW_ERROR_FUNC.lock().unwrap().replace(prop_ref);

    let prop = exports.get_named_property::<JsFunction>("generateSeed")?;
    let prop_ref = env.create_reference(prop)?;
    GENERATE_SEED_FUNC.lock().unwrap().replace(prop_ref);

    exports.create_named_method("initializeContext", initialize_context)?;
    exports.create_named_method("isPoint", is_point)?;
    exports.create_named_method("pointAdd", point_add)?;
    exports.create_named_method("pointAddScalar", point_add_scalar)?;
    exports.create_named_method("pointCompress", point_compress)?;
    exports.create_named_method("pointFromScalar", point_from_scalar)?;
    exports.create_named_method("pointMultiply", point_multiply)?;
    exports.create_named_method("privateAdd", private_add)?;
    exports.create_named_method("privateSub", private_sub)?;
    exports.create_named_method("signWithEntropy", sign_with_entropy)?;
    exports.create_named_method("verify", verify)?;

    Ok(())
}

#[contextless_function]
fn initialize_context(env: Env) -> ContextlessResult<JsUnknown> {
    get_context(&env);
    Ok(None)
}

#[js_function(1)]
fn is_point(ctx: CallContext) -> NapiResult<JsBoolean> {
    let p = get_typed_array(&ctx, 0)?;
    let is_ok = unsafe { pubkey_parse(p.as_ptr(), p.len()).is_ok() };
    ctx.env.get_boolean(is_ok)
}

#[js_function(3)]
fn point_add(ctx: CallContext) -> NapiResult<JsUnknown> {
    let pk1 = get_pubkey!(ctx, 0);
    let pk2 = get_pubkey!(ctx, 1);

    unsafe {
        let mut pk = PublicKey::new();
        let ptrs = [pk1.as_ptr(), pk2.as_ptr()];
        if secp256k1_ec_pubkey_combine(
            secp256k1_context_no_precomp,
            &mut pk,
            ptrs.as_ptr() as *const *const PublicKey,
            ptrs.len() as i32,
        ) == 1
        {
            let mut output = get_output_buffer(&ctx, 2)?;
            pubkey_serialize(&pk, output.as_mut_ptr(), output.len());
            buffer2unknown(output)
        } else {
            Ok(ctx.env.get_null()?.into_unknown())
        }
    }
}

#[js_function(3)]
fn point_add_scalar(ctx: CallContext) -> NapiResult<JsUnknown> {
    let mut pk = get_pubkey!(ctx, 0);
    let tweak = get_typed_array(&ctx, 1)?;
    unsafe {
        if secp256k1_ec_pubkey_tweak_add(
            get_context(&ctx.env),
            pk.as_mut_ptr() as *mut PublicKey,
            tweak.as_ptr(),
        ) == 1
        {
            let mut output = get_output_buffer(&ctx, 2)?;
            pubkey_serialize(&pk, output.as_mut_ptr(), output.len());
            buffer2unknown(output)
        } else {
            Ok(ctx.env.get_null()?.into_unknown())
        }
    }
}

#[js_function(2)]
fn point_compress(ctx: CallContext) -> NapiResult<JsUnknown> {
    let pk = get_pubkey!(ctx, 0);
    let mut output = get_output_buffer(&ctx, 1)?;
    unsafe {
        pubkey_serialize(&pk, output.as_mut_ptr(), output.len());
    }
    buffer2unknown(output)
}

#[js_function(2)]
fn point_from_scalar(ctx: CallContext) -> NapiResult<JsUnknown> {
    let d = get_typed_array(&ctx, 0)?;
    unsafe {
        let mut pk = PublicKey::new();
        if secp256k1_ec_pubkey_create(get_context(&ctx.env), &mut pk, d.as_ptr()) == 1 {
            let mut output = get_output_buffer(&ctx, 1)?;
            pubkey_serialize(&pk, output.as_mut_ptr(), output.len());
            buffer2unknown(output)
        } else {
            Ok(ctx.env.get_null()?.into_unknown())
        }
    }
}

#[js_function(3)]
fn point_multiply(ctx: CallContext) -> NapiResult<JsUnknown> {
    let mut pk = get_pubkey!(ctx, 0);
    let tweak = get_typed_array(&ctx, 1)?;
    unsafe {
        if secp256k1_ec_pubkey_tweak_mul(get_context(&ctx.env), &mut pk, tweak.as_ptr()) == 1 {
            let mut output = get_output_buffer(&ctx, 2)?;
            pubkey_serialize(&pk, output.as_mut_ptr(), output.len());
            buffer2unknown(output)
        } else {
            Ok(ctx.env.get_null()?.into_unknown())
        }
    }
}

#[js_function(2)]
fn private_add(ctx: CallContext) -> NapiResult<JsUnknown> {
    let d = get_typed_array(&ctx, 0)?;
    let tweak = get_typed_array(&ctx, 1)?;
    let mut d = ctx.env.create_arraybuffer_with_data(d.to_vec())?;
    unsafe {
        if secp256k1_ec_seckey_tweak_add(
            secp256k1_context_no_precomp,
            d.as_mut_ptr(),
            tweak.as_ptr(),
        ) == 1
        {
            buffer2unknown(d)
        } else {
            Ok(ctx.env.get_null()?.into_unknown())
        }
    }
}

#[js_function(2)]
fn private_sub(ctx: CallContext) -> NapiResult<JsUnknown> {
    let d = get_typed_array(&ctx, 0)?;
    let tweak = get_typed_array(&ctx, 1)?;
    let mut d = ctx.env.create_arraybuffer_with_data(d.to_vec())?;
    let mut tweak = ctx.env.create_arraybuffer_with_data(tweak.to_vec())?;
    unsafe {
        assert_eq!(
            secp256k1_ec_seckey_negate(secp256k1_context_no_precomp, tweak.as_mut_ptr()),
            1
        );
        if secp256k1_ec_seckey_tweak_add(
            secp256k1_context_no_precomp,
            d.as_mut_ptr(),
            tweak.as_ptr(),
        ) == 1
        {
            buffer2unknown(d)
        } else {
            Ok(ctx.env.get_null()?.into_unknown())
        }
    }
}

#[js_function(3)]
fn sign_with_entropy(ctx: CallContext) -> NapiResult<JsTypedArray> {
    let h = get_typed_array(&ctx, 0)?;
    let d = get_typed_array(&ctx, 1)?;
    let e = ctx.get::<JsUnknown>(2)?;

    unsafe {
        let mut sig = Signature::new();
        let noncedata = match JsTypedArray::try_from(e) {
            Ok(e) => e.into_value()?.as_ptr(),
            Err(_) => core::ptr::null(),
        } as *const c_void;

        assert_eq!(
            secp256k1_ecdsa_sign(
                get_context(&ctx.env),
                &mut sig,
                h.as_ptr(),
                d.as_ptr(),
                secp256k1_nonce_function_rfc6979,
                noncedata
            ),
            1
        );

        let data = vec![0; SIGNATURE_SIZE];
        let mut signature = ctx.env.create_arraybuffer_with_data(data)?;

        assert_eq!(
            secp256k1_ecdsa_signature_serialize_compact(
                secp256k1_context_no_precomp,
                signature.as_mut_ptr(),
                &sig,
            ),
            1
        );

        let buffer = signature.into_raw();
        buffer.into_typedarray(TypedArrayType::Uint8, SIGNATURE_SIZE, 0)
    }
}

#[js_function(4)]
fn verify(ctx: CallContext) -> NapiResult<JsUnknown> {
    let h = get_typed_array(&ctx, 0)?;
    let pk = get_pubkey!(ctx, 1);
    let signature = get_typed_array(&ctx, 2)?;
    let strict = get_number(&ctx, 3)?;

    unsafe {
        let mut sig = Signature::new();
        if secp256k1_ecdsa_signature_parse_compact(
            secp256k1_context_no_precomp,
            &mut sig,
            signature.as_ptr(),
        ) == 0
        {
            throw_error!(ctx, ERROR_BAD_SIGNATURE);
        }

        if strict == 0 {
            secp256k1_ecdsa_signature_normalize(secp256k1_context_no_precomp, &mut sig, &sig);
        }

        let retcode = secp256k1_ecdsa_verify(get_context(&ctx.env), &sig, h.as_ptr(), &pk);
        Ok(ctx.env.get_boolean(retcode == 1)?.into_unknown())
    }
}
