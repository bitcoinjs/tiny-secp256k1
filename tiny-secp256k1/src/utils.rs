use super::consts::{PUBLIC_KEY_COMPRESSED_SIZE, PUBLIC_KEY_UNCOMPRESSED_SIZE};

pub(crate) fn assume_compression(compressed: Option<bool>, p: Option<usize>) -> usize {
    // To allow for XOnly PubkeyRef length to indicate compressed,
    // We bitwise OR 1 (32 -> 33, while 33 and 65 stay unchanged)
    compressed.map_or_else(
        || p.map_or(PUBLIC_KEY_COMPRESSED_SIZE, |v| v | 1),
        |v| {
            if v {
                PUBLIC_KEY_COMPRESSED_SIZE
            } else {
                PUBLIC_KEY_UNCOMPRESSED_SIZE
            }
        },
    )
}

// pub(crate) unsafe fn x_only_pubkey_from_pubkey(
//     pubkey: &PubkeyRef,
// ) -> InvalidInputResult<(XOnlyPublicKey, i32)> {
//     let mut xonly_pk = XOnlyPublicKey::new();
//     let mut parity: i32 = 0;
//     let pubkey = pubkey_parse(pubkey)?;
//     x_only_pubkey_from_pubkey_struct(&mut xonly_pk, &mut parity, &pubkey);
//     Ok((xonly_pk, parity))
// }

// pub(crate) unsafe fn x_only_pubkey_from_pubkey_struct(
//     xonly_pk: &mut XOnlyPublicKey,
//     parity: &mut i32,
//     pubkey: &PublicKey,
// ) {
//     assert_eq!(
//         secp256k1_xonly_pubkey_from_pubkey(get_context(), xonly_pk, parity, pubkey),
//         1
//     );
// }

// pub(crate) unsafe fn pubkey_parse(pubkey: &PubkeyRef) -> InvalidInputResult<PublicKey> {
//     let mut pk = PublicKey::new();
//     let mut container: [u8; 33];

//     // Only use container if XOnly
//     let (input, inputlen) = match pubkey {
//         PubkeyRef::XOnly(v) => {
//             container = [0_u8; 33];
//             container[0] = 2;
//             container[1..33].copy_from_slice(&v[0..32]);
//             (container.as_ptr(), 33)
//         }
//         v => (v.as_ptr(), v.len()),
//     };
//     if secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, &mut pk, input, inputlen) == 1 {
//         Ok(pk)
//     } else {
//         Err(Error::BadPoint)
//     }
// }

// pub(crate) unsafe fn x_only_pubkey_parse(input: *const u8) -> InvalidInputResult<XOnlyPublicKey> {
//     let mut pk = XOnlyPublicKey::new();
//     if secp256k1_xonly_pubkey_parse(secp256k1_context_no_precomp, &mut pk, input) == 1 {
//         Ok(pk)
//     } else {
//         Err(Error::BadPoint)
//     }
// }

// pub(crate) unsafe fn pubkey_serialize(pk: &PublicKey, output: *mut u8, mut outputlen: usize) {
//     let flags = if outputlen == PUBLIC_KEY_COMPRESSED_SIZE {
//         SECP256K1_SER_COMPRESSED
//     } else {
//         SECP256K1_SER_UNCOMPRESSED
//     };
//     assert_eq!(
//         secp256k1_ec_pubkey_serialize(
//             secp256k1_context_no_precomp,
//             output,
//             &mut outputlen,
//             pk.as_ptr().cast::<PublicKey>(),
//             flags,
//         ),
//         1
//     );
// }

// pub(crate) unsafe fn x_only_pubkey_serialize(pk: &XOnlyPublicKey, output: *mut u8) {
//     assert_eq!(
//         secp256k1_xonly_pubkey_serialize(
//             secp256k1_context_no_precomp,
//             output,
//             pk.as_ptr().cast::<XOnlyPublicKey>(),
//         ),
//         1
//     );
// }
