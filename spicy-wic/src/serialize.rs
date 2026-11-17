// canonical encodings for hashing and transmission: arkworks compressed serialization

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::error::{Result, SpicyError};

pub fn to_bytes<T: CanonicalSerialize + ?Sized>(t: &T) -> Vec<u8> {
    let mut v = Vec::with_capacity(t.compressed_size());
    t.serialize_compressed(&mut v)
        .expect("serialization into a Vec cannot fail");
    v
}

// strict decoding: field elements below the modulus, points decompressed via the curve equation
pub fn from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    debug_assert_eq!(<ark_pallas::PallasConfig as ark_ec::CurveConfig>::COFACTOR, &[1u64]);
    debug_assert_eq!(<ark_vesta::VestaConfig as ark_ec::CurveConfig>::COFACTOR, &[1u64]);
    let mut r = bytes;
    let t = T::deserialize_compressed_unchecked(&mut r).map_err(SpicyError::from)?;
    if !r.is_empty() {
        return Err(SpicyError::Serialization("trailing bytes".into()));
    }
    Ok(t)
}
