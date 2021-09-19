use core::panic;

use oblong::{curve::EllipticalCurve, point::EllipticalPoint};

pub fn main() {
    let curve = EllipticalCurve::secp256k1();

    let private_key = curve.gen_private_key();

    let uncompressed_pub_key = match curve.nth_point(&private_key) {
        EllipticalPoint::Value(p) => p,
        EllipticalPoint::Identity => panic!("The identity is not useful"),
    };

    let public_key = uncompressed_pub_key.compress();
    let _pub_key_uncompressed = curve.uncompress(&public_key);
}
