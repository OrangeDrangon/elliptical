use num::{BigInt, Integer, One, Zero};

pub mod curve;
pub mod point;

trait EllipticalCurveOperations {
    type Output;
    fn inverse_mod(&self, modulus: &Self::Output) -> Self::Output;
    fn sqrt_mod(&self, modulus: &Self::Output) -> Self::Output;
}

impl EllipticalCurveOperations for BigInt {
    type Output = Self;
    fn inverse_mod(&self, modulus: &Self::Output) -> Self::Output {
        let gcd = self.extended_gcd(modulus);

        if gcd.gcd != 1.into() {
            panic!("No inv mod");
        }

        gcd.x.mod_floor(modulus)
    }

    /// sqrt mod as implemented here: https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/numbertheory.py#L178
    fn sqrt_mod(&self, modulus: &Self::Output) -> Self::Output {
        if self.is_zero() {
            return BigInt::zero();
        }

        if modulus == &BigInt::from(2) {
            return self.clone();
        }

        // check jacobi
        // https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/numbertheory.py#L148

        let useful = self.modpow(&((modulus + 1) / 4), modulus);

        if modulus.mod_floor(&BigInt::from(4)) == BigInt::from(3) {
            return useful;
        }

        if modulus.mod_floor(&BigInt::from(8)) == BigInt::from(5) {
            if &useful == &BigInt::one() {
                return self.modpow(&((modulus + 3) / 8), modulus);
            } else if &useful == &(modulus - BigInt::one()) {
                return (BigInt::from(2)
                    * self
                    * (self * BigInt::from(4)).modpow(&((modulus - 5) / 8), modulus))
                .mod_floor(modulus);
            }
        }

        panic!("not reached");
    }
}
