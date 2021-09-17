use num::bigint::Sign;
use num::{BigInt, BigUint, Integer, One, Zero};

trait EllipticalCurveOperations {
    type Output;
    fn elliptical_mod(&self, n: &Self::Output) -> Self::Output;
    fn elliptical_inverse_mod(&self, n: &Self::Output) -> Self::Output;
}

impl EllipticalCurveOperations for BigInt {
    type Output = Self;
    fn elliptical_mod(&self, n: &Self::Output) -> Self::Output {
        let mut r = self % n;

        if r < BigInt::zero() {
            r += n;
        }

        r
    }

    fn elliptical_inverse_mod(&self, n: &Self::Output) -> Self::Output {
        let gcd = self.extended_gcd(n);

        if gcd.gcd != 1.into() {
            panic!("No inv mod");
        }

        gcd.x.elliptical_mod(n)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EllipticalPoint {
    Identity,
    Value(EllipticalPointValue),
}

impl EllipticalPoint {
    pub fn with_value(x: BigInt, y: BigInt) -> Self {
        Self::Value(EllipticalPointValue::new(x, y))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EllipticalPointValue {
    x: BigInt,
    y: BigInt,
}

impl EllipticalPointValue {
    pub fn new(x: BigInt, y: BigInt) -> Self {
        Self { x, y }
    }

    pub fn x(&self) -> &BigInt {
        &self.x
    }
    pub fn y(&self) -> &BigInt {
        &self.y
    }
}

/// A struct to represent an elliptic curve given the form `y^2 = x^3 + ax + b`.
#[derive(Debug, Clone, PartialEq)]
pub struct EllipticalCurveParameters {
    a: BigInt,
    b: BigInt,
    p: BigInt,
}

impl EllipticalCurveParameters {
    pub fn generic(a: BigInt, b: BigInt, p: BigInt) -> Self {
        Self { a, b, p }
    }

    pub fn scep256k1() -> Self {
        Self::generic(
            BigInt::zero(),
            BigInt::new(Sign::Plus, vec![7]),
            BigInt::parse_bytes(
                b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
                16,
            )
            .unwrap(),
        )
    }

    // Inclusive bounds for the order of all elliptic curves with a given `p`
    pub fn order_bounds(&self) -> (BigInt, BigInt) {
        let start = self.p() + BigInt::one();
        let end = BigInt::from(2) * self.p().sqrt();
        let lower = &start - &end;
        let upper = &start + &end;

        (lower, upper)
    }

    pub fn j_invariant(&self) -> BigInt {
        let four_a_cubed = BigInt::from(4) * self.a().pow(3);
        let twenty_seven_b_squared = BigInt::from(27) * self.p().pow(2);

        BigInt::from(-1728) * (&four_a_cubed / (&four_a_cubed + &twenty_seven_b_squared))
    }

    pub fn a(&self) -> &BigInt {
        &self.a
    }
    pub fn b(&self) -> &BigInt {
        &self.b
    }
    pub fn p(&self) -> &BigInt {
        &self.p
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EllipticalCurve {
    params: EllipticalCurveParameters,
    generator: EllipticalPoint,
    order: BigInt,
}

impl EllipticalCurve {
    pub fn generic_with_order(
        params: EllipticalCurveParameters,
        generator: EllipticalPointValue,
        order: BigInt,
    ) -> Self {
        let s = Self {
            params,
            generator: EllipticalPoint::Value(generator),
            order,
        };

        assert!(s.contains_point(s.generator()));

        let (lower, upper) = s.params().order_bounds();
        assert!(s.order() >= &lower && s.order() <= &upper);

        s
    }

    pub fn generic(params: EllipticalCurveParameters, generator: EllipticalPointValue) -> Self {
        let (lower, _) = params.order_bounds();

        Self::generic_with_order(params, generator, lower)
    }

    pub fn secp256k1() -> Self {
        let params = EllipticalCurveParameters::scep256k1();

        let generator = EllipticalPointValue::new(
            BigInt::parse_bytes(
                b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                16,
            )
            .unwrap(),
            BigInt::parse_bytes(
                b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
                16,
            )
            .unwrap(),
        );

        let order = BigInt::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .unwrap();

        EllipticalCurve::generic_with_order(params, generator, order)
    }

    pub fn contains_point(&self, point: &EllipticalPoint) -> bool {
        match point {
            EllipticalPoint::Identity => true,
            EllipticalPoint::Value(p) => {
                let calculated_y = p.x().pow(3) + self.params().a() * p.x() + self.params().b();
                let y_squared = p.y().pow(2);

                (calculated_y - y_squared).elliptical_mod(self.params().p()) == BigInt::zero()
            }
        }
    }

    pub fn nth_point(&self, n: &BigUint) -> EllipticalPoint {
        self.multiply_unsigned(self.generator(), n)
    }

    pub fn double(&self, point: &EllipticalPoint) -> EllipticalPoint {
        assert!(self.contains_point(point));

        match point {
            EllipticalPoint::Identity => EllipticalPoint::Identity,
            EllipticalPoint::Value(p) => {
                let lambda = self.get_double_lambda(p);

                self.summed_point_from_lambda(p, p, Some(lambda))
            }
        }
    }

    pub fn add_points(&self, first: &EllipticalPoint, second: &EllipticalPoint) -> EllipticalPoint {
        assert!(self.contains_point(first));
        assert!(self.contains_point(second));

        match (first, second) {
            (EllipticalPoint::Identity, EllipticalPoint::Identity) => EllipticalPoint::Identity,
            (EllipticalPoint::Identity, EllipticalPoint::Value(p))
            | (EllipticalPoint::Value(p), EllipticalPoint::Identity) => {
                EllipticalPoint::with_value(p.x().clone(), p.y().clone())
            }
            (EllipticalPoint::Value(p), EllipticalPoint::Value(q)) => {
                let lambda = if p == q {
                    // Same x and y
                    Some(self.get_double_lambda(p))
                } else if p.x() != q.x() {
                    // Different x
                    let numerator = q.y() - p.y();
                    Some(numerator * (q.x() - p.x()).elliptical_inverse_mod(self.params().p()))
                } else {
                    None
                };

                self.summed_point_from_lambda(p, q, lambda)
            }
        }
    }

    pub fn multiply_unsigned(
        &self,
        point: &EllipticalPoint,
        unsigned: &BigUint,
    ) -> EllipticalPoint {
        assert!(self.contains_point(point));

        if unsigned.is_zero() {
            return EllipticalPoint::Identity;
        }

        let mut result = point.clone();
        let mut running_adder = point.clone();

        let new_unsigned = unsigned - BigUint::one();

        for bit in new_unsigned.to_radix_le(2) {
            assert!(bit < 2);

            if bit == 1 {
                result = self.add_points(&result, &running_adder);
            }

            running_adder = self.double(&running_adder);
        }

        result.clone()
    }

    pub fn params(&self) -> &EllipticalCurveParameters {
        &self.params
    }

    pub fn generator(&self) -> &EllipticalPoint {
        &self.generator
    }

    pub fn order(&self) -> &BigInt {
        &self.order
    }

    fn get_double_lambda(&self, point: &EllipticalPointValue) -> BigInt {
        let numerator = BigInt::from(3) * point.x().pow(2) + self.params().a();
        numerator * (BigInt::from(2) * point.y()).elliptical_inverse_mod(self.params().p())
    }

    fn summed_point_from_lambda(
        &self,
        p: &EllipticalPointValue,
        q: &EllipticalPointValue,
        lambda: Option<BigInt>,
    ) -> EllipticalPoint {
        match lambda {
            None => EllipticalPoint::Identity,
            Some(lambda) => {
                let r_x = (lambda.pow(2) - p.x() - q.x()).elliptical_mod(self.params().p());
                let r_y = (lambda * (p.x() - &r_x) - p.y()).elliptical_mod(self.params().p());

                EllipticalPoint::with_value(r_x, r_y)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_0_7_37() -> EllipticalCurve {
        let params =
            EllipticalCurveParameters::generic(BigInt::from(0), BigInt::from(7), BigInt::from(37));

        let generator = EllipticalPointValue::new(BigInt::from(6), BigInt::from(1));

        EllipticalCurve::generic(params, generator)
    }

    fn test_25_15_15661() -> EllipticalCurve {
        let params = EllipticalCurveParameters::generic(
            BigInt::from(25),
            BigInt::from(15),
            BigInt::from(15661),
        );

        let generator = EllipticalPointValue::new(BigInt::from(21), BigInt::from(99));

        EllipticalCurve::generic(params, generator)
    }

    #[test]
    fn test_point_doubling_identity_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::Identity;

        let expected = EllipticalPoint::Identity;
        let result = curve.double(&p);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_doubling_6_1_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(6), BigInt::from(1));

        let expected = EllipticalPoint::with_value(BigInt::from(18), BigInt::from(17));
        let result = curve.double(&p);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_doubling_9_12_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(9), BigInt::from(12));

        let expected = EllipticalPoint::with_value(BigInt::from(3), BigInt::from(21));
        let result = curve.double(&p);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_doubling_add_6_1_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(6), BigInt::from(1));
        let q = EllipticalPoint::with_value(BigInt::from(6), BigInt::from(1));

        let expected = EllipticalPoint::with_value(BigInt::from(18), BigInt::from(17));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_doubling_add_9_12_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(9), BigInt::from(12));
        let q = EllipticalPoint::with_value(BigInt::from(9), BigInt::from(12));

        let expected = EllipticalPoint::with_value(BigInt::from(3), BigInt::from(21));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_add_identity_plus_identity_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::Identity;
        let q = EllipticalPoint::Identity;

        let expected = EllipticalPoint::Identity;
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_add_6_1_plus_identity_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(6), BigInt::from(1));
        let q = EllipticalPoint::Identity;

        let expected = EllipticalPoint::with_value(BigInt::from(6), BigInt::from(1));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_add_identity_plus_22_6_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::Identity;
        let q = EllipticalPoint::with_value(BigInt::from(22), BigInt::from(6));

        let expected = EllipticalPoint::with_value(BigInt::from(22), BigInt::from(6));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_add_4_2_plus_4_16_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(4), BigInt::from(21));
        let q = EllipticalPoint::with_value(BigInt::from(4), BigInt::from(16));

        let expected = EllipticalPoint::Identity;
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_add_6_1_plus_22_6_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(6), BigInt::from(1));
        let q = EllipticalPoint::with_value(BigInt::from(22), BigInt::from(6));

        let expected = EllipticalPoint::with_value(BigInt::from(13), BigInt::from(13));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_add_9_12_plus_32_17_curve_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(9), BigInt::from(12));
        let q = EllipticalPoint::with_value(BigInt::from(32), BigInt::from(17));

        let expected = EllipticalPoint::with_value(BigInt::from(5), BigInt::from(13));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_multiply_9_12_times_1_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(9), BigInt::from(12));

        let expected = EllipticalPoint::with_value(BigInt::from(9), BigInt::from(12));
        let result = curve.multiply_unsigned(&p, &BigUint::one());

        assert_eq!(expected, result)
    }

    #[test]
    fn test_multiply_9_12_times_2_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(9), BigInt::from(12));

        let expected = EllipticalPoint::with_value(BigInt::from(3), BigInt::from(21));
        let result = curve.multiply_unsigned(&p, &BigUint::from(2usize));

        assert_eq!(expected, result)
    }

    #[test]
    fn test_multiply_23_1_times_123_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(23), BigInt::from(1));

        let expected = EllipticalPoint::with_value(BigInt::from(24), BigInt::from(17));
        let result = curve.multiply_unsigned(&p, &BigUint::from(123usize));

        assert_eq!(expected, result)
    }

    #[test]
    fn test_multiply_23_1_times_34435322_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(23), BigInt::from(1));

        let expected = EllipticalPoint::with_value(BigInt::from(23), BigInt::from(36));
        let result = curve.multiply_unsigned(&p, &BigUint::from(34435322usize));

        assert_eq!(expected, result)
    }

    #[test]
    fn test_multiply_23_1_times_0_0_7_37() {
        let curve = test_0_7_37();

        let p = EllipticalPoint::with_value(BigInt::from(23), BigInt::from(1));

        let expected = EllipticalPoint::Identity;
        let result = curve.multiply_unsigned(&p, &BigUint::zero());

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_doubling_identity_curve_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::Identity;

        let expected = EllipticalPoint::Identity;
        let result = curve.double(&p);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_doubling_233_33_curve_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::with_value(BigInt::from(233), BigInt::from(33));

        let expected = EllipticalPoint::with_value(BigInt::from(7817), BigInt::from(4209));
        let result = curve.double(&p);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_doubling_add_6_1_curve_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::with_value(BigInt::from(233), BigInt::from(33));
        let q = EllipticalPoint::with_value(BigInt::from(233), BigInt::from(33));

        let expected = EllipticalPoint::with_value(BigInt::from(7817), BigInt::from(4209));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_add_identity_plus_identity_curve_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::Identity;
        let q = EllipticalPoint::Identity;

        let expected = EllipticalPoint::Identity;
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_add_94_54_plus_identity_curve_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::with_value(BigInt::from(94), BigInt::from(54));
        let q = EllipticalPoint::Identity;

        let expected = EllipticalPoint::with_value(BigInt::from(94), BigInt::from(54));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_point_add_identity_plus_21_99_curve_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::Identity;
        let q = EllipticalPoint::with_value(BigInt::from(21), BigInt::from(99));

        let expected = EllipticalPoint::with_value(BigInt::from(21), BigInt::from(99));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_add_6_1_plus_22_6_curve_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::with_value(BigInt::from(94), BigInt::from(54));
        let q = EllipticalPoint::with_value(BigInt::from(21), BigInt::from(99));

        let expected = EllipticalPoint::with_value(BigInt::from(13595), BigInt::from(8054));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_add_94_54_plus_32_17_curve_11946_4901_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::with_value(BigInt::from(94), BigInt::from(54));
        let q = EllipticalPoint::with_value(BigInt::from(11946), BigInt::from(4901));

        let expected = EllipticalPoint::with_value(BigInt::from(5938), BigInt::from(2424));
        let result = curve.add_points(&p, &q);

        assert_eq!(expected, result)
    }

    #[test]
    fn test_multiply_94_54_times_1_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::with_value(BigInt::from(94), BigInt::from(54));

        let expected = EllipticalPoint::with_value(BigInt::from(94), BigInt::from(54));
        let result = curve.multiply_unsigned(&p, &BigUint::one());

        assert_eq!(expected, result)
    }

    #[test]
    fn test_multiply_94_54_times_2_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::with_value(BigInt::from(94), BigInt::from(54));

        let expected = EllipticalPoint::with_value(BigInt::from(13426), BigInt::from(4704));
        let result = curve.multiply_unsigned(&p, &BigUint::from(2usize));

        assert_eq!(expected, result)
    }

    #[test]
    fn test_multiply_460_120_times_123_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::with_value(BigInt::from(460), BigInt::from(120));

        let expected = EllipticalPoint::with_value(BigInt::from(438), BigInt::from(912));
        let result = curve.multiply_unsigned(&p, &BigUint::from(123usize));

        assert_eq!(expected, result)
    }

    #[test]
    fn test_multiply_460_120_times_34435322_25_15_15661() {
        let curve = test_25_15_15661();

        let p = EllipticalPoint::with_value(BigInt::from(460), BigInt::from(120));

        let expected = EllipticalPoint::with_value(BigInt::from(409), BigInt::from(5304));
        let result = curve.multiply_unsigned(&p, &BigUint::from(34435322usize));

        assert_eq!(expected, result)
    }
}
