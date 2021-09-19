use num::{BigInt, Integer};

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

impl From<(i32, i32)> for EllipticalPoint {
    fn from((x, y): (i32, i32)) -> Self {
        Self::with_value(BigInt::from(x), BigInt::from(y))
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

    pub fn compress(&self) -> EllipticalCompressedPointValue {
        EllipticalCompressedPointValue::new(self)
    }

    pub fn x(&self) -> &BigInt {
        &self.x
    }
    pub fn y(&self) -> &BigInt {
        &self.y
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EllipticalCompressedPointParity {
    Odd,
    Even,
}

impl From<BigInt> for EllipticalCompressedPointParity {
    fn from(n: BigInt) -> Self {
        match n.is_even() {
            true => Self::Even,
            false => Self::Odd,
        }
    }
}

impl From<&BigInt> for EllipticalCompressedPointParity {
    fn from(n: &BigInt) -> Self {
        match n.is_even() {
            true => Self::Even,
            false => Self::Odd,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EllipticalCompressedPointValue {
    x: BigInt,
    parity: EllipticalCompressedPointParity,
}

impl EllipticalCompressedPointValue {
    fn new(point: &EllipticalPointValue) -> Self {
        let parity = EllipticalCompressedPointParity::from(point.y());

        Self {
            x: point.x().clone(),
            parity,
        }
    }

    pub fn x(&self) -> &BigInt {
        &self.x
    }

    pub fn parity(&self) -> EllipticalCompressedPointParity {
        self.parity.clone()
    }
}
