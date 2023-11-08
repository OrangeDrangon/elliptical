use num::{bigint::Sign, BigInt, Integer};

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

impl EllipticalCompressedPointParity {
    fn as_byte(&self) -> u8 {
        match self {
            Self::Odd => 0,
            Self::Even => 1,
        }
    }

    fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Odd,
            1 => Self::Even,
            _ => unreachable!(),
        }
    }
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

    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes = vec![self.parity().as_byte()];
        let (sign, x) = self.x().to_bytes_be();
        let sign = match sign {
            Sign::Plus => 0,
            Sign::Minus => 1,
            _ => unreachable!(),
        };

        bytes.push(sign);
        bytes.extend(x);

        bytes.into()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let parity = EllipticalCompressedPointParity::from_byte(bytes[0]);
        let sign = match bytes[1] {
            0 => Sign::Plus,
            1 => Sign::Minus,
            _ => unreachable!(),
        };

        let value = &bytes[2..];

        Self {
            parity,
            x: BigInt::from_bytes_be(sign, value),
        }
    }
}
