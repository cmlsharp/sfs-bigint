use crypto_bigint::Encoding;
use derive_more::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};
use num_traits::{Num, One, Zero};
use serde::{Deserialize, Serialize};
use std::ops::Neg;
use std::str::FromStr;

use crypto_bigint::Limb;

const fn mul_add_64(a: u64, mul: u64, add: u64) -> (u64, u64) {
    let product = (a as u128) * (mul as u128) + (add as u128);
    (product as u64, (product >> 64) as u64)
}

const fn str_to_limbs<const N: usize>(s: &str, radix: u32) -> [u64; N] {
    let bytes = s.as_bytes();
    let mut out = [0u64; N];

    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        let digit = match ch {
            b'0'..=b'9' => (ch - b'0') as u32,
            b'a'..=b'z' => 10 + (ch - b'a') as u32,
            b'A'..=b'Z' => 10 + (ch - b'A') as u32,
            _ => panic!("invalid character"),
        };

        if digit >= radix {
            panic!("digit out of range for radix");
        }

        let mut carry = digit as u64;
        let mut j = 0;
        while j < N {
            let (lo, hi) = mul_add_64(out[j], radix as u64, carry);
            out[j] = lo;
            carry = hi;
            j += 1;
        }

        i += 1;
    }

    out
}

macro_rules! impl_bigint_wrapper {
    ($name:ident, $wrapped:path, $width:literal) => {
        #[derive(
            Copy,
            Clone,
            Eq,
            PartialEq,
            Hash,
            Ord,
            PartialOrd,
            Default,
            Add,
            AddAssign,
            Div,
            DivAssign,
            Mul,
            MulAssign,
            Sub,
            SubAssign,
            Serialize,
            Deserialize,
            Rem,
            RemAssign,
            BitAnd,
            BitAndAssign,
            BitOr,
            BitOrAssign,
            BitXor,
            BitXorAssign,
            Not,
            Shl,
            ShlAssign,
            Shr,
            ShrAssign,
        )]
        #[mul(forward)]
        #[div(forward)]
        #[rem(forward)]
        pub struct $name($wrapped);

        impl $name {
            pub const BYTES: usize = $width / 8;
            pub const WORDS: usize = $width / 64;
            pub const ZERO: Self = $name(<$wrapped>::ZERO);
            pub const ONE: Self = $name(<$wrapped>::ONE);
            pub const MAX: Self = $name(<$wrapped>::MAX);

            /// Returns `true` if the bit at index `i` is set.
            pub fn bit(&self, i: usize) -> bool {
                self.0
                    .bit_vartime(i.try_into().expect("bit indices must be < 2**32"))
            }

            ///Calculate the number of bits required to represent a given number in variable-time with respect to `self`.
            pub fn bit_length(&self) -> usize {
                self.0.bits_vartime() as usize
            }
            /// Construct `Self` from little-endian bytes
            pub fn from_le_bytes(bytes: [u8; Self::BYTES]) -> Self {
                Self(Encoding::from_le_bytes(bytes))
            }

            pub const fn from_words(words: [u64; Self::WORDS]) -> Self {
                Self(<$wrapped>::from_words(words))
            }

            /// it is better to use `from_str_radix` (which returns a Result) on non-const inputs.
            /// this function panics on invalid strings, but it is usable in const contexts
            pub const fn from_str_radix_const(s: &str, radix: u32) -> Self {
                Self::from_words(str_to_limbs(s, radix))
            }

            pub const fn from_le_slice(byte_slice: &[u8]) -> Self {
                Self(<$wrapped>::from_le_slice(byte_slice))
            }
        }

        impl Neg for $name {
            type Output = Self;
            fn neg(self) -> Self::Output {
                Self(self.0.wrapping_neg())
            }
        }
        impl Zero for $name {
            fn zero() -> Self {
                Self(<$wrapped>::zero())
            }

            fn is_zero(&self) -> bool {
                self.0.is_zero()
            }
        }

        impl One for $name {
            fn one() -> Self {
                Self(<$wrapped>::one())
            }

            fn is_one(&self) -> bool {
                self.0.is_one()
            }
        }

        impl Num for $name {
            type FromStrRadixErr = <$wrapped as Num>::FromStrRadixErr;
            fn from_str_radix(s: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
                Num::from_str_radix(s, radix).map(Self)
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self(From::from(value))
            }
        }

        // Ideally you'd write a version of this that didn't alloc, but it's fine for now
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0.to_string_radix_vartime(10))
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))?;
                f.write_str("(")?;
                std::fmt::Display::fmt(self, f)?;
                f.write_str(")")
            }
        }

        impl std::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:x}", &self.0)
            }
        }

        impl std::fmt::UpperHex for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:X}", &self.0)
            }
        }

        impl std::fmt::Binary for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:b}", &self.0)
            }
        }

        impl std::fmt::Octal for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0.to_string_radix_vartime(8))
            }
        }

        impl FromStr for $name {
            type Err = <$wrapped as Num>::FromStrRadixErr;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                <$wrapped>::from_str_radix(s, 10).map($name)
            }
        }
    };
}

#[derive(Clone, Debug)]
pub struct U256Params {
    range: std::ops::RangeInclusive<U256>,
}

impl U256Params {
    pub fn range(range: std::ops::RangeInclusive<impl Into<U256>>) -> Self {
        let (start, end) = range.into_inner();
        Self {
            range: start.into()..=end.into(),
        }
    }
}
impl Default for U256Params {
    fn default() -> Self {
        Self {
            range: U256::ZERO..=U256::MAX,
        }
    }
}

use proptest::prelude::*;
impl Arbitrary for U256 {
    type Parameters = U256Params;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        let lo = params.range.start().0;
        let hi = params.range.end().0;

        any::<[u64; 4]>()
            .prop_map(move |limbs| {
                let val = crypto_bigint::U256::from_words(limbs);

                let range_size = hi.wrapping_sub(&lo).wrapping_add(&crypto_bigint::U256::ONE);

                match crypto_bigint::NonZero::new(range_size).into() {
                    Some(nz) => Self(lo.wrapping_add(&val.rem(&nz))),
                    None => Self(val), // range_size wrapped to 0, meaning full range
                }
            })
            .boxed()
    }
}

impl_bigint_wrapper!(U256, crypto_bigint::U256, 256);
impl_bigint_wrapper!(U512, crypto_bigint::U512, 512);

impl U256 {
    /// Calculates the double-width product of `self` and `other`
    pub fn widening_mul(&self, other: &Self) -> U512 {
        U512(self.0.widening_mul(&other.0))
    }

    /// This is used purely for constructing unit tests, can be ignored by students
    pub fn arbitrary_range(range: std::ops::RangeInclusive<Self>) -> impl Strategy<Value = Self> {
        any_with::<U256>(U256Params { range })
    }

    /// Calculates self + rhs and returns a tuple containing the sum and the output carry.
    /// If the output carry is false, this is equivalent to normal addition. If carry is true,
    /// this indicates that the sum 'overflowed' and is equal to `(self + rhs) % 2**256`
    pub fn carrying_add(&self, rhs: &Self) -> (Self, bool) {
        let (res, Limb(carry)) = self.0.adc(&rhs.0, Limb::ZERO);
        debug_assert!(carry == 0 || carry == 1);
        (U256(res), carry != 0)
    }

    /// Calculates self - rhs and returns a tuple containing the difference and the output
    /// borrow. If `borrow` is false, this is equivalent to normal integer subtraction.
    /// If `borrow` is true, this is equal to `self - rhs`
    pub fn borrowing_sub(&self, rhs: &Self) -> (Self, bool) {
        let (res, Limb(borrow)) = self.0.sbb(&rhs.0, Limb::ZERO);
        debug_assert!(borrow == 0 || borrow == u64::MAX);
        (U256(res), borrow != 0)
    }
}

impl From<U256> for U512 {
    fn from(value: U256) -> Self {
        U512(From::from(&value.0))
    }
}

impl U512 {
    pub fn split(self) -> (U256, U256) {
        let (lhs, rhs) = self.0.split();
        (U256(lhs), U256(rhs))
    }
}
