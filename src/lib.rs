use crypto_bigint::Encoding;
use derive_more::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Not, Rem, RemAssign, Sub, SubAssign,
};
use num_traits::{Num, One, Zero};
use serde::{Deserialize, Serialize};
use std::ops::Neg;

use crypto_bigint::Limb;

macro_rules! impl_bigint_wrapper {
    ($name:ident, $wrapped:path, $width:literal) => {
        #[derive(
            Copy,
            Clone,
            Eq,
            PartialEq,
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
        )]
        #[mul(forward)]
        #[div(forward)]
        #[rem(forward)]
        pub struct $name($wrapped);

        impl $name {
            pub const BYTES: usize = $width / 8;
            pub const WORDS: usize = $width / 64;

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

            pub fn from_words(words: [u64; Self::WORDS]) -> Self {
                Self(<$wrapped>::from_words(words))
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
    };
}

impl_bigint_wrapper!(U256, crypto_bigint::U256, 256);
impl_bigint_wrapper!(U512, crypto_bigint::U512, 512);

impl U256 {
    /// Calculates the double-width product of `self` and `other`
    pub fn widening_mul(&self, other: &Self) -> U512 {
        U512(self.0.widening_mul(&other.0))
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
        debug_assert!(borrow == 0 || borrow == 1);
        (U256(res), borrow != 0)
    }
}
