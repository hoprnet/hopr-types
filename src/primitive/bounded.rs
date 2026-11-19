use std::fmt::{Display, Formatter};

use crate::primitive::prelude::GeneralError;

/// Unsigned integer (`usize`) that has an explicit upper bound.
/// Trying to convert an integer that's above this bound will fail.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BoundedSize<const B: usize>(usize);

impl<const B: usize> BoundedSize<B> {
    /// Maximum value - evaluates to `B`.
    pub const MAX: Self = Self(B);
    /// Minimum value - evaluates to 0.
    pub const MIN: Self = Self(0);
}

impl<const B: usize> TryFrom<u8> for BoundedSize<B> {
    type Error = GeneralError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        usize::from(value).try_into()
    }
}

impl<const B: usize> TryFrom<u16> for BoundedSize<B> {
    type Error = GeneralError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        usize::from(value).try_into()
    }
}

impl<const B: usize> TryFrom<u32> for BoundedSize<B> {
    type Error = GeneralError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        usize::try_from(value)
            .map_err(|_| GeneralError::InvalidInput)
            .and_then(Self::try_from)
    }
}

impl<const B: usize> TryFrom<u64> for BoundedSize<B> {
    type Error = GeneralError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        usize::try_from(value)
            .map_err(|_| GeneralError::InvalidInput)
            .and_then(Self::try_from)
    }
}

impl<const B: usize> TryFrom<usize> for BoundedSize<B> {
    type Error = GeneralError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value <= B {
            Ok(Self(value))
        } else {
            Err(GeneralError::InvalidInput)
        }
    }
}

impl<const B: usize> TryFrom<i8> for BoundedSize<B> {
    type Error = GeneralError;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        isize::from(value).try_into()
    }
}

impl<const B: usize> TryFrom<i16> for BoundedSize<B> {
    type Error = GeneralError;

    fn try_from(value: i16) -> Result<Self, Self::Error> {
        isize::from(value).try_into()
    }
}

impl<const B: usize> TryFrom<i32> for BoundedSize<B> {
    type Error = GeneralError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        isize::try_from(value)
            .map_err(|_| GeneralError::InvalidInput)
            .and_then(Self::try_from)
    }
}

impl<const B: usize> TryFrom<i64> for BoundedSize<B> {
    type Error = GeneralError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        isize::try_from(value)
            .map_err(|_| GeneralError::InvalidInput)
            .and_then(Self::try_from)
    }
}

impl<const B: usize> TryFrom<isize> for BoundedSize<B> {
    type Error = GeneralError;

    fn try_from(value: isize) -> Result<Self, Self::Error> {
        if value >= 0 {
            Self::try_from(value as usize)
        } else {
            Err(GeneralError::InvalidInput)
        }
    }
}

impl<const B: usize> Display for BoundedSize<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<const B: usize> From<BoundedSize<B>> for u8 {
    fn from(value: BoundedSize<B>) -> Self {
        value.0 as u8
    }
}

impl<const B: usize> From<BoundedSize<B>> for u16 {
    fn from(value: BoundedSize<B>) -> Self {
        value.0 as u16
    }
}

impl<const B: usize> From<BoundedSize<B>> for u32 {
    fn from(value: BoundedSize<B>) -> Self {
        value.0 as u32
    }
}

impl<const B: usize> From<BoundedSize<B>> for u64 {
    fn from(value: BoundedSize<B>) -> Self {
        value.0 as u64
    }
}

impl<const B: usize> From<BoundedSize<B>> for usize {
    fn from(value: BoundedSize<B>) -> Self {
        value.0
    }
}

/// A value in the closed interval `[0.0, 1.0]`.
///
/// The interval is closed: `0.0` and `1.0` are both valid and carry meaning. Zero is a real
/// observation or setting, such as a measured-dead stream, a zero rate, a zero penalty, or an
/// unusable peer. One is a fully healthy or fully successful one. `-0.0` compares equal to zero
/// and is accepted.
///
/// [`new`](Self::new) and [`TryFrom<f64>`] reject `NaN`, both infinities, and every value outside
/// the interval, so a `Probability` needs no clamp and no NaN check downstream. Deserialization
/// behind the `serde` feature validates the same way; serialization stays a plain `f64`.
///
/// ```
/// use hopr_types::primitive::bounded::Probability;
///
/// let half = Probability::new(0.5)?;
/// assert_eq!(half.get(), 0.5);
/// assert!(Probability::try_from(1.5).is_err());
/// # Ok::<(), hopr_types::primitive::errors::GeneralError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "f64"))]
pub struct Probability(f64);

impl Probability {
    /// Zero, the inclusive lower endpoint.
    ///
    /// Measured-dead stream, zero rate, or unusable peer.
    pub const ZERO: Self = Self(0.0);

    /// One, the inclusive upper endpoint.
    ///
    /// Fully healthy peer or full rate.
    pub const ONE: Self = Self(1.0);

    /// Creates a probability from `value`, rejecting anything outside `[0.0, 1.0]`.
    ///
    /// Accepts `-0.0` because it compares equal to zero, and normalizes it to `0.0`. Rejects
    /// `NaN` and both infinities.
    pub const fn new(value: f64) -> Result<Self, GeneralError> {
        if value >= 0.0 && value <= 1.0 {
            // Adding zero folds `-0.0` into `0.0` so the representation is unique.
            Ok(Self(value + 0.0))
        } else {
            Err(GeneralError::InvalidInput)
        }
    }

    /// Returns the midpoint of `self` and `other`.
    ///
    /// The midpoint of two values in `[0.0, 1.0]` is itself in the range, so no validation applies.
    pub const fn avg(self, other: Self) -> Self {
        Self((self.0 + other.0) / 2.0)
    }

    /// Returns the larger of `self` and `other`.
    pub const fn max(self, other: Self) -> Self {
        if other.0 > self.0 { other } else { self }
    }

    /// Returns the smaller of `self` and `other`.
    pub const fn min(self, other: Self) -> Self {
        if other.0 < self.0 { other } else { self }
    }

    /// Returns the underlying `f64`, guaranteed to lie in `[0.0, 1.0]`.
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for Probability {
    type Error = GeneralError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Probability> for f64 {
    fn from(value: Probability) -> Self {
        value.0
    }
}

/// Wrapper for [`Vec`] that has an explicit upper bound on the number of elements.
/// The Structure remains heap-allocated to avoid blowing up the size of types where it is used.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BoundedVec<T, const N: usize>(Vec<T>);

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self(vec![])
    }
}

impl<T, const N: usize> TryFrom<Vec<T>> for BoundedVec<T, N> {
    type Error = GeneralError;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() <= N {
            Ok(Self(value))
        } else {
            Err(GeneralError::InvalidInput)
        }
    }
}

impl<T, const N: usize> IntoIterator for BoundedVec<T, N> {
    type IntoIter = std::vec::IntoIter<Self::Item>;
    type Item = T;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T, const N: usize> FromIterator<T> for BoundedVec<T, N> {
    fn from_iter<V: IntoIterator<Item = T>>(iter: V) -> Self {
        Self(iter.into_iter().take(N).collect())
    }
}

impl<T, const N: usize> From<[T; N]> for BoundedVec<T, N> {
    fn from(value: [T; N]) -> Self {
        Self(Vec::from(value))
    }
}

impl<T, const N: usize> From<BoundedVec<T, N>> for Vec<T> {
    fn from(value: BoundedVec<T, N>) -> Self {
        value.0
    }
}

impl<T, const N: usize> AsRef<[T]> for BoundedVec<T, N> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Default + Copy, const N: usize> From<BoundedVec<T, N>> for [T; N] {
    fn from(value: BoundedVec<T, N>) -> Self {
        let mut out = [T::default(); N];
        value
            .0
            .into_iter()
            .enumerate()
            .for_each(|(i, e)| out[i] = e);
        out
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use crate::primitive::bounded::{BoundedSize, BoundedVec, Probability};
    use crate::primitive::errors::GeneralError;

    #[test]
    fn bounded_size_should_not_allow_bigger_numbers() {
        let min_bounded_size: usize = BoundedSize::<10>::MIN.into();
        assert_eq!(0usize, min_bounded_size);
        let max_bounded_size: usize = BoundedSize::<10>::MAX.into();
        assert_eq!(10usize, max_bounded_size);

        assert!(BoundedSize::<10>::try_from(5).is_ok_and(|b| u8::from(b) == 5));
        assert!(BoundedSize::<10>::try_from(11).is_err());
    }

    #[test]
    fn bounded_vec_should_not_fit_more_than_allowed() {
        assert!(BoundedVec::<i32, 3>::try_from(vec![]).is_ok_and(|b| Vec::from(b).is_empty()));
        assert!(
            BoundedVec::<i32, 3>::try_from(vec![1, 2]).is_ok_and(|b| Vec::from(b) == vec![1, 2])
        );
        assert!(
            BoundedVec::<i32, 3>::try_from(vec![1, 2, 3])
                .is_ok_and(|b| Vec::from(b) == vec![1, 2, 3])
        );
        assert!(BoundedVec::<i32, 3>::try_from(vec![1, 2, 3, 4]).is_err());

        assert_eq!(
            vec![1, 2, 3],
            Vec::from(BoundedVec::<i32, 3>::from_iter(vec![1, 2, 3, 4]))
        );
    }

    #[test]
    fn probability_should_accept_values_inside_the_closed_interval() {
        for value in [0.0, 1.0, 0.5, 1e-9, 0.999_999, -0.0] {
            assert!(
                Probability::new(value).is_ok_and(|probability| probability.get() == value),
                "new must accept {value}"
            );
            assert!(
                Probability::try_from(value).is_ok_and(|probability| probability.get() == value),
                "TryFrom must accept {value}"
            );
        }
    }

    #[test]
    fn probability_should_reject_values_outside_the_closed_interval() {
        for value in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -0.1,
            1.1,
            -12323.0,
            12323.0,
        ] {
            assert_eq!(
                Probability::new(value),
                Err(GeneralError::InvalidInput),
                "new must reject {value}"
            );
            assert!(
                Probability::try_from(value).is_err(),
                "TryFrom must reject {value}"
            );
        }
    }

    #[test]
    fn probability_should_support_its_helpers() -> anyhow::Result<()> {
        let quarter = Probability::new(0.25).context("0.25 is a valid probability")?;
        let half = Probability::new(0.5).context("0.5 is a valid probability")?;
        let three_quarters = Probability::new(0.75).context("0.75 is a valid probability")?;

        assert_eq!(Probability::ZERO.avg(Probability::ONE), half);
        assert_eq!(quarter.avg(three_quarters), half);
        assert_eq!(half.avg(half), half);

        assert_eq!(quarter.max(three_quarters), three_quarters);
        assert_eq!(three_quarters.min(quarter), quarter);
        assert_eq!(Probability::ZERO.max(Probability::ZERO), Probability::ZERO);
        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn probability_should_serialize_as_a_bare_f64() -> anyhow::Result<()> {
        let probability = Probability::new(0.25).context("0.25 is a valid probability")?;
        let json = serde_json::to_string(&probability).context("serialization must succeed")?;
        assert_eq!(json, "0.25");
        assert_eq!(
            serde_json::from_str::<Probability>(&json).context("deserialization must succeed")?,
            probability
        );
        assert!(serde_json::from_str::<Probability>("1.5").is_err());
        assert!(serde_json::from_str::<Probability>("-0.5").is_err());
        Ok(())
    }
}
