use crate::primitive::errors::{GeneralError, GeneralError::ParseError, Result};

/// Trait that defines 1:1 mapper between key identifiers and public keys.
///
/// This is used to uniquely map between short public key identifiers (commonly used in the Sphinx header),
/// and actual routing addresses (public keys) of the nodes.
pub trait KeyIdMapping<Id, K> {
    /// Maps public key to its unique identifier.
    fn map_key_to_id(&self, key: &K) -> Option<Id>;
    /// Maps public key identifier to the actual public key.
    fn map_id_to_public(&self, id: &Id) -> Option<K>;
    /// Convenience method to map a slice of public keys to IDs.
    fn map_keys_to_ids(&self, keys: &[K]) -> Vec<Option<Id>> {
        keys.iter().map(|key| self.map_key_to_id(key)).collect()
    }
    /// Convenience method to map a slice of IDs to public keys.
    fn map_ids_to_keys(&self, ids: &[Id]) -> Vec<Option<K>> {
        ids.iter().map(|id| self.map_id_to_public(id)).collect()
    }
}

/// A generic type that can be converted to a hexadecimal string.
///
/// Implementors of this trait should automatically take care of the optional `0x` prefix.
pub trait ToHex {
    /// Hexadecimal representation of this type.
    fn to_hex(&self) -> String;

    /// Tries to parse the type from the hexadecimal representation.
    fn from_hex(str: &str) -> Result<Self>
    where
        Self: Sized;
}

/// Represents a type that can be encoded to/decoded from a fixed-sized byte array of size `N`.
///
/// This requires processing and memory allocation to represent the type in binary encoding.
///
/// Differences between [BytesEncodable] and [BytesRepresentable]:
/// - [BytesRepresentable] is already internally carrying the encoded representation of the type, so no additional
///   encoding or allocation is required to represent the type as a byte array.
/// - [BytesEncodable] requires additional transformation and allocation to represent the type as a fixed size byte
///   array.
/// - [BytesEncodable] is the strict superset of [BytesRepresentable]: meaning the former can be possibly implemented
///   for a type that already implements the latter, but it is not possible vice versa.
pub trait BytesEncodable<const N: usize, E = GeneralError>:
    Into<[u8; N]> + for<'a> TryFrom<&'a [u8], Error = E>
{
    /// Size of the encoded byte array. Defaults to `N` and should not be overridden.
    const SIZE: usize = N;

    /// Convenience function to represent
    ///
    /// Shorthand for `let v: [u8; N] = self.into()`.
    #[inline]
    fn into_encoded(self) -> [u8; N] {
        self.into()
    }

    /// Convenience function to encode the type into a Box.
    #[inline]
    fn into_boxed(self) -> Box<[u8]> {
        Box::new(self.into_encoded())
    }
}

/// Represents a type already internally represented by a fixed size byte array,
/// and therefore requires no memory allocation to represent the type in binary encoding.
///
/// This is a strict subset of [BytesEncodable], see its documentation for details.
pub trait BytesRepresentable<E = GeneralError>:
    AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E>
{
    /// Size of the encoded byte array.
    const SIZE: usize;

    /// Convenience function to copy this type's binary representation into a Box.
    #[inline]
    fn into_boxed(self) -> Box<[u8]> {
        self.as_ref().into()
    }
}

/// Stack buffer size used by [`ToHex::from_hex`]'s fast decode path. Sized comfortably above the
/// largest known `BytesRepresentable::SIZE` in this crate (96 bytes, for `Acknowledgement`).
const HEX_DECODE_STACK_BUF_SIZE: usize = 128;

impl<T: BytesRepresentable> ToHex for T {
    fn to_hex(&self) -> String {
        format!("0x{}", const_hex::encode(self.as_ref()))
    }

    fn from_hex(str: &str) -> Result<Self> {
        if !str.is_empty() && str.len().is_multiple_of(2) {
            let data = str
                .strip_prefix("0x")
                .or_else(|| str.strip_prefix("0X"))
                .unwrap_or(str);

            let half_len = data.len() / 2;
            // `half_len` is the decoded byte length; common fixed-size values fit in the
            // stack buffer, while larger inputs use the heap fallback below.
            if half_len <= HEX_DECODE_STACK_BUF_SIZE {
                let mut buf = [0u8; HEX_DECODE_STACK_BUF_SIZE];
                const_hex::decode_to_slice(data, &mut buf[..half_len])
                    .map_err(|e| ParseError(e.to_string()))?;
                return T::try_from(&buf[..half_len]);
            }

            const_hex::decode(data)
                .map_err(|e| ParseError(e.to_string()))
                .and_then(|bytes| T::try_from(&bytes))
        } else {
            Err(ParseError("invalid hex length".into()))
        }
    }
}

impl<const N: usize> BytesRepresentable<std::array::TryFromSliceError> for [u8; N] {
    const SIZE: usize = N;
}

/// Allows type to be multiplied and divided by a float in range [0.0, 1.0].
pub trait UnitaryFloatOps: Sized {
    /// Multiply with float in the interval [0.0, 1.0]
    fn mul_f64(&self, rhs: f64) -> Result<Self>;
    /// Divide by float in the interval (0.0, 1.0]
    fn div_f64(&self, rhs: f64) -> Result<Self>;
}

/// Extension trait for fixed size numbers to allow conversion to/from endian representations.
pub trait IntoEndian<const N: usize> {
    /// Create an instance from Big Endian bytes. Should panic if size is more than `N`.
    fn from_be_bytes<T: AsRef<[u8]>>(bytes: T) -> Self;
    /// Create an instance from Little Endian bytes. Should panic if size is more than `N`.
    fn from_le_bytes<T: AsRef<[u8]>>(bytes: T) -> Self;
    /// Convert instance to Little Endian bytes.
    fn to_le_bytes(self) -> [u8; N];
    /// Convert instance to Big Endian bytes.
    fn to_be_bytes(self) -> [u8; N];
}

/// A trait that's added an extension method to represent a time object as `Duration` since Unix epoch.
pub trait AsUnixTimestamp {
    /// Represents self as `Duration` since Unix epoch.
    fn as_unix_timestamp(&self) -> std::time::Duration;
}

impl AsUnixTimestamp for std::time::SystemTime {
    #[allow(unstable_name_collisions)]
    fn as_unix_timestamp(&self) -> std::time::Duration {
        self.saturating_sub(std::time::SystemTime::UNIX_EPOCH)
    }
}

/// A trait that adds an extension method to perform saturated substractions on `SystemTime` instances.
pub trait SaturatingSub {
    /// Performs saturated substraction on `SystemTime` instances.
    fn saturating_sub(&self, earlier: std::time::SystemTime) -> std::time::Duration;
}

impl SaturatingSub for std::time::SystemTime {
    fn saturating_sub(&self, earlier: std::time::SystemTime) -> std::time::Duration {
        self.duration_since(earlier)
            .unwrap_or(std::time::Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct TestBytes<const N: usize>([u8; N]);

    impl<const N: usize> AsRef<[u8]> for TestBytes<N> {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl<const N: usize> TryFrom<&[u8]> for TestBytes<N> {
        type Error = GeneralError;

        fn try_from(value: &[u8]) -> Result<Self> {
            Ok(Self(
                value
                    .try_into()
                    .map_err(|_| ParseError("TestBytes".into()))?,
            ))
        }
    }

    impl<const N: usize> BytesRepresentable for TestBytes<N> {
        const SIZE: usize = N;
    }

    #[test]
    fn from_hex_roundtrips_at_stack_buffer_boundary() -> anyhow::Result<()> {
        let value = TestBytes([0xab; HEX_DECODE_STACK_BUF_SIZE]);
        assert_eq!(value, TestBytes::from_hex(&value.to_hex())?);
        Ok(())
    }

    #[test]
    fn from_hex_roundtrips_beyond_stack_buffer() -> anyhow::Result<()> {
        let value = TestBytes([0xcd; HEX_DECODE_STACK_BUF_SIZE + 72]);
        assert_eq!(value, TestBytes::from_hex(&value.to_hex())?);

        let unprefixed = value.to_hex().trim_start_matches("0x").to_string();
        assert_eq!(value, TestBytes::from_hex(&unprefixed)?);
        Ok(())
    }

    #[test]
    fn from_hex_rejects_invalid_hex_beyond_stack_buffer() {
        let str = format!("0x{}", "g".repeat((HEX_DECODE_STACK_BUF_SIZE + 72) * 2));
        assert!(TestBytes::<{ HEX_DECODE_STACK_BUF_SIZE + 72 }>::from_hex(&str).is_err());
    }

    #[test]
    fn from_hex_rejects_mismatched_size() {
        let str = format!("0x{}", "ab".repeat(HEX_DECODE_STACK_BUF_SIZE / 2));
        assert!(TestBytes::<HEX_DECODE_STACK_BUF_SIZE>::from_hex(&str).is_err());
    }
}
