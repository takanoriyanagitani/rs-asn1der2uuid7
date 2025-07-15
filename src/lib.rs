use std::io;

use uuid::Timestamp;

use der::Encode;
use der::Sequence;

/// Represents the seeds for generating a UUIDv7.
///
/// This struct holds the necessary components to create a UUIDv7: a precise
/// Unix timestamp and a source of random data.
#[derive(Debug, PartialEq, Eq)]
pub struct UuidV7Seeds {
    /// 48-bit Unix timestamp in milliseconds.
    pub unix_ts_ms: u64,
    /// A 128-bit value, typically from a UUIDv4 or other random source,
    /// used to provide random data for the UUIDv7.
    pub random_bytes: u128,
}

impl UuidV7Seeds {
    /// Creates a new UUIDv7 `u128` value by overwriting the appropriate
    /// bits of the `random_bytes` with the timestamp, version, and variant.
    ///
    /// This method follows the "overwrite" strategy seen in some implementations,
    /// ensuring that all non-specified bits are filled with high-quality randomness.
    ///
    /// The UUIDv7 layout is applied as follows:
    /// 1. The top 48 bits are replaced with `unix_ts_ms`.
    /// 2. The 4 "version" bits (bits 76-79) are set to `0111` (7).
    /// 3. The 2 "variant" bits (bits 62-63) are set to `10` (2).
    ///
    /// All other bits are preserved from the initial `random_bytes`.
    pub fn to_u128(&self) -> u128 {
        let mut uuid = self.random_bytes;

        // Clear the top 48 bits and insert the timestamp.
        uuid &= 0x0000_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;
        uuid |= (self.unix_ts_ms as u128) << 80;

        // Clear the version bits (76-79) and set them to 7 (0b0111).
        uuid &= 0xFFFF_FFFF_FFFF_0FFF_FFFF_FFFF_FFFF_FFFF;
        uuid |= 7u128 << 76;

        // Clear the variant bits (62-63) and set them to 2 (0b10).
        uuid &= 0xFFFF_FFFF_FFFF_FFFF_3FFF_FFFF_FFFF_FFFF;
        uuid |= 2u128 << 62;

        uuid
    }
}

impl From<UuidV7Seeds> for u128 {
    /// Converts `UuidV7Seeds` into a `u128` UUID representation.
    fn from(seeds: UuidV7Seeds) -> Self {
        seeds.to_u128()
    }
}

/// Wraps a `u128` value and provides methods to extract UUIDv7 fields
/// without validation. This is useful for inspecting the raw parts of a potential UUIDv7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedUuidV7(pub u128);

impl UnverifiedUuidV7 {
    /// Extracts the 48-bit Unix timestamp in milliseconds.
    pub fn unix_ts_ms(&self) -> u64 {
        (self.0 >> 80) as u64
    }

    /// Extracts the 4-bit version field.
    pub fn version(&self) -> u8 {
        ((self.0 >> 76) & 0x0F) as u8
    }

    /// Extracts the 12-bit `rand_a` part.
    pub fn rand_a(&self) -> u16 {
        ((self.0 >> 64) & 0x0FFF) as u16
    }

    /// Extracts the 2-bit variant field.
    pub fn variant(&self) -> u8 {
        ((self.0 >> 62) & 0x03) as u8
    }

    /// Extracts the 62-bit `rand_b` part.
    pub fn rand_b(&self) -> u64 {
        (self.0 & 0x3FFF_FFFF_FFFF_FFFF) as u64
    }
}

/// Represents a validated UUIDv7.
///
/// This struct ensures that the wrapped `u128` value conforms to the UUIDv7
/// specification regarding its version and variant bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UuidV7(u128);

impl UuidV7 {
    /// Returns the inner `u128` value of the validated UUIDv7.
    pub fn as_u128(&self) -> u128 {
        self.0
    }
}

/// Error type for UUIDv7 validation failures.
#[derive(Debug, PartialEq, Eq)]
pub enum UuidV7Error {
    /// The version bits are not `0b0111` (7).
    InvalidVersion(u8),
    /// The variant bits are not `0b10` (2).
    InvalidVariant(u8),
}

impl TryFrom<UnverifiedUuidV7> for UuidV7 {
    type Error = UuidV7Error;

    fn try_from(unverified_uuid: UnverifiedUuidV7) -> Result<Self, Self::Error> {
        let version = unverified_uuid.version();
        if version != 7 {
            return Err(UuidV7Error::InvalidVersion(version));
        }

        let variant = unverified_uuid.variant();
        if variant != 2 {
            return Err(UuidV7Error::InvalidVariant(variant));
        }

        Ok(UuidV7(unverified_uuid.0))
    }
}

/// Represents the raw, parsed components of a UUIDv7.
///
/// This struct provides a structured view of a UUIDv7's constituent parts,
/// as extracted from a `u128` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawUuidV7 {
    /// The 48-bit Unix timestamp in milliseconds.
    pub unix_ts_ms: u64,
    /// The 4-bit version field.
    pub version: u8,
    /// The 12-bit `rand_a` part.
    pub rand_a: u16,
    /// The 2-bit variant field.
    pub rand_b: u64,
    /// The 62-bit `rand_b` part.
    pub variant: u8,
}

impl From<UnverifiedUuidV7> for RawUuidV7 {
    /// Converts an `UnverifiedUuidV7` into a `RawUuidV7` by extracting its components.
    fn from(unverified_uuid: UnverifiedUuidV7) -> Self {
        RawUuidV7 {
            unix_ts_ms: unverified_uuid.unix_ts_ms(),
            version: unverified_uuid.version(),
            rand_a: unverified_uuid.rand_a(),
            variant: unverified_uuid.variant(),
            rand_b: unverified_uuid.rand_b(),
        }
    }
}

use der::asn1::BitString;
use uuid::Uuid;

/// Represents the ASN.1 structure of a Raw UUIDv7.
///
/// This struct is intended for serialization/deserialization to/from ASN.1 DER.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct RawUuidV7Asn1 {
    /// The 48-bit Unix timestamp in milliseconds.
    pub unix_ts_ms: u64,

    /// The 4-bit version field.
    pub version: u8,

    /// The 12-bit `rand_a` part as an ASN.1 BitString.
    pub rand_a: BitString,

    /// The 2-bit variant field as an ASN.1 BitString.
    pub variant: BitString,

    /// The 62-bit `rand_b` part as an ASN.1 BitString.
    pub rand_b: BitString,
}

impl RawUuidV7Asn1 {
    pub fn to_der_bytes(&self) -> Result<Vec<u8>, io::Error> {
        self.to_der().map_err(io::Error::other)
    }
}

impl TryFrom<RawUuidV7> for RawUuidV7Asn1 {
    type Error = der::Error;

    fn try_from(raw_uuid: RawUuidV7) -> Result<Self, Self::Error> {
        // Convert u16 (12 bits) to BitString (2 bytes, 4 unused bits)
        let rand_a_bitstring = BitString::new(4, &raw_uuid.rand_a.to_be_bytes()[..])?;

        // Convert u8 (2 bits) to BitString (1 byte, 6 unused bits)
        let variant_bitstring = BitString::new(6, &raw_uuid.variant.to_be_bytes()[..])?;

        // Convert u64 (62 bits) to BitString (8 bytes, 2 unused bits)
        let rand_b_bitstring = BitString::new(2, &raw_uuid.rand_b.to_be_bytes()[..])?;

        Ok(RawUuidV7Asn1 {
            unix_ts_ms: raw_uuid.unix_ts_ms,
            version: raw_uuid.version,
            rand_a: rand_a_bitstring,
            variant: variant_bitstring,
            rand_b: rand_b_bitstring,
        })
    }
}

impl TryFrom<u128> for RawUuidV7Asn1 {
    type Error = der::Error;

    fn try_from(uuid_u128: u128) -> Result<Self, Self::Error> {
        let unverified_uuid = UnverifiedUuidV7(uuid_u128);
        let raw_uuid: RawUuidV7 = unverified_uuid.into();
        RawUuidV7Asn1::try_from(raw_uuid)
    }
}

impl TryFrom<Uuid> for RawUuidV7Asn1 {
    type Error = der::Error;

    fn try_from(uuid_value: Uuid) -> Result<Self, Self::Error> {
        RawUuidV7Asn1::try_from(uuid_value.as_u128())
    }
}

pub fn new_raw_uuid_v7_asn1(now: Timestamp) -> Result<RawUuidV7Asn1, io::Error> {
    let v7: Uuid = Uuid::new_v7(now);
    v7.try_into().map_err(io::Error::other)
}

pub fn new_raw_uuid_v7_asn1_now() -> Result<RawUuidV7Asn1, io::Error> {
    let v7: Uuid = Uuid::now_v7();
    v7.try_into().map_err(io::Error::other)
}
