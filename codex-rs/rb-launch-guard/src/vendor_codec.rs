use crate::vendor_release::VendorReleaseError;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const DIGEST_BYTES: usize = 32;
const TIMESTAMP_BYTES: usize = 20;

pub(crate) fn decode_carrier(
    encoded: &str,
    decoded_limit: usize,
) -> Result<Vec<u8>, VendorReleaseError> {
    let encoded_limit = decoded_limit / 3 * 4
        + match decoded_limit % 3 {
            0 => 0,
            1 => 2,
            2 => 3,
            _ => unreachable!("remainder modulo three is at most two"),
        };
    if encoded.len() > encoded_limit {
        return Err(VendorReleaseError::CarrierTooLong);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| VendorReleaseError::InvalidCarrier)?;
    if decoded.len() > decoded_limit || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(VendorReleaseError::InvalidEncoding);
    }
    Ok(decoded)
}

pub(crate) fn parse_timestamp(bytes: &str) -> Result<i64, VendorReleaseError> {
    if bytes.len() != TIMESTAMP_BYTES
        || bytes.as_bytes()[4] != b'-'
        || bytes.as_bytes()[7] != b'-'
        || bytes.as_bytes()[10] != b'T'
        || bytes.as_bytes()[13] != b':'
        || bytes.as_bytes()[16] != b':'
        || bytes.as_bytes()[19] != b'Z'
        || !bytes.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
    {
        return Err(VendorReleaseError::InvalidTimestamp);
    }
    OffsetDateTime::parse(bytes, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .map_err(|_| VendorReleaseError::InvalidTimestamp)
}

pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], VendorReleaseError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(VendorReleaseError::InvalidArtifact)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(VendorReleaseError::InvalidArtifact)?;
        self.offset = end;
        Ok(value)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, VendorReleaseError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16_len(&mut self, limit: usize) -> Result<usize, VendorReleaseError> {
        let value = usize::from(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| VendorReleaseError::InvalidArtifact)?,
        ));
        if value == 0 || value > limit {
            return Err(VendorReleaseError::InvalidArtifact);
        }
        Ok(value)
    }

    pub(crate) fn u32_len(&mut self, limit: usize) -> Result<usize, VendorReleaseError> {
        let value = usize::try_from(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| VendorReleaseError::InvalidBundle)?,
        ))
        .map_err(|_| VendorReleaseError::InvalidBundle)?;
        if value == 0 || value > limit {
            return Err(VendorReleaseError::InvalidBundle);
        }
        Ok(value)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, VendorReleaseError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| VendorReleaseError::InvalidArtifact)?,
        ))
    }

    pub(crate) fn digest(&mut self) -> Result<[u8; DIGEST_BYTES], VendorReleaseError> {
        self.take(DIGEST_BYTES)?
            .try_into()
            .map_err(|_| VendorReleaseError::InvalidArtifact)
    }

    pub(crate) fn timestamp(&mut self) -> Result<i64, VendorReleaseError> {
        let value = std::str::from_utf8(self.take(TIMESTAMP_BYTES)?)
            .map_err(|_| VendorReleaseError::InvalidTimestamp)?;
        parse_timestamp(value)
    }

    pub(crate) fn sorted_digests(&mut self) -> Result<Vec<[u8; DIGEST_BYTES]>, VendorReleaseError> {
        let count = usize::from(self.u8()?);
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let value = self.digest()?;
            if values.last().is_some_and(|previous| previous >= &value) {
                return Err(VendorReleaseError::InvalidArtifact);
            }
            values.push(value);
        }
        Ok(values)
    }

    pub(crate) fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
