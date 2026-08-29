use std::fmt;
use std::io;
use std::io::BufRead;

use tokio::io::AsyncBufRead;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedUtf8Line {
    pub text: String,
    pub terminated_by_lf: bool,
    pub physical_bytes: usize,
}

#[derive(Debug)]
pub enum BoundedLineError {
    InvalidLimit,
    Io(io::Error),
    InvalidUtf8(std::string::FromUtf8Error),
    PhysicalFrameTooLong { max_physical_bytes: usize },
}

impl fmt::Display for BoundedLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => formatter.write_str("physical frame limit must be positive"),
            Self::Io(error) => write!(formatter, "physical frame read failed: {error}"),
            Self::InvalidUtf8(_) => formatter.write_str("physical frame is not valid UTF-8"),
            Self::PhysicalFrameTooLong { max_physical_bytes } => write!(
                formatter,
                "physical frame exceeds the {max_physical_bytes}-byte limit including LF"
            ),
        }
    }
}

impl std::error::Error for BoundedLineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidUtf8(error) => Some(error),
            Self::InvalidLimit | Self::PhysicalFrameTooLong { .. } => None,
        }
    }
}

/// Reads at most one LF-delimited physical frame while this helper's frame
/// buffer retains no more than `max_physical_bytes + 1` probe bytes. A caller's
/// [`BufRead`] implementation may retain its own independent read buffer. The
/// limit includes LF and an optional preceding CR. EOF without LF is returned
/// to let the caller choose policy.
pub fn read_bounded_utf8_line<R: BufRead>(
    reader: &mut R,
    max_physical_bytes: usize,
) -> Result<Option<BoundedUtf8Line>, BoundedLineError> {
    let probe_limit = probe_limit(max_physical_bytes)?;
    let mut bytes = Vec::with_capacity(max_physical_bytes.min(8192));
    std::io::Read::take(reader, probe_limit)
        .read_until(b'\n', &mut bytes)
        .map_err(BoundedLineError::Io)?;
    finish_line(bytes, max_physical_bytes)
}

/// Async counterpart to [`read_bounded_utf8_line`] with identical byte and
/// terminator semantics.
pub async fn read_bounded_utf8_line_async<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_physical_bytes: usize,
) -> Result<Option<BoundedUtf8Line>, BoundedLineError> {
    let probe_limit = probe_limit(max_physical_bytes)?;
    let mut bytes = Vec::with_capacity(max_physical_bytes.min(8192));
    AsyncReadExt::take(reader, probe_limit)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(BoundedLineError::Io)?;
    finish_line(bytes, max_physical_bytes)
}

/// Reads an LF/CRLF-delimited line with a ceiling on decoded payload bytes.
/// A non-CR byte immediately beyond the payload ceiling is terminal without
/// waiting for EOF. A CR at that boundary receives exactly one byte of
/// lookahead so a ceiling-sized payload followed by CRLF remains valid.
pub fn read_bounded_utf8_payload_line<R: BufRead>(
    reader: &mut R,
    max_payload_bytes: usize,
) -> Result<Option<BoundedUtf8Line>, BoundedLineError> {
    let read_limit = u64::try_from(max_payload_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(max_payload_bytes.saturating_add(1).min(8192));
    std::io::Read::take(&mut *reader, read_limit)
        .read_until(b'\n', &mut bytes)
        .map_err(BoundedLineError::Io)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let mut extra = None;
    if bytes.last() != Some(&b'\n')
        && bytes.len() > max_payload_bytes
        && bytes.last() == Some(&b'\r')
    {
        let mut byte = [0_u8; 1];
        match std::io::Read::read(reader, &mut byte).map_err(BoundedLineError::Io)? {
            0 => {}
            1 => extra = Some(byte[0]),
            _ => unreachable!("one-byte read returned more than one byte"),
        }
    }
    finish_payload_line(bytes, extra, max_payload_bytes)
}

/// Async counterpart to [`read_bounded_utf8_payload_line`].
pub async fn read_bounded_utf8_payload_line_async<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_payload_bytes: usize,
) -> Result<Option<BoundedUtf8Line>, BoundedLineError> {
    let read_limit = u64::try_from(max_payload_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(max_payload_bytes.saturating_add(1).min(8192));
    AsyncReadExt::take(&mut *reader, read_limit)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(BoundedLineError::Io)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let mut extra = None;
    if bytes.last() != Some(&b'\n')
        && bytes.len() > max_payload_bytes
        && bytes.last() == Some(&b'\r')
    {
        match AsyncReadExt::read_u8(reader).await {
            Ok(byte) => extra = Some(byte),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(error) => return Err(BoundedLineError::Io(error)),
        }
    }
    finish_payload_line(bytes, extra, max_payload_bytes)
}

fn probe_limit(max_physical_bytes: usize) -> Result<u64, BoundedLineError> {
    if max_physical_bytes == 0 {
        return Err(BoundedLineError::InvalidLimit);
    }
    Ok(u64::try_from(max_physical_bytes.saturating_add(1)).unwrap_or(u64::MAX))
}

fn finish_line(
    mut bytes: Vec<u8>,
    max_physical_bytes: usize,
) -> Result<Option<BoundedUtf8Line>, BoundedLineError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > max_physical_bytes {
        return Err(BoundedLineError::PhysicalFrameTooLong { max_physical_bytes });
    }
    let physical_bytes = bytes.len();
    let terminated_by_lf = bytes.last() == Some(&b'\n');
    if terminated_by_lf {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    let text = String::from_utf8(bytes).map_err(BoundedLineError::InvalidUtf8)?;
    Ok(Some(BoundedUtf8Line {
        text,
        terminated_by_lf,
        physical_bytes,
    }))
}

fn finish_payload_line(
    mut bytes: Vec<u8>,
    extra: Option<u8>,
    max_payload_bytes: usize,
) -> Result<Option<BoundedUtf8Line>, BoundedLineError> {
    let mut physical_bytes = bytes.len();
    let terminated_by_lf = if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        true
    } else if bytes.last() == Some(&b'\r') && extra == Some(b'\n') {
        bytes.pop();
        physical_bytes = physical_bytes.saturating_add(1);
        true
    } else {
        false
    };
    if bytes.len() > max_payload_bytes {
        return Err(BoundedLineError::PhysicalFrameTooLong {
            max_physical_bytes: max_payload_bytes,
        });
    }
    let text = String::from_utf8(bytes).map_err(BoundedLineError::InvalidUtf8)?;
    Ok(Some(BoundedUtf8Line {
        text,
        terminated_by_lf,
        physical_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn physical_limit_counts_lf_and_crlf() {
        let mut lf = BufReader::new(&b"abc\n"[..]);
        assert_eq!(
            read_bounded_utf8_line(&mut lf, 4).expect("LF frame"),
            Some(BoundedUtf8Line {
                text: "abc".to_string(),
                terminated_by_lf: true,
                physical_bytes: 4,
            })
        );

        let mut crlf = BufReader::new(&b"abc\r\n"[..]);
        assert!(matches!(
            read_bounded_utf8_line(&mut crlf, 4),
            Err(BoundedLineError::PhysicalFrameTooLong {
                max_physical_bytes: 4
            })
        ));
    }

    #[test]
    fn partial_eof_and_invalid_utf8_are_distinguishable() {
        let mut partial = BufReader::new(&b"{}"[..]);
        assert_eq!(
            read_bounded_utf8_line(&mut partial, 3).expect("partial frame"),
            Some(BoundedUtf8Line {
                text: "{}".to_string(),
                terminated_by_lf: false,
                physical_bytes: 2,
            })
        );

        let mut invalid = BufReader::new(&b"\xff\n"[..]);
        assert!(matches!(
            read_bounded_utf8_line(&mut invalid, 2),
            Err(BoundedLineError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn payload_limit_rejects_non_cr_lookahead_and_accepts_ceiling_crlf() {
        let mut overlong = BufReader::new(&b"abcd"[..]);
        assert!(matches!(
            read_bounded_utf8_payload_line(&mut overlong, 3),
            Err(BoundedLineError::PhysicalFrameTooLong {
                max_physical_bytes: 3
            })
        ));

        let mut crlf = BufReader::new(&b"abc\r\n"[..]);
        assert_eq!(
            read_bounded_utf8_payload_line(&mut crlf, 3).expect("ceiling CRLF"),
            Some(BoundedUtf8Line {
                text: "abc".to_string(),
                terminated_by_lf: true,
                physical_bytes: 5,
            })
        );
    }

    #[test]
    fn async_payload_limit_matches_sync_lookahead_semantics() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime")
            .block_on(async {
                let mut overlong = tokio::io::BufReader::new(&b"abcd"[..]);
                assert!(matches!(
                    read_bounded_utf8_payload_line_async(&mut overlong, 3).await,
                    Err(BoundedLineError::PhysicalFrameTooLong {
                        max_physical_bytes: 3
                    })
                ));

                let mut crlf = tokio::io::BufReader::new(&b"abc\r\n"[..]);
                assert_eq!(
                    read_bounded_utf8_payload_line_async(&mut crlf, 3)
                        .await
                        .expect("async ceiling CRLF"),
                    Some(BoundedUtf8Line {
                        text: "abc".to_string(),
                        terminated_by_lf: true,
                        physical_bytes: 5,
                    })
                );
            });
    }
}
