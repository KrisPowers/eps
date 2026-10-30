//! What an HTTPS service's TLS shows: its certificate, read from the DER the
//! handshake hands over, and whether it still accepts TLS 1.0 or 1.1.
//!
//! The legacy check sends a ClientHello offering only the old version and
//! reads the first record back; the handshake goes no further.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

/// The parts of a leaf certificate worth reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    /// The subject's common name, else its organization.
    pub subject: String,
    pub issuer: String,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// The DNS names and addresses it covers.
    pub names: Vec<String>,
    /// Issued by itself rather than a certificate authority.
    pub self_signed: bool,
}

/// What one HTTPS service's TLS showed.
#[derive(Debug, Clone, Default)]
pub struct TlsReport {
    pub cert: Option<Cert>,
    /// Old protocol versions it accepted: `TLS 1.0`, `TLS 1.1`.
    pub legacy: Vec<&'static str>,
}

const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
const ALT_NAMES: &[u8] = &[0x55, 0x1d, 0x11];

/// One DER element: its tag, its content, and what follows it.
fn next(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// Reads a DER certificate. `None` when it doesn't parse.
pub fn parse(der: &[u8]) -> Option<Cert> {
    let (_, cert, _) = next(der)?;
    let (_, tbs, _) = next(cert)?;
    let mut rest = tbs;
    // The version is optional, tagged [0].
    let (tag, _, after) = next(rest)?;
    if tag == 0xa0 {
        rest = after;
    }
    let (_, _, rest) = next(rest)?; // serial number
    let (_, _, rest) = next(rest)?; // signature algorithm
    let (_, issuer, rest) = next(rest)?;
    let (_, validity, rest) = next(rest)?;
    let (_, subject, rest) = next(rest)?;
    let (_, _, mut rest) = next(rest)?; // public key

    let mut names = Vec::new();
    while let Some((tag, body, after)) = next(rest) {
        rest = after;
        if tag == 0xa3 {
            names = alt_names(body);
        }
    }

    let (from_tag, from, after) = next(validity)?;
    let (to_tag, to, _) = next(after)?;
    Some(Cert {
        subject: name(subject),
        issuer: name(issuer),
        not_before: time(from_tag, from)?,
        not_after: time(to_tag, to)?,
        names,
        self_signed: issuer == subject,
    })
}

/// A distinguished name's common name, else its organization.
fn name(rdns: &[u8]) -> String {
    let (mut common, mut org) = (None, None);
    let mut sets = rdns;
    while let Some((_, set, after)) = next(sets) {
        sets = after;
        let mut pairs = set;
        while let Some((_, pair, after)) = next(pairs) {
            pairs = after;
            let Some((_, oid, value)) = next(pair) else {
                continue;
            };
            let Some((_, value, _)) = next(value) else {
                continue;
            };
            let value = String::from_utf8_lossy(value).into_owned();
            if oid == COMMON_NAME {
                common = Some(value);
            } else if oid == ORGANIZATION {
                org = Some(value);
            }
        }
    }
    common.or(org).unwrap_or_default()
}

/// The names in the subject alternative name extension, from the
/// extensions block.
fn alt_names(block: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some((_, list, _)) = next(block) else {
        return out;
    };
    let mut exts = list;
    while let Some((_, ext, after)) = next(exts) {
        exts = after;
        let Some((_, oid, rest)) = next(ext) else {
            continue;
        };
        if oid != ALT_NAMES {
            continue;
        }
        // An optional `critical` flag comes before the value.
        let Some((mut tag, mut value, after)) = next(rest) else {
            continue;
        };
        if tag == 0x01 {
            let Some((t, v, _)) = next(after) else {
                continue;
            };
            (tag, value) = (t, v);
        }
        if tag != 0x04 {
            continue;
        }
        let Some((_, general, _)) = next(value) else {
            continue;
        };
        let mut items = general;
        while let Some((tag, body, after)) = next(items) {
            items = after;
            match tag {
                0x82 => out.push(String::from_utf8_lossy(body).into_owned()),
                0x87 => {
                    if let Ok(v4) = <[u8; 4]>::try_from(body) {
                        out.push(Ipv4Addr::from(v4).to_string());
                    } else if let Ok(v6) = <[u8; 16]>::try_from(body) {
                        out.push(Ipv6Addr::from(v6).to_string());
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// A UTCTime or GeneralizedTime as Unix seconds.
fn time(tag: u8, raw: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(raw).ok()?;
    let (year, rest) = match tag {
        0x17 => {
            let y: i64 = s.get(0..2)?.parse().ok()?;
            (if y >= 50 { 1900 + y } else { 2000 + y }, s.get(2..)?)
        }
        0x18 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let num = |i: usize| -> Option<i64> { rest.get(i..i + 2)?.parse().ok() };
    let seconds = num(8).unwrap_or(0);
    Some(days(year, num(0)?, num(2)?) * 86_400 + num(4)? * 3600 + num(6)? * 60 + seconds)
}

/// Days from 1970-01-01 to a date, by Howard Hinnant's civil calendar
/// algorithm.
fn days(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The old versions `host:port` accepts, each tried with a ClientHello that
/// offers only it, waiting up to `wait` for the answer.
pub async fn legacy(host: &str, port: u16, wait: Duration) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (label, minor) in [("TLS 1.0", 1u8), ("TLS 1.1", 2)] {
        if accepts(host, port, minor, wait).await {
            out.push(label);
        }
    }
    out
}

/// Whether the server answers a ClientHello for TLS 1.`minor - 1` with a
/// ServerHello for that same version, rather than an alert.
async fn accepts(host: &str, port: u16, minor: u8, wait: Duration) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let hello = client_hello(bare, minor);
    let talk = async {
        let stream = TcpStream::connect((bare, port)).await.ok()?;
        let mut left = hello.as_slice();
        while !left.is_empty() {
            stream.writable().await.ok()?;
            match stream.try_write(left) {
                Ok(n) => left = &left[n..],
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(_) => return None,
            }
        }
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        while got.len() < 11 {
            stream.readable().await.ok()?;
            match stream.try_read(&mut buf) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(_) => return None,
            }
        }
        Some(got)
    };
    match timeout(wait, talk).await {
        Ok(Some(b)) => server_hello(&b, minor),
        _ => false,
    }
}

/// A handshake record holding a ServerHello for version 3.`minor`.
fn server_hello(b: &[u8], minor: u8) -> bool {
    b.len() >= 11 && b[0] == 0x16 && b[5] == 0x02 && b[9] == 3 && b[10] == minor
}

/// Cipher suites TLS 1.0 and 1.1 servers commonly take: ECDHE, DHE and RSA
/// with AES-CBC, and 3DES.
const SUITES: [u16; 9] = [
    0xc014, 0xc013, 0xc00a, 0xc009, 0x0039, 0x0033, 0x0035, 0x002f, 0x000a,
];

/// A ClientHello offering only version 3.`minor`, naming `host` when it is a
/// name rather than an address.
fn client_hello(host: &str, minor: u8) -> Vec<u8> {
    let mut ext = Vec::new();
    if host.parse::<IpAddr>().is_err() {
        let name = host.as_bytes();
        let n = name.len() as u16;
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&(n + 5).to_be_bytes());
        ext.extend_from_slice(&(n + 3).to_be_bytes());
        ext.push(0x00);
        ext.extend_from_slice(&n.to_be_bytes());
        ext.extend_from_slice(name);
    }
    // Supported groups x25519, secp256r1 and secp384r1; uncompressed points;
    // an empty renegotiation_info.
    ext.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
    ]);
    ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    ext.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

    let mut body = vec![0x03, minor];
    body.extend_from_slice(&[0x5a; 32]);
    body.push(0);
    body.extend_from_slice(&((SUITES.len() * 2) as u16).to_be_bytes());
    for suite in SUITES {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DER element with a short or long length.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    fn rdn(oid: &[u8], value: &str) -> Vec<u8> {
        let pair = [tlv(0x06, oid), tlv(0x0c, value.as_bytes())].concat();
        tlv(0x31, &tlv(0x30, &pair))
    }

    fn cert(issuer: &str, subject: &str, names: &[&str]) -> Vec<u8> {
        let general: Vec<u8> = names.iter().flat_map(|n| tlv(0x82, n.as_bytes())).collect();
        let san = tlv(
            0x30,
            &[tlv(0x06, ALT_NAMES), tlv(0x04, &tlv(0x30, &general))].concat(),
        );
        let tbs = [
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[1]),
            tlv(0x30, &[]),
            tlv(0x30, &rdn(COMMON_NAME, issuer)),
            tlv(
                0x30,
                &[tlv(0x17, b"240101000000Z"), tlv(0x18, b"20300601120000Z")].concat(),
            ),
            tlv(0x30, &rdn(COMMON_NAME, subject)),
            tlv(0x30, &[]),
            tlv(0xa3, &tlv(0x30, &san)),
        ]
        .concat();
        tlv(0x30, &[tlv(0x30, &tbs), tlv(0x30, &[]), tlv(0x03, &[0])].concat())
    }

    #[test]
    fn reads_a_certificate() {
        let c = parse(&cert("Example CA", "api.example", &["api.example", "*.example"])).unwrap();
        assert_eq!(c.subject, "api.example");
        assert_eq!(c.issuer, "Example CA");
        assert_eq!(c.names, ["api.example", "*.example"]);
        assert!(!c.self_signed);
        assert_eq!(c.not_before, 1_704_067_200);
        assert_eq!(c.not_after, 1_906_545_600);
    }

    #[test]
    fn self_signed_when_issuer_is_subject() {
        assert!(parse(&cert("box", "box", &[])).unwrap().self_signed);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse(&[0x30, 0x05, 0x01]), None);
        assert_eq!(parse(&[]), None);
    }

    #[test]
    fn epoch_days() {
        assert_eq!(days(1970, 1, 1), 0);
        assert_eq!(days(2000, 3, 1), 11_017);
    }

    #[test]
    fn hello_is_one_handshake_record() {
        let h = client_hello("api.example", 1);
        assert_eq!(&h[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(u16::from_be_bytes([h[3], h[4]]) as usize, h.len() - 5);
        assert_eq!(h[5], 0x01);
        assert_eq!(&h[9..11], &[0x03, 0x01]);
    }

    #[test]
    fn server_hello_must_match_version() {
        let hello = [0x16, 0x03, 0x01, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c, 0x03, 0x01];
        assert!(server_hello(&hello, 1));
        assert!(!server_hello(&hello, 2));
        assert!(!server_hello(&[0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46], 1));
    }
}
