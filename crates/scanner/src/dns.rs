//! The target's DNS records, asked of the system's resolver over UDP: its
//! addresses, aliases, mail and name servers, text records (SPF among them),
//! CAA, its DMARC policy, and the reverse name of the address scanned.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures::future::join_all;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// One record in an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    /// `A`, `MX`, `TXT`, ...
    pub kind: &'static str,
    pub value: String,
    /// Seconds.
    pub ttl: u32,
}

/// How long the resolver gets per question.
const WAIT: Duration = Duration::from_secs(2);

const A: u16 = 1;
const NS: u16 = 2;
const CNAME: u16 = 5;
const PTR: u16 = 12;
const MX: u16 = 15;
const TXT: u16 = 16;
const AAAA: u16 = 28;
const CAA: u16 = 257;

const KINDS: &[(u16, &str)] = &[
    (A, "A"),
    (NS, "NS"),
    (CNAME, "CNAME"),
    (PTR, "PTR"),
    (MX, "MX"),
    (TXT, "TXT"),
    (AAAA, "AAAA"),
    (CAA, "CAA"),
];

/// The first resolver in `/etc/resolv.conf`. `None` where there is none,
/// such as on Windows.
pub fn resolver() -> Option<SocketAddr> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .find_map(|s| s.trim().parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
}

/// Every record found for `host`, which was scanned at `ip`, all questions
/// asked at once. A name gets its records and DMARC policy; an address only
/// its reverse name. Empty when there is no resolver to ask.
pub async fn lookup(host: &str, ip: IpAddr) -> Vec<Record> {
    let Some(server) = resolver() else {
        return Vec::new();
    };
    let mut asks: Vec<(String, u16)> = Vec::new();
    if host.parse::<IpAddr>().is_err() && host.contains('.') {
        for kind in [A, AAAA, CNAME, MX, NS, TXT, CAA] {
            asks.push((host.to_string(), kind));
        }
        asks.push((format!("_dmarc.{host}"), TXT));
    }
    asks.push((reverse(ip), PTR));
    let asked = asks
        .iter()
        .enumerate()
        .map(|(i, (name, kind))| query(server, name, *kind, 0x5000 + i as u16));
    join_all(asked).await.into_iter().flatten().collect()
}

async fn query(server: SocketAddr, name: &str, kind: u16, id: u16) -> Vec<Record> {
    let local: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let ask = async {
        let socket = UdpSocket::bind(local).await.ok()?;
        socket.send_to(&question(name, kind, id), server).await.ok()?;
        let mut buf = vec![0u8; 4096];
        let (n, _) = socket.recv_from(&mut buf).await.ok()?;
        answers(&buf[..n], id, kind)
    };
    timeout(WAIT, ask).await.ok().flatten().unwrap_or_default()
}

/// A query for `name`'s records of `kind`, recursion desired.
fn question(name: &str, kind: u16, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let bytes = &label.as_bytes()[..label.len().min(63)];
        q.push(bytes.len() as u8);
        q.extend_from_slice(bytes);
    }
    q.push(0);
    q.extend_from_slice(&kind.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    q
}

/// The records of `kind` in a response to query `id`.
fn answers(msg: &[u8], id: u16, kind: u16) -> Option<Vec<Record>> {
    let word = |at: usize| -> Option<u16> {
        Some(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]))
    };
    if msg.len() < 12 || word(0)? != id {
        return None;
    }
    let mut at = 12;
    for _ in 0..word(4)? {
        at = name(msg, at)?.1 + 4;
    }
    let mut out = Vec::new();
    for _ in 0..word(6)? {
        let (owner, next) = name(msg, at)?;
        let head = msg.get(next..next + 10)?;
        let found = u16::from_be_bytes([head[0], head[1]]);
        let ttl = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        let start = next + 10;
        let len = u16::from_be_bytes([head[8], head[9]]) as usize;
        let data = msg.get(start..start + len)?;
        at = start + len;
        if found != kind {
            continue;
        }
        let Some(value) = rdata(msg, start, data, found) else {
            continue;
        };
        let label = KINDS.iter().find(|(k, _)| *k == found).map_or("?", |(_, l)| *l);
        out.push(Record {
            name: owner,
            kind: label,
            value,
            ttl,
        });
    }
    Some(out)
}

/// The name at `at`, following compression pointers, and where what
/// follows it starts.
fn name(msg: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    // A bound on the labels and pointers followed, so a looping pointer ends.
    for _ in 0..128 {
        let len = *msg.get(at)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(at + 1)));
        }
        if len & 0xc0 == 0xc0 {
            if end.is_none() {
                end = Some(at + 2);
            }
            at = ((len & 0x3f) << 8) | *msg.get(at + 1)? as usize;
            continue;
        }
        let label = msg.get(at + 1..at + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        at += 1 + len;
    }
    None
}

/// A record's data as text: an address, a name, `10 mail.example`, a TXT
/// record's strings joined, or `0 issue "ca.example"`.
fn rdata(msg: &[u8], start: usize, data: &[u8], kind: u16) -> Option<String> {
    match kind {
        A => Some(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?).to_string()),
        AAAA => Some(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?).to_string()),
        NS | CNAME | PTR => Some(name(msg, start)?.0),
        MX => {
            let pref = u16::from_be_bytes([*data.first()?, *data.get(1)?]);
            Some(format!("{pref} {}", name(msg, start + 2)?.0))
        }
        TXT => {
            let mut text = String::new();
            let mut i = 0;
            while i < data.len() {
                let n = data[i] as usize;
                text.push_str(&String::from_utf8_lossy(data.get(i + 1..i + 1 + n)?));
                i += 1 + n;
            }
            Some(text)
        }
        CAA => {
            let flags = *data.first()?;
            let tag_len = *data.get(1)? as usize;
            let tag = String::from_utf8_lossy(data.get(2..2 + tag_len)?);
            let value = String::from_utf8_lossy(data.get(2 + tag_len..)?);
            Some(format!("{flags} {tag} \"{value}\""))
        }
        _ => None,
    }
}

/// The name a reverse lookup of `ip` asks for.
fn reverse(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<String> = v6
                .octets()
                .iter()
                .rev()
                .map(|b| format!("{:x}.{:x}", b & 0xf, b >> 4))
                .collect();
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response to `question(name, kind, id)` carrying `records`, each
    /// owned by the question's name through a compression pointer.
    fn response(name: &str, kind: u16, id: u16, records: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut msg = question(name, kind, id);
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg[7] = records.len() as u8;
        for (t, data) in records {
            msg.extend_from_slice(&[0xc0, 0x0c]);
            msg.extend_from_slice(&t.to_be_bytes());
            msg.extend_from_slice(&[0, 1, 0, 0, 0x01, 0x2c]);
            msg.extend_from_slice(&(data.len() as u16).to_be_bytes());
            msg.extend_from_slice(data);
        }
        msg
    }

    #[test]
    fn reads_addresses_and_skips_other_kinds() {
        let msg = response(
            "example.com",
            A,
            7,
            &[(A, vec![93, 184, 215, 14]), (CNAME, vec![0xc0, 0x0c])],
        );
        let got = answers(&msg, 7, A).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "example.com");
        assert_eq!(got[0].value, "93.184.215.14");
        assert_eq!(got[0].ttl, 300);
    }

    #[test]
    fn reads_compressed_mx_and_txt() {
        let mut mx = vec![0, 10, 4];
        mx.extend_from_slice(b"mail");
        mx.extend_from_slice(&[0xc0, 0x0c]);
        let msg = response("example.com", MX, 9, &[(MX, mx)]);
        assert_eq!(answers(&msg, 9, MX).unwrap()[0].value, "10 mail.example.com");

        let mut txt = vec![6];
        txt.extend_from_slice(b"v=spf1");
        txt.push(5);
        txt.extend_from_slice(b" -all");
        let msg = response("example.com", TXT, 3, &[(TXT, txt)]);
        assert_eq!(answers(&msg, 3, TXT).unwrap()[0].value, "v=spf1 -all");
    }

    #[test]
    fn rejects_other_ids_and_loops() {
        let msg = response("example.com", A, 7, &[(A, vec![1, 2, 3, 4])]);
        assert_eq!(answers(&msg, 8, A), None);
        assert_eq!(name(&[0xc0, 0x00], 0), None);
    }

    #[test]
    fn reverse_names() {
        assert_eq!(reverse("10.0.0.5".parse().unwrap()), "5.0.0.10.in-addr.arpa");
        assert!(reverse("::1".parse().unwrap()).starts_with("1.0.0.0."));
    }
}
