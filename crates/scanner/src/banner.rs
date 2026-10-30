//! A service's greeting: what it sends as soon as a connection opens, before
//! it is sent anything. SSH, FTP, SMTP, POP3, IMAP and MySQL name themselves
//! this way, often with their version. Nothing is written to the socket.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// How long a service gets to speak first. HTTP and most others wait to be
/// asked, so this is the time a silent port costs.
pub const WAIT: Duration = Duration::from_millis(1500);

/// The greeting of each of `ports` that has one, read up to `concurrency` at
/// a time.
pub async fn grab_all(
    ip: IpAddr,
    ports: &[u16],
    concurrency: usize,
    connect: Duration,
) -> Vec<(u16, String)> {
    stream::iter(ports.iter().copied())
        .map(|port| async move { (port, grab(ip, port, connect).await) })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|(port, text)| async move { text.map(|t| (port, t)) })
        .collect()
        .await
}

/// Connects to `port` and reads what the service says first. `None` when it
/// says nothing readable within [`WAIT`].
pub async fn grab(ip: IpAddr, port: u16, connect: Duration) -> Option<String> {
    let stream = timeout(connect, TcpStream::connect(SocketAddr::new(ip, port)))
        .await
        .ok()?
        .ok()?;
    let read = async {
        let mut buf = [0u8; 512];
        loop {
            stream.readable().await.ok()?;
            match stream.try_read(&mut buf) {
                Ok(n) => return clean(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(_) => return None,
            }
        }
    };
    timeout(WAIT, read).await.ok()?
}

/// The first readable line of a greeting, at most 120 characters. Binary
/// greetings, such as MySQL's, carry their version as a printable run among
/// control bytes, so any byte that isn't printable ends a line.
pub fn clean(bytes: &[u8]) -> Option<String> {
    let text: String = bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '\n'
            }
        })
        .collect();
    let line = text.split('\n').map(str::trim).find(|l| l.len() >= 3)?;
    Some(line.chars().take(120).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_greeting_first_line() {
        assert_eq!(
            clean(b"SSH-2.0-OpenSSH_9.6\r\n").as_deref(),
            Some("SSH-2.0-OpenSSH_9.6")
        );
        assert_eq!(
            clean(b"220 mail.example ESMTP Postfix\r\n250 ok\r\n").as_deref(),
            Some("220 mail.example ESMTP Postfix")
        );
    }

    #[test]
    fn binary_greeting_printable_run() {
        assert_eq!(
            clean(b"\x4a\x00\x00\x00\x0a8.0.36\x00\x08\x00\x00\x00").as_deref(),
            Some("8.0.36")
        );
    }

    #[test]
    fn nothing_readable() {
        assert_eq!(clean(b""), None);
        assert_eq!(clean(b"\x00\x01\x02"), None);
    }
}
