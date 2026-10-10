//! Minimal DNS wire format, shared by mDNS discovery, reverse lookups and the
//! DNS benchmark in the network doctor.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use tokio::net::UdpSocket;

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
    Txt(Vec<String>),
    Srv { port: u16, target: String },
    Other,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub id: u16,
    pub is_response: bool,
    pub rcode: u8,
    /// Answer, authority and additional records together.
    pub records: Vec<Record>,
}

fn push_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        let bytes = &label.as_bytes()[..label.len().min(63)];
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0);
}

/// Builds a query with one or more questions.
pub fn build_query(id: u16, questions: &[(&str, u16)], recursion: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&(if recursion { 0x0100u16 } else { 0 }).to_be_bytes());
    buf.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for (name, qtype) in questions {
        push_name(&mut buf, name);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
    }
    buf
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).context("truncated")?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from(self.u8()?) << 8 | u16::from(self.u8()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from(self.u16()?) << 16 | u32::from(self.u16()?))
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).context("overflow")?;
        let out = self.buf.get(self.pos..end).context("truncated")?;
        self.pos = end;
        Ok(out)
    }

    fn name(&mut self) -> Result<String> {
        let (name, next) = read_name(self.buf, self.pos)?;
        self.pos = next;
        Ok(name)
    }
}

/// Reads a possibly-compressed name at `pos`; returns it and the offset just
/// past it in the original (uncompressed) position.
fn read_name(buf: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos).context("truncated name")?;
        match len {
            0 => {
                end.get_or_insert(pos + 1);
                break;
            }
            l if l & 0xC0 == 0xC0 => {
                let lo = *buf.get(pos + 1).context("truncated pointer")?;
                end.get_or_insert(pos + 2);
                pos = usize::from(l & 0x3F) << 8 | usize::from(lo);
                jumps += 1;
                ensure!(jumps < 32, "compression loop");
            }
            l => {
                let l = usize::from(l);
                let label = buf.get(pos + 1..pos + 1 + l).context("truncated label")?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                pos += 1 + l;
                ensure!(labels.len() < 128, "name too long");
            }
        }
    }
    Ok((labels.join("."), end.unwrap_or(pos)))
}

pub fn parse(buf: &[u8]) -> Result<Message> {
    let mut r = Reader { buf, pos: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    let qd = r.u16()?;
    let counts = [r.u16()?, r.u16()?, r.u16()?];
    for _ in 0..qd {
        r.name()?;
        r.bytes(4)?;
    }
    let mut records = Vec::new();
    for _ in 0..counts.iter().map(|c| usize::from(*c)).sum::<usize>() {
        let name = r.name()?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        let _ttl = r.u32()?;
        let len = usize::from(r.u16()?);
        let start = r.pos;
        let rdata = r.bytes(len)?;
        let data = match rtype {
            TYPE_A if len == 4 => RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            TYPE_AAAA if len == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                RData::Aaaa(Ipv6Addr::from(o))
            }
            TYPE_PTR => RData::Ptr(read_name(buf, start)?.0),
            TYPE_SRV if len >= 7 => RData::Srv {
                port: u16::from(rdata[4]) << 8 | u16::from(rdata[5]),
                target: read_name(buf, start + 6)?.0,
            },
            TYPE_TXT => {
                let mut strings = Vec::new();
                let mut i = 0;
                while i < rdata.len() {
                    let l = usize::from(rdata[i]);
                    let s = rdata.get(i + 1..i + 1 + l).context("bad txt")?;
                    if !s.is_empty() {
                        strings.push(String::from_utf8_lossy(s).into_owned());
                    }
                    i += 1 + l;
                }
                RData::Txt(strings)
            }
            _ => RData::Other,
        };
        records.push(Record { name, rtype, data });
    }
    Ok(Message { id, is_response: flags & 0x8000 != 0, rcode: (flags & 0x000F) as u8, records })
}

pub fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

pub fn random_id() -> u16 {
    let mut b = [0u8; 2];
    let _ = getrandom::fill(&mut b);
    u16::from_ne_bytes(b)
}

/// Sends one query and waits for the matching answer.
pub async fn query(server: SocketAddr, name: &str, qtype: u16, timeout: Duration) -> Result<(Message, Duration)> {
    let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    let id = random_id();
    let packet = build_query(id, &[(name, qtype)], true);
    let start = Instant::now();
    socket.send(&packet).await?;
    let mut buf = [0u8; 2048];
    let deadline = start + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("no answer from {server}");
        }
        let n = tokio::time::timeout(remaining, socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("no answer from {server}"))??;
        if let Ok(msg) = parse(&buf[..n])
            && msg.id == id
            && msg.is_response
        {
            return Ok((msg, start.elapsed()));
        }
    }
}

/// Reverse lookup of a LAN address. Home routers usually answer these with the
/// name each device gave the DHCP server.
pub async fn reverse_lookup(server: SocketAddr, ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let (msg, _) = query(server, &reverse_name(ip), TYPE_PTR, timeout).await.ok()?;
    msg.records.into_iter().find_map(|r| match r.data {
        RData::Ptr(name) if !name.is_empty() => Some(name),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_query() {
        let q = build_query(0x1234, &[("example.com", TYPE_A)], true);
        let msg = parse(&q).unwrap();
        assert_eq!(msg.id, 0x1234);
        assert!(!msg.is_response);
        assert!(msg.records.is_empty());
    }

    #[test]
    fn parses_compressed_answers() {
        // Response for _ipp._tcp.local PTR -> "Office Printer._ipp._tcp.local" plus SRV, TXT and A.
        let mut b = vec![0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0];
        let name_at = b.len();
        push_name(&mut b, "_ipp._tcp.local");
        b.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 120]);
        let mut rdata = vec![14];
        rdata.extend_from_slice(b"Office Printer");
        rdata.extend_from_slice(&[0xC0, name_at as u8]);
        b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        let inst_at = b.len();
        b.extend_from_slice(&rdata);
        // SRV
        b.extend_from_slice(&[0xC0, inst_at as u8, 0, 33, 0, 1, 0, 0, 0, 120]);
        let mut srv = vec![0, 0, 0, 0, 0x02, 0x77];
        srv.extend_from_slice(&[3, b'n', b'p', b'i', 0xC0, (name_at + 10) as u8]);
        b.extend_from_slice(&(srv.len() as u16).to_be_bytes());
        b.extend_from_slice(&srv);
        // TXT
        b.extend_from_slice(&[0xC0, inst_at as u8, 0, 16, 0, 1, 0, 0, 0, 120]);
        let txt = b"\x0aty=HP 4100\x07pdl=pdf";
        b.extend_from_slice(&(txt.len() as u16).to_be_bytes());
        b.extend_from_slice(txt);
        // A
        push_name(&mut b, "npi.local");
        b.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 30]);

        let msg = parse(&b).unwrap();
        assert!(msg.is_response);
        assert_eq!(msg.records.len(), 4);
        assert_eq!(msg.records[0].data, RData::Ptr("Office Printer._ipp._tcp.local".into()));
        assert_eq!(msg.records[1].data, RData::Srv { port: 631, target: "npi.local".into() });
        assert_eq!(msg.records[2].data, RData::Txt(vec!["ty=HP 4100".into(), "pdl=pdf".into()]));
        assert_eq!(msg.records[3].data, RData::A(Ipv4Addr::new(192, 168, 1, 30)));
    }

    #[test]
    fn rejects_pointer_loops_and_truncation() {
        let mut b = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        b.extend_from_slice(&[0xC0, 12]);
        assert!(parse(&b).is_err());
        assert!(parse(&[0, 1, 2]).is_err());
    }

    #[test]
    fn reverse_names() {
        assert_eq!(reverse_name(Ipv4Addr::new(192, 168, 1, 7)), "7.1.168.192.in-addr.arpa");
    }
}
