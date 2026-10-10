//! Wake-on-LAN magic packets.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use crate::oui;

pub fn magic_packet(mac: [u8; 6]) -> Vec<u8> {
    let mut p = vec![0xFF; 6];
    for _ in 0..16 {
        p.extend_from_slice(&mac);
    }
    p
}

/// Sends the packet to the subnet broadcast and the global broadcast, on the
/// two ports devices commonly listen on.
pub async fn wake(mac: &str, subnet_broadcast: Ipv4Addr) -> Result<()> {
    let octets = oui::octets(mac).with_context(|| format!("{mac:?} isn't a valid MAC address"))?;
    let packet = magic_packet(octets);
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    let mut sent = false;
    for addr in [subnet_broadcast, Ipv4Addr::BROADCAST] {
        for port in [9, 7] {
            sent |= socket.send_to(&packet, SocketAddr::from((addr, port))).await.is_ok();
        }
    }
    anyhow::ensure!(sent, "couldn't send the wake-up packet on this network");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_magic_packet() {
        let p = magic_packet([1, 2, 3, 4, 5, 6]);
        assert_eq!(p.len(), 102);
        assert_eq!(&p[..6], &[0xFF; 6]);
        assert_eq!(&p[6..12], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&p[96..], &[1, 2, 3, 4, 5, 6]);
    }
}
