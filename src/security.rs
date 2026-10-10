//! Plain-language security advice. Each finding says what it means and what
//! to do, and has a stable id so people can dismiss it.

use crate::model::{Device, DeviceKind, Finding, NetworkInfo, Severity};

fn finding(
    id: String,
    severity: Severity,
    title: String,
    explanation: &str,
    fix: &str,
    device: Option<&Device>,
) -> Finding {
    Finding {
        id,
        severity,
        title,
        explanation: explanation.to_string(),
        fix: fix.to_string(),
        device_id: device.map(|d| d.id.clone()),
        ignored: false,
    }
}

/// Findings about one device, based on what it exposes.
pub fn device_findings(d: &Device) -> Vec<Finding> {
    let mut out = Vec::new();
    let name = d.display_name().to_string();
    let mut add = |port: u16, severity: Severity, what: &str, explanation: &str, fix: &str| {
        if d.has_port(port) {
            out.push(finding(
                format!("port-{port}:{}", d.id),
                severity,
                format!("{name} has {what} open (port {port})"),
                explanation,
                fix,
                Some(d),
            ));
        }
    };

    add(
        23,
        Severity::High,
        "Telnet",
        "Telnet sends passwords as plain text and is the #1 way botnets such as Mirai take over cameras and routers, usually with factory-default passwords.",
        "Turn off Telnet in the device's settings and update its firmware. If you can't, change its password and move it to a guest or IoT network.",
    );
    add(
        2375,
        Severity::High,
        "the Docker API without encryption",
        "Anyone on your network can control Docker on this machine, which is the same as having full administrator access to it.",
        "Stop exposing Docker on TCP 2375. Use the local socket, or port 2376 with TLS certificates.",
    );
    add(
        21,
        Severity::Medium,
        "FTP",
        "FTP sends usernames, passwords and files unencrypted, so anyone on the network can read them.",
        "Switch to SFTP or SMB with encryption, or turn FTP off if you don't use it.",
    );
    add(
        3389,
        Severity::Medium,
        "Windows Remote Desktop",
        "Remote Desktop is a frequent target for password guessing and ransomware. On a home network it's fine only if you use it on purpose and have a strong password.",
        "If you don't use Remote Desktop, turn it off in Windows Settings > System > Remote Desktop. If you do, make sure Network Level Authentication is on and never forward this port on your router.",
    );
    add(
        5900,
        Severity::Medium,
        "VNC screen sharing",
        "VNC often has a weak or no password and lets someone see and control the screen.",
        "Turn off screen sharing if you don't use it, or set a strong password and limit it to specific users.",
    );
    add(
        6379,
        Severity::Medium,
        "a Redis database",
        "Redis usually has no password by default; anyone on the network can read or change its data, and sometimes run commands.",
        "Bind Redis to localhost or set `requirepass`, and enable protected mode.",
    );
    add(
        27017,
        Severity::Medium,
        "a MongoDB database",
        "Older or misconfigured MongoDB installs allow anyone to read and delete data without a password.",
        "Enable authentication and bind MongoDB to localhost unless other machines need it.",
    );
    add(
        9200,
        Severity::Medium,
        "Elasticsearch",
        "Elasticsearch without security enabled lets anyone on the network read or delete all of its data.",
        "Enable Elasticsearch security (it's on by default from version 8) or bind it to localhost.",
    );
    add(
        1883,
        Severity::Low,
        "an MQTT broker without TLS",
        "MQTT controls smart-home devices. Without a password, anything on your network can switch your devices or read their sensors.",
        "Require a username and password on the broker, or use port 8883 with TLS.",
    );
    add(
        5555,
        Severity::High,
        "Android debugging (ADB)",
        "ADB over the network gives full control of an Android device or TV to anyone on the network, without a password.",
        "Turn off 'ADB debugging' / 'Network debugging' in the device's Developer options.",
    );
    add(
        7547,
        Severity::Medium,
        "ISP remote management (TR-069)",
        "Your internet provider uses this to manage the router. It has had serious bugs in the past and should not be reachable from inside your home network.",
        "Make sure the router firmware is up to date; ask your provider if you're unsure.",
    );

    if d.has_port(445) && !matches!(d.kind, DeviceKind::Computer | DeviceKind::Nas | DeviceKind::Server) {
        out.push(finding(
            format!("port-445:{}", d.id),
            if d.kind == DeviceKind::Router { Severity::Medium } else { Severity::Low },
            format!("{name} shares files over SMB (port 445)"),
            "File sharing on a device that isn't a computer or NAS is easy to forget about, and often uses old, weak versions of SMB.",
            "If you don't use file sharing on this device, turn it off. Otherwise set a password and make sure SMBv1 is disabled.",
            Some(d),
        ));
    }
    if d.has_port(554) && d.kind == DeviceKind::Camera {
        out.push(finding(
            format!("port-554:{}", d.id),
            Severity::Low,
            format!("{name} serves a video stream (RTSP)"),
            "Camera streams are sometimes viewable without a password, or with the factory default one.",
            "Open the camera's settings and make sure the stream requires a password you chose. Update its firmware.",
            Some(d),
        ));
    }
    if d.is_gateway && d.has_port(80) && !d.has_port(443) {
        out.push(finding(
            format!("router-http:{}", d.id),
            Severity::Low,
            "Your router's admin page isn't encrypted".to_string(),
            "When you log in to the router, the password crosses the network as plain text. Anyone else on your Wi-Fi could capture it.",
            "Use the router's HTTPS admin page if it has one, and only log in from a wired connection or a network you trust. A firmware update may add HTTPS.",
            Some(d),
        ));
    }
    if d.is_gateway
        && d.upnp.as_ref().and_then(|u| u.device_type.as_deref()).is_some_and(|t| t.contains("InternetGatewayDevice"))
    {
        out.push(finding(
            format!("router-upnp:{}", d.id),
            Severity::Info,
            "UPnP port forwarding is turned on".to_string(),
            "UPnP lets games, video calls and smart devices open ports on your router automatically. It's convenient, but malware on any device can use it to expose itself to the internet.",
            "If nothing you use needs it (game consoles often do), turn UPnP off in the router's settings.",
            Some(d),
        ));
    }
    out
}

/// Findings about the network as a whole.
pub fn network_findings(info: &NetworkInfo, devices: &[Device], previous_gateway_mac: Option<&str>) -> Vec<Finding> {
    let mut out = Vec::new();

    if info.ip.is_link_local() {
        out.push(finding(
            "self-apipa".into(),
            Severity::High,
            "This computer didn't get an address from the router".into(),
            "Your address starts with 169.254, which means the router's DHCP server didn't answer. You're effectively offline.",
            "Unplug the router for 30 seconds and plug it back in. If that doesn't help, reconnect to the Wi-Fi or check the cable.",
            None,
        ));
    }

    // Two IPs claiming the router's hardware address = someone may be
    // intercepting traffic (ARP spoofing).
    if let Some(gw) = devices.iter().find(|d| d.is_gateway)
        && let Some(gw_mac) = &gw.mac
    {
        let impostors: Vec<&Device> = devices
            .iter()
            .filter(|d| !d.is_gateway && !d.is_self && d.mac.as_deref() == Some(gw_mac.as_str()))
            .collect();
        for imp in impostors {
            out.push(finding(
                    format!("arp-spoof:{}", imp.id),
                    Severity::High,
                    format!("{} is using the router's hardware address", imp.ip),
                    "Two addresses share the router's MAC. Some mesh systems and routers with several addresses do this legitimately, but it is also the signature of an 'ARP spoofing' attack, where a device intercepts everyone's traffic.",
                    "If you don't have a mesh or multi-address router, check which device has this address and disconnect it. Restarting the router clears spoofed entries.",
                    Some(imp),
                ));
        }
        if let Some(prev) = previous_gateway_mac
            && prev != gw_mac
        {
            out.push(finding(
                        format!("gateway-changed:{gw_mac}"),
                        Severity::Medium,
                        "Your router was swapped for a different one".into(),
                        "Your usual devices are here, but the router they connect through isn't the one NattoWok saw on this network before. That's expected if you got a new router or your provider replaced it. Otherwise, another device may be impersonating your router to intercept traffic.",
                        "If you didn't change your router, restart it and scan again. If this stays, unplug devices you don't recognise and check the router's admin page. Dismiss this once you know the new router is yours.",
                        Some(gw),
                    ));
        }
    }

    let unreviewed = devices.iter().filter(|d| !d.trusted && !d.is_self && !d.is_gateway).count();
    if unreviewed > 0 {
        out.push(finding(
            "unreviewed-devices".into(),
            Severity::Info,
            format!("{unreviewed} device{} you haven't reviewed yet", if unreviewed == 1 { "" } else { "s" }),
            "Marking devices you recognise as trusted means NattoWok can tell you right away when something new joins your network.",
            "Go through the device list and mark the ones you recognise as trusted. Give them names while you're at it.",
            None,
        ));
    }
    out
}

/// 100 minus penalties for the findings people haven't dismissed.
pub fn health_score<'a>(findings: impl Iterator<Item = &'a Finding>) -> u8 {
    let penalty: u32 = findings.filter(|f| !f.ignored).map(|f| f.severity.penalty()).sum();
    100u32.saturating_sub(penalty) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::OpenPort;
    use std::net::Ipv4Addr;

    fn dev(ip: u8, mac: &str) -> Device {
        Device::new(Ipv4Addr::new(192, 168, 1, ip), Some(mac.into()))
    }

    fn port(p: u16) -> OpenPort {
        OpenPort { port: p, service: String::new(), banner: None }
    }

    #[test]
    fn telnet_is_high() {
        let mut d = dev(9, "00:11:22:33:44:55");
        d.open_ports.push(port(23));
        let f = device_findings(&d);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].id, "port-23:00:11:22:33:44:55");
    }

    #[test]
    fn smb_on_computer_is_fine() {
        let mut d = dev(9, "00:11:22:33:44:55");
        d.kind = DeviceKind::Computer;
        d.open_ports.push(port(445));
        assert!(device_findings(&d).is_empty());
        d.kind = DeviceKind::Tv;
        assert_eq!(device_findings(&d).len(), 1);
    }

    #[test]
    fn detects_arp_spoofing() {
        let info = NetworkInfo {
            interface: "en0".into(),
            interface_label: None,
            ip: Ipv4Addr::new(192, 168, 1, 2),
            prefix: 24,
            scan_range: "192.168.1.0/24".into(),
            mac: None,
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            gateway_mac: None,
            dns_servers: vec![],
            mtu: None,
            link_speed_mbps: None,
            wireless: false,
        };
        let mut gw = dev(1, "00:11:22:33:44:55");
        gw.is_gateway = true;
        gw.trusted = true;
        let mut evil = dev(66, "00:11:22:33:44:55");
        evil.trusted = true;
        let f = network_findings(&info, &[gw.clone(), evil], None);
        assert!(f.iter().any(|f| f.id.starts_with("arp-spoof") && f.severity == Severity::High));
        let f = network_findings(&info, &[gw], Some("AA:AA:AA:AA:AA:AA"));
        assert!(f.iter().any(|f| f.id.starts_with("gateway-changed")));
    }

    #[test]
    fn score_ignores_dismissed() {
        let mut f = finding("x".into(), Severity::High, "t".into(), "", "", None);
        assert_eq!(health_score([f.clone()].iter()), 80);
        f.ignored = true;
        assert_eq!(health_score([f].iter()), 100);
    }
}
